//! Round-trips each client-side signing export through the verifiers.
//!
//! These run natively: the exports only construct a `JsError` on failure, so
//! the success paths need no JS host.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{bootstrap, commitment, DeviceCertificate, Link};
use cygnus_wasm::{
    content_hash, create_device_certificate, parse_link, public_key, rotation_commitment,
    sign_event, user_successor, verify_chain, verify_device_signature,
    verify_user_principal_response,
};
use ed25519_zebra::SigningKey;
use rezzy_json::Value;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test;

const DISPLAY: &str = "@alice:chat.example.org";

fn seed(byte: u8) -> String {
    B64.encode([byte; 32])
}

struct Identity {
    principal: String,
    genesis: String,
    master_pub: String,
    custodian: String,
}

/// §7: the client sends its master key and rotation commitment; a server
/// (simulated here with `bootstrap::user_genesis`) answers with the genesis.
fn bootstrap_identity() -> Identity {
    let master_pub = public_key(&seed(0x2F)).unwrap();
    let custodian = [0x5A; 32];
    let genesis = bootstrap::user_genesis(
        &bootstrap::RotationKey::from_seed([0x21; 32]),
        custodian,
        <[u8; 32]>::try_from(B64.decode(&master_pub).unwrap().as_slice()).unwrap(),
        DISPLAY,
    )
    .unwrap();
    let principal = genesis.principal().to_id();
    let accepted = verify_user_principal_response(
        &seed(0x21),
        &master_pub,
        &principal,
        vec![genesis.to_b64()],
    )
    .unwrap();
    assert_eq!(accepted, genesis.to_b64());
    Identity {
        principal,
        genesis: accepted,
        master_pub,
        custodian: B64.encode(custodian),
    }
}

#[test]
fn public_key_matches_ed25519_zebra() {
    let key = SigningKey::from([0x07; 32]);
    assert_eq!(
        public_key(&seed(0x07)).unwrap(),
        B64.encode(<[u8; 32]>::from(key.verification_key()))
    );
}

#[test]
fn rotation_commitment_commits_to_the_rotation_public_key() {
    let rotation = bootstrap::RotationKey::from_seed([0x21; 32]);
    assert_eq!(
        rotation_commitment(&seed(0x21)).unwrap(),
        B64.encode(commitment(&rotation.public_key()))
    );
}

#[test]
fn accepted_principal_response_verifies_as_a_chain() {
    let identity = bootstrap_identity();
    assert_eq!(
        verify_chain(vec![identity.genesis.clone()]).unwrap(),
        identity.principal
    );
    let genesis = Link::from_b64(&identity.genesis).unwrap();
    assert_eq!(
        B64.encode(genesis.body.next_commit),
        rotation_commitment(&seed(0x21)).unwrap()
    );
}

#[test]
fn device_certificate_verifies_under_the_master_key() {
    let identity = bootstrap_identity();
    let certificate = create_device_certificate(
        &identity.principal,
        &seed(0x2F),
        &seed(0x51),
        "WEB01",
        &seed(0x52),
    )
    .unwrap();
    let master =
        <[u8; 32]>::try_from(B64.decode(&identity.master_pub).unwrap().as_slice()).unwrap();
    let verified = DeviceCertificate::parse_and_verify(
        &Value::parse_strict(&certificate).unwrap(),
        &identity.principal,
        &master,
    )
    .unwrap();
    assert_eq!(verified.device_id, "WEB01");
    assert_eq!(
        B64.encode(verified.device_key),
        public_key(&seed(0x52)).unwrap()
    );
}

#[test]
fn signed_event_carries_its_hash_and_a_verifiable_device_signature() {
    let identity = bootstrap_identity();
    let certificate = create_device_certificate(
        &identity.principal,
        &seed(0x2F),
        &seed(0x51),
        "WEB01",
        &seed(0x52),
    )
    .unwrap();
    let event = format!(
        r#"{{"type":"m.room.message","sender":"{}","room_id":"!room","content":{{"msgtype":"m.text","body":"hi"}},"origin_server_ts":1,"depth":2,"prev_events":[],"auth_events":[],"device_certificate":{certificate}}}"#,
        identity.principal
    );
    let signed = sign_event(&event, &identity.principal, "WEB01", &seed(0x52)).unwrap();

    verify_device_signature(
        &signed,
        &identity.principal,
        "WEB01",
        &public_key(&seed(0x52)).unwrap(),
    )
    .unwrap();
    let parsed = Value::parse_strict(&signed).unwrap();
    assert_eq!(
        parsed["hashes"]["sha256"].as_str(),
        Some(content_hash(&signed).unwrap().as_str())
    );
}

/// Exercises the exported `signEvent`: a matching certificate is accepted and
/// a certificate for another device is rejected.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen_test]
fn sign_event_accepts_a_matching_certificate_and_rejects_a_tampered_one() {
    let identity = bootstrap_identity();
    let certificate = create_device_certificate(
        &identity.principal,
        &seed(0x2F),
        &seed(0x51),
        "WEB01",
        &seed(0x52),
    )
    .unwrap();
    let event = format!(
        r#"{{"type":"m.room.message","sender":"{}","room_id":"!room","content":{{"msgtype":"m.text","body":"hi"}},"origin_server_ts":1,"depth":2,"prev_events":[],"auth_events":[],"device_certificate":{certificate}}}"#,
        identity.principal
    );

    let signed = sign_event(&event, &identity.principal, "WEB01", &seed(0x52)).unwrap();
    verify_device_signature(
        &signed,
        &identity.principal,
        "WEB01",
        &public_key(&seed(0x52)).unwrap(),
    )
    .unwrap();

    let mut invalid = Value::parse_strict(&event).unwrap();
    invalid["device_certificate"]["device_id"] = "OTHER".into();
    let invalid = rezzy_json::to_canonical_string(&invalid).unwrap();
    assert!(sign_event(&invalid, &identity.principal, "WEB01", &seed(0x52)).is_err());
}

#[test]
fn user_successor_extends_the_chain() {
    let identity = bootstrap_identity();
    let next = user_successor(
        &identity.genesis,
        &seed(0x21),
        &seed(0x22),
        &identity.custodian,
        &identity.master_pub,
        DISPLAY,
    )
    .unwrap();
    assert_eq!(
        verify_chain(vec![identity.genesis.clone(), next.clone()]).unwrap(),
        identity.principal
    );
    let link = Link::from_b64(&next).unwrap();
    assert_eq!(link.body.height, 1);
    assert_eq!(
        B64.encode(link.body.next_commit),
        rotation_commitment(&seed(0x22)).unwrap()
    );
}

/// Parses genesis and successor user links and reports their identity fields.
#[test]
fn parse_link_reports_user_fields() {
    let identity = bootstrap_identity();
    let next = user_successor(
        &identity.genesis,
        &seed(0x21),
        &seed(0x22),
        &identity.custodian,
        &identity.master_pub,
        DISPLAY,
    )
    .unwrap();
    let custodian = cygnus_core::Principal {
        kind: cygnus_core::Kind::Server,
        root: [0x5A; 32],
    }
    .to_id();
    for (link, height) in [(&identity.genesis, "0"), (&next, "1")] {
        let parsed = Value::parse_strict(&parse_link(link).unwrap()).unwrap();
        assert_eq!(parsed["kind"].as_str(), Some("user"));
        assert_eq!(parsed["height"].as_str(), Some(height));
        assert_eq!(
            parsed["principal"].as_str(),
            Some(identity.principal.as_str())
        );
        assert_eq!(parsed["custodian"].as_str(), Some(custodian.as_str()));
        assert_eq!(
            parsed["master_key"].as_str(),
            Some(identity.master_pub.as_str())
        );
        assert_eq!(parsed["display_user_id"].as_str(), Some(DISPLAY));
        assert!(parsed["server_name"].is_null());
        assert!(parsed["online_key"].is_null());
    }
}

/// Parses a server link and confirms the custodial relationship to a user link.
#[test]
fn parse_link_reports_server_fields_and_the_custodian_principal() {
    let online = SigningKey::from([0x01; 32]);
    let server = bootstrap::server_genesis(
        &bootstrap::RotationKey::from_seed([0x02; 32]),
        &online,
        "chat.example.org",
    )
    .unwrap();
    let parsed = Value::parse_strict(&parse_link(&server.to_b64()).unwrap()).unwrap();
    assert_eq!(parsed["kind"].as_str(), Some("server"));
    assert_eq!(parsed["height"].as_str(), Some("0"));
    let principal = server.principal().to_id();
    assert_eq!(parsed["principal"].as_str(), Some(principal.as_str()));
    assert_eq!(parsed["server_name"].as_str(), Some("chat.example.org"));
    assert_eq!(
        parsed["online_key"].as_str(),
        Some(public_key(&seed(0x01)).unwrap().as_str())
    );
    for field in ["custodian", "master_key", "display_user_id"] {
        assert!(parsed[field].is_null(), "{field}");
    }

    // The assisted-mode check: a user genesis custodied by this server names
    // the server's principal as its custodian.
    let user = bootstrap::user_genesis(
        &bootstrap::RotationKey::from_seed([0x21; 32]),
        server.principal().root,
        [0x2F; 32],
        DISPLAY,
    )
    .unwrap();
    let user = Value::parse_strict(&parse_link(&user.to_b64()).unwrap()).unwrap();
    assert_eq!(user["custodian"].as_str(), Some(principal.as_str()));
}
