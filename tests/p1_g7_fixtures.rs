//! P1 negative fixtures (checks 1–3) and the G7 merge signing-height and
//! chain-binding checks (29–30), derived from the vendored P1 PDUs.
//!
//! Each negative case changes one thing in an upstream PDU and re-signs it
//! with the reference model's deterministic seeds: server A's online keys are
//! `[0x01; 32]` (h=0, retired) and `[0x03; 32]` (h=1, current).

use cygnus_core::{
    auth::{
        authorize_active_epoch, authorize_create, authorize_user_event, AuthContext, MemberState,
    },
    bundle::{signer_chain, verify_epoch_custodian_signature},
    envelope,
    link::Link,
    Error,
};
use ed25519_zebra::SigningKey;
use rezzy_json::Value;

fn events() -> Vec<Value> {
    Value::parse(include_str!("vectors/pid_pdu_vectors.json"))
        .unwrap()
        .get("events")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|event| event.get("pdu").unwrap().clone())
        .collect()
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn server_a(events: &[Value]) -> String {
    events[2]
        .get("state_key")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

fn server_b(events: &[Value]) -> String {
    events[9]
        .get("state_key")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

fn id(event: &Value) -> String {
    envelope::event_id(event).unwrap()
}

/// Drop `server`'s signatures and re-sign as `server` at `height` with `key`.
fn resign(event: &mut Value, server: &str, height: u64, key: &SigningKey) {
    event
        .get_mut("signatures")
        .and_then(Value::as_object_mut)
        .unwrap()
        .remove(server);
    envelope::set_content_hash(event).unwrap();
    envelope::sign_custodian(event, server, height, key).unwrap();
}

fn links(event: &Value, field: &str) -> Vec<Link> {
    event["content"][field]
        .as_array()
        .unwrap()
        .iter()
        .map(|link| Link::from_b64(link.as_str().unwrap()).unwrap())
        .collect()
}

/// The P1 room after the create, both genesis introductions and A's advance.
fn founded(events: &[Value]) -> AuthContext {
    let create = authorize_create(&events[0], &id(&events[0])).unwrap();
    let mut context = AuthContext::default();
    context.creators.insert(create.user_principal.to_id());
    for event in &events[1..=3] {
        let epoch = authorize_active_epoch(event, &id(event), &context).unwrap();
        context.insert_epoch(epoch);
    }
    context
}

// --- P1 -------------------------------------------------------------------

#[test]
fn p1_create_signed_with_the_retired_server_key_is_rejected() {
    let events = events();
    let server = server_a(&events);

    // The creator chain ends at A1, so only the h=1 key may sign the create.
    // Signing at h=0 with the retired key leaves no h=1 signature.
    let mut retired = events[0].clone();
    resign(&mut retired, &server, 0, &key(0x01));
    assert_eq!(
        authorize_create(&retired, &id(&retired)).err(),
        Some(Error::Signature)
    );

    // Labelling the retired key's signature as h=1 does not help.
    let mut relabelled = events[0].clone();
    resign(&mut relabelled, &server, 1, &key(0x01));
    assert_eq!(
        authorize_create(&relabelled, &id(&relabelled)).err(),
        Some(Error::Signature)
    );

    // Control: the same re-signing with the current key is accepted.
    let mut current = events[0].clone();
    resign(&mut current, &server, 1, &key(0x03));
    authorize_create(&current, &id(&current)).unwrap();
}

#[test]
fn p1_a_second_genesis_introduction_for_server_a_is_rejected() {
    let events = events();
    let context = founded(&events);
    let server = server_a(&events);
    assert_eq!(context.server_epoch(&server).unwrap().tip().body.height, 1);

    // Re-introduce A from genesis (links [A0], signer_links [A0, A1]) as a
    // new event, signed with A's current key.
    let mut again = events[2].clone();
    again["origin_server_ts"] = 1_792_860_000_100u64.into();
    resign(&mut again, &server, 1, &key(0x03));
    assert_ne!(id(&again), id(&events[2]));

    // A0 is checked as a successor of the selected tip A1 and fails on
    // height (the reference model's "genesis cannot have a parent").
    assert_eq!(
        authorize_active_epoch(&again, &id(&again), &context).err(),
        Some(Error::Successor("height"))
    );
}

#[test]
fn p1_malformed_device_certificate_is_rejected() {
    let events = events();
    let mut context = founded(&events);
    let alice = events[0]["sender"].as_str().unwrap().to_owned();
    context.members.insert(
        alice,
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(server_a(&events)),
        },
    );
    authorize_user_event(&events[7], &context).unwrap();

    let mut message = events[7].clone();
    message["device_certificate"]["device_key"] = "!".into();
    resign(&mut message, &server_a(&events), 1, &key(0x03));
    assert_eq!(
        authorize_user_event(&message, &context),
        Err(Error::Certificate("invalid base64url key"))
    );
}

// --- G7 merge -------------------------------------------------------------

#[test]
fn g7_create_and_signer_links_use_the_actual_server_signing_height() {
    let events = events();
    let server = server_a(&events);

    // The create is signed at A's creator-chain tip (h=1), not at genesis.
    let creator_links: Vec<Link> = events[0]["content"]["creator_links"]["server"]
        .as_array()
        .unwrap()
        .iter()
        .map(|link| Link::from_b64(link.as_str().unwrap()).unwrap())
        .collect();
    assert_eq!(creator_links.last().unwrap().body.height, 1);
    assert!(events[0]["signatures"][server.as_str()]
        .get("ed25519:1")
        .is_some());

    // A's genesis introduction carries subject links [A0] but is signed at
    // h=1: its signer_links run ahead of the introduced subject chain.
    for event in [&events[1], &events[2]] {
        let signer = signer_chain(event).unwrap();
        assert_eq!(signer.last().unwrap().body.height, 1);
        verify_epoch_custodian_signature(event, &signer).unwrap();
        // Truncating the signer chain to the subject height breaks it.
        assert_eq!(
            verify_epoch_custodian_signature(event, &signer[..1]),
            Err(Error::Signature)
        );
    }
    assert_eq!(links(&events[2], "links").last().unwrap().body.height, 0);
}

#[test]
fn g7_creator_and_signer_chains_are_bound_to_the_subject_server() {
    let events = events();
    let a = server_a(&events);
    let b = server_b(&events);

    // A's signature copied under B's name: B's chain is not the creator
    // chain, so the create still lacks A's signature.
    let mut foreign_create = events[0].clone();
    let signatures = foreign_create
        .get_mut("signatures")
        .and_then(Value::as_object_mut)
        .unwrap();
    let a_signature = signatures.remove(&a).unwrap();
    signatures.insert(b.clone(), a_signature);
    assert_eq!(
        authorize_create(&foreign_create, &id(&foreign_create)).err(),
        Some(Error::Signature)
    );

    // An epoch for A cannot be signed through B's chain, and B's epoch cannot
    // borrow A's chain, even when the signature itself is valid.
    let b_chain = signer_chain(&events[9]).unwrap();
    assert_eq!(
        verify_epoch_custodian_signature(&events[2], &b_chain),
        Err(Error::Epoch("custodian principal does not match event"))
    );
    let a_chain = signer_chain(&events[2]).unwrap();
    assert_eq!(
        verify_epoch_custodian_signature(&events[9], &a_chain),
        Err(Error::Epoch("custodian principal does not match event"))
    );
    // Controls: each epoch verifies through its own server's chain.
    verify_epoch_custodian_signature(&events[2], &a_chain).unwrap();
    verify_epoch_custodian_signature(&events[9], &b_chain).unwrap();
}
