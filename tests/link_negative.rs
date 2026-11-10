//! Link-layer negative checks from `pid_vectors.json` / `pid_ref.py`:
//! "user rotation cannot replace its committed master key",
//! "online key cannot sign a rotation" and
//! "tampered body fails rotation signature".
//!
//! Fixtures are read from the vendored vectors, not retyped.

use cygnus_core::sig::SigningKey;
use cygnus_core::{link::Payload, Error, Link};
use rezzy_json::Value;

fn link(name: &str) -> Link {
    let text = std::fs::read_to_string("tests/vectors/pid_vectors.json").unwrap();
    let vectors = Value::parse(&text).unwrap();
    let b64 = vectors
        .get("links")
        .and_then(|links| links.get(name))
        .and_then(|link| link.get("link_b64u"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing link {name}"))
        .to_owned();
    Link::from_b64(&b64).unwrap()
}

fn key(byte: u8) -> SigningKey {
    SigningKey::from([byte; 32])
}

#[test]
#[ignore = "vendored vectors carry Ed25519 signatures; regenerate for the WOTS+ format"]
fn user_rotation_cannot_replace_its_committed_master_key() {
    let genesis = link("U0_user_genesis");
    let migration = link("U1_user_migration");
    genesis.verify_genesis().unwrap();
    migration.verify_successor(&genesis).unwrap();

    // Same successor, but with a different master key, signed by the key the
    // genesis committed to (Appendix A seed 0x21), so only the master-key
    // rule can reject it.
    let mut body = migration.body.clone();
    let Payload::User { master_key, .. } = &mut body.payload else {
        panic!("user link expected");
    };
    *master_key = Some([0x77; 32]);
    let forged = Link::sign_successor(body, &key(0x21)).unwrap();
    assert_eq!(
        forged.verify_successor(&genesis),
        Err(Error::Successor("master_key"))
    );
}

#[test]
#[ignore = "vendored vectors carry Ed25519 signatures; regenerate for the WOTS+ format"]
fn online_key_cannot_sign_a_rotation() {
    let genesis = link("A0_server_genesis");
    let rotation = link("A1_server_rotation");
    rotation.verify_successor(&genesis).unwrap();

    // The server's online key (seed 0x01) signs the rotation instead of the
    // pre-committed rotation key. Its hash is not the genesis commitment.
    let stolen = Link::sign_successor(rotation.body.clone(), &key(0x01)).unwrap();
    assert_eq!(stolen.verify_successor(&genesis), Err(Error::Commitment));
}

#[test]
#[ignore = "vendored vectors carry Ed25519 signatures; regenerate for the WOTS+ format"]
fn tampered_body_fails_rotation_signature() {
    let genesis = link("A0_server_genesis");
    let rotation = link("A1_server_rotation");

    let mut body = rotation.body_bytes.clone();
    *body.last_mut().unwrap() = b'x';
    let tampered = Link::parse(&[body, rotation.trailer.clone()].concat()).unwrap();
    assert_eq!(tampered.verify_successor(&genesis), Err(Error::Signature));
}
