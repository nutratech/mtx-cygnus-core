//! Conformance vector for the version-1 group blob.
//!
//! `fixtures/group-blob-v1.b64` is one real export: Alice created the room and
//! committed an Add for Bob, so it holds two states (the retained genesis and
//! the epoch-1 tip) at `seq` 2. `OpenMLS` output is randomized, so the vector
//! is captured once instead of derived. The blob is unreleased and mutates in
//! place, so regenerate it whenever the v1 layout changes:
//!
//! ```text
//! CYGNUS_REGEN_BLOB_VECTOR=1 cargo test -p cygnus-dmls --test blob_vector
//! ```
//!
//! The seeds in the fixture are test constants; the blob holds no real secret.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_dmls::{
    content::{ExtremityRef, KeyPackageContent},
    engine,
    registry::{GroupEntry, Registry, BLOB_VERSION},
    wire, MemberIdentity,
};

const ROOM: &str = "!vector:example.org";
const FIXTURE: &str = "tests/fixtures/group-blob-v1.b64";

fn principal(byte: u8) -> String {
    format!("@{}", B64.encode([byte; 32]))
}

fn generate() -> String {
    let group_id = wire::group_id(ROOM);
    let alice = engine::Signer::new(MemberIdentity::new(principal(1), "A1").unwrap(), [1u8; 32]);
    let bob = engine::Signer::new(MemberIdentity::new(principal(2), "B1").unwrap(), [2u8; 32]);
    let (branch, summary) = engine::create_group(&alice, group_id).unwrap();
    let mut entry = GroupEntry::new(group_id);
    entry.insert_root(summary.commit_id, branch).unwrap();
    let package = engine::key_package(&bob, None).unwrap();
    let bytes = KeyPackageContent::parse(&package.content, &bob.member_key())
        .unwrap()
        .key_package;
    engine::commit_add(
        &mut entry,
        &alice,
        &ExtremityRef::genesis(&group_id),
        &bytes,
    )
    .unwrap();
    B64.encode(entry.export())
}

fn fixture() -> Vec<u8> {
    if std::env::var_os("CYGNUS_REGEN_BLOB_VECTOR").is_some() {
        std::fs::write(FIXTURE, generate()).unwrap();
    }
    let text = std::fs::read_to_string(FIXTURE).expect("fixture (see module docs to regenerate)");
    B64.decode(text.trim()).unwrap()
}

/// Re-seal a mutated body with a valid trailing hash.
fn reseal(mut body: Vec<u8>) -> Vec<u8> {
    let hash = blake3::hash(&body);
    body.extend_from_slice(hash.as_bytes());
    body
}

#[test]
fn fixture_imports_and_re_exports_byte_for_byte() {
    let blob = fixture();
    assert_eq!(&blob[..4], b"CYDM");
    assert_eq!(u16::from_be_bytes([blob[4], blob[5]]), BLOB_VERSION);
    let mut registry = Registry::new();
    let info = registry.import(&blob).unwrap();
    assert_eq!(info.group_id, wire::group_id(ROOM));
    assert_eq!(info.seq, 2);
    assert_eq!(info.extremities.len(), 1);
    assert_eq!(registry.export(&info.group_id).unwrap(), blob);
    // The same-seq idempotency rule depends on that identity.
    assert!(registry.import(&blob).is_ok());
}

#[test]
fn damaged_blobs_are_refused_with_stable_codes() {
    let blob = fixture();
    let code = |bytes: &[u8]| {
        Registry::new()
            .import(bytes)
            .map(|_| "ok")
            .map_err(|e| e.code())
            .unwrap_err()
    };
    for at in [0, 10, blob.len() / 2, blob.len() - 1] {
        let mut flipped = blob.clone();
        flipped[at] ^= 1;
        assert_eq!(code(&flipped), "bad_state", "flip at {at}");
    }
    assert_eq!(code(&blob[..blob.len() - 1]), "bad_state");
    assert_eq!(code(&[]), "bad_state");

    let body = blob[..blob.len() - 32].to_vec();
    let mut magic = body.clone();
    magic[0] ^= 1;
    assert_eq!(code(&reseal(magic)), "bad_state");
    let mut version = body;
    version[4..6].copy_from_slice(&(BLOB_VERSION + 1).to_be_bytes());
    assert_eq!(code(&reseal(version)), "unsupported_version");
}
