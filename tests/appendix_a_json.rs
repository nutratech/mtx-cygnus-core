//! Appendix A vectors consumed directly from the upstream JSON fixture.

use cygnus_core::{link::verify_slice, Link};
use rezzy_json::Value;

fn vectors() -> Value {
    Value::parse(include_str!("vectors/pid_vectors.json")).expect("valid upstream JSON")
}

fn string<'a>(value: &'a Value, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

fn hex32(value: &str) -> [u8; 32] {
    hex::decode(value)
        .expect("hex")
        .try_into()
        .expect("32-byte value")
}

#[test]
#[ignore = "vendored vectors carry Ed25519 signatures; regenerate for the WOTS+ format"]
fn parses_and_verifies_every_appendix_a_link_vector() {
    let vectors = vectors();
    let links = vectors.get("links").and_then(Value::as_object).unwrap();
    let mut parsed = std::collections::BTreeMap::new();

    for (name, fixture) in links {
        let link = Link::from_b64(string(fixture, "link_b64u"))
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(
            link.to_b64(),
            string(fixture, "link_b64u"),
            "{name} encoding"
        );
        assert_eq!(
            link.body_bytes.len() as u64,
            fixture.get("body_len").unwrap().as_u64().unwrap()
        );
        assert_eq!(
            link.trailer.len() as u64,
            fixture.get("trailer_len").unwrap().as_u64().unwrap()
        );
        assert_eq!(
            link.body_bytes,
            hex::decode(string(fixture, "body_hex")).unwrap()
        );
        assert_eq!(
            link.trailer,
            hex::decode(string(fixture, "trailer_hex")).unwrap()
        );
        assert_eq!(link.digest(), hex32(string(fixture, "digest_hex")));
        assert_eq!(
            link.body.next_commit,
            hex32(string(fixture, "next_commit_hex"))
        );
        // Only genesis fixtures record `principal`; later links inherit the
        // genesis principal through `root`; `verify_slice` enforces continuity.
        if let Some(principal) = fixture.get("principal").and_then(Value::as_str) {
            assert_eq!(
                &link.principal().to_id()[1..],
                principal,
                "{name} principal"
            );
        }
        parsed.insert(name.as_str(), link);
    }

    parsed["A0_server_genesis"].verify_genesis().unwrap();
    parsed["B0_server_genesis"].verify_genesis().unwrap();
    parsed["U0_user_genesis"].verify_genesis().unwrap();
    verify_slice(
        &parsed["A0_server_genesis"],
        std::slice::from_ref(&parsed["A1_server_rotation"]),
    )
    .unwrap();
    verify_slice(
        &parsed["U0_user_genesis"],
        std::slice::from_ref(&parsed["U1_user_migration"]),
    )
    .unwrap();
}

#[test]
fn appendix_a_reference_model_checks_all_pass() {
    let vectors = vectors();
    let checks = vectors.get("checks").and_then(Value::as_array).unwrap();
    assert!(!checks.is_empty());
    for check in checks {
        assert_eq!(check.get("pass").and_then(Value::as_bool), Some(true));
    }
}
