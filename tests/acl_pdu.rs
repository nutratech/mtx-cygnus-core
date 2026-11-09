//! Server ACL principal encoding checks from PDU vectors P1/P8.

use cygnus_core::binding::validate_server_acl_content;
use rezzy_json::Value;

#[test]
fn accepts_canonical_server_principal_and_domain_entries() {
    let content = Value::parse(
        r#"{"allow":["~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","*.example.org"],"deny":[]}"#,
    )
    .unwrap();
    let acl = validate_server_acl_content(&content).unwrap();
    assert_eq!(acl.allow.len(), 2);
    assert!(acl.deny.is_empty());
}

#[test]
fn rejects_malformed_or_noncanonical_principal_acl_entries() {
    for entry in [
        "~*",
        "~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+",
        "~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/",
        "~AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    ] {
        let content = Value::parse(&format!("{{\"allow\":[\"{entry}\"],\"deny\":[]}}")).unwrap();
        assert!(
            validate_server_acl_content(&content).is_err(),
            "accepted {entry}"
        );
    }
}

#[test]
fn requires_acl_entries_to_be_string_arrays() {
    for raw in [r#"{"allow":"example.org"}"#, r#"{"deny":[1]}"#] {
        assert!(validate_server_acl_content(&Value::parse(raw).unwrap()).is_err());
    }
}
