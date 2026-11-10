//! Event envelope redaction, hashing, and signature tests.

use cygnus_core::envelope::{
    content_hash_b64, device_signing_bytes, event_id, redact_event, set_content_hash,
    sign_custodian, sign_device, verify_custodian_signature, verify_device_signature,
    DEVICE_EVENT_TAG,
};
use cygnus_core::sig::SigningKey;
use rezzy_json::{json, Value};

#[test]
fn redaction_keeps_cygnus_fields_and_room_v12_content_rules() {
    let event = json!({
        "type": "m.room.member",
        "room_id": "!room:example.org",
        "sender": "@alice:example.org",
        "device_certificate": {"version": 1},
        "unsigned": {"age": 50},
        "content": {
            "membership": "join",
            "custodian": "~server-principal",
            "displayname": "Alice",
            "third_party_invite": {
                "display_name": "ignored",
                "signed": {"mxid": "@alice:example.org", "token": "abc"}
            }
        }
    });
    let redacted = redact_event(&event).unwrap();
    assert_eq!(
        redacted.get("device_certificate").unwrap(),
        &json!({"version": 1})
    );
    assert_eq!(redacted.get("unsigned"), None);
    assert_eq!(
        redacted
            .get("content")
            .unwrap()
            .get("membership")
            .unwrap()
            .as_str(),
        Some("join")
    );
    assert_eq!(
        redacted
            .get("content")
            .unwrap()
            .get("custodian")
            .unwrap()
            .as_str(),
        Some("~server-principal")
    );
    assert_eq!(redacted.get("content").unwrap().get("displayname"), None);
    assert_eq!(
        redacted
            .get("content")
            .unwrap()
            .get("third_party_invite")
            .unwrap(),
        &json!({"signed": {"mxid": "@alice:example.org", "token": "abc"}})
    );
}

#[test]
fn epoch_events_keep_full_content_and_ordinary_events_are_redacted() {
    let epoch = json!({"type": "m.room.user_epoch", "content": {"links": ["abc"], "future": true}});
    assert_eq!(
        redact_event(&epoch).unwrap().get("content"),
        epoch.get("content")
    );

    let message = json!({"type": "m.room.message", "content": {"msgtype": "m.text", "body": "hi"}});
    assert_eq!(
        redact_event(&message).unwrap().get("content").unwrap(),
        &json!({})
    );
}

#[test]
fn redacted_server_acl_keeps_allow_deny_and_ip_literal_policy() {
    let event = json!({
        "type": "m.room.server_acl",
        "content": {
            "allow": ["*.example.org"],
            "deny": ["evil.example.org"],
            "allow_ip_literals": false,
            "irrelevant": "removed"
        }
    });
    let redacted = redact_event(&event).unwrap();
    assert_eq!(
        redacted.get("content").unwrap(),
        &json!({
            "allow": ["*.example.org"],
            "deny": ["evil.example.org"],
            "allow_ip_literals": false
        })
    );
}

#[test]
fn device_signing_object_excludes_event_id() {
    let without = json!({
        "type": "m.room.message",
        "sender": "@alice:example.org",
        "content": {"body": "hi"}
    });
    let mut with = without.clone();
    with.insert("event_id".to_owned(), Value::String("$event-id".to_owned()));
    assert_eq!(
        device_signing_bytes(&without).unwrap(),
        device_signing_bytes(&with).unwrap()
    );
}

#[test]
fn client_signs_device_then_custodian_and_detects_tampering() {
    let device = SigningKey::from([0x71; 32]);
    let custodian = SigningKey::from([0x72; 32]);
    let sender = "@user-principal";
    let server = "~server-principal";
    let mut event = json!({
        "type": "m.room.message",
        "room_id": "!room:example.org",
        "sender": sender,
        "origin_server_ts": 1234,
        "depth": 7,
        "prev_events": ["$prev"],
        "auth_events": [],
        "device_certificate": {"version": 1, "device_id": "PHONE"},
        "content": {"msgtype": "m.text", "body": "hello"}
    });

    set_content_hash(&mut event).unwrap();
    let expected_hash = content_hash_b64(&event).unwrap();
    assert_eq!(
        event.get("hashes").unwrap().get("sha256").unwrap().as_str(),
        Some(expected_hash.as_str())
    );
    let expected_event_id = event_id(&event).unwrap();
    sign_device(&mut event, sender, "PHONE", &device).unwrap();
    sign_custodian(&mut event, server, 4, &custodian).unwrap();

    assert_eq!(event_id(&event).unwrap(), expected_event_id);
    verify_device_signature(
        &event,
        sender,
        "PHONE",
        &<[u8; 32]>::from(device.verification_key()),
    )
    .unwrap();
    verify_custodian_signature(
        &event,
        server,
        4,
        &<[u8; 32]>::from(custodian.verification_key()),
    )
    .unwrap();
    assert!(device_signing_bytes(&event)
        .unwrap()
        .starts_with(DEVICE_EVENT_TAG));

    event
        .get_mut("content")
        .unwrap()
        .insert("body".to_owned(), Value::String("tampered".to_owned()));
    assert_ne!(
        content_hash_b64(&event).unwrap(),
        event
            .get("hashes")
            .unwrap()
            .get("sha256")
            .unwrap()
            .as_str()
            .unwrap(),
        "the content hash detects content changes"
    );
    // Ordinary message content is redacted from signing bytes; the signed
    // content hash binds it. A covered envelope field must break signatures.
    assert!(verify_device_signature(
        &event,
        sender,
        "PHONE",
        &<[u8; 32]>::from(device.verification_key())
    )
    .is_ok());
    event.insert("origin_server_ts".to_owned(), Value::parse("1235").unwrap());
    assert!(verify_device_signature(
        &event,
        sender,
        "PHONE",
        &<[u8; 32]>::from(device.verification_key())
    )
    .is_err());
    assert!(verify_custodian_signature(
        &event,
        server,
        4,
        &<[u8; 32]>::from(custodian.verification_key())
    )
    .is_err());
}
