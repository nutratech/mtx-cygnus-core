//! P1 event authorization paths from the Appendix C founding flow.

use cygnus_core::{
    auth::{
        authorize_active_epoch, authorize_create, authorize_user_event, AuthContext, MemberState,
    },
    bundle::EpochStatus,
    Error,
};
use rezzy_json::Value;

fn events() -> Vec<Value> {
    Value::parse(include_str!("vectors/pid_pdu_vectors.json"))
        .unwrap()
        .get("events")
        .and_then(Value::as_array)
        .unwrap()
        .clone()
}

fn event_id(events: &[Value], index: usize) -> &str {
    events[index]
        .get("event_id")
        .and_then(Value::as_str)
        .unwrap()
}

fn pdu(events: &[Value], index: usize) -> &Value {
    events[index].get("pdu").unwrap()
}

#[test]
fn authorizes_create_epoch_introductions_advancement_join_and_message() {
    let events = events();
    let create = authorize_create(pdu(&events, 0), event_id(&events, 0)).unwrap();
    let alice = create.user_principal.to_id();
    let server = create.server_principal.to_id();

    let mut auth = AuthContext::default();
    auth.creators.insert(alice.clone());

    let user_epoch = authorize_active_epoch(pdu(&events, 1), event_id(&events, 1), &auth).unwrap();
    assert_eq!(user_epoch.status(), EpochStatus::Active);
    auth.user_epochs.insert(alice.clone(), user_epoch);

    let server_epoch =
        authorize_active_epoch(pdu(&events, 2), event_id(&events, 2), &auth).unwrap();
    auth.server_epochs.insert(server.clone(), server_epoch);

    let advanced = authorize_active_epoch(pdu(&events, 3), event_id(&events, 3), &auth).unwrap();
    assert_eq!(advanced.tip().body.height, 1);
    auth.server_epochs.insert(server.clone(), advanced);

    // The join event is self-targeted and establishes the custodian binding.
    authorize_user_event(pdu(&events, 4), &auth).unwrap();
    auth.members.insert(
        alice.clone(),
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(server),
        },
    );
    authorize_user_event(pdu(&events, 7), &auth).unwrap();
}

#[test]
fn ordinary_user_event_rejects_a_modified_device_signature() {
    let events = events();
    let create = authorize_create(pdu(&events, 0), event_id(&events, 0)).unwrap();
    let alice = create.user_principal.to_id();
    let server = create.server_principal.to_id();
    let mut auth = AuthContext::default();
    auth.creators.insert(alice.clone());
    auth.user_epochs.insert(
        alice.clone(),
        authorize_active_epoch(pdu(&events, 1), event_id(&events, 1), &auth).unwrap(),
    );
    auth.server_epochs.insert(
        server.clone(),
        authorize_active_epoch(pdu(&events, 2), event_id(&events, 2), &auth).unwrap(),
    );
    auth.server_epochs.insert(
        server.clone(),
        authorize_active_epoch(pdu(&events, 3), event_id(&events, 3), &auth).unwrap(),
    );
    auth.members.insert(
        alice.clone(),
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(server),
        },
    );

    let mut message = pdu(&events, 7).clone();
    let signature = message["signatures"][alice.as_str()]["ed25519:TEST51"]
        .as_str()
        .unwrap()
        .to_owned();
    // Change one character in place: the signature stays well-formed (86
    // base64url characters, 64 bytes), so rejection must come from verification.
    let mut chars: Vec<char> = signature.chars().collect();
    chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert_eq!(tampered.len(), signature.len());
    message["signatures"][alice.as_str()]["ed25519:TEST51"] = Value::String(tampered);
    assert_eq!(
        authorize_user_event(&message, &auth),
        Err(Error::Signature),
        "a well-formed but altered device signature must fail verification"
    );
}
