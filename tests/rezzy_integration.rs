//! Rezzy base-authorization adapter tests. Compiled only with `state-res`.

#![cfg(feature = "state-res")]

use cygnus_core::rezzy_integration::{
    adapter_event, base_auth_applies, check_base_auth, validate_auth_event_citations, EventMap,
    RezzyError, RoomAuthState,
};
use rezzy::{json, JsonValue as Value};

const CREATE_ID: &str = "$create";
const MEMBER_ID: &str = "$member";
const CREATOR: &str = "@creator";

fn create_event() -> Value {
    json!({
        "event_id": CREATE_ID,
        "type": "m.room.create",
        "state_key": "",
        "sender": CREATOR,
        "room_id": "!room",
        "depth": 0,
        "origin_server_ts": 1,
        "prev_events": [],
        "auth_events": [],
        "content": {
            "room_version": "tk.nutra.cygnus.1",
            "creator_links": {"server": [], "user": []}
        }
    })
}

fn member_event() -> Value {
    json!({
        "event_id": MEMBER_ID,
        "type": "m.room.member",
        "state_key": CREATOR,
        "sender": CREATOR,
        "room_id": "!room",
        "depth": 1,
        "origin_server_ts": 2,
        "prev_events": [CREATE_ID],
        "auth_events": [CREATE_ID],
        "content": {"membership": "join", "custodian": "~server"}
    })
}

fn message_event(sender: &str, depth: u64) -> Value {
    json!({
        "event_id": format!("$message{depth}"),
        "type": "m.room.message",
        "sender": sender,
        "room_id": "!room",
        "depth": depth,
        "origin_server_ts": 3,
        "prev_events": [MEMBER_ID],
        "auth_events": [MEMBER_ID],
        "content": {"msgtype": "m.text", "body": "hi"}
    })
}

fn room_state() -> RoomAuthState {
    RoomAuthState::from_state_events([
        (CREATE_ID.to_owned(), create_event()),
        (MEMBER_ID.to_owned(), member_event()),
    ])
    .unwrap()
}

fn event_map() -> EventMap {
    EventMap::from([
        (
            CREATE_ID.to_owned(),
            adapter_event(&create_event()).unwrap(),
        ),
        (
            MEMBER_ID.to_owned(),
            adapter_event(&member_event()).unwrap(),
        ),
    ])
}

#[test]
fn cygnus_room_version_is_native_to_rezzy_and_the_event_is_untouched() {
    use rezzy::basespec::rezzy_types::StateResVersion;
    assert_eq!(
        StateResVersion::from_room_version("tk.nutra.cygnus.1"),
        Some(StateResVersion::V2_1)
    );
    let create = create_event();
    let lean = adapter_event(&create).unwrap();
    assert_eq!(
        lean.content.get("room_version").and_then(Value::as_str),
        Some("tk.nutra.cygnus.1")
    );
}

#[test]
fn joined_creator_message_passes_base_authorization_with_citations() {
    let state = room_state();
    let events = event_map();
    assert_eq!(
        check_base_auth(&message_event(CREATOR, 2), &state, Some(&events)),
        Ok(())
    );
}

#[test]
fn non_member_message_fails_base_authorization() {
    let state = room_state();
    let error = check_base_auth(&message_event("@stranger", 2), &state, None).unwrap_err();
    assert!(matches!(error, RezzyError::Auth(_)), "{error}");
}

#[test]
fn stale_auth_event_citation_is_rejected() {
    let state = room_state();
    let mut events = event_map();
    events.remove(MEMBER_ID);
    let error = check_base_auth(&message_event(CREATOR, 2), &state, Some(&events)).unwrap_err();
    assert!(matches!(error, RezzyError::Auth(_)), "{error}");
}

#[test]
fn create_in_auth_events_is_rejected_for_v12() {
    let mut message = message_event(CREATOR, 2);
    message["auth_events"] = json!([CREATE_ID, MEMBER_ID]);
    let error = check_base_auth(&message, &room_state(), Some(&event_map())).unwrap_err();
    assert!(
        error.to_string().contains("m.room.create in auth_events"),
        "{error}"
    );
}

#[test]
fn duplicate_state_pairs_are_rejected() {
    let mut second = member_event();
    second["event_id"] = json!("$other-member");
    let error = RoomAuthState::from_state_events([
        (CREATE_ID.to_owned(), create_event()),
        (MEMBER_ID.to_owned(), member_event()),
        ("$other-member".to_owned(), second),
    ])
    .unwrap_err();
    assert!(matches!(error, RezzyError::Parse(_)), "{error}");
}

#[test]
fn state_event_pair_must_match_its_embedded_event_id() {
    let mut member = member_event();
    member["event_id"] = json!("$embedded");
    let error = RoomAuthState::from_state_events([("$supplied".to_owned(), member)]).unwrap_err();
    assert!(matches!(error, RezzyError::Parse(_)), "{error}");
}

#[test]
fn conflicting_pdus_with_the_same_state_event_id_are_rejected() {
    let first = member_event();
    let mut second = first.clone();
    second["content"]["custodian"] = json!("~other");
    let error = RoomAuthState::from_state_events([
        (MEMBER_ID.to_owned(), first),
        (MEMBER_ID.to_owned(), second),
    ])
    .unwrap_err();
    assert!(matches!(error, RezzyError::Parse(_)), "{error}");
}

#[test]
fn stale_epoch_auth_event_citation_is_rejected() {
    let state = room_state();
    let mut events = event_map();
    let mut stale_member = adapter_event(&member_event()).unwrap();
    stale_member.event_id = "$stale-member".to_owned();
    events.insert(stale_member.event_id.clone(), stale_member);
    let epoch = json!({
        "type": "m.room.user_epoch",
        "event_id": "$epoch",
        "auth_events": ["$stale-member"]
    });
    let error = validate_auth_event_citations(&epoch, &state, &events).unwrap_err();
    assert!(matches!(error, RezzyError::Auth(_)), "{error}");
}

#[test]
fn p1_fixture_events_pass_rezzy_base_authorization() {
    let fixture = Value::parse(include_str!("vectors/pid_pdu_vectors.json")).unwrap();
    let events = fixture.get("events").and_then(Value::as_array).unwrap();
    let mut state_events: std::collections::BTreeMap<(String, String), (String, Value)> =
        std::collections::BTreeMap::new();
    let mut known = EventMap::new();
    let mut checked = 0;

    for (index, entry) in events.iter().enumerate() {
        let event_id = entry
            .get("event_id")
            .and_then(Value::as_str)
            .unwrap()
            .to_owned();
        let mut pdu = entry.get("pdu").unwrap().clone();
        pdu.as_object_mut()
            .unwrap()
            .insert("event_id".to_owned(), Value::String(event_id.clone()));

        let state = RoomAuthState::from_state_events(state_events.values().cloned()).unwrap();
        if base_auth_applies(&pdu) {
            check_base_auth(&pdu, &state, Some(&known))
                .unwrap_or_else(|error| panic!("event {index} ({event_id}): {error}"));
            checked += 1;
        }

        known.insert(event_id.clone(), adapter_event(&pdu).unwrap());
        if let Some(state_key) = pdu.get("state_key").and_then(Value::as_str) {
            let event_type = pdu.get("type").and_then(Value::as_str).unwrap().to_owned();
            state_events.insert((event_type, state_key.to_owned()), (event_id, pdu));
        }
    }

    assert_eq!(known.len(), events.len());
    // Epoch and seal events are skipped by design; the rest must be checked.
    assert_eq!(checked, 7, "unexpected number of P1 events base-authorized");
}
