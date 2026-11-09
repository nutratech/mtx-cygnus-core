//! Rezzy base-authorization adapter tests. Compiled only with `state-res`.

#![cfg(feature = "state-res")]

use cygnus_core::rezzy_integration::{
    adapter_event, check_base_auth, EventMap, RezzyError, RoomAuthState, BASE_ROOM_VERSION,
};
use rezzy_json::{json, Value};

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
fn maps_the_cygnus_create_version_to_v12_without_touching_the_event() {
    let create = create_event();
    let lean = adapter_event(&create).unwrap();
    assert_eq!(
        lean.content.get("room_version").and_then(Value::as_str),
        Some(BASE_ROOM_VERSION)
    );
    assert_eq!(
        create
            .get("content")
            .and_then(|c| c.get("room_version"))
            .and_then(Value::as_str),
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
