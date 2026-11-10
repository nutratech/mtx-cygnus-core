//! Rezzy base-authorization adapter tests. Compiled only with `state-res`.

#![cfg(feature = "state-res")]

use cygnus_core::{
    auth::{AuthContext, MemberState},
    rezzy_integration::{
        adapter_event, authorize_pdu, base_auth_applies, check_base_auth,
        validate_auth_event_citations, Authorized, EventMap, RezzyError, RoomAuthState,
    },
};
use rezzy::{json, JsonValue as Value};
use std::collections::BTreeMap;

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

/// The vendored P1–P3 PDUs, each with its `event_id` attached.
fn fixture_pdus() -> Vec<(String, Value)> {
    let fixture = Value::parse(include_str!("vectors/pid_pdu_vectors.json")).unwrap();
    fixture
        .get("events")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|entry| {
            let event_id = entry.get("event_id").and_then(Value::as_str).unwrap();
            let mut pdu = entry.get("pdu").unwrap().clone();
            pdu["event_id"] = Value::String(event_id.to_owned());
            (event_id.to_owned(), pdu)
        })
        .collect()
}

/// Room state and the matching Cygnus view, advanced one accepted PDU at a
/// time, as a server applying a linear history would.
#[derive(Default)]
struct Replay {
    state_events: BTreeMap<(String, String), (String, Value)>,
    known: EventMap,
    context: AuthContext,
}

impl Replay {
    fn authorize(&self, event_id: &str, pdu: &Value) -> Result<Authorized, RezzyError> {
        let state = RoomAuthState::from_state_events(self.state_events.values().cloned()).unwrap();
        authorize_pdu(pdu, event_id, &self.context, &state, &self.known)
    }

    fn apply(&mut self, event_id: &str, pdu: &Value, authorized: Authorized) {
        match authorized {
            Authorized::Create(create) => {
                self.context.creators.insert(create.user_principal.to_id());
            }
            Authorized::Epoch(epoch) => {
                self.context.insert_epoch(*epoch);
            }
            Authorized::Seal(_) => {}
            Authorized::Event => {
                if pdu["type"].as_str() == Some("m.room.member") {
                    let content = &pdu["content"];
                    self.context.members.insert(
                        pdu["state_key"].as_str().unwrap().to_owned(),
                        MemberState {
                            membership: content["membership"].as_str().unwrap().to_owned(),
                            custodian: content["custodian"].as_str().map(str::to_owned),
                        },
                    );
                }
            }
        }
        self.known
            .insert(event_id.to_owned(), adapter_event(pdu).unwrap());
        if let Some(state_key) = pdu.get("state_key").and_then(Value::as_str) {
            let event_type = pdu["type"].as_str().unwrap().to_owned();
            self.state_events.insert(
                (event_type, state_key.to_owned()),
                (event_id.to_owned(), pdu.clone()),
            );
        }
    }

    fn run(pdus: &[(String, Value)]) -> Self {
        let mut replay = Self::default();
        for (index, (event_id, pdu)) in pdus.iter().enumerate() {
            let authorized = replay
                .authorize(event_id, pdu)
                .unwrap_or_else(|error| panic!("event {index} ({event_id}): {error}"));
            replay.apply(event_id, pdu, authorized);
        }
        replay
    }
}

/// P1 check 0 (and the P2/P3 continuation): every fixture PDU passes
/// citations, base v12 auth and the Cygnus overlay through one entry point.
#[test]
fn p1_founding_flow_passes_the_combined_entry_point() {
    let pdus = fixture_pdus();
    let replay = Replay::run(&pdus);
    assert_eq!(replay.known.len(), pdus.len());
    assert_eq!(replay.context.creators.len(), 1);
}

/// P4 check 21: once Alice's user epoch has been superseded, an event that
/// still cites her earlier epoch is rejected as stale before any Cygnus check.
#[test]
fn citing_a_superseded_user_epoch_is_stale() {
    let pdus = fixture_pdus();
    // Stop right after event 8 (Alice's user epoch advances to B), so her
    // membership is still current and only the epoch citation is stale.
    let replay = Replay::run(&pdus[..9]);
    // Message 7 was sent via A and cites Alice's genesis epoch (event 1).
    let (stale_epoch, _) = &pdus[1];
    let (message_id, message) = &pdus[7];
    assert!(message["auth_events"]
        .as_array()
        .unwrap()
        .iter()
        .any(|id| id.as_str() == Some(stale_epoch)));
    let error = replay.authorize(message_id, message).unwrap_err();
    assert_eq!(
        error,
        RezzyError::Auth(format!(
            "auth event {stale_epoch} is stale; current state is {}",
            pdus[8].0
        ))
    );
}

#[test]
fn combined_entry_point_reports_overlay_rejections() {
    let pdus = fixture_pdus();
    let replay = Replay::run(&pdus[..7]);
    // Edited content passes citations and base auth, then fails the Cygnus
    // content-hash check.
    let (message_id, message) = &pdus[7];
    replay.authorize(message_id, message).unwrap();
    let mut tampered = message.clone();
    tampered["content"]["body"] = Value::String("edited".to_owned());
    let error = replay.authorize(message_id, &tampered).unwrap_err();
    assert!(matches!(error, RezzyError::Cygnus(_)), "{error}");
}
