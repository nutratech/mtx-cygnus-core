//! §9 full tip-bundle structure and client reference lookup.

use cygnus_core::bundle::TipBundle;
use rezzy_json::Value;

fn p1_events() -> Vec<(String, Value)> {
    Value::parse(include_str!("vectors/pid_pdu_vectors.json"))
        .unwrap()
        .get("events")
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|event| {
            (
                event
                    .get("event_id")
                    .and_then(Value::as_str)
                    .unwrap()
                    .to_owned(),
                event.get("pdu").unwrap().clone(),
            )
        })
        .collect()
}

fn bundle() -> TipBundle {
    TipBundle {
        room_id: "!30zU4L44nR8z-TbH4R7So2CfI9UJzMYnMhzY9NKHXgY".to_owned(),
        forward_extremities: vec!["$BXkrdLiSP578J-TcBTJKLVTHoYgEhN33tOiDFORGzMo".to_owned()],
        events: p1_events(),
    }
}

#[test]
fn verifies_p1_bundle_ids_room_create_and_extremity() {
    let verified = bundle().verify().unwrap();
    assert_eq!(verified.room_id(), bundle().room_id);
    assert_eq!(verified.forward_extremities().len(), 1);
    assert_eq!(verified.create().room_id, verified.room_id());
    assert!(verified
        .event("$C8i5Ge_hS22gMYJ787v2i-SpIKe2xT5-YrXrLhJVCVQ")
        .is_some());
}

#[test]
fn client_can_resolve_each_event_id_it_intends_to_cite() {
    let verified = bundle().verify().unwrap();
    let cited = vec![
        "$30zU4L44nR8z-TbH4R7So2CfI9UJzMYnMhzY9NKHXgY".to_owned(),
        "$fi3T31nHNiiYBgbqjRI6dSCQvMYG6gBQTYxFVoOFJLY".to_owned(),
    ];
    assert_eq!(verified.require_events(&cited).unwrap().len(), 2);
    assert!(verified.require_events(&["$missing".to_owned()]).is_err());
}

#[test]
fn rejects_event_id_room_and_extremity_mismatches() {
    let mut wrong_id = bundle();
    wrong_id.events[1].0 = "$wrong".to_owned();
    assert!(wrong_id.verify().is_err());

    let mut wrong_room = bundle();
    wrong_room.room_id = "!different".to_owned();
    assert!(wrong_room.verify().is_err());

    let mut missing_extremity = bundle();
    missing_extremity.forward_extremities = vec!["$absent".to_owned()];
    assert!(missing_extremity.verify().is_err());
}

#[test]
fn rejects_missing_create_and_duplicate_extremities() {
    let mut no_create = bundle();
    no_create.events.remove(0);
    assert!(no_create.verify().is_err());

    let mut duplicate = bundle();
    duplicate
        .forward_extremities
        .push(duplicate.forward_extremities[0].clone());
    assert!(duplicate.verify().is_err());
}
