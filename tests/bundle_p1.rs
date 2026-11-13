//! P1 founding-flow create and epoch structure from Appendix C.

use cygnus_core::bundle::{
    signer_chain, verify_epoch_custodian_signature, VerifiedCreate, VerifiedEpoch,
};
use rezzy_json::Value;

fn vectors() -> Vec<Value> {
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
fn p1_create_validates_room_id_both_chains_and_both_signatures() {
    let events = vectors();
    let created = VerifiedCreate::verify(pdu(&events, 0), event_id(&events, 0)).unwrap();
    let fixture = Value::parse(include_str!("vectors/pid_pdu_vectors.json")).unwrap();
    assert_eq!(
        Some(created.room_id.as_str()),
        fixture.get("room_id").and_then(Value::as_str)
    );
    assert_eq!(created.user_links.len(), 1);
    assert_eq!(created.server_links.len(), 2);
}

#[test]
fn p1_genesis_epochs_and_server_rotation_verify_against_link_state() {
    let events = vectors();
    let user = VerifiedEpoch::active(pdu(&events, 1), event_id(&events, 1), None).unwrap();
    let server = VerifiedEpoch::active(pdu(&events, 2), event_id(&events, 2), None).unwrap();
    let advanced =
        VerifiedEpoch::active(pdu(&events, 3), event_id(&events, 3), Some(&server)).unwrap();

    let signer_links = signer_chain(pdu(&events, 1)).unwrap();
    verify_epoch_custodian_signature(pdu(&events, 1), &signer_links).unwrap();
    verify_epoch_custodian_signature(pdu(&events, 2), &signer_links).unwrap();
    verify_epoch_custodian_signature(pdu(&events, 3), &created_server_links(&events)).unwrap();

    assert_eq!(user.status(), cygnus_core::bundle::EpochStatus::Active);
    assert_eq!(user.links().len(), 1);
    assert_eq!(server.links().len(), 1);
    assert_eq!(advanced.links().len(), 2);
    assert_eq!(advanced.tip().body.height, 1);
}

fn created_server_links(events: &[Value]) -> Vec<cygnus_core::Link> {
    VerifiedCreate::verify(pdu(events, 0), event_id(events, 0))
        .unwrap()
        .server_links
}

#[test]
fn p1_create_rejects_a_modified_required_signature() {
    let events = vectors();
    let mut create = pdu(&events, 0).clone();
    let signatures = create.get_mut("signatures").unwrap();
    let server_signer = signatures
        .as_object_mut()
        .unwrap()
        .get_mut("~1AreHGP7Cv7EMZkhE3ChnfH_mR6pqDmBL9CPpBr87yA")
        .unwrap();
    let signature = server_signer
        .as_object_mut()
        .unwrap()
        .get_mut("ed25519:1")
        .unwrap();
    *signature = Value::String(
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            .to_owned(),
    );

    assert!(VerifiedCreate::verify(&create, event_id(&events, 0)).is_err());
}

#[test]
fn first_epoch_introduction_cannot_include_a_rotation_slice() {
    let events = vectors();
    let mut introduction = pdu(&events, 1).clone();
    let links = introduction
        .get_mut("content")
        .unwrap()
        .get_mut("links")
        .unwrap()
        .as_array_mut()
        .unwrap();
    links.push(Value::String("not-a-link".to_owned()));

    assert!(VerifiedEpoch::active(&introduction, event_id(&events, 1), None).is_err());
}
