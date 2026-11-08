//! Appendix C PDU hash and event-ID vectors from the MSC reference model.

use cygnus_core::envelope::{content_hash_b64, event_id, reference_hash};
use rezzy_json::Value;

#[test]
fn all_appendix_c_event_hashes_and_ids_match_the_reference_model() {
    let vectors = Value::parse(include_str!("vectors/pid_pdu_vectors.json")).unwrap();
    let events = vectors.get("events").and_then(Value::as_array).unwrap();
    assert_eq!(events.len(), 12);

    for event in events {
        let step = event.get("step").and_then(Value::as_str).unwrap();
        let pdu = event.get("pdu").expect("PDU fixture");
        let hashes = pdu.get("hashes").expect("hashes");
        let expected_content_hash = hashes.get("sha256").and_then(Value::as_str).unwrap();
        assert_eq!(
            content_hash_b64(pdu).unwrap(),
            expected_content_hash,
            "{step}"
        );

        let expected_reference_hash = event
            .get("reference_hash_hex")
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(
            hex::encode(reference_hash(pdu).unwrap()),
            expected_reference_hash,
            "{step}"
        );
        assert_eq!(
            event_id(pdu).unwrap(),
            event.get("event_id").and_then(Value::as_str).unwrap(),
            "{step}"
        );
    }
}

#[test]
fn appendix_c_reference_model_marks_each_pdu_check_as_passing() {
    let vectors = Value::parse(include_str!("vectors/pid_pdu_vectors.json")).unwrap();
    let checks = vectors.get("checks").and_then(Value::as_array).unwrap();
    assert_eq!(checks.len(), 53);
    assert!(checks
        .iter()
        .all(|check| check.get("pass").and_then(Value::as_bool) == Some(true)));
}
