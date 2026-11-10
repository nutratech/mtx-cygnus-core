//! `m.room.server_seal` cutover checks, ported from
//! `tools/reference_models/pid_cutover.py`.
//!
//! The graph below intentionally mirrors the reference prototype's event IDs
//! and `prev_events` so the same resolution cases run in Rust.

use cygnus_core::seal::{GraphEvent, SealGraph, ServerSeal};
use cygnus_core::{commitment, Kind, Link, Principal};
use ed25519_consensus::SigningKey;
use rezzy_json::Value;

fn server_principal() -> (Principal, String) {
    let online = SigningKey::from([0x11; 32]);
    let rotation = SigningKey::from([0x12; 32]);
    let genesis = Link::sign_server_genesis(
        cygnus_core::Body {
            root: [0; 32],
            height: 0,
            prev: [0; 32],
            next_commit: commitment(&rotation.verification_key().to_bytes()),
            payload: cygnus_core::Payload::Server {
                online_key: online.verification_key().to_bytes(),
                server_name: "chat.example.org".to_owned(),
            },
        },
        &online,
    )
    .unwrap();
    let principal = genesis.principal();
    let id = principal.to_id();
    (principal, id)
}

fn graph() -> SealGraph {
    let mut graph = SealGraph::new();
    let events = [
        GraphEvent::plain("$e0", &[], "S", 0),
        GraphEvent::plain("$m0", &["$e0"], "S", 0),
        GraphEvent::sealed("$seal1", &["$m0"], "S", 1, 1),
        GraphEvent::plain("$m1clean", &["$seal1"], "S", 1),
        GraphEvent::plain("$evil", &["$e0"], "S", 0),
        GraphEvent::plain("$other", &["$e0"], "T", 0),
        GraphEvent::plain("$relay1", &["$e0"], "R", 1),
        GraphEvent::plain("$relay2", &["$relay1"], "R", 2),
        GraphEvent::sealed("$seal2", &["$m1clean"], "S", 2, 2),
        GraphEvent::plain("$b2b", &["$e0"], "S", 1),
        GraphEvent::plain("$otherpost", &["$e0"], "T", 0),
        GraphEvent::plain("$alicemsg", &["$e0"], "U", 0),
        GraphEvent::sealed(
            "$seal2b",
            &["$m1clean", "$b2b", "$otherpost", "$alicemsg"],
            "S",
            2,
            2,
        ),
        GraphEvent::sealed("$seal2same", &["$seal2"], "S", 2, 2),
        GraphEvent::sealed("$seal3bad", &["$seal2b"], "S", 3, 3),
        GraphEvent::sealed("$seal3smuggle", &["$seal1", "$seal2b"], "S", 3, 3),
        GraphEvent::sealed("$seal3branch", &["$seal1", "$b2b"], "S", 3, 3),
        GraphEvent::sealed("$seal3clean", &["$m1clean", "$otherpost"], "S", 3, 3),
        GraphEvent::sealed("$seal3alice", &["$m1clean", "$alicemsg"], "S", 3, 3),
        GraphEvent::sealed("$seal3recover", &["$seal2", "$m1clean"], "S", 3, 3),
        GraphEvent::sealed("$seal1late", &["$e0"], "S", 1, 1),
        GraphEvent::sealed("$seal2late", &["$seal1", "$evil"], "S", 2, 2),
        GraphEvent::sealed("$seal3conflicta", &["$seal1", "$m1clean"], "S", 3, 3),
        GraphEvent::sealed("$seal3conflictb", &["$seal1", "$b2b"], "S", 3, 3),
        GraphEvent::sealed("$seallow", &["$m0"], "S", 0, 1),
    ];
    for event in events {
        graph.insert(event).unwrap();
    }
    graph
}

fn winner(graph: &SealGraph, candidates: &[&str]) -> Option<String> {
    graph
        .resolve_seal(candidates)
        .map(|event| event.event_id.clone())
}

#[test]
fn cutover_filter_keeps_only_the_seal_causal_past() {
    let graph = graph();
    assert!(!graph.cutover_allows("$evil", Some("$seal1")));
    assert!(graph.cutover_allows("$m0", Some("$seal1")));
    assert!(graph.cutover_allows("$other", Some("$seal1")));
    assert!(graph.cutover_allows("$evil", Some("$relay1")));
    assert!(graph.cutover_allows("$evil", None));
}

#[test]
fn a_later_relay_neither_seals_nor_erases_the_current_seal() {
    let graph = graph();
    assert_eq!(winner(&graph, &["$seal1"]).as_deref(), Some("$seal1"));
    assert!(!graph.cutover_allows("$evil", Some("$seal1")));
    assert_eq!(winner(&graph, &["$seal1"]), winner(&graph, &["$seal1"]));
}

#[test]
fn a_new_seal_descends_from_a_lower_seal() {
    let graph = graph();
    assert!(graph.is_ancestor("$seal1", "$seal2"));
}

#[test]
fn two_seals_at_one_height_conflict_and_fall_back() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2same"]).as_deref(),
        Some("$seal1")
    );
}

#[test]
fn the_highest_unambiguous_seal_wins() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2"]).as_deref(),
        Some("$seal2")
    );
}

#[test]
fn a_seal_signed_below_its_height_is_not_valid() {
    let graph = graph();
    assert!(!graph.seal_auth_ok("$seallow"));
    assert!(graph.seal_auth_ok("$seal1"));
}

#[test]
fn a_same_height_conflict_retains_the_previous_seal() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2b"]).as_deref(),
        Some("$seal1")
    );
}

#[test]
fn conflict_resolution_is_order_independent() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2b"]),
        winner(&graph, &["$seal2b", "$seal2", "$seal1"])
    );
}

#[test]
fn duplicate_seal_event_ids_are_idempotent() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2"]).as_deref(),
        Some("$seal2")
    );
}

#[test]
fn a_later_seal_advances_from_the_last_unambiguous_seal() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2b", "$seal3clean"]).as_deref(),
        Some("$seal3clean")
    );
}

#[test]
fn a_later_seal_descends_through_a_conflicted_lower_height() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2b", "$seal3bad"]).as_deref(),
        Some("$seal3bad")
    );
}

#[test]
fn a_later_seal_may_merge_a_lower_conflict() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2b", "$seal3smuggle"]).as_deref(),
        Some("$seal3smuggle")
    );
}

#[test]
fn a_higher_seals_ancestry_decides_which_old_events_survive() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2b", "$seal3branch"]).as_deref(),
        Some("$seal3branch")
    );
    assert!(graph.cutover_allows("$b2b", Some("$seal3branch")));
    assert!(!graph.cutover_allows("$m1clean", Some("$seal3branch")));
}

#[test]
fn a_countersigned_user_event_survives_a_lower_conflict() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2b", "$seal3alice"]).as_deref(),
        Some("$seal3alice")
    );
}

#[test]
fn a_higher_seal_recovers_without_tainting_honest_events() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2b", "$seal3clean"]).as_deref(),
        Some("$seal3clean")
    );
    assert!(graph.cutover_allows("$m1clean", Some("$seal3clean")));
    assert!(!graph.cutover_allows("$b2b", Some("$seal3clean")));
    assert!(graph.cutover_allows("$otherpost", Some("$seal3clean")));
}

#[test]
fn siblings_citing_the_honest_tip_do_not_erase_it() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1", "$seal2", "$seal2b", "$seal3recover"]).as_deref(),
        Some("$seal3recover")
    );
    assert!(graph.cutover_allows("$m1clean", Some("$seal3recover")));
}

#[test]
fn a_retired_lower_seal_does_not_displace_the_current_seal() {
    let graph = graph();
    assert_eq!(
        winner(&graph, &["$seal1late", "$seal2"]).as_deref(),
        Some("$seal2")
    );
}

#[test]
fn a_conflict_falls_back_only_through_common_ancestry() {
    let graph = graph();
    assert_eq!(
        winner(
            &graph,
            &["$seal1", "$seal2late", "$seal3conflicta", "$seal3conflictb"]
        )
        .as_deref(),
        Some("$seal1")
    );
}

#[test]
fn duplicate_event_ids_are_rejected_when_content_differs() {
    let mut graph = SealGraph::new();
    graph.insert(GraphEvent::plain("$a", &[], "S", 0)).unwrap();
    graph.insert(GraphEvent::plain("$a", &[], "S", 0)).unwrap();
    assert!(graph
        .insert(GraphEvent::plain("$a", &["$b"], "S", 0))
        .is_err());
}

#[test]
fn server_seal_parsing_checks_the_structural_fields() {
    let (expected, principal) = server_principal();
    let event = Value::parse(&format!(
        r#"{{"type":"m.room.server_seal","state_key":"{principal}","content":{{"sealed_height":4,"previous_seal":"$old"}}}}"#
    ))
    .unwrap();
    let seal = ServerSeal::parse(&event).unwrap();
    assert_eq!(seal.server, expected);
    assert_eq!(seal.server.kind, Kind::Server);
    assert_eq!(seal.sealed_height, 4);
    assert_eq!(seal.previous_seal.as_deref(), Some("$old"));

    let null_previous = Value::parse(&format!(
        r#"{{"type":"m.room.server_seal","state_key":"{principal}","content":{{"sealed_height":1,"previous_seal":null}}}}"#
    ))
    .unwrap();
    assert_eq!(
        ServerSeal::parse(&null_previous).unwrap().previous_seal,
        None
    );

    for content in [
        r#"{"sealed_height":0}"#,
        r#"{"sealed_height":-1}"#,
        r#"{"sealed_height":"1"}"#,
        r"{}",
        r#"{"sealed_height":1,"previous_seal":7}"#,
    ] {
        let event = Value::parse(&format!(
            r#"{{"type":"m.room.server_seal","state_key":"{principal}","content":{content}}}"#
        ))
        .unwrap();
        assert!(ServerSeal::parse(&event).is_err(), "accepted {content}");
    }

    let wrong_type = Value::parse(&format!(
        r#"{{"type":"m.room.server_epoch","state_key":"{principal}","content":{{"sealed_height":1}}}}"#
    ))
    .unwrap();
    assert!(ServerSeal::parse(&wrong_type).is_err());
}
