//! P2 custodian migration and rebinding path from Appendix C.

use cygnus_core::{
    auth::{
        authorize_active_epoch, authorize_create, authorize_user_event, AuthContext, MemberState,
    },
    binding::{validate_server_acl_content, Acl},
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

fn p1_context(events: &[Value]) -> (AuthContext, String, String) {
    let create = authorize_create(pdu(events, 0), event_id(events, 0)).unwrap();
    let alice = create.user_principal.to_id();
    let server_a = create.server_principal.to_id();
    let mut context = AuthContext::default();
    context.creators.insert(alice.clone());

    let alice_epoch =
        authorize_active_epoch(pdu(events, 1), event_id(events, 1), &context).unwrap();
    context.user_epochs.insert(alice.clone(), alice_epoch);
    let server_a_genesis =
        authorize_active_epoch(pdu(events, 2), event_id(events, 2), &context).unwrap();
    context
        .server_epochs
        .insert(server_a.clone(), server_a_genesis);
    let server_a_current =
        authorize_active_epoch(pdu(events, 3), event_id(events, 3), &context).unwrap();
    context
        .server_epochs
        .insert(server_a.clone(), server_a_current);

    let member = pdu(events, 4)
        .get("content")
        .and_then(Value::as_object)
        .unwrap();
    context.members.insert(
        alice.clone(),
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(
                member
                    .get("custodian")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
            ),
        },
    );
    context.join_rule = Some(
        pdu(events, 5)["content"]["join_rule"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    context.server_acl = Some(validate_server_acl_content(&pdu(events, 6)["content"]).unwrap());
    (context, alice, server_a)
}

#[test]
#[ignore = "vendored vectors carry Ed25519 signatures; regenerate for the WOTS+ format"]
fn authorizes_user_move_new_server_introduction_rebind_and_message() {
    let events = events();
    let (mut context, alice, old_custodian_id) = p1_context(&events);

    let moved_user =
        authorize_active_epoch(pdu(&events, 8), event_id(&events, 8), &context).unwrap();
    context.user_epochs.insert(alice.clone(), moved_user);

    // The migration names B before B has an epoch in this room. A cannot
    // continue speaking for Alice after the user epoch moves to B, and B's
    // ordinary event is premature until its server epoch is introduced.
    assert!(authorize_user_event(pdu(&events, 7), &context).is_err());
    assert!(authorize_user_event(pdu(&events, 11), &context).is_err());

    let server_b = authorize_active_epoch(pdu(&events, 9), event_id(&events, 9), &context).unwrap();
    let server_b_id = server_b.principal().to_id();
    context.server_epochs.insert(server_b_id.clone(), server_b);

    // Once B is introduced, the old custodian's signature remains invalid.
    assert!(authorize_user_event(pdu(&events, 7), &context).is_err());
    // Rebound to B, so the membership check passes and the A-signed message is
    // rejected on its server signature rather than on the stale binding.
    let mut bound_to_b = context.clone();
    bound_to_b.members.insert(
        alice.clone(),
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(server_b_id.clone()),
        },
    );
    assert_eq!(
        authorize_user_event(pdu(&events, 7), &bound_to_b),
        Err(Error::Signature),
    );

    let mut acl_denied = context.clone();
    acl_denied.server_acl.as_mut().unwrap().deny = vec![old_custodian_id];
    assert!(authorize_user_event(pdu(&events, 10), &acl_denied).is_err());
    acl_denied.join_rule = Some("public".to_owned());
    authorize_user_event(pdu(&events, 10), &acl_denied).unwrap();

    // An allow list that omits the old custodian excludes it just as a deny
    // entry would, even with an empty deny list.
    let mut allow_excludes = context.clone();
    allow_excludes.server_acl = Some(Acl {
        allow: vec![server_b_id.clone()],
        deny: Vec::new(),
    });
    assert!(authorize_user_event(pdu(&events, 10), &allow_excludes).is_err());
    allow_excludes.join_rule = Some("public".to_owned());
    authorize_user_event(pdu(&events, 10), &allow_excludes).unwrap();

    // Before the membership event binds Alice to B, ordinary events are
    // rejected even though both epochs and the new custodian are valid.
    assert!(authorize_user_event(pdu(&events, 11), &context).is_err());

    authorize_user_event(pdu(&events, 10), &context).unwrap();
    context.members.insert(
        alice,
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(server_b_id),
        },
    );
    authorize_user_event(pdu(&events, 11), &context).unwrap();
}
