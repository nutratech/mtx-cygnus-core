//! Regression tests for findings from the PR review: burned relays, ACL allow
//! lists, state ID mismatches and `event_id` handling in the content hash.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{
    auth::{authorize_active_epoch, AuthContext, MemberState},
    bootstrap::{server_genesis, user_genesis, user_successor, RotationKey},
    bundle::{EpochParts, EpochStatus, VerifiedEpoch},
    envelope,
    link::{Link, Payload},
    Error,
};
use ed25519_zebra::SigningKey;
use rezzy_json::{Object, Value};

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn pubkey(key: &SigningKey) -> [u8; 32] {
    <[u8; 32]>::from(key.verification_key())
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn active(event_id: &str, links: Vec<Link>) -> VerifiedEpoch {
    VerifiedEpoch::from_parts_unchecked(EpochParts {
        event_id: event_id.to_owned(),
        principal: links[0].principal(),
        status: EpochStatus::Active,
        links,
        fork_height: None,
        claim: vec![],
        branches: None,
        ancestors: vec![],
    })
}

#[test]
fn content_hash_ignores_an_attached_event_id() {
    let event = Value::parse(
        r#"{"type":"m.room.message","room_id":"!r","sender":"@x","content":{"body":"hi"}}"#,
    )
    .unwrap();
    let mut with_id = event.clone();
    with_id
        .as_object_mut()
        .unwrap()
        .insert("event_id".to_owned(), Value::String("$anything".to_owned()));
    assert_eq!(
        envelope::content_hash(&event).unwrap(),
        envelope::content_hash(&with_id).unwrap()
    );
    assert_eq!(
        envelope::event_id(&event).unwrap(),
        envelope::event_id(&with_id).unwrap()
    );
}

#[test]
fn content_hash_still_binds_the_content() {
    let a = Value::parse(r#"{"type":"t","content":{"body":"a"}}"#).unwrap();
    let b = Value::parse(r#"{"type":"t","content":{"body":"b"}}"#).unwrap();
    assert_ne!(
        envelope::content_hash(&a).unwrap(),
        envelope::content_hash(&b).unwrap()
    );
}

/// A burned user's stale custodian cannot vouch for a relay signature.
#[test]
fn burned_user_cannot_supply_the_relay_custodian() {
    let server_rotation = RotationKey::from_seed([0x11; 32]);
    let server_online = key(0x12);
    let server = server_genesis(&server_rotation, &server_online, "b.example").unwrap();
    let server_id = server.principal().to_id();
    let master = pubkey(&key(0x2F));

    let alice_first = RotationKey::from_seed([0x21; 32]);
    let alice_second = RotationKey::from_seed([0x22; 32]);
    let alice_genesis =
        user_genesis(&alice_first, server.digest(), master, "@alice:b.example").unwrap();
    let alice_next = user_successor(
        &alice_genesis,
        &alice_first,
        &alice_second,
        server.digest(),
        master,
        "@alice:b.example",
    )
    .unwrap();
    let alice = alice_genesis.principal().to_id();

    let bob_genesis = user_genesis(
        &RotationKey::from_seed([0x31; 32]),
        server.digest(),
        pubkey(&key(0x30)),
        "@bob:b.example",
    )
    .unwrap();
    let bob = bob_genesis.principal().to_id();

    let mut context = AuthContext::default();
    context.insert_epoch(active("$server", vec![server.clone()]));
    context.insert_epoch(active("$alice", vec![alice_genesis]));
    let mut parts = active("$bob", vec![bob_genesis]).into_parts();
    parts.status = EpochStatus::Burned;
    let burned = VerifiedEpoch::from_parts_unchecked(parts);
    context.insert_epoch(burned);
    for user in [&alice, &bob] {
        context.members.insert(
            user.clone(),
            MemberState {
                membership: "join".to_owned(),
                custodian: Some(server_id.clone()),
            },
        );
    }

    let mut event = Object::new();
    event.insert("type".into(), "m.room.user_epoch".into());
    event.insert("sender".into(), bob.into());
    event.insert("state_key".into(), alice.clone().into());
    event.insert(
        "content".into(),
        user_content(&[alice_next], std::slice::from_ref(&server)),
    );
    event.insert("origin_server_ts".into(), 1u64.into());
    let mut event = Value::Object(event);
    envelope::set_content_hash(&mut event).unwrap();
    envelope::sign_custodian(&mut event, &server_id, 0, &server_online).unwrap();

    assert_eq!(
        authorize_active_epoch(&event, &envelope::event_id(&event).unwrap(), &context).unwrap_err(),
        Error::Authorization("epoch event has no permitted signer")
    );
}

/// Build user-epoch content carrying both the chain and the signer chain.
fn user_content(links: &[Link], signer_links: &[Link]) -> Value {
    let tip = links.last().unwrap();
    let Payload::User {
        custodian,
        master_key,
        display_user_id,
    } = &tip.body.payload
    else {
        panic!("expected a user link");
    };
    let mut content = Object::new();
    content.insert("status".into(), "active".into());
    content.insert(
        "links".into(),
        Value::Array(links.iter().map(|link| link.to_b64().into()).collect()),
    );
    content.insert("height".into(), tip.body.height.into());
    content.insert("tip".into(), b64(&tip.digest()).into());
    content.insert("custodian".into(), format!("~{}", b64(custodian)).into());
    content.insert("display_user_id".into(), display_user_id.clone().into());
    if let Some(master_key) = master_key {
        content.insert("master_key".into(), b64(master_key).into());
    }
    content.insert(
        "signer_links".into(),
        Value::Array(
            signer_links
                .iter()
                .map(|link| link.to_b64().into())
                .collect(),
        ),
    );
    Value::Object(content)
}
