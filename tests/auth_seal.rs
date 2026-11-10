//! §7 `m.room.server_seal` authorization against caller-selected state.

use cygnus_core::sig::SigningKey;
use cygnus_core::{
    auth::{authorize_seal, AuthContext, MemberState},
    bootstrap::{server_genesis, server_successor, user_genesis, RotationKey},
    bundle::{EpochParts, EpochStatus, VerifiedEpoch},
    envelope,
    link::{Kind, Link},
    Error, Principal,
};
use rezzy_json::{Object, Value};

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn pubkey(key: &SigningKey) -> [u8; 32] {
    key.verification_key().to_bytes()
}

fn rotation(seed: u8) -> RotationKey {
    RotationKey::from_seed([seed; 32])
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

fn seal_event(
    sender: &str,
    server: &str,
    sealed_height: u64,
    signer_height: u64,
    key: &SigningKey,
) -> Value {
    let mut content = Object::new();
    content.insert("sealed_height".into(), sealed_height.into());
    let mut event = Object::new();
    event.insert("type".into(), "m.room.server_seal".into());
    event.insert("sender".into(), sender.into());
    event.insert("state_key".into(), server.into());
    event.insert("content".into(), Value::Object(content));
    event.insert("origin_server_ts".into(), 1_792_860_000_000u64.into());
    let mut event = Value::Object(event);
    envelope::set_content_hash(&mut event).unwrap();
    envelope::sign_custodian(&mut event, server, signer_height, key).unwrap();
    event
}

struct Fixture {
    context: AuthContext,
    server: String,
    alice: String,
    online: SigningKey,
}

fn fixture(membership: &str) -> Fixture {
    let online0 = key(0x01);
    let online = key(0x03);
    let rotation0 = rotation(0x02);
    let server0 = server_genesis(&rotation0, &online0, "chat.example.org").unwrap();
    let server1 = server_successor(
        &server0,
        &rotation0,
        &rotation(0x04),
        &online,
        "chat.example.org",
    )
    .unwrap();
    let server_id = server0.principal().to_id();
    let alice = user_genesis(
        &rotation(0x21),
        server0.digest(),
        pubkey(&key(0x2F)),
        "@alice:chat.example.org",
    )
    .unwrap();
    let alice_id = alice.principal().to_id();

    let mut context = AuthContext::default();
    context
        .server_epochs
        .insert(server_id.clone(), active("$server", vec![server0, server1]));
    context
        .user_epochs
        .insert(alice_id.clone(), active("$alice", vec![alice]));
    context.members.insert(
        alice_id.clone(),
        MemberState {
            membership: membership.to_owned(),
            custodian: Some(server_id.clone()),
        },
    );

    Fixture {
        context,
        server: server_id,
        alice: alice_id,
        online,
    }
}

#[test]
fn accepts_a_seal_from_a_joined_sender_custodied_by_the_subject_server() {
    let fixture = fixture("join");
    let event = seal_event(&fixture.alice, &fixture.server, 1, 1, &fixture.online);

    let seal = authorize_seal(&event, &fixture.context).unwrap();
    assert_eq!(seal.sealed_height, 1);
    assert_eq!(seal.server.to_id(), fixture.server);
}

#[test]
fn rejects_a_seal_sender_custodied_by_another_server() {
    let mut fixture = fixture("join");
    let other = RotationKey::from_seed([0x99; 32]);
    let other_server = server_genesis(&other, &key(0x98), "other.example.net").unwrap();
    let detached = user_genesis(
        &rotation(0x22),
        other_server.digest(),
        pubkey(&key(0x30)),
        "@alice:other.example.net",
    )
    .unwrap();
    fixture
        .context
        .user_epochs
        .insert(fixture.alice.clone(), active("$detached", vec![detached]));

    let event = seal_event(&fixture.alice, &fixture.server, 1, 0, &fixture.online);
    assert_eq!(
        authorize_seal(&event, &fixture.context),
        Err(Error::Authorization(
            "seal sender is not custodied by the subject server"
        ))
    );
}

#[test]
fn rejects_a_non_joined_seal_sender() {
    let fixture = fixture("leave");
    let event = seal_event(&fixture.alice, &fixture.server, 1, 0, &fixture.online);
    assert_eq!(
        authorize_seal(&event, &fixture.context),
        Err(Error::Authorization("seal sender is not joined"))
    );
}

#[test]
fn rejects_a_seal_above_the_signing_epoch_height() {
    let fixture = fixture("join");
    let event = seal_event(&fixture.alice, &fixture.server, 2, 1, &fixture.online);
    assert_eq!(
        authorize_seal(&event, &fixture.context),
        Err(Error::Authorization(
            "seal height exceeds its signing epoch"
        ))
    );
}

#[test]
fn seal_must_be_signed_by_the_current_epoch_key() {
    let rotation0 = rotation(0x02);
    let online0 = key(0x01);
    let online1 = key(0x03);
    let a0 = server_genesis(&rotation0, &online0, "chat.example.org").unwrap();
    let a1 = server_successor(
        &a0,
        &rotation0,
        &rotation(0x04),
        &online1,
        "chat.example.org",
    )
    .unwrap();
    let server = a0.principal().to_id();
    let alice = user_genesis(
        &rotation(0x21),
        a0.digest(),
        pubkey(&key(0x2F)),
        "@alice:chat.example.org",
    )
    .unwrap();
    let alice_id = alice.principal().to_id();
    let mut context = AuthContext::default();
    context
        .server_epochs
        .insert(server.clone(), active("$a1", vec![a0, a1]));
    context
        .user_epochs
        .insert(alice_id.clone(), active("$alice", vec![alice]));
    context.members.insert(
        alice_id.clone(),
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(server.clone()),
        },
    );

    let retired = seal_event(&alice_id, &server, 1, 0, &online0);
    assert_eq!(authorize_seal(&retired, &context), Err(Error::Signature));

    let current = seal_event(&alice_id, &server, 1, 1, &online1);
    authorize_seal(&current, &context).unwrap();
}

#[test]
fn rejects_a_seal_whose_subject_is_not_a_server_principal() {
    let fixture = fixture("join");
    let mut event = seal_event(&fixture.alice, &fixture.server, 1, 0, &fixture.online);
    event.insert(
        "state_key".into(),
        principal_id(Kind::User, [0x77; 32]).into(),
    );
    envelope::set_content_hash(&mut event).unwrap();
    envelope::sign_custodian(&mut event, &fixture.server, 1, &fixture.online).unwrap();
    assert!(matches!(
        authorize_seal(&event, &fixture.context),
        Err(Error::Seal(_))
    ));
}

#[test]
fn rejects_a_forged_seal_signature() {
    let fixture = fixture("join");
    let event = seal_event(&fixture.alice, &fixture.server, 1, 1, &key(0x66));
    assert_eq!(
        authorize_seal(&event, &fixture.context),
        Err(Error::Signature)
    );
}

#[test]
fn seal_content_hash_is_required() {
    let fixture = fixture("join");
    let mut event = seal_event(&fixture.alice, &fixture.server, 1, 0, &fixture.online);
    event
        .get_mut("content")
        .unwrap()
        .insert("sealed_height".into(), 3.into());
    assert!(authorize_seal(&event, &fixture.context).is_err());
}

fn principal_id(kind: Kind, root: [u8; 32]) -> String {
    Principal { kind, root }.to_id()
}
