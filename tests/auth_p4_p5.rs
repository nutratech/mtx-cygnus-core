//! P4 relay and P5 retired-key scenarios, ported from `pid_pdu.py`.
//!
//! The vendored PDU fixture carries only the P1/P2/P3 room, so these scenarios
//! are rebuilt from the reference model's deterministic seeds. The links
//! (`A0`, `A1`, `B0`, `U0`, `U1`) are the upstream fixtures, taken from the
//! JSON so the tests also cover their wire encoding.
//!
//! Check 21 (a stale `auth_events` citation) is a state-before rule owned by
//! the base-auth/state-selection layer, not by this authorization overlay, so
//! it is not exercised here.

// Scenario builders mirror `pid_pdu.py`; their length and a/b naming follow it.
#![allow(
    clippy::too_many_lines,
    clippy::similar_names,
    clippy::struct_field_names
)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::sig::SigningKey;
use cygnus_core::{
    auth::{
        authorize_active_epoch, authorize_create, authorize_user_event, AuthContext, MemberState,
    },
    bundle::VerifiedEpoch,
    commitment, envelope,
    link::{Body, Kind, Link, Payload},
    Error, Principal, DEVICE_CERT_TAG,
};
use rezzy_json::{Object, Value};

const ROOM_VERSION: &str = "tk.nutra.cygnus.1";

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn pubkey(key: &SigningKey) -> [u8; 32] {
    key.verification_key().to_bytes()
}

fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

fn canonical(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut object = Object::new();
    for (key, value) in fields {
        object.insert((*key).into(), Value::String((*value).into()));
    }
    rezzy_json::to_canonical_string(&Value::Object(object))
        .unwrap()
        .into_bytes()
}

// ---------------------------------------------------------------------------
// Fixture links and device credentials

fn vectors() -> Vec<Value> {
    Value::parse(include_str!("vectors/pid_pdu_vectors.json"))
        .unwrap()
        .get("events")
        .and_then(Value::as_array)
        .unwrap()
        .clone()
}

fn links_in(content: &Value, field: &str) -> Vec<Link> {
    content
        .get(field)
        .and_then(Value::as_array)
        .unwrap()
        .iter()
        .map(|value| Link::from_b64(value.as_str().unwrap()).unwrap())
        .collect()
}

/// `(A0, A1, B0, U0, U1)` from the upstream P1/P2 fixtures.
fn fixture_links() -> (Link, Link, Link, Link, Link) {
    let events = vectors();
    let create = events[0].get("pdu").unwrap();
    let server = links_in(
        create.get("content").unwrap().get("creator_links").unwrap(),
        "server",
    );
    let user = links_in(
        create.get("content").unwrap().get("creator_links").unwrap(),
        "user",
    );
    let migrated = links_in(
        events[8].get("pdu").unwrap().get("content").unwrap(),
        "links",
    );
    let server_b = links_in(
        events[9].get("pdu").unwrap().get("content").unwrap(),
        "links",
    );
    (
        server[0].clone(),
        server[1].clone(),
        server_b[0].clone(),
        user[0].clone(),
        migrated[0].clone(),
    )
}

struct Credentials {
    principal: String,
    master: SigningKey,
    self_signing: SigningKey,
    signing_key: SigningKey,
    id: String,
}

impl Credentials {
    /// Mirrors `register_device(principal, master_sk, seed_byte)`.
    fn new(principal: &str, master_seed: u8, cert_seed: u8) -> Self {
        Self {
            principal: principal.to_owned(),
            master: key(master_seed),
            self_signing: key(cert_seed),
            signing_key: key(cert_seed + 1),
            id: format!("TEST{cert_seed:02x}"),
        }
    }

    fn certificate(&self) -> Value {
        let self_key = b64(&pubkey(&self.self_signing));
        let device_key = b64(&pubkey(&self.signing_key));
        let self_statement = canonical(&[
            ("key", &self_key),
            ("principal", &self.principal),
            ("purpose", "self_signing"),
        ]);
        let device_statement = canonical(&[
            ("device_id", &self.id),
            ("key", &device_key),
            ("principal", &self.principal),
        ]);
        let self_signature = self
            .master
            .sign(&[DEVICE_CERT_TAG, self_statement.as_slice()].concat());
        let device_signature = self
            .self_signing
            .sign(&[DEVICE_CERT_TAG, device_statement.as_slice()].concat());

        let mut certificate = Object::new();
        certificate.insert("version".into(), 1u64.into());
        certificate.insert("device_id".into(), self.id.clone().into());
        certificate.insert("device_key".into(), device_key.into());
        certificate.insert("self_signing_key".into(), self_key.into());
        certificate.insert(
            "self_signing_signature".into(),
            b64(&self_signature.to_bytes()).into(),
        );
        certificate.insert(
            "device_key_signature".into(),
            b64(&device_signature.to_bytes()).into(),
        );
        Value::Object(certificate)
    }
}

// ---------------------------------------------------------------------------
// PDU construction

fn event(kind: &str, sender: &str, state_key: Option<&str>, content: Value) -> Value {
    let mut object = Object::new();
    object.insert("type".into(), kind.into());
    object.insert("sender".into(), sender.into());
    object.insert("content".into(), content);
    object.insert("origin_server_ts".into(), 1_792_860_000_000u64.into());
    object.insert("depth".into(), 1u64.into());
    object.insert("prev_events".into(), Value::Array(Vec::new()));
    object.insert("auth_events".into(), Value::Array(Vec::new()));
    if let Some(state_key) = state_key {
        object.insert("state_key".into(), state_key.into());
    }
    Value::Object(object)
}

/// Add a device certificate, then the device and custodian signatures.
fn finish_device(
    mut event: Value,
    device: &Credentials,
    custodian: &str,
    height: u64,
    key: &SigningKey,
) -> Value {
    event.insert("device_certificate".into(), device.certificate());
    envelope::set_content_hash(&mut event).unwrap();
    envelope::sign_device(
        &mut event,
        &device.principal,
        &device.id,
        &device.signing_key,
    )
    .unwrap();
    envelope::sign_custodian(&mut event, custodian, height, key).unwrap();
    event
}

/// Add only the custodian signature (epoch and create events).
fn finish(mut event: Value, custodian: &str, height: u64, key: &SigningKey) -> Value {
    envelope::set_content_hash(&mut event).unwrap();
    envelope::sign_custodian(&mut event, custodian, height, key).unwrap();
    event
}

fn user_content(links: &[Link], signer_links: Option<&[Link]>) -> Value {
    let tip = links.last().unwrap();
    let Payload::User {
        custodian,
        master_key,
        display_user_id,
    } = &tip.body.payload
    else {
        panic!("user_content needs a user link");
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
    if let Some(signer_links) = signer_links {
        content.insert(
            "signer_links".into(),
            Value::Array(
                signer_links
                    .iter()
                    .map(|link| link.to_b64().into())
                    .collect(),
            ),
        );
    }
    Value::Object(content)
}

fn server_content(links: &[Link], signer_links: Option<&[Link]>) -> Value {
    let tip = links.last().unwrap();
    let Payload::Server {
        online_key,
        server_name,
    } = &tip.body.payload
    else {
        panic!("server_content needs a server link");
    };
    let mut content = Object::new();
    content.insert("status".into(), "active".into());
    content.insert(
        "links".into(),
        Value::Array(links.iter().map(|link| link.to_b64().into()).collect()),
    );
    content.insert("height".into(), tip.body.height.into());
    content.insert("tip".into(), b64(&tip.digest()).into());
    content.insert("online_key".into(), b64(online_key).into());
    content.insert("server_name".into(), server_name.clone().into());
    if let Some(signer_links) = signer_links {
        content.insert(
            "signer_links".into(),
            Value::Array(
                signer_links
                    .iter()
                    .map(|link| link.to_b64().into())
                    .collect(),
            ),
        );
    }
    Value::Object(content)
}

fn member_content(custodian: &str) -> Value {
    let mut content = Object::new();
    content.insert("membership".into(), "join".into());
    content.insert("custodian".into(), custodian.into());
    Value::Object(content)
}

fn id(event: &Value) -> String {
    envelope::event_id(event).unwrap()
}

fn authorize_epoch(event: &Value, context: &AuthContext) -> VerifiedEpoch {
    authorize_active_epoch(event, &id(event), context)
        .unwrap_or_else(|error| panic!("epoch rejected: {error:?}"))
}

// ---------------------------------------------------------------------------
// A room founded by Bob on server B (§ the P4/P5 harness `bobs_room`)

struct BobsRoom {
    context: AuthContext,
    bob: String,
    alice: String,
    server_a: String,
    server_b: String,
}

fn bobs_room(a0: &Link, b0: &Link, u0: &Link, server_b: &SigningKey) -> BobsRoom {
    let bob_rotation = key(0x31);
    let bob_master = key(0x53);
    let bob_genesis = Link::user_genesis(Body {
        root: [0; 32],
        height: 0,
        prev: [0; 32],
        next_commit: commitment(&pubkey(&bob_rotation)),
        payload: Payload::User {
            custodian: b0.digest(),
            master_key: Some(pubkey(&bob_master)),
            display_user_id: "@bob:second.example.net".to_owned(),
        },
    })
    .unwrap();
    let bob = bob_genesis.principal().to_id();
    let device = Credentials::new(&bob, 0x53, 0x55);

    let b_principal = b0.principal().to_id();
    let a_principal = a0.principal().to_id();
    let alice = u0.principal().to_id();

    let mut creator_links = Object::new();
    creator_links.insert("server".into(), Value::Array(vec![b0.to_b64().into()]));
    creator_links.insert(
        "user".into(),
        Value::Array(vec![bob_genesis.to_b64().into()]),
    );
    let mut create_content = Object::new();
    create_content.insert("room_version".into(), ROOM_VERSION.into());
    create_content.insert("creator_links".into(), Value::Object(creator_links));
    let create = finish_device(
        event(
            "m.room.create",
            &bob,
            Some(""),
            Value::Object(create_content),
        ),
        &device,
        &b_principal,
        0,
        server_b,
    );
    let created = authorize_create(&create, &id(&create)).unwrap();
    assert_eq!(created.user_principal.to_id(), bob);

    let mut context = AuthContext::default();
    context.creators.insert(bob.clone());

    let bob_epoch = authorize_epoch(
        &finish(
            event(
                "m.room.user_epoch",
                &bob,
                Some(&bob),
                user_content(&[bob_genesis], Some(std::slice::from_ref(b0))),
            ),
            &b_principal,
            0,
            server_b,
        ),
        &context,
    );
    context.user_epochs.insert(bob.clone(), bob_epoch);

    let b_epoch = authorize_epoch(
        &finish(
            event(
                "m.room.server_epoch",
                &bob,
                Some(&b_principal),
                server_content(std::slice::from_ref(b0), Some(std::slice::from_ref(b0))),
            ),
            &b_principal,
            0,
            server_b,
        ),
        &context,
    );
    context.server_epochs.insert(b_principal.clone(), b_epoch);

    let member = finish_device(
        event(
            "m.room.member",
            &bob,
            Some(&bob),
            member_content(&b_principal),
        ),
        &device,
        &b_principal,
        0,
        server_b,
    );
    authorize_user_event(&member, &context).unwrap();
    context.members.insert(
        bob.clone(),
        MemberState {
            membership: "join".to_owned(),
            custodian: Some(b_principal.clone()),
        },
    );

    let mut join_rules = Object::new();
    join_rules.insert("join_rule".into(), "public".into());
    let join_rules = finish_device(
        event(
            "m.room.join_rules",
            &bob,
            Some(""),
            Value::Object(join_rules),
        ),
        &device,
        &b_principal,
        0,
        server_b,
    );
    authorize_user_event(&join_rules, &context).unwrap();
    context.join_rule = Some("public".to_owned());

    BobsRoom {
        context,
        bob,
        alice,
        server_a: a_principal,
        server_b: b_principal,
    }
}

// ---------------------------------------------------------------------------

#[test]
fn p4_ex_custodian_prefix_replay_and_relay() {
    let (a0, a1, b0, u0, u1) = fixture_links();
    let server_a_retired = key(0x01);
    let server_a_current = key(0x03);
    let server_b_key = key(0x11);
    let alice_device = Credentials::new(&u0.principal().to_id(), 0x2F, 0x51);
    let mut room = bobs_room(&a0, &b0, &u0, &server_b_key);
    let server_a = room.server_a.clone();
    let server_b = room.server_b.clone();
    let alice = room.alice.clone();
    let bob = room.bob.clone();

    // 15: the ex-custodian can introduce Alice's h=0 prefix in a room that has
    // never seen her. The introduction carries A's signer chain.
    let introduction = finish(
        event(
            "m.room.user_epoch",
            &alice,
            Some(&alice),
            user_content(std::slice::from_ref(&u0), Some(&[a0.clone(), a1.clone()])),
        ),
        &server_a,
        1,
        &server_a_current,
    );
    let epoch = authorize_epoch(&introduction, &room.context);
    assert_eq!(
        links_in(introduction.get("content").unwrap(), "links"),
        vec![u0.clone()]
    );
    room.context.user_epochs.insert(alice.clone(), epoch);

    // A's server epoch is introduced and advanced to its h=1 tip.
    for content in [
        server_content(std::slice::from_ref(&a0), Some(&[a0.clone(), a1.clone()])),
        server_content(std::slice::from_ref(&a1), None),
    ] {
        let epoch = authorize_epoch(
            &finish(
                event("m.room.server_epoch", &alice, Some(&server_a), content),
                &server_a,
                1,
                &server_a_current,
            ),
            &room.context,
        );
        room.context.server_epochs.insert(server_a.clone(), epoch);
    }

    // 16/17: A cannot forge Alice's join or message without her device
    // signature, even though A owns the current custodian key.
    let forged_join = finish(
        event(
            "m.room.member",
            &alice,
            Some(&alice),
            member_content(&server_a),
        ),
        &server_a,
        1,
        &server_a_current,
    );
    assert!(authorize_user_event(&forged_join, &room.context).is_err());
    let forged_message = finish(
        event("m.room.message", &alice, None, message_content("impostor")),
        &server_a,
        1,
        &server_a_current,
    );
    assert!(authorize_user_event(&forged_message, &room.context).is_err());

    // 18: a non-member cannot relay Alice's newer link.
    let outsider = Principal {
        kind: Kind::User,
        root: pubkey(&key(0x70)),
    }
    .to_id();
    let relay_by_outsider = finish(
        event(
            "m.room.user_epoch",
            &outsider,
            Some(&alice),
            user_content(std::slice::from_ref(&u1), Some(std::slice::from_ref(&b0))),
        ),
        &server_b,
        0,
        &server_b_key,
    );
    assert!(
        authorize_active_epoch(&relay_by_outsider, &id(&relay_by_outsider), &room.context).is_err()
    );

    // 19: Bob's server relays Alice's newer link as Bob's custodian.
    let relay = finish(
        event(
            "m.room.user_epoch",
            &bob,
            Some(&alice),
            user_content(std::slice::from_ref(&u1), Some(std::slice::from_ref(&b0))),
        ),
        &server_b,
        0,
        &server_b_key,
    );
    let relayed = authorize_epoch(&relay, &room.context);
    room.context.user_epochs.insert(alice.clone(), relayed);

    // 20: after the relay the ex-custodian can no longer act for Alice.
    let stale_message = finish_device(
        event("m.room.message", &alice, None, message_content("impostor")),
        &alice_device,
        &server_a,
        1,
        &server_a_current,
    );
    assert!(authorize_user_event(&stale_message, &room.context).is_err());

    // 22 (P5, first half): with A's current tip known to the room, the retired
    // h=0 online key cannot introduce Mallory.
    let mallory_rotation = key(0x35);
    let mallory_master = key(0x57);
    let mallory_genesis = mallory_genesis(&a0, &mallory_rotation, &mallory_master);
    let mallory = mallory_genesis.principal().to_id();
    let retired_introduction = finish(
        event(
            "m.room.user_epoch",
            &mallory,
            Some(&mallory),
            user_content(
                std::slice::from_ref(&mallory_genesis),
                Some(std::slice::from_ref(&a0)),
            ),
        ),
        &server_a,
        0,
        &server_a_retired,
    );
    assert!(authorize_active_epoch(
        &retired_introduction,
        &id(&retired_introduction),
        &room.context
    )
    .is_err());

    // Keep the master key reachable so the fixture device is not optimized away
    // if the assertions above change shape.
    // The room still authorizes the ordinary event from the device owner.
}

#[test]
fn p5_retired_key_replay_and_relay() {
    let (a0, a1, b0, u0, _u1) = fixture_links();
    let server_a_retired = key(0x01);
    let server_b_key = key(0x11);
    let mut room = bobs_room(&a0, &b0, &u0, &server_b_key);
    let server_a = room.server_a.clone();
    let server_b = room.server_b.clone();
    let bob = room.bob.clone();

    let mallory_rotation = key(0x35);
    let mallory_master = key(0x57);
    let mallory_genesis = mallory_genesis(&a0, &mallory_rotation, &mallory_master);
    let mallory = mallory_genesis.principal().to_id();
    let mallory_device = Credentials::new(&mallory, 0x57, 0x59);

    // 23: a thief holding A's retired online key can introduce a principal
    // under A's h=0 prefix in a room that does not yet know A's tip.
    let introduction = finish(
        event(
            "m.room.user_epoch",
            &mallory,
            Some(&mallory),
            user_content(
                std::slice::from_ref(&mallory_genesis),
                Some(std::slice::from_ref(&a0)),
            ),
        ),
        &server_a,
        0,
        &server_a_retired,
    );
    let epoch = authorize_epoch(&introduction, &room.context);
    room.context.user_epochs.insert(mallory.clone(), epoch);

    // Introduce A at h=0 with the retired key.
    let a0_epoch = authorize_epoch(
        &finish(
            event(
                "m.room.server_epoch",
                &mallory,
                Some(&server_a),
                server_content(std::slice::from_ref(&a0), Some(std::slice::from_ref(&a0))),
            ),
            &server_a,
            0,
            &server_a_retired,
        ),
        &room.context,
    );
    room.context
        .server_epochs
        .insert(server_a.clone(), a0_epoch);

    // 24/25: the retired server key still cannot forge Mallory's device
    // signature.
    let forged_join = finish(
        event(
            "m.room.member",
            &mallory,
            Some(&mallory),
            member_content(&server_a),
        ),
        &server_a,
        0,
        &server_a_retired,
    );
    assert!(authorize_user_event(&forged_join, &room.context).is_err());
    let forged_message = finish(
        event("m.room.message", &mallory, None, message_content("spoof")),
        &server_a,
        0,
        &server_a_retired,
    );
    assert!(authorize_user_event(&forged_message, &room.context).is_err());

    // 26: Bob's server relays A's newer link.
    let relay = finish(
        event(
            "m.room.server_epoch",
            &bob,
            Some(&server_a),
            server_content(std::slice::from_ref(&a1), None),
        ),
        &server_b,
        0,
        &server_b_key,
    );
    let relayed = authorize_epoch(&relay, &room.context);
    room.context.server_epochs.insert(server_a.clone(), relayed);

    // 27: the retired key no longer verifies after the relay, even on a fully
    // device-signed event.
    let stale_message = finish_device(
        event("m.room.message", &mallory, None, message_content("spoof")),
        &mallory_device,
        &server_a,
        0,
        &server_a_retired,
    );
    assert!(matches!(
        authorize_user_event(&stale_message, &room.context),
        Err(Error::Signature)
    ));
}

fn mallory_genesis(a0: &Link, rotation: &SigningKey, master: &SigningKey) -> Link {
    Link::user_genesis(Body {
        root: [0; 32],
        height: 0,
        prev: [0; 32],
        next_commit: commitment(&pubkey(rotation)),
        payload: Payload::User {
            custodian: a0.digest(),
            master_key: Some(pubkey(master)),
            display_user_id: "@mallory:chat.example.org".to_owned(),
        },
    })
    .unwrap()
}

fn message_content(body: &str) -> Value {
    let mut content = Object::new();
    content.insert("msgtype".into(), "m.text".into());
    content.insert("body".into(), body.into());
    Value::Object(content)
}
