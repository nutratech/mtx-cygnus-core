//! Event-level burn proofs from §4.2/§5.4, including bridge validation.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{
    bundle::{EpochParts, EpochStatus, VerifiedEpoch},
    commitment, envelope,
    link::{Body, Kind, Link, Payload},
    Principal,
};
use ed25519_zebra::SigningKey;
use rezzy_json::Value;

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn body(
    root: [u8; 32],
    height: u64,
    prev: [u8; 32],
    next_commit: [u8; 32],
    custodian: [u8; 32],
    localpart: &str,
) -> Body {
    Body {
        root,
        height,
        prev,
        next_commit,
        payload: Payload::User {
            custodian,
            master_key: Some([0xA5; 32]),
            display_user_id: format!("@{localpart}:chat.example.org"),
        },
    }
}

fn chains() -> (Vec<Link>, Vec<SigningKey>) {
    let custodian = [0x55; 32];
    let keys = vec![key(0x11), key(0x12), key(0x13)];
    let genesis = Link::user_genesis(body(
        [0; 32],
        0,
        [0; 32],
        commitment(&<[u8; 32]>::from(keys[0].verification_key())),
        custodian,
        "alice",
    ))
    .unwrap();
    let root = genesis.digest();
    let h1 = Link::sign_successor(
        body(
            root,
            1,
            genesis.digest(),
            commitment(&<[u8; 32]>::from(keys[1].verification_key())),
            custodian,
            "alice",
        ),
        &keys[0],
    )
    .unwrap();
    let h2 = Link::sign_successor(
        body(
            root,
            2,
            h1.digest(),
            commitment(&<[u8; 32]>::from(keys[2].verification_key())),
            custodian,
            "alice",
        ),
        &keys[1],
    )
    .unwrap();
    (vec![genesis, h1, h2], keys)
}

/// Create a sibling user link at the parent's next height with a distinct
/// display name chosen by `nonce`.
fn sibling(parent: &Link, signer: &SigningKey, nonce: u8) -> Link {
    let next = key(0x80 + nonce);
    let custodian = match &parent.body.payload {
        Payload::User { custodian, .. } => *custodian,
        Payload::Server { .. } => unreachable!(),
    };
    Link::sign_successor(
        body(
            parent.principal().root,
            parent.body.height + 1,
            parent.digest(),
            commitment(&<[u8; 32]>::from(next.verification_key())),
            custodian,
            if nonce % 2 == 0 { "alice" } else { "alice-alt" },
        ),
        signer,
    )
    .unwrap()
}

fn active(id: &str, links: Vec<Link>) -> VerifiedEpoch {
    VerifiedEpoch::from_parts_unchecked(EpochParts {
        event_id: id.to_owned(),
        principal: links[0].principal(),
        status: EpochStatus::Active,
        links,
        fork_height: None,
        claim: vec![],
        branches: None,
        ancestors: vec![],
    })
}

/// Build a burned user-epoch PDU carrying a fork proof.
fn burn_event(
    anchor: &VerifiedEpoch,
    fork_height: u64,
    parent: &Link,
    bridge: &[Link],
    a: &Link,
    b: &Link,
) -> Value {
    let parent_bytes = parent.body.encode().unwrap();
    let bridge = bridge
        .iter()
        .map(Link::to_b64)
        .collect::<Vec<_>>()
        .join("\",\"");
    let bridge_json = if bridge.is_empty() {
        String::new()
    } else {
        format!("\"{bridge}\"")
    };
    Value::parse(&format!(
        "{{\"type\":\"m.room.user_epoch\",\"state_key\":\"{}\",\"sender\":\"@bob:chat.example.org\",\"content\":{{\"status\":\"burned\",\"fork_height\":{fork_height},\"parent\":\"{}\",\"bridge\":[{bridge_json}],\"branch_a\":\"{}\",\"branch_b\":\"{}\"}}}}",
        anchor.principal().to_id(), B64.encode(&parent_bytes), a.to_b64(), b.to_b64()
    ))
    .unwrap()
}

/// Verify a burn event against its active anchor.
fn verify_burn(event: &Value, anchor: &VerifiedEpoch) -> Result<VerifiedEpoch, cygnus_core::Error> {
    VerifiedEpoch::burned(event, envelope::event_id(event)?, anchor)
}

#[test]
fn burn_parser_accepts_current_tip_fork_proof_and_derives_claim() {
    let (links, keys) = chains();
    let anchor = active("$anchor", links[..2].to_vec());
    let alternate = sibling(&links[0], &keys[0], 3);
    let event = burn_event(&anchor, 1, &links[0], &[], &links[1], &alternate);

    let burn = verify_burn(&event, &anchor).unwrap();
    assert_eq!(burn.status(), EpochStatus::Burned);
    assert_eq!(burn.fork_height(), Some(1));
    assert_eq!(
        burn.claim().iter().map(Link::digest).collect::<Vec<_>>(),
        vec![links[0].digest()]
    );
    assert_eq!(burn.branches().unwrap().0.digest(), links[1].digest());
}

#[test]
fn burn_parser_accepts_a_bridge_from_the_room_tip_to_a_future_fork() {
    let (links, keys) = chains();
    let anchor = active("$genesis", links[..1].to_vec());
    let a = links[2].clone();
    let b = sibling(&links[1], &keys[1], 4);
    let event = burn_event(&anchor, 2, &links[1], &[links[1].clone()], &a, &b);

    let burn = verify_burn(&event, &anchor).unwrap();
    assert_eq!(burn.fork_height(), Some(2));
    assert_eq!(
        burn.claim().iter().map(Link::digest).collect::<Vec<_>>(),
        vec![links[0].digest(), links[1].digest()]
    );
}

#[test]
fn burn_parser_rejects_wrong_anchor_and_malformed_branch_proofs() {
    let (links, keys) = chains();
    let anchor = active("$genesis", links[..1].to_vec());
    let a = links[1].clone();
    let b = sibling(&links[0], &keys[0], 5);
    let event = burn_event(&anchor, 1, &links[0], &[], &a, &b);
    let mut parts = anchor.clone().into_parts();
    parts.principal = Principal {
        kind: Kind::Server,
        root: anchor.principal().root,
    };
    let wrong_anchor = VerifiedEpoch::from_parts_unchecked(parts);
    assert!(verify_burn(&event, &wrong_anchor).is_err());

    let duplicate = burn_event(&anchor, 1, &links[0], &[], &a, &a);
    assert!(verify_burn(&duplicate, &anchor).is_err());

    let wrong_parent =
        Link::user_genesis(body([0; 32], 0, [0; 32], [0; 32], [0x55; 32], "alice")).unwrap();
    let bad_parent = burn_event(&anchor, 1, &wrong_parent, &[], &a, &b);
    assert!(verify_burn(&bad_parent, &anchor).is_err());
}
