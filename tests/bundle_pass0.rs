//! Pass 0 and burn-liveness conformance, ported from the T1-T7 scenarios in
//! `tools/reference_models/pid_ref.py`.
//!
//! These build `VerifiedEpoch` values directly: each link is a real signed
//! link, but the epoch wrapper is assembled so the tests exercise resolution
//! semantics (the reference model's `EpochEvent`) without re-deriving event
//! JSON. Event-level `VerifiedEpoch::burned` parsing is covered separately.

use cygnus_core::bundle::{resolve_pass0, ActiveAncestor, EpochStatus, VerifiedEpoch};
use cygnus_core::commitment;
use cygnus_core::link::{Body, Link, Payload};
use ed25519_consensus::SigningKey;

const MXID: &str = "@carol:chat.example.org";

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn pubkey(key: &SigningKey) -> [u8; 32] {
    key.verification_key().to_bytes()
}

fn user_body(
    root: [u8; 32],
    height: u64,
    prev: [u8; 32],
    next_commit: [u8; 32],
    custodian: [u8; 32],
) -> Body {
    Body {
        root,
        height,
        prev,
        next_commit,
        payload: Payload::User {
            custodian,
            master_key: None,
            display_user_id: MXID.to_owned(),
        },
    }
}

/// Honest chain of `n + 1` links (heights `0..=n`), rotation keys
/// `seed..seed+n`. Link `h` is signed by key `h-1`, matching the reference
/// model's `user_chain`.
fn user_chain(custodian: [u8; 32], n: usize, seed: u8) -> (Vec<Link>, Vec<SigningKey>) {
    let keys: Vec<SigningKey> = (0..=n)
        .map(|i| key(seed + u8::try_from(i).expect("chain length fits in u8")))
        .collect();
    let genesis = Link::user_genesis(user_body(
        [0; 32],
        0,
        [0; 32],
        commitment(&pubkey(&keys[0])),
        custodian,
    ))
    .unwrap();
    let root = genesis.digest();
    let mut links = vec![genesis];
    for i in 1..=n {
        let parent = &links[i - 1];
        links.push(
            Link::sign_successor(
                user_body(
                    root,
                    parent.body.height + 1,
                    parent.digest(),
                    commitment(&pubkey(&keys[i])),
                    custodian,
                ),
                &keys[i - 1],
            )
            .unwrap(),
        );
    }
    (links, keys)
}

/// A forged successor signed by the (consumed) rotation key `signer`. Returns
/// the link and the next rotation key the attacker committed to.
fn attacker_link(
    parent: &Link,
    signer: &SigningKey,
    custodian: [u8; 32],
    nonce: u8,
) -> (Link, SigningKey) {
    let next = key(0xC0 + nonce);
    let root = parent.principal().root;
    let link = Link::sign_successor(
        user_body(
            root,
            parent.body.height + 1,
            parent.digest(),
            commitment(&pubkey(&next)),
            custodian,
        ),
        signer,
    )
    .unwrap();
    (link, next)
}

fn active(id: &str, links: Vec<Link>, previous: Option<&VerifiedEpoch>) -> VerifiedEpoch {
    let mut ancestors = previous.map_or_else(Vec::new, |p| p.ancestors.clone());
    if let Some(previous) = previous {
        ancestors.push(ActiveAncestor {
            event_id: previous.event_id.clone(),
            links: previous.links.clone(),
        });
    }
    VerifiedEpoch {
        event_id: id.to_owned(),
        principal: links[0].principal(),
        status: EpochStatus::Active,
        links,
        fork_height: None,
        claim: Vec::new(),
        branches: None,
        ancestors,
    }
}

fn burned(
    id: &str,
    anchor: &VerifiedEpoch,
    fork_height: u64,
    claim: Vec<Link>,
    branch_a: Link,
    branch_b: Link,
) -> VerifiedEpoch {
    let mut ancestors = anchor.ancestors.clone();
    ancestors.push(ActiveAncestor {
        event_id: anchor.event_id.clone(),
        links: anchor.links.clone(),
    });
    VerifiedEpoch {
        event_id: id.to_owned(),
        principal: anchor.principal,
        status: EpochStatus::Burned,
        links: anchor.links.clone(),
        fork_height: Some(fork_height),
        claim,
        branches: Some((branch_a, branch_b)),
        ancestors,
    }
}

fn resolved(candidates: &[VerifiedEpoch]) -> String {
    resolve_pass0(candidates).expect("a resolution").event_id
}

#[test]
fn t1_lagging_burn_is_stale_once_a_newer_tip_is_in_the_merge() {
    let custodian = key(0x40).verification_key().to_bytes();
    let (links, keys) = user_chain(custodian, 2, 0x41);
    let (forged1, _) = attacker_link(&links[0], &keys[0], custodian, 1);

    let e0 = active("$e0", links[..1].to_vec(), None);
    let e1 = active("$e1", links[..2].to_vec(), Some(&e0));
    let e2 = active("$e2", links[..3].to_vec(), Some(&e1));

    // Burn forking at h=1, anchored on the h=2 tip: below the established tip.
    let stale = burned(
        "$b_stale",
        &e2,
        1,
        links[..1].to_vec(),
        links[1].clone(),
        forged1.clone(),
    );
    assert_eq!(
        resolved(&[e0.clone(), e1.clone(), e2.clone(), stale]),
        "$e2"
    );

    // The same burn is live in a room still at the h=1 handover tip.
    let lagging = burned(
        "$b_lag",
        &e1,
        1,
        links[..1].to_vec(),
        links[1].clone(),
        forged1,
    );
    assert_eq!(resolved(&[e0, e1.clone(), lagging.clone()]), "$b_lag");
    // And stale again once h=2 is present.
    assert_eq!(resolved(&[e1, e2, lagging]), "$e2");
}

#[test]
fn t2_live_burn_wins_over_the_longer_attacker_branch() {
    let custodian = key(0x50).verification_key().to_bytes();
    let (links, keys) = user_chain(custodian, 3, 0x51);

    let c0 = active("$c0", links[..2].to_vec(), None);
    let honest = active("$y", links.clone(), Some(&c0));

    let (mut forged, mut next) = attacker_link(&links[1], &keys[1], custodian, 0);
    let mut forged_chain = vec![forged.clone()];
    for i in 0..4 {
        let (link, n) = attacker_link(&forged, &next, custodian, 10 + i);
        forged = link.clone();
        forged_chain.push(link);
        next = n;
    }
    let attacker = active(
        "$x",
        [links[..2].to_vec(), forged_chain.clone()].concat(),
        Some(&c0),
    );

    let honest_burn = burned(
        "$hb",
        &c0,
        2,
        links[..2].to_vec(),
        links[2].clone(),
        forged_chain[0].clone(),
    );

    assert_eq!(
        resolved(&[
            c0.clone(),
            honest.clone(),
            attacker.clone(),
            honest_burn.clone()
        ]),
        "$hb",
        "a live burn outranks the longer attacker branch"
    );
    assert_eq!(
        resolved(&[c0.clone(), honest.clone(), attacker.clone()]),
        "$c0",
        "without a burn, conflicting branches freeze at the common epoch"
    );
    assert_eq!(
        resolved(&[honest, attacker]),
        "$c0",
        "the common epoch is reachable through auth-chain ancestors"
    );
}

#[test]
fn t4_burn_only_conflict_selects_the_earliest_fork_height() {
    let custodian = key(0x70).verification_key().to_bytes();
    let (links, keys) = user_chain(custodian, 2, 0x71);
    let t0 = active("$t0", links.clone(), None);

    let (a3, _) = attacker_link(&links[2], &keys[2], custodian, 7);
    let (b3, _) = attacker_link(&links[2], &keys[2], custodian, 8);
    let live = burned("$live", &t0, 3, links.clone(), a3, b3);

    let (sibling, _) = attacker_link(&links[1], &keys[1], custodian, 9);
    let at_tip = burned(
        "$tip",
        &t0,
        2,
        links[..2].to_vec(),
        links[2].clone(),
        sibling,
    );

    assert_eq!(resolved(&[t0, live.clone()]), "$live");
    assert_eq!(resolved(&[live, at_tip]), "$tip");
}

#[test]
fn t5_linear_tip_wins_and_equal_tips_break_by_event_id() {
    let custodian = key(0x80).verification_key().to_bytes();
    let (links, _) = user_chain(custodian, 2, 0x81);

    let p0 = active("$p0", links[..1].to_vec(), None);
    let p1 = active("$p1", links[..2].to_vec(), Some(&p0));
    // Deliberately swap the IDs: the lexicographically smaller ID must win.
    let larger_id = active("$p2b", links[..3].to_vec(), Some(&p1));
    let smaller_id = active("$p2a", links[..3].to_vec(), Some(&p1));

    assert_eq!(resolved(&[p0, p1, larger_id, smaller_id]), "$p2a");
}

#[test]
fn t6_concurrent_introductions_freeze_at_a_genesis_epoch() {
    let custodian = key(0x90).verification_key().to_bytes();
    let (links, keys) = user_chain(custodian, 1, 0x91);
    let (forged, _) = attacker_link(&links[0], &keys[0], custodian, 3);

    let ga = active("$ga", links[..1].to_vec(), None);
    let gb = active("$gb", links[..1].to_vec(), None);
    let a1 = active("$a1", links[..2].to_vec(), Some(&ga));
    let b1 = active("$b1", vec![links[0].clone(), forged.clone()], Some(&gb));

    assert_eq!(
        resolved(&[ga.clone(), gb.clone(), a1.clone(), b1.clone()]),
        "$ga"
    );

    let burn = burned(
        "$burn6",
        &ga,
        1,
        links[..1].to_vec(),
        links[1].clone(),
        forged,
    );
    assert_eq!(resolved(&[ga, gb, a1, b1, burn]), "$burn6");
}

#[test]
fn t7_freeze_is_order_independent_across_heights() {
    let custodian = key(0x30).verification_key().to_bytes();
    let (links, keys) = user_chain(custodian, 15, 0x31);

    let mut base = vec![active("$sw_e0", links[..1].to_vec(), None)];
    for i in 1..links.len() {
        let event = active(
            &format!("$sw_e{i}"),
            links[..=i].to_vec(),
            Some(base.last().unwrap()),
        );
        base.push(event);
    }

    for h in 1..=10 {
        let parent = base[h - 1].clone();
        let y1 = active(&format!("$y1_{h}"), links[..=h].to_vec(), Some(&parent));
        let y2 = active(&format!("$y2_{h}"), links[..=h + 1].to_vec(), Some(&y1));
        let (f1, next) = attacker_link(
            &links[h - 1],
            &keys[h - 1],
            custodian,
            u8::try_from(h).expect("sweep height fits"),
        );
        let (f2, _) = attacker_link(
            &f1,
            &next,
            custodian,
            u8::try_from(h + 1).expect("sweep height fits"),
        );
        let x1 = active(
            &format!("$x1_{h}"),
            [links[..h].to_vec(), vec![f1.clone()]].concat(),
            Some(&parent),
        );
        let x2 = active(
            &format!("$x2_{h}"),
            [links[..h].to_vec(), vec![f1, f2]].concat(),
            Some(&x1),
        );

        let candidates = [y1, y2, x1, x2];
        assert_eq!(resolved(&candidates), parent.event_id);
        let reversed: Vec<_> = candidates.into_iter().rev().collect();
        assert_eq!(resolved(&reversed), parent.event_id);
        let rotated: Vec<_> = reversed.into_iter().cycle().skip(2).take(4).collect();
        assert_eq!(resolved(&rotated), parent.event_id);
    }
}
