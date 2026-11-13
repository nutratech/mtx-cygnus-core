//! §8 name-binding and ingress conformance, ported from `pid_ref.py`.

use cygnus_core::binding::{admit, Acl, BindingState, Ingress, NameBinding};
use cygnus_core::commitment;
use cygnus_core::link::{Body, Link, Payload};
use cygnus_core::Principal;
use ed25519_zebra::SigningKey;

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn pubkey(key: &SigningKey) -> [u8; 32] {
    <[u8; 32]>::from(key.verification_key())
}

fn server_genesis(online: &SigningKey, rotation: &SigningKey, name: &str) -> Link {
    let body = Body {
        root: [0; 32],
        height: 0,
        prev: [0; 32],
        next_commit: commitment(&pubkey(rotation)),
        payload: Payload::Server {
            online_key: pubkey(online),
            server_name: name.to_owned(),
        },
    };
    Link::sign_server_genesis(body, online).unwrap()
}

fn server_rotation(
    parent: &Link,
    signer: &SigningKey,
    next: &SigningKey,
    online: &SigningKey,
    name: &str,
) -> Link {
    let body = Body {
        root: parent.principal().root,
        height: parent.body.height + 1,
        prev: parent.digest(),
        next_commit: commitment(&pubkey(next)),
        payload: Payload::Server {
            online_key: pubkey(online),
            server_name: name.to_owned(),
        },
    };
    Link::sign_successor(body, signer).unwrap()
}

struct Chain {
    a0: Link,
    renamed: Link,
    divergent: Link,
    fork_a: Link,
    fork_b: Link,
    alias3: Link,
    alias4: Link,
}

fn chain() -> (Principal, Chain) {
    let online0 = key(0xA1);
    let online1 = key(0xA2);
    let rot0 = key(0xB1);
    let rot1 = key(0xB2);
    let rot2 = key(0xB3);

    let a0 = server_genesis(&online0, &rot0, "chat.example.org");
    let principal = a0.principal();
    let renamed = server_rotation(&a0, &rot0, &rot1, &online1, "new.example.org");
    let divergent = server_rotation(&a0, &rot0, &rot1, &online1, "divergent.example.org");
    let fork_a = server_rotation(&renamed, &rot1, &rot2, &online1, "current.example.org");
    let fork_b = server_rotation(&renamed, &rot1, &rot2, &online1, "forked-deny.example.org");
    let alias3 = server_rotation(&renamed, &rot1, &rot2, &online1, "third.example.org");
    let alias4 = server_rotation(&alias3, &rot2, &key(0xB4), &online1, "fourth.example.org");

    (
        principal,
        Chain {
            a0,
            renamed,
            divergent,
            fork_a,
            fork_b,
            alias3,
            alias4,
        },
    )
}

fn acl(allow: &[&str], deny: &[&str]) -> Acl {
    Acl {
        allow: allow.iter().map(|s| (*s).to_owned()).collect(),
        deny: deny.iter().map(|s| (*s).to_owned()).collect(),
    }
}

#[test]
fn lookup_takeover_contests_the_earlier_principal() {
    let mut bindings = NameBinding::default();
    bindings.observe("old.example", Some("P1"));
    bindings.observe("old.example", Some("P2"));
    assert_eq!(bindings.state("old.example", "P1"), BindingState::Contested);
    assert_eq!(bindings.state("old.example", "P2"), BindingState::Verified);
}

#[test]
fn outage_preserves_contested_and_retries_formerly_verified() {
    let mut bindings = NameBinding::default();
    bindings.observe("old.example", Some("P1"));
    bindings.observe("old.example", Some("P2"));
    bindings.observe("old.example", None);
    assert_eq!(bindings.state("old.example", "P1"), BindingState::Contested);
    assert_eq!(
        bindings.state("old.example", "P2"),
        BindingState::FormerlyVerified
    );
    assert!(bindings.needs_reverification("old.example"));
    assert!(!bindings.admits_name_allow("old.example", "P1"));
    assert!(bindings.admits_name_allow("old.example", "P2"));
}

#[test]
fn successful_recovery_restores_the_earlier_principal() {
    let mut bindings = NameBinding::default();
    bindings.observe("old.example", Some("P1"));
    bindings.observe("old.example", Some("P2"));
    bindings.observe("old.example", Some("P1"));
    assert_eq!(bindings.state("old.example", "P1"), BindingState::Verified);
    assert_eq!(bindings.state("old.example", "P2"), BindingState::Contested);
    assert!(bindings.admits_name_allow("old.example", "P1"));
    assert!(!bindings.admits_name_allow("old.example", "P2"));
}

#[test]
fn single_pair_outage_preserves_formerly_verified_admission() {
    let mut bindings = NameBinding::default();
    bindings.observe("single.example", Some("P3"));
    bindings.observe("single.example", None);
    assert_eq!(
        bindings.state("single.example", "P3"),
        BindingState::FormerlyVerified
    );
    assert!(bindings.needs_reverification("single.example"));
    assert!(bindings.admits_name_allow("single.example", "P3"));
}

#[test]
fn formerly_verified_pair_recovers_on_same_result() {
    let mut bindings = NameBinding::default();
    bindings.observe("single.example", Some("P3"));
    bindings.observe("single.example", None);
    bindings.observe("single.example", Some("P3"));
    assert_eq!(
        bindings.state("single.example", "P3"),
        BindingState::Verified
    );
    assert!(bindings.admits_name_allow("single.example", "P3"));
}

#[test]
fn admits_rename_before_room_processes_epoch_advancement() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("new.example.org", Some(&principal.to_id()));
    let branches = vec![vec![chain.a0.clone(), chain.renamed.clone()]];
    assert_eq!(
        admit(
            &acl(&["*"], &[]),
            &principal,
            "new.example.org",
            Some(&chain.a0),
            Some(&branches),
            &bindings,
        ),
        Ingress::Admit
    );
}

#[test]
fn rejects_alias_from_before_the_room_epoch_tip() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("chat.example.org", Some(&principal.to_id()));
    let branches = vec![vec![chain.a0.clone(), chain.renamed.clone()]];
    assert_eq!(
        admit(
            &acl(&["*"], &[]),
            &principal,
            "chat.example.org",
            Some(&chain.renamed),
            Some(&branches),
            &bindings,
        ),
        Ingress::Reject
    );
}

#[test]
fn deny_matches_a_name_on_another_validated_fork_branch() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("current.example.org", Some(&principal.to_id()));
    let branches = vec![
        vec![
            chain.a0.clone(),
            chain.renamed.clone(),
            chain.fork_a.clone(),
        ],
        vec![
            chain.a0.clone(),
            chain.renamed.clone(),
            chain.fork_b.clone(),
        ],
    ];
    assert_eq!(
        admit(
            &acl(&["*"], &["forked-deny.example.org"]),
            &principal,
            "current.example.org",
            Some(&chain.renamed),
            Some(&branches),
            &bindings,
        ),
        Ingress::Reject
    );
}

#[test]
fn rejects_name_on_branch_that_does_not_contain_tip() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("divergent.example.org", Some(&principal.to_id()));
    let branches = vec![vec![chain.a0.clone(), chain.divergent.clone()]];
    assert_eq!(
        admit(
            &acl(&["*"], &[]),
            &principal,
            "divergent.example.org",
            Some(&chain.renamed),
            Some(&branches),
            &bindings,
        ),
        Ingress::Reject
    );
}

#[test]
fn still_rejects_when_tip_branch_is_also_supplied() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("divergent.example.org", Some(&principal.to_id()));
    let branches = vec![
        vec![chain.a0.clone(), chain.renamed.clone()],
        vec![chain.a0.clone(), chain.divergent.clone()],
    ];
    assert_eq!(
        admit(
            &acl(&["*"], &[]),
            &principal,
            "divergent.example.org",
            Some(&chain.renamed),
            Some(&branches),
            &bindings,
        ),
        Ingress::Reject
    );
}

#[test]
fn historical_deny_finds_oldest_prior_alias() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("fourth.example.org", Some(&principal.to_id()));
    let branches = vec![vec![
        chain.a0.clone(),
        chain.renamed.clone(),
        chain.alias3.clone(),
        chain.alias4.clone(),
    ]];
    assert_eq!(
        admit(
            &acl(&["*"], &["chat.example.org"]),
            &principal,
            "fourth.example.org",
            Some(&chain.alias4),
            Some(&branches),
            &bindings,
        ),
        Ingress::Reject
    );
}

#[test]
fn first_contact_with_complete_links_evaluates_ingress() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("new.example.org", Some(&principal.to_id()));
    let branches = vec![vec![chain.a0.clone(), chain.renamed.clone()]];
    assert_eq!(
        admit(
            &acl(&["*"], &["blocked.example.org"]),
            &principal,
            "new.example.org",
            None,
            Some(&branches),
            &bindings,
        ),
        Ingress::Admit
    );
}

#[test]
fn first_contact_without_links_defers() {
    let (principal, chain) = chain();
    let mut bindings = NameBinding::default();
    bindings.observe("new.example.org", Some(&principal.to_id()));
    assert_eq!(
        admit(
            &acl(&["*"], &["blocked.example.org"]),
            &principal,
            "new.example.org",
            None,
            None,
            &bindings,
        ),
        Ingress::Defer
    );
    let _ = chain;
}
