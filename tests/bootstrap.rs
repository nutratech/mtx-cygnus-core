//! Client bootstrap: fresh rotation keys, commitments, and link building.

use core::convert::Infallible;
use cygnus_core::{
    bootstrap::{
        server_genesis, server_successor, user_genesis, user_successor,
        verify_user_principal_response, RotationKey,
    },
    commitment,
    link::{verify_slice, Body, Kind, Link, Payload},
    Error,
};
use ed25519_zebra::SigningKey;
use rand_core::{TryCryptoRng, TryRng};

fn key(seed: u8) -> SigningKey {
    SigningKey::from([seed; 32])
}

fn rotation(seed: u8) -> RotationKey {
    RotationKey::from_seed([seed; 32])
}

struct TestRng(u8);

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(u32::from(self.0))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(u64::from(self.0))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
        dest.fill(self.0);
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

#[test]
fn rotation_key_generation_uses_the_callers_rng() {
    let generated = RotationKey::generate(&mut TestRng(0x21));
    let from_seed = rotation(0x21);
    assert_eq!(generated.public_key(), from_seed.public_key());
    assert_eq!(generated.commitment(), from_seed.commitment());
}

#[test]
fn user_genesis_commits_the_next_rotation_key_and_stays_unsigned() {
    let rotation = rotation(0x21);
    let custodian = [0x11; 32];
    let master = <[u8; 32]>::from(key(0x2F).verification_key());
    let link = user_genesis(&rotation, custodian, master, "@alice:chat.example.org").unwrap();

    link.verify_genesis().unwrap();
    assert!(link.trailer.is_empty());
    assert_eq!(link.body.root, [0; 32]);
    assert_eq!(link.body.height, 0);
    assert_eq!(link.body.prev, [0; 32]);
    assert_eq!(link.body.next_commit, rotation.commitment());
    assert_ne!(rotation.commitment(), rotation.public_key());
    assert_eq!(link.body.next_commit, commitment(&rotation.public_key()));

    let Payload::User {
        custodian: actual_custodian,
        master_key,
        display_user_id,
    } = &link.body.payload
    else {
        panic!("expected a user payload");
    };
    assert_eq!(*actual_custodian, custodian);
    assert_eq!(*master_key, Some(master));
    assert_eq!(display_user_id, "@alice:chat.example.org");
    assert_eq!(link.principal().kind, Kind::User);
}

#[test]
fn principal_request_contains_only_public_key_and_commitment_and_verifies_response() {
    let rotation_key = rotation(0x21);
    let master = <[u8; 32]>::from(key(0x2F).verification_key());
    let request = rotation_key.principal_request(&master);
    let request_value = request.to_value();
    assert_eq!(request_value.as_object().unwrap().len(), 2);
    assert_eq!(
        request_value["master_key"].as_str().unwrap(),
        request.master_key
    );
    assert_eq!(
        request_value["next_commit"].as_str().unwrap(),
        request.next_commit
    );

    // The custodian returns the genesis link; the client checks its digest,
    // master-key binding and commitment before accepting the new principal.
    let genesis =
        user_genesis(&rotation_key, [0x11; 32], master, "@alice:chat.example.org").unwrap();
    let principal = genesis.principal().to_id();
    let returned =
        verify_user_principal_response(&rotation_key, &master, &principal, &[genesis.to_b64()])
            .unwrap();
    assert_eq!(returned, genesis);

    let other_master = <[u8; 32]>::from(key(0x30).verification_key());
    assert!(verify_user_principal_response(
        &rotation_key,
        &other_master,
        &principal,
        &[genesis.to_b64()]
    )
    .is_err());
    assert!(verify_user_principal_response(
        &rotation(0x22),
        &master,
        &principal,
        &[genesis.to_b64()]
    )
    .is_err());
    assert!(verify_user_principal_response(
        &rotation_key,
        &master,
        "@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        &[genesis.to_b64()]
    )
    .is_err());
}

#[test]
fn server_genesis_proves_possession_of_the_online_key() {
    let rotation = rotation(0x02);
    let online = key(0x01);
    let link = server_genesis(&rotation, &online, "chat.example.org").unwrap();

    link.verify_genesis().unwrap();
    assert_eq!(link.body.next_commit, rotation.commitment());
    let Payload::Server {
        online_key,
        server_name,
    } = &link.body.payload
    else {
        panic!("expected a server payload");
    };
    assert_eq!(*online_key, <[u8; 32]>::from(online.verification_key()));
    assert_eq!(server_name, "chat.example.org");
    assert_eq!(link.principal().kind, Kind::Server);

    // A genesis signed by a different key does not prove possession.
    let body = Body {
        root: [0; 32],
        height: 0,
        prev: [0; 32],
        next_commit: rotation.commitment(),
        payload: Payload::Server {
            online_key: <[u8; 32]>::from(online.verification_key()),
            server_name: "chat.example.org".to_owned(),
        },
    };
    let forged = Link::sign_server_genesis(body, &key(0x03)).unwrap();
    assert_eq!(forged.verify_genesis(), Err(Error::Signature));
}

#[test]
fn client_extends_the_chain_after_a_handover() {
    let custodian = [0x11; 32];
    let master = <[u8; 32]>::from(key(0x2F).verification_key());
    let first = rotation(0x21);
    let second = rotation(0x22);
    let third = rotation(0x23);

    let genesis = user_genesis(&first, custodian, master, "@alice:chat.example.org").unwrap();
    let h1 = user_successor(
        &genesis,
        &first,
        &second,
        custodian,
        master,
        "@alice:chat.example.org",
    )
    .unwrap();
    h1.verify_successor(&genesis).unwrap();
    assert_eq!(h1.body.next_commit, second.commitment());

    // The client immediately signs the next link with the key it held.
    let h2 = user_successor(
        &h1,
        &second,
        &third,
        custodian,
        master,
        "@alice:chat.example.org",
    )
    .unwrap();
    let slice = [h1, h2];
    let tip = verify_slice(&genesis, &slice).unwrap();
    assert_eq!(tip.body.height, 2);
    assert_eq!(tip.principal(), genesis.principal());
}

#[test]
fn successor_rejects_a_key_that_does_not_match_the_parent_commitment() {
    let custodian = [0x11; 32];
    let master = <[u8; 32]>::from(key(0x2F).verification_key());
    let first = rotation(0x21);
    let genesis = user_genesis(&first, custodian, master, "@alice:chat.example.org").unwrap();

    let error = user_successor(
        &genesis,
        &rotation(0x99),
        &rotation(0x22),
        custodian,
        master,
        "@alice:chat.example.org",
    )
    .unwrap_err();
    assert_eq!(error, Error::Commitment);
}

#[test]
fn user_successor_refuses_to_change_the_master_key() {
    let custodian = [0x11; 32];
    let master = <[u8; 32]>::from(key(0x2F).verification_key());
    let other_master = <[u8; 32]>::from(key(0x30).verification_key());
    let first = rotation(0x21);
    let genesis = user_genesis(&first, custodian, master, "@alice:chat.example.org").unwrap();

    let error = user_successor(
        &genesis,
        &first,
        &rotation(0x22),
        custodian,
        other_master,
        "@alice:chat.example.org",
    )
    .unwrap_err();
    assert_eq!(error, Error::Successor("master_key"));
}

#[test]
fn server_successor_rotates_the_online_key_and_commitment() {
    let first = rotation(0x02);
    let second = rotation(0x04);
    let fresh_online = key(0x05);
    let genesis = server_genesis(&first, &key(0x01), "chat.example.org").unwrap();

    let h1 =
        server_successor(&genesis, &first, &second, &fresh_online, "chat.example.org").unwrap();
    h1.verify_successor(&genesis).unwrap();
    assert_eq!(h1.body.next_commit, second.commitment());

    let Payload::Server { online_key, .. } = &h1.body.payload else {
        panic!("expected a server payload");
    };
    assert_eq!(
        *online_key,
        <[u8; 32]>::from(fresh_online.verification_key())
    );
}

#[test]
fn successor_helpers_enforce_the_parent_kind() {
    let user = rotation(0x21);
    let genesis = user_genesis(
        &user,
        [0x11; 32],
        <[u8; 32]>::from(key(0x2F).verification_key()),
        "@alice:chat.example.org",
    )
    .unwrap();

    assert_eq!(
        server_successor(
            &genesis,
            &user,
            &rotation(0x22),
            &key(0x01),
            "chat.example.org"
        ),
        Err(Error::Successor("kind"))
    );
}
