//! DMLS group encryption for Cygnus principals.
//!
//! This crate is the bridge between MSC00FC identities and RFC 9420 MLS:
//!
//! - the MLS signature key is the Cygnus **device** key, not a separate key;
//! - the MLS basic credential commits to the `(principal, device_id)` pair;
//! - an MLS group is the group ratchet behind a Cygnus room.
//!
//! The DMLS fork-resolution and `m.room.device_root` rules are layered on top
//! of this in a later slice. This module deliberately exposes the raw group
//! operations first so the cryptographic path is executable and tested.

use std::fmt::Debug;

use cygnus_core::{Kind, Principal};

pub mod api;
mod branch_meta;
pub mod content;
pub mod device_root;
pub mod engine;
pub mod merge;
pub mod registry;
pub mod registry_json;
pub mod tree;
pub mod wire;
use ed25519_zebra::SigningKey;
use openmls::prelude::{
    tls_codec::{Deserialize, Serialize},
    *,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The ciphersuite used by Cygnus DMLS groups.
///
/// Ed25519 signatures bind MLS leaves to the same device keys Cygnus uses for
/// event co-signing.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Errors from the DMLS group layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A principal or device identifier is malformed.
    #[error("invalid DMLS identity: {0}")]
    Identity(&'static str),
    /// No MLS group has been created or joined on this client.
    #[error("this client has no DMLS group")]
    NoGroup,
    /// A group already exists on this client.
    #[error("this client already has a DMLS group")]
    AlreadyInGroup,
    /// The message was not the MLS message type expected here.
    #[error("unexpected MLS message type")]
    UnexpectedMessage,
    /// `OpenMLS` rejected an operation.
    #[error("MLS error: {0}")]
    Mls(String),
}

/// Result alias for the DMLS layer.
pub type Result<T> = core::result::Result<T, Error>;

fn mls<E: Debug>(error: E) -> Error {
    Error::Mls(format!("{error:?}"))
}

/// A Cygnus member identity as committed by an MLS credential.
///
/// The credential encoding is length-prefixed and domain-separated so it can
/// never collide with a legacy Matrix user ID or another credential format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberIdentity {
    /// The user principal (`@` plus 43 base64url characters).
    pub principal: String,
    /// The Matrix device ID of the session holding the device key.
    pub device_id: String,
}

impl MemberIdentity {
    /// Validate and construct a member identity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Identity`] if the principal is not a canonical user
    /// principal or the device ID is outside the Cygnus device-ID grammar.
    pub fn new(principal: impl Into<String>, device_id: impl Into<String>) -> Result<Self> {
        let principal = principal.into();
        let device_id = device_id.into();

        let parsed = Principal::parse(&principal).map_err(|_| Error::Identity("principal"))?;
        if parsed.kind != Kind::User {
            return Err(Error::Identity("principal must be a user principal"));
        }
        if device_id.is_empty()
            || device_id.len() > 255
            || !device_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(Error::Identity("device_id"));
        }

        Ok(Self {
            principal,
            device_id,
        })
    }

    /// The canonical bytes carried in the MLS basic credential.
    #[must_use]
    pub fn credential_bytes(&self) -> Vec<u8> {
        const TAG: &[u8] = b"cygnus-dmls-credential-v1\0";
        let principal = self.principal.as_bytes();
        let device_id = self.device_id.as_bytes();
        let mut out = Vec::with_capacity(TAG.len() + 4 + principal.len() + device_id.len());
        out.extend_from_slice(TAG);
        out.extend_from_slice(
            &u16::try_from(principal.len())
                .expect("validated principal fits in u16")
                .to_be_bytes(),
        );
        out.extend_from_slice(principal);
        out.extend_from_slice(
            &u16::try_from(device_id.len())
                .expect("validated device_id fits in u16")
                .to_be_bytes(),
        );
        out.extend_from_slice(device_id);
        out
    }

    /// Decode the bytes [`Self::credential_bytes`] wrote.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Identity`] if the tag is wrong, the lengths do not add
    /// up, or the decoded fields fail the same validation as [`Self::new`].
    pub fn from_credential_bytes(bytes: &[u8]) -> Result<Self> {
        const TAG: &[u8] = b"cygnus-dmls-credential-v1\0";
        fn field<'a>(rest: &mut &'a [u8]) -> Result<&'a [u8]> {
            if rest.len() < 2 {
                return Err(Error::Identity("credential"));
            }
            let len = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let end = 2 + len;
            if rest.len() < end {
                return Err(Error::Identity("credential"));
            }
            let value = &rest[2..end];
            *rest = &rest[end..];
            Ok(value)
        }

        let mut rest = bytes
            .strip_prefix(TAG)
            .ok_or(Error::Identity("credential"))?;
        let principal = field(&mut rest)?;
        let device_id = field(&mut rest)?;
        if !rest.is_empty() {
            return Err(Error::Identity("credential"));
        }
        let principal =
            std::str::from_utf8(principal).map_err(|_| Error::Identity("credential"))?;
        let device_id =
            std::str::from_utf8(device_id).map_err(|_| Error::Identity("credential"))?;
        Self::new(principal, device_id)
    }
}

/// One Cygnus/DMLS participant and its local MLS state.
pub struct DmlsClient {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: MemberIdentity,
    join_config: MlsGroupJoinConfig,
    group: Option<MlsGroup>,
}

impl Debug for DmlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DmlsClient")
            .field("identity", &self.identity)
            .field("has_group", &self.group.is_some())
            .finish_non_exhaustive()
    }
}

/// The output of accepting a member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddMemberOutput {
    /// Serialized MLS Commit for existing members.
    pub commit: Vec<u8>,
    /// Serialized MLS Welcome for the new member.
    pub welcome: Vec<u8>,
}

/// What a received MLS message contained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// Decrypted application plaintext.
    Application(Vec<u8>),
    /// A Commit that was validated and merged into the local group state.
    Commit,
    /// A standalone proposal. The caller must decide whether to store it.
    Proposal,
}

impl DmlsClient {
    /// Create a client whose MLS signing key is the Cygnus device key derived
    /// from `device_seed`.
    ///
    /// # Errors
    ///
    /// Currently infallible; the `Result` is kept for future validation.
    pub fn new(identity: MemberIdentity, device_seed: [u8; 32]) -> Result<Self> {
        let provider = OpenMlsRustCrypto::default();
        let signing_key = SigningKey::from(device_seed);
        let public_key = <[u8; 32]>::from(signing_key.verification_key());
        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            device_seed.to_vec(),
            public_key.to_vec(),
        );
        // Never `signer.store(..)`: it would write the device private key into
        // the storage map that registry snapshots serialize.

        let credential = BasicCredential::new(identity.credential_bytes());
        let credential = CredentialWithKey {
            credential: credential.into(),
            signature_key: public_key.to_vec().into(),
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        Ok(Self {
            provider,
            signer,
            credential,
            identity,
            join_config,
            group: None,
        })
    }

    /// The member identity bound to this client.
    #[must_use]
    pub fn identity(&self) -> &MemberIdentity {
        &self.identity
    }

    /// Whether this client has created or joined a group.
    #[must_use]
    pub fn has_group(&self) -> bool {
        self.group.is_some()
    }

    /// The current MLS epoch, if a group exists.
    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        self.group.as_ref().map(|group| group.epoch().as_u64())
    }

    /// Build and store a single-use key package for this device.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Mls`] if `OpenMLS` rejects the key package.
    pub fn key_package(&self) -> Result<Vec<u8>> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(mls)?;
        bundle.key_package().tls_serialize_detached().map_err(mls)
    }

    /// Create a new MLS group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyInGroup`] if this client already has a group, or
    /// [`Error::Mls`] if `OpenMLS` rejects the group parameters.
    pub fn create_group(&mut self, group_id: &[u8]) -> Result<()> {
        if self.group.is_some() {
            return Err(Error::AlreadyInGroup);
        }
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group = MlsGroup::new_with_group_id(
            &self.provider,
            &self.signer,
            &config,
            GroupId::from_slice(group_id),
            self.credential.clone(),
        )
        .map_err(mls)?;
        self.group = Some(group);
        Ok(())
    }

    /// Join a group from a serialized Welcome message.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyInGroup`] if this client already has a group,
    /// [`Error::UnexpectedMessage`] if the bytes are not a Welcome, or
    /// [`Error::Mls`] if `OpenMLS` rejects the Welcome.
    pub fn join_group(&mut self, welcome: &[u8]) -> Result<()> {
        if self.group.is_some() {
            return Err(Error::AlreadyInGroup);
        }
        let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(mls)?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            return Err(Error::UnexpectedMessage);
        };
        let staged =
            StagedWelcome::new_from_welcome(&self.provider, &self.join_config, welcome, None)
                .map_err(mls)?;
        self.group = Some(staged.into_group(&self.provider).map_err(mls)?);
        Ok(())
    }

    /// Add a member by their serialized `KeyPackage`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoGroup`] if this client has no group, or
    /// [`Error::Mls`]/[`Error::UnexpectedMessage`] for invalid input.
    pub fn add_member(&mut self, key_package: &[u8]) -> Result<AddMemberOutput> {
        let group = self.group.as_mut().ok_or(Error::NoGroup)?;
        let mut bytes = key_package;
        let key_package = KeyPackageIn::tls_deserialize(&mut bytes).map_err(mls)?;
        let key_package = key_package
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(mls)?;

        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &[key_package])
            .map_err(mls)?;
        group.merge_pending_commit(&self.provider).map_err(mls)?;

        Ok(AddMemberOutput {
            commit: commit.to_bytes().map_err(mls)?,
            welcome: welcome.to_bytes().map_err(mls)?,
        })
    }

    /// Encrypt application plaintext for the current group.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoGroup`] if this client has no group, or
    /// [`Error::Mls`] if encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let group = self.group.as_mut().ok_or(Error::NoGroup)?;
        group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(mls)?
            .to_bytes()
            .map_err(mls)
    }

    /// Process an MLS message, merging a Commit immediately.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoGroup`] if this client has no group, or
    /// [`Error::Mls`] if `OpenMLS` rejects the message.
    pub fn receive(&mut self, message: &[u8]) -> Result<Received> {
        let group = self.group.as_mut().ok_or(Error::NoGroup)?;
        let message = MlsMessageIn::tls_deserialize_exact(message).map_err(mls)?;
        let message = message.try_into_protocol_message().map_err(mls)?;
        let processed = group
            .process_message(&self.provider, message)
            .map_err(mls)?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(application) => {
                Ok(Received::Application(application.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                group
                    .merge_staged_commit(&self.provider, *staged)
                    .map_err(mls)?;
                Ok(Received::Commit)
            }
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => Ok(Received::Proposal),
        }
    }

    /// Issue a self-update Commit and merge it locally.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NoGroup`] if this client has no group, or
    /// [`Error::Mls`] if `OpenMLS` rejects the update.
    pub fn self_update(&mut self) -> Result<Vec<u8>> {
        let group = self.group.as_mut().ok_or(Error::NoGroup)?;
        let bundle = group
            .self_update(&self.provider, &self.signer, LeafNodeParameters::default())
            .map_err(mls)?;
        let (commit, _welcome, _group_info) = bundle.into_contents();
        group.merge_pending_commit(&self.provider).map_err(mls)?;
        commit.to_bytes().map_err(mls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";
    const BOB: &str = "@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    fn client(principal: &str, device_id: &str, seed: u8) -> DmlsClient {
        DmlsClient::new(
            MemberIdentity::new(principal, device_id).unwrap(),
            [seed; 32],
        )
        .unwrap()
    }

    #[test]
    fn identity_uses_cygnus_user_principals() {
        assert!(MemberIdentity::new(ALICE, "ALICE1").is_ok());
        assert!(
            MemberIdentity::new("~soEUx9hiteZoLx9OwBJ94-GCuVrDksXROkIYuLn8Lb0", "SERVER").is_err()
        );
        assert!(MemberIdentity::new("@nope", "D").is_err());
        assert!(MemberIdentity::new(ALICE, "").is_err());
        assert!(MemberIdentity::new(ALICE, "bad id").is_err());
    }

    #[test]
    fn credential_bytes_round_trip_and_reject_tampering() {
        let identity = MemberIdentity::new(ALICE, "ALICE1").unwrap();
        let bytes = identity.credential_bytes();
        assert_eq!(
            MemberIdentity::from_credential_bytes(&bytes).unwrap(),
            identity
        );
        assert!(MemberIdentity::from_credential_bytes(b"not a credential").is_err());
        for cut in 1..4 {
            assert!(MemberIdentity::from_credential_bytes(&bytes[..bytes.len() - cut]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(MemberIdentity::from_credential_bytes(&trailing).is_err());
    }

    #[test]
    fn alice_adds_bob_and_exchanges_messages() {
        let mut alice = client(ALICE, "ALICE1", 1);
        let mut bob = client(BOB, "BOB1", 2);

        alice.create_group(b"cygnus-dmls-test").unwrap();
        let bob_key_package = bob.key_package().unwrap();
        let add = alice.add_member(&bob_key_package).unwrap();
        bob.join_group(&add.welcome).unwrap();

        assert_eq!(alice.epoch(), Some(1));
        assert_eq!(bob.epoch(), Some(1));

        let ciphertext = alice.encrypt(b"hello bob").unwrap();
        assert_eq!(
            bob.receive(&ciphertext).unwrap(),
            Received::Application(b"hello bob".to_vec())
        );

        let ciphertext = bob.encrypt(b"hello alice").unwrap();
        assert_eq!(
            alice.receive(&ciphertext).unwrap(),
            Received::Application(b"hello alice".to_vec())
        );
    }

    #[test]
    fn fork_resolution_helpers_are_reachable() {
        let mut alice = client(ALICE, "ALICE1", 5);
        let mut bob = client(BOB, "BOB1", 6);

        alice.create_group(b"cygnus-dmls-fork").unwrap();
        let bob_key_package = bob.key_package().unwrap();
        let add = alice.add_member(&bob_key_package).unwrap();
        bob.join_group(&add.welcome).unwrap();

        let group = alice.group.as_mut().unwrap();
        let own = group.own_leaf_index();
        {
            let builder = group.recover_fork_by_readding(&[own]).unwrap();
            let complement = builder.complement_partition();
            assert_eq!(complement.len(), 1);
            assert_ne!(complement[0].index, own);
        }

        let reboot = group.reboot(GroupId::from_slice(b"cygnus-dmls-reboot"));
        assert_eq!(reboot.old_members().count(), 1);
    }

    #[test]
    fn self_update_advances_both_sides() {
        let mut alice = client(ALICE, "ALICE1", 3);
        let mut bob = client(BOB, "BOB1", 4);

        alice.create_group(b"cygnus-dmls-update").unwrap();
        let bob_key_package = bob.key_package().unwrap();
        let add = alice.add_member(&bob_key_package).unwrap();
        bob.join_group(&add.welcome).unwrap();

        let commit = bob.self_update().unwrap();
        assert_eq!(alice.receive(&commit).unwrap(), Received::Commit);
        assert_eq!(alice.epoch(), Some(2));
        assert_eq!(bob.epoch(), Some(2));

        let ciphertext = bob.encrypt(b"new epoch").unwrap();
        assert_eq!(
            alice.receive(&ciphertext).unwrap(),
            Received::Application(b"new epoch".to_vec())
        );
    }
}
