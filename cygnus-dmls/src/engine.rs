//! Stateless-by-call operations over the [`crate::registry::Registry`].
//!
//! Every function takes the device seed as an argument and builds a
//! `SignatureKeyPair` for the call; the seed is never stored, so it cannot
//! reach a persisted blob.

use cygnus_core::{Kind, Principal};
use openmls::prelude::{tls_codec::Deserialize, tls_codec::Serialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use rezzy_json::Value;

use crate::{
    content::{ContentError, EncryptedContent, KeyPackageContent},
    registry::{decode_secrets, encode_secrets, HeldBranch, RegistryError},
    wire::{self, MemberKey},
    MemberIdentity, CIPHERSUITE,
};

/// Errors from engine operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The identity or seed is unusable.
    #[error("bad_argument: {0}")]
    BadArgument(&'static str),
    /// A content builder or parser failed.
    #[error(transparent)]
    Content(#[from] ContentError),
    /// A registry operation failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// `OpenMLS` failed.
    #[error("crypto: {0}")]
    Mls(String),
    /// The ciphertext names an epoch this branch state does not hold.
    #[error("missing_state: epoch {0} is not held")]
    MissingState(u64),
    /// The bytes were not the MLS message type expected here.
    #[error("bad_argument: unexpected_message")]
    UnexpectedMessage,
}

impl EngineError {
    /// The stable error code surfaced to JavaScript.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadArgument(_) | Self::UnexpectedMessage => "bad_argument",
            Self::Content(error) => error.code(),
            Self::Registry(error) => error.code(),
            Self::Mls(_) => "crypto",
            Self::MissingState(_) => "missing_state",
        }
    }
}

fn mls<E: std::fmt::Debug>(error: E) -> EngineError {
    EngineError::Mls(format!("{error:?}"))
}

/// A device signer and credential built from the per-call seed.
pub struct Signer {
    pair: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: MemberIdentity,
}

impl Signer {
    /// Build from an identity and the device seed. Nothing is stored.
    #[must_use]
    pub fn new(identity: MemberIdentity, seed: [u8; 32]) -> Self {
        let public = <[u8; 32]>::from(ed25519_zebra::SigningKey::from(seed).verification_key());
        let pair =
            SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.credential_bytes()).into(),
            signature_key: public.to_vec().into(),
        };
        Self {
            pair,
            credential,
            identity,
        }
    }

    /// The member key (`principal:device`).
    #[must_use]
    pub fn member_key(&self) -> MemberKey {
        MemberKey {
            principal: self.identity.principal.clone(),
            device_id: self.identity.device_id.clone(),
        }
    }

    /// The public half of the device signing key.
    #[must_use]
    pub fn signature_key(&self) -> &[u8] {
        self.pair.public()
    }
}

/// Output of [`key_package`].
#[derive(Debug)]
pub struct KeyPackageOut {
    /// The `m.dmls.key_package` content.
    pub content: Value,
    /// `key_package_id`.
    pub key_package_id: [u8; 32],
    /// Private material to persist (encrypted) before publishing.
    pub secrets: Vec<u8>,
}

/// Build a key package and the secrets blob that lets this device redeem it.
///
/// # Errors
///
/// [`EngineError`] if `OpenMLS` or content building fails.
pub fn key_package(signer: &Signer, expires_ts: Option<u64>) -> Result<KeyPackageOut, EngineError> {
    // Validate once: the principal must be a user principal.
    if Principal::parse(&signer.identity.principal).map(|p| p.kind) != Ok(Kind::User) {
        return Err(EngineError::BadArgument("principal"));
    }
    let provider = OpenMlsRustCrypto::default();
    let bundle = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &provider,
            &signer.pair,
            signer.credential.clone(),
        )
        .map_err(mls)?;
    let key_package = bundle.key_package().tls_serialize_detached().map_err(mls)?;
    let content = KeyPackageContent {
        owner: signer.member_key(),
        key_package,
        expires_ts,
    };
    Ok(KeyPackageOut {
        key_package_id: wire::key_package_id(&content.key_package),
        content: content.to_value()?,
        secrets: encode_secrets(&provider),
    })
}

/// A group state and the local facts needed to key it in the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSummary {
    /// The room-derived group ID.
    pub group_id: [u8; 32],
    /// The commit that produced this state, or the genesis ID at epoch 0.
    pub commit_id: [u8; 32],
    /// The MLS epoch of the state.
    pub mls_epoch: u64,
    /// Current members, sorted by `principal:device`.
    pub members: Vec<MemberKey>,
}

/// The result of decrypting one application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decrypted {
    /// The plaintext bytes.
    pub plaintext: Vec<u8>,
    /// The epoch the message was encrypted in.
    pub mls_epoch: u64,
    /// The sender named by the MLS leaf; the authoritative identity.
    pub sender: MemberKey,
}

fn group_id_of(group: &MlsGroup) -> Result<[u8; 32], EngineError> {
    group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| EngineError::BadArgument("group_id"))
}

fn member_of(credential: &Credential) -> Result<MemberKey, EngineError> {
    let basic = BasicCredential::try_from(credential.clone())
        .map_err(|_| EngineError::BadArgument("credential"))?;
    let identity = MemberIdentity::from_credential_bytes(basic.identity())
        .map_err(|_| EngineError::BadArgument("credential"))?;
    Ok(MemberKey {
        principal: identity.principal,
        device_id: identity.device_id,
    })
}

fn summarize(
    group: &MlsGroup,
    group_id: [u8; 32],
    commit_id: [u8; 32],
) -> Result<GroupSummary, EngineError> {
    if group_id_of(group)? != group_id {
        return Err(EngineError::BadArgument("group_id"));
    }
    let mut members = group
        .members()
        .map(|member| member_of(&member.credential))
        .collect::<Result<Vec<_>, _>>()?;
    members.sort_by_key(MemberKey::to_wire);
    Ok(GroupSummary {
        group_id,
        commit_id,
        mls_epoch: group.epoch().as_u64(),
        members,
    })
}

fn verify_own_leaf(group: &MlsGroup, signer: &Signer) -> Result<(), EngineError> {
    let leaf = group
        .own_leaf()
        .ok_or(EngineError::BadArgument("own_leaf"))?;
    if leaf.signature_key().as_slice() != signer.signature_key() {
        return Err(EngineError::BadArgument("seed"));
    }
    Ok(())
}

/// Create the epoch-0 group for `group_id` and its local root branch.
///
/// Nothing is published: the creator holds the genesis extremity
/// `(0, genesis_commit_id(group_id))`, and the first room event is the epoch-1
/// Commit whose `base` is that extremity.
///
/// # Errors
///
/// [`EngineError`] if `OpenMLS` rejects the group parameters.
pub fn create_group(
    signer: &Signer,
    group_id: [u8; 32],
) -> Result<(HeldBranch, GroupSummary), EngineError> {
    let provider = OpenMlsRustCrypto::default();
    let config = MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .use_ratchet_tree_extension(true)
        .build();
    let group = MlsGroup::new_with_group_id(
        &provider,
        &signer.pair,
        &config,
        GroupId::from_slice(&group_id),
        signer.credential.clone(),
    )
    .map_err(mls)?;
    let summary = summarize(&group, group_id, wire::genesis_commit_id(&group_id))?;
    Ok((HeldBranch::new(provider, group), summary))
}

/// Redeem a Welcome using the secrets blob stored for its `KeyPackage`.
///
/// `commit_id` is the Commit the Welcome is bound to, copied from the verified
/// [`crate::content::WelcomeContent`].
///
/// # Errors
///
/// [`EngineError::Registry`] for a malformed secrets blob,
/// [`EngineError::UnexpectedMessage`] if `welcome` is not a Welcome, or
/// [`EngineError::BadArgument`] if it joins a different group or a leaf that is
/// not this device's signing key.
pub fn join_welcome(
    signer: &Signer,
    secrets: &[u8],
    welcome: &[u8],
    group_id: &[u8; 32],
    commit_id: [u8; 32],
) -> Result<(HeldBranch, GroupSummary), EngineError> {
    let provider = decode_secrets(secrets)?;
    let message = MlsMessageIn::tls_deserialize_exact(welcome).map_err(mls)?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(EngineError::UnexpectedMessage);
    };
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let staged = StagedWelcome::new_from_welcome(&provider, &config, welcome, None).map_err(mls)?;
    let group = staged.into_group(&provider).map_err(mls)?;
    if group_id_of(&group)? != *group_id {
        return Err(EngineError::BadArgument("group_id"));
    }
    verify_own_leaf(&group, signer)?;
    let summary = summarize(&group, *group_id, commit_id)?;
    Ok((HeldBranch::new(provider, group), summary))
}

/// Encrypt one application message at the branch's current epoch.
///
/// # Errors
///
/// [`EngineError`] if the group is not for `group_id`, the caller's leaf is
/// gone, or `OpenMLS` cannot encrypt.
pub fn encrypt(
    signer: &Signer,
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    group_id: &[u8; 32],
    plaintext: &[u8],
) -> Result<Value, EngineError> {
    if group_id_of(group)? != *group_id {
        return Err(EngineError::BadArgument("group_id"));
    }
    let message = group
        .create_message(provider, &signer.pair, plaintext)
        .map_err(mls)?;
    let ciphertext = message.to_bytes().map_err(mls)?;
    EncryptedContent {
        group_id: *group_id,
        mls_epoch: group.epoch().as_u64(),
        sender_device: signer.identity.device_id.clone(),
        ciphertext,
    }
    .to_value()
    .map_err(Into::into)
}

/// Decrypt one application message from the branch's current epoch.
///
/// The caller must select the branch whose epoch matches the ciphertext; a
/// mismatch is [`EngineError::MissingState`] and Hydrogen buffers the message.
///
/// # Errors
///
/// [`EngineError::Content`] for malformed content, [`EngineError::MissingState`]
/// for an epoch this branch does not hold, or [`EngineError::Mls`] if
/// `OpenMLS` cannot process the message.
pub fn decrypt(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    group_id: &[u8; 32],
    content: &Value,
) -> Result<Decrypted, EngineError> {
    let content = EncryptedContent::parse(content, group_id)?;
    if group_id_of(group)? != *group_id {
        return Err(EngineError::BadArgument("group_id"));
    }
    if content.mls_epoch != group.epoch().as_u64() {
        return Err(EngineError::MissingState(content.mls_epoch));
    }
    let message = MlsMessageIn::tls_deserialize_exact(&content.ciphertext).map_err(mls)?;
    let protocol =
        ProtocolMessage::try_from(message).map_err(|_| EngineError::UnexpectedMessage)?;
    let processed = group.process_message(provider, protocol).map_err(mls)?;
    let mls_epoch = processed.epoch().as_u64();
    let sender = member_of(processed.credential())?;
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(application) => Ok(Decrypted {
            plaintext: application.into_bytes(),
            mls_epoch,
            sender,
        }),
        _ => Err(EngineError::UnexpectedMessage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::EncryptedContent;
    use crate::registry::decode_secrets;

    const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";
    const BOB: &str = "@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const ROOM: &str = "!room:example.org";

    fn signer(principal: &str, device_id: &str, seed: u8) -> Signer {
        Signer::new(
            MemberIdentity::new(principal, device_id).unwrap(),
            [seed; 32],
        )
    }

    #[test]
    fn key_package_content_round_trips_and_secrets_hold_no_seed() {
        let seed = [0x5A_u8; 32];
        let signer = Signer::new(MemberIdentity::new(ALICE, "D1").unwrap(), seed);
        let out = key_package(&signer, Some(1_800_000_000_000)).unwrap();

        let parsed = KeyPackageContent::parse(&out.content, &signer.member_key()).unwrap();
        assert_eq!(parsed.key_package_id(), out.key_package_id);

        let needle = &seed[..];
        assert!(!out.secrets.windows(needle.len()).any(|w| w == needle));
        assert!(decode_secrets(&out.secrets).is_ok());
        let mut cut = out.secrets.clone();
        cut.pop();
        assert_eq!(decode_secrets(&cut).unwrap_err().code(), "bad_state");
    }

    #[test]
    fn group_is_created_at_the_genesis_extremity_without_publishing() {
        let alice = signer(ALICE, "ALICE1", 1);
        let group_id = wire::group_id(ROOM);
        let (branch, summary) = create_group(&alice, group_id).unwrap();

        assert_eq!(summary.group_id, group_id);
        assert_eq!(summary.mls_epoch, 0);
        assert_eq!(summary.commit_id, wire::genesis_commit_id(&group_id));
        assert_eq!(summary.members, vec![alice.member_key()]);
        assert_eq!(branch.epoch(), 0);
        assert_eq!(branch.resolves().len(), 0);
    }

    /// Bob's package and the provider that holds its private half.
    fn bob_key_package(bob: &Signer) -> (KeyPackage, Vec<u8>) {
        let provider = OpenMlsRustCrypto::default();
        let bundle = KeyPackage::builder()
            .build(CIPHERSUITE, &provider, &bob.pair, bob.credential.clone())
            .unwrap();
        (bundle.key_package().clone(), encode_secrets(&provider))
    }

    #[test]
    fn welcome_join_encrypt_and_decrypt_use_the_leaf_identity() {
        let alice = signer(ALICE, "ALICE1", 1);
        let bob = signer(BOB, "BOB1", 2);
        let group_id = wire::group_id(ROOM);
        let (mut alice_branch, _) = create_group(&alice, group_id).unwrap();
        let (bob_package, bob_secrets) = bob_key_package(&bob);

        let (alice_group, alice_provider) = alice_branch.parts_mut();
        let (commit, welcome, _info) = alice_group
            .add_members(alice_provider, &alice.pair, &[bob_package])
            .unwrap();
        alice_group.merge_pending_commit(alice_provider).unwrap();
        assert_eq!(alice_group.epoch().as_u64(), 1);

        let commit_bytes = commit.to_bytes().unwrap();
        let commit_id = wire::commit_id(&commit_bytes);
        let (mut bob_branch, bob_summary) = join_welcome(
            &bob,
            &bob_secrets,
            &welcome.to_bytes().unwrap(),
            &group_id,
            commit_id,
        )
        .unwrap();
        assert_eq!(bob_summary.mls_epoch, 1);
        assert_eq!(bob_summary.commit_id, commit_id);
        assert_eq!(
            bob_summary.members,
            vec![bob.member_key(), alice.member_key()]
        );

        let content = encrypt(&alice, alice_group, alice_provider, &group_id, b"hello").unwrap();
        let (bob_group, bob_provider) = bob_branch.parts_mut();
        let plain = decrypt(bob_group, bob_provider, &group_id, &content).unwrap();
        assert_eq!(plain.plaintext, b"hello");
        assert_eq!(plain.mls_epoch, 1);
        assert_eq!(plain.sender, alice.member_key());
    }

    #[test]
    fn decrypt_defers_an_epoch_the_branch_does_not_hold() {
        let alice = signer(ALICE, "ALICE1", 1);
        let bob = signer(BOB, "BOB1", 2);
        let group_id = wire::group_id(ROOM);
        let (mut alice_branch, _) = create_group(&alice, group_id).unwrap();
        let (bob_package, bob_secrets) = bob_key_package(&bob);

        let (alice_group, alice_provider) = alice_branch.parts_mut();
        let (commit, welcome, _info) = alice_group
            .add_members(alice_provider, &alice.pair, &[bob_package])
            .unwrap();
        alice_group.merge_pending_commit(alice_provider).unwrap();
        let content = encrypt(&alice, alice_group, alice_provider, &group_id, b"later").unwrap();
        let mut parsed = EncryptedContent::parse(&content, &group_id).unwrap();
        parsed.mls_epoch = 9;
        let future = parsed.to_value().unwrap();

        let (mut bob_branch, _) = join_welcome(
            &bob,
            &bob_secrets,
            &welcome.to_bytes().unwrap(),
            &group_id,
            wire::commit_id(&commit.to_bytes().unwrap()),
        )
        .unwrap();
        let (bob_group, bob_provider) = bob_branch.parts_mut();
        assert_eq!(
            decrypt(bob_group, bob_provider, &group_id, &future)
                .unwrap_err()
                .code(),
            "missing_state"
        );
        // The real message still decrypts: a deferral leaves the branch usable.
        assert_eq!(
            decrypt(bob_group, bob_provider, &group_id, &content)
                .unwrap()
                .plaintext,
            b"later"
        );
    }

    #[test]
    fn join_rejects_a_welcome_for_another_group() {
        let alice = signer(ALICE, "ALICE1", 1);
        let bob = signer(BOB, "BOB1", 2);
        let group_id = wire::group_id(ROOM);
        let (mut alice_branch, _) = create_group(&alice, group_id).unwrap();
        let (bob_package, bob_secrets) = bob_key_package(&bob);

        let (alice_group, alice_provider) = alice_branch.parts_mut();
        let (commit, welcome, _info) = alice_group
            .add_members(alice_provider, &alice.pair, &[bob_package])
            .unwrap();
        alice_group.merge_pending_commit(alice_provider).unwrap();

        let other = wire::group_id("!other:example.org");
        let error = join_welcome(
            &bob,
            &bob_secrets,
            &welcome.to_bytes().unwrap(),
            &other,
            wire::commit_id(&commit.to_bytes().unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "bad_argument");

        // A seed that does not own the redeemed package is refused.
        let impostor = signer(BOB, "BOB1", 3);
        let error = join_welcome(
            &impostor,
            &bob_secrets,
            &welcome.to_bytes().unwrap(),
            &group_id,
            wire::commit_id(&commit.to_bytes().unwrap()),
        )
        .unwrap_err();
        assert_eq!(error.code(), "bad_argument");
    }
}
