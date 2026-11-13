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

use std::collections::BTreeSet;

use crate::{
    content::{
        CommitContent, ContentError, EncryptedContent, ExtremityRef, KeyPackageContent, PlanSummary,
    },
    registry::{decode_secrets, encode_secrets, GroupEntry, HeldBranch, RegistryError},
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

/// The output of a locally produced Commit.
#[derive(Debug)]
pub struct CommitOut {
    /// `m.dmls.commit` content, ready to send.
    pub content: Value,
    /// The Welcome bytes for the added member, to be bound to the Commit event.
    pub welcome: Vec<u8>,
    /// The new extremity's commit id.
    pub commit_id: [u8; 32],
    /// The state the Commit produced.
    pub summary: GroupSummary,
}

/// Commit an Add for `key_package` on top of `base` and install the result as
/// a new tip.
///
/// `base` must name a held state (the genesis reference for a fresh group). It
/// is retained as a non-tip, so a second Commit on the same base still applies
/// and the two can later be merged. On any error the entry is unchanged.
///
/// # Errors
///
/// [`EngineError`] for a missing base, a stale base epoch, an invalid key
/// package, or an `OpenMLS` failure.
pub fn commit_add(
    entry: &mut GroupEntry,
    signer: &Signer,
    base: &ExtremityRef,
    key_package: &[u8],
) -> Result<CommitOut, EngineError> {
    let group_id = entry.group_id();
    let base_id = base.id.commit_id;
    let resolves = BTreeSet::from([base_id]);
    let base_ref = base.clone();
    let key_package = key_package.to_vec();

    let (commit_id, content, welcome, summary) =
        entry.apply_with(&base_id, None, &resolves, |group, provider| {
            if group.epoch().as_u64() != base_ref.id.mls_epoch {
                return Err(RegistryError::Rejected("stale_epoch"));
            }
            let as_reg = |e: EngineError| RegistryError::Mls(e.to_string());
            verify_own_leaf(group, signer).map_err(as_reg)?;
            let mut bytes = key_package.as_slice();
            let package = KeyPackageIn::tls_deserialize(&mut bytes)
                .map_err(mls)
                .map_err(as_reg)?
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(mls)
                .map_err(as_reg)?;
            let (commit, welcome, _info) = group
                .add_members(provider, &signer.pair, &[package])
                .map_err(mls)
                .map_err(as_reg)?;
            group
                .merge_pending_commit(provider)
                .map_err(mls)
                .map_err(as_reg)?;
            let commit = commit.to_bytes().map_err(mls).map_err(as_reg)?;
            let welcome = welcome.to_bytes().map_err(mls).map_err(as_reg)?;
            let group_info = group
                .export_group_info(provider.crypto(), &signer.pair, true)
                .map_err(mls)
                .map_err(as_reg)?
                .to_bytes()
                .map_err(mls)
                .map_err(as_reg)?;
            let commit_id = wire::commit_id(&commit);
            let content = CommitContent {
                group_id,
                base: base_ref.clone(),
                resolves: vec![base_ref],
                commit,
                group_info,
                proposals: Vec::new(),
                plan: PlanSummary::default(),
            }
            .to_value()
            .map_err(|e| RegistryError::Mls(e.to_string()))?;
            let summary = summarize(group, group_id, commit_id).map_err(as_reg)?;
            Ok((commit_id, (commit_id, content, welcome, summary)))
        })?;
    Ok(CommitOut {
        content,
        welcome,
        commit_id,
        summary,
    })
}

/// Caller-supplied facts about a received Commit event that wasm cannot know.
#[derive(Debug, Clone)]
pub struct ApplyCtx {
    /// The member the 00FC envelope authenticated as the event's sender.
    pub sender: MemberKey,
    /// Event ids known to be ancestors of the Commit event in the room DAG.
    pub ancestors: BTreeSet<String>,
}

/// The protocol outcome of applying a received Commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// A new extremity was installed (or was already held).
    Applied(GroupSummary),
    /// A dependency is not held yet; retry after more events. State untouched.
    Deferred(&'static str),
    /// Permanently invalid; the code is stable. State untouched.
    Rejected(&'static str),
}

/// Apply a received `m.dmls.commit`: stateless checks first, then the
/// registry's copy-then-swap apply.
///
/// # Errors
///
/// [`EngineError::BadArgument`] for an event type this slice does not handle.
/// Every protocol failure is returned as an [`ApplyOutcome`], not an error.
pub fn apply_commit(
    entry: &mut GroupEntry,
    event_type: &str,
    content: &Value,
    ctx: &ApplyCtx,
) -> Result<ApplyOutcome, EngineError> {
    if event_type != wire::COMMIT_EVENT {
        return Err(EngineError::BadArgument("event_type"));
    }
    let group_id = entry.group_id();
    let parsed = match CommitContent::parse(event_type, content, &group_id) {
        Ok(parsed) => parsed,
        Err(error) => return Ok(ApplyOutcome::Rejected(error.code())),
    };
    for reference in parsed.resolves.iter().chain([&parsed.base]) {
        if let Some(event) = &reference.event_id {
            if !ctx.ancestors.contains(event) {
                return Ok(ApplyOutcome::Deferred("unheld_ancestor"));
            }
        }
    }

    let base_id = parsed.base.id.commit_id;
    let new_id = parsed.commit_id();
    let resolves: BTreeSet<[u8; 32]> = parsed.resolves.iter().map(|r| r.id.commit_id).collect();
    let base_epoch = parsed.base.id.mls_epoch;
    let target_epoch = parsed.mls_epoch();
    let commit = parsed.commit;
    let sender = ctx.sender.clone();

    let result = entry.apply(&base_id, new_id, &resolves, |group, provider| {
        if group.epoch().as_u64() != base_epoch {
            return Err(RegistryError::Rejected("mismatch:base"));
        }
        let message = MlsMessageIn::tls_deserialize_exact(&commit)
            .map_err(|e| RegistryError::Mls(format!("{e:?}")))?;
        let protocol = ProtocolMessage::try_from(message)
            .map_err(|_| RegistryError::Rejected("malformed:commit"))?;
        let processed = group
            .process_message(provider, protocol)
            .map_err(|e| RegistryError::Mls(format!("{e:?}")))?;
        let committer = member_of(processed.credential())
            .map_err(|_| RegistryError::Rejected("malformed:credential"))?;
        if committer != sender {
            return Err(RegistryError::Rejected("mismatch:sender"));
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(RegistryError::Rejected("malformed:commit"));
        };
        group
            .merge_staged_commit(provider, *staged)
            .map_err(|e| RegistryError::Mls(format!("{e:?}")))?;
        if group.epoch().as_u64() != target_epoch {
            return Err(RegistryError::Rejected("mismatch:mls_epoch"));
        }
        summarize(group, group_id, new_id).map_err(|e| RegistryError::Mls(e.to_string()))
    });

    Ok(match result {
        Ok(summary) => ApplyOutcome::Applied(summary),
        Err(RegistryError::AlreadyHeld) => {
            let held = entry
                .branch(&new_id)
                .ok_or(EngineError::BadArgument("state"))?;
            ApplyOutcome::Applied(summarize(held.group(), group_id, new_id)?)
        }
        Err(RegistryError::MissingBase) => ApplyOutcome::Deferred("missing_base_state"),
        Err(RegistryError::MissingBranch) => ApplyOutcome::Deferred("missing_branch"),
        Err(RegistryError::ExtremityCap(_)) => ApplyOutcome::Deferred("extremity_cap"),
        Err(error) => ApplyOutcome::Rejected(error.code()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::EncryptedContent;
    use crate::merge::ExtremityId;
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

    const CAROL: &str = "@QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";

    fn package_bytes(signer: &Signer) -> (Vec<u8>, Vec<u8>) {
        let (package, secrets) = bob_key_package(signer);
        (package.tls_serialize_detached().unwrap(), secrets)
    }

    fn alice_entry(alice: &Signer, group_id: [u8; 32]) -> GroupEntry {
        let (branch, summary) = create_group(alice, group_id).unwrap();
        let mut entry = GroupEntry::new(group_id);
        entry.insert_root(summary.commit_id, branch).unwrap();
        entry
    }

    #[test]
    fn two_adds_on_the_genesis_base_are_sibling_tips() {
        let alice = signer(ALICE, "ALICE1", 1);
        let group_id = wire::group_id(ROOM);
        let mut entry = alice_entry(&alice, group_id);
        let genesis = ExtremityRef::genesis(&group_id);
        let (bob_kp, _) = package_bytes(&signer(BOB, "BOB1", 2));
        let (carol_kp, _) = package_bytes(&signer(CAROL, "CAROL1", 3));

        let one = commit_add(&mut entry, &alice, &genesis, &bob_kp).unwrap();
        let two = commit_add(&mut entry, &alice, &genesis, &carol_kp).unwrap();

        assert_ne!(one.commit_id, two.commit_id);
        assert_eq!(entry.extremity_count(), 2);
        assert_eq!(entry.state_count(), 3, "genesis is retained as a non-tip");
        assert_eq!(one.summary.mls_epoch, 1);
        assert_eq!(two.summary.mls_epoch, 1);
        for out in [&one, &two] {
            let parsed = CommitContent::parse(wire::COMMIT_EVENT, &out.content, &group_id).unwrap();
            assert!(parsed.base.is_genesis(&group_id));
            assert_eq!(parsed.commit_id(), out.commit_id);
        }
    }

    #[test]
    fn a_member_applies_the_next_commit_and_defers_or_rejects_without_mutation() {
        let alice = signer(ALICE, "ALICE1", 1);
        let bob = signer(BOB, "BOB1", 2);
        let group_id = wire::group_id(ROOM);
        let mut alice_entry = alice_entry(&alice, group_id);
        let genesis = ExtremityRef::genesis(&group_id);
        let (bob_kp, bob_secrets) = package_bytes(&bob);
        let (carol_kp, _) = package_bytes(&signer(CAROL, "CAROL1", 3));

        let first = commit_add(&mut alice_entry, &alice, &genesis, &bob_kp).unwrap();
        let (bob_branch, joined) = join_welcome(
            &bob,
            &bob_secrets,
            &first.welcome,
            &group_id,
            first.commit_id,
        )
        .unwrap();
        assert_eq!(joined.mls_epoch, 1);
        let mut bob_entry = GroupEntry::new(group_id);
        bob_entry.insert_root(first.commit_id, bob_branch).unwrap();

        let base = ExtremityRef::new(ExtremityId::new(1, first.commit_id), "$first");
        let second = commit_add(&mut alice_entry, &alice, &base, &carol_kp).unwrap();
        let ctx = |sender: &Signer, ancestors: &[&str]| ApplyCtx {
            sender: sender.member_key(),
            ancestors: ancestors.iter().map(|e| (*e).to_owned()).collect(),
        };
        let before = bob_entry.export();

        // Unknown ancestor: deferred, nothing changes.
        assert_eq!(
            apply_commit(
                &mut bob_entry,
                wire::COMMIT_EVENT,
                &second.content,
                &ctx(&alice, &[])
            )
            .unwrap(),
            ApplyOutcome::Deferred("unheld_ancestor")
        );
        // Wrong authenticated sender: rejected, nothing changes.
        assert_eq!(
            apply_commit(
                &mut bob_entry,
                wire::COMMIT_EVENT,
                &second.content,
                &ctx(&bob, &["$first"])
            )
            .unwrap(),
            ApplyOutcome::Rejected("mismatch:sender")
        );
        assert_eq!(bob_entry.export(), before);

        // A group that does not hold the base defers.
        let mut empty = GroupEntry::new(group_id);
        assert_eq!(
            apply_commit(
                &mut empty,
                wire::COMMIT_EVENT,
                &second.content,
                &ctx(&alice, &["$first"])
            )
            .unwrap(),
            ApplyOutcome::Deferred("missing_base_state")
        );

        // The real apply installs epoch 2 with three members.
        let ApplyOutcome::Applied(summary) = apply_commit(
            &mut bob_entry,
            wire::COMMIT_EVENT,
            &second.content,
            &ctx(&alice, &["$first"]),
        )
        .unwrap() else {
            panic!("expected applied")
        };
        assert_eq!(summary.mls_epoch, 2);
        assert_eq!(summary.commit_id, second.commit_id);
        assert_eq!(summary.members.len(), 3);
        assert_eq!(bob_entry.extremities(), vec![second.commit_id]);
        assert!(
            bob_entry.branch(&first.commit_id).is_some(),
            "parent retained"
        );

        // Re-applying is idempotent and does not bump seq.
        let after = bob_entry.export();
        assert!(matches!(
            apply_commit(
                &mut bob_entry,
                wire::COMMIT_EVENT,
                &second.content,
                &ctx(&alice, &["$first"])
            )
            .unwrap(),
            ApplyOutcome::Applied(_)
        ));
        assert_eq!(bob_entry.export(), after);
    }

    #[test]
    fn decrypt_tries_each_sibling_tip_at_the_same_epoch() {
        let alice = signer(ALICE, "ALICE1", 1);
        let bob = signer(BOB, "BOB1", 2);
        let dave_principal = format!("@{}", "w".repeat(43));
        let dave = signer(&dave_principal, "DAVE1", 4);
        let group_id = wire::group_id(ROOM);

        let mut alice_entry = alice_entry(&alice, group_id);
        let genesis = ExtremityRef::genesis(&group_id);
        let (bob_kp, bob_secrets) = package_bytes(&bob);
        let (carol_kp, _) = package_bytes(&signer(CAROL, "CAROL1", 3));
        let (dave_kp, _) = package_bytes(&dave);

        // Epoch 1: Alice and Bob.
        let first = commit_add(&mut alice_entry, &alice, &genesis, &bob_kp).unwrap();
        let (bob_branch, _) = join_welcome(
            &bob,
            &bob_secrets,
            &first.welcome,
            &group_id,
            first.commit_id,
        )
        .unwrap();
        let mut bob_entry = GroupEntry::new(group_id);
        bob_entry.insert_root(first.commit_id, bob_branch).unwrap();

        // Two epoch-2 Commits from the same epoch-1 base: Add Carol, Add Dave.
        let base = ExtremityRef::new(ExtremityId::new(1, first.commit_id), "$first");
        let add_carol = commit_add(&mut alice_entry, &alice, &base, &carol_kp).unwrap();
        let add_dave = commit_add(&mut alice_entry, &alice, &base, &dave_kp).unwrap();
        assert_ne!(add_carol.commit_id, add_dave.commit_id);
        assert_eq!(alice_entry.extremity_count(), 2);

        let ctx = ApplyCtx {
            sender: alice.member_key(),
            ancestors: ["$first".to_owned()].into_iter().collect(),
        };
        for out in [&add_carol, &add_dave] {
            assert!(matches!(
                apply_commit(&mut bob_entry, wire::COMMIT_EVENT, &out.content, &ctx).unwrap(),
                ApplyOutcome::Applied(_)
            ));
        }
        assert_eq!(bob_entry.extremity_count(), 2);
        for id in bob_entry.extremities() {
            assert_eq!(bob_entry.branch(&id).unwrap().epoch(), 2);
        }

        // Alice speaks on the Add-Dave branch.
        let content = alice_entry
            .update(&add_dave.commit_id, |group, provider| {
                encrypt(&alice, group, provider, &group_id, b"on the dave branch")
                    .map_err(|e| RegistryError::Mls(e.to_string()))
            })
            .unwrap();

        // Bob holds both epoch-2 branches. The other one cannot decrypt, and
        // because update() is copy-then-swap the failed trial leaves the blob
        // byte-identical rather than advancing the wrong ratchet.
        let before = bob_entry.export();
        assert!(bob_entry
            .update(&add_carol.commit_id, |group, provider| {
                decrypt(group, provider, &group_id, &content)
                    .map(|_| ())
                    .map_err(|e| RegistryError::Mls(e.to_string()))
            })
            .is_err());
        assert_eq!(
            bob_entry.export(),
            before,
            "a failed trial must not persist"
        );

        // The second held branch at that epoch is the right one.
        let plain = bob_entry
            .update(&add_dave.commit_id, |group, provider| {
                decrypt(group, provider, &group_id, &content)
                    .map_err(|e| RegistryError::Mls(e.to_string()))
            })
            .unwrap();
        assert_eq!(plain.plaintext, b"on the dave branch");
        assert_eq!(plain.mls_epoch, 2);
        assert_eq!(plain.sender, alice.member_key());
    }
}
