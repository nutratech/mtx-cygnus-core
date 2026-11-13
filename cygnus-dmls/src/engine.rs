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

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    branch_meta::BranchMeta,
    content::{
        CommitContent, ContentError, EncryptedContent, ExternalCommitContent, ExtremityRef,
        KeyPackageContent, PlanSummary, RebootContent,
    },
    device_root::{plan_with_device_roots, DeviceRootRegistry},
    merge::{Branch, ExtremityId, MemberId, MergeError, MergePlan},
    registry::{decode_secrets, encode_secrets, GroupEntry, HeldBranch, RegistryError},
    tree::LeafSource,
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

/// The identity of this device's own leaf in any held state of `entry`.
///
/// Lets exports that take only a group id and the device seed build the
/// [`Signer`] without the caller restating who it is; a wrong seed is then
/// caught by the engine's own-leaf key check.
///
/// # Errors
///
/// [`EngineError::BadArgument`] if no state is held or the leaf is unusable.
pub fn own_identity(entry: &GroupEntry) -> Result<MemberIdentity, EngineError> {
    let (_, branch) = entry
        .branches()
        .next()
        .ok_or(EngineError::BadArgument("own_leaf"))?;
    let leaf = branch
        .group()
        .own_leaf()
        .ok_or(EngineError::BadArgument("own_leaf"))?;
    let key = member_of(leaf.credential())?;
    MemberIdentity::new(key.principal, key.device_id)
        .map_err(|_| EngineError::BadArgument("credential"))
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
    let mut branch = HeldBranch::new(provider, group);
    branch.set_meta(
        BranchMeta::from_group(branch.group(), &group_id)
            .map_err(|e| EngineError::Mls(e.to_string()))?
            .encode(),
    );
    Ok((branch, summary))
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
    let mut branch = HeldBranch::new(provider, group);
    branch.set_meta(
        BranchMeta::from_group(branch.group(), group_id)
            .map_err(|e| EngineError::Mls(e.to_string()))?
            .encode(),
    );
    Ok((branch, summary))
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
    verify_own_leaf(group, signer)?;
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

/// Encrypt at the named branch, or the sole tip, and advance its ratchet.
///
/// # Errors
///
/// [`EngineError::Registry`] with `fork_unresolved` when several tips are held
/// and none is named, `missing_base_state` for an unheld branch, or any error
/// of [`encrypt`]. The entry is unchanged on error.
pub fn encrypt_at(
    entry: &mut GroupEntry,
    signer: &Signer,
    at: Option<&[u8; 32]>,
    plaintext: &[u8],
) -> Result<Value, EngineError> {
    let id = entry.resolve_tip(at)?;
    let group_id = entry.group_id();
    // Checked up front so a wrong seed is `bad_argument`, not a wrapped crypto
    // failure from inside the copy-then-swap closure.
    if let Some(held) = entry.branch(&id) {
        verify_own_leaf(held.group(), signer)?;
    }
    entry
        .update(&id, |group, provider| {
            encrypt(signer, group, provider, &group_id, plaintext)
                .map_err(|e| RegistryError::Mls(e.to_string()))
        })
        .map_err(Into::into)
}

/// The outcome of [`decrypt_in`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptOutcome {
    /// Decrypted on the branch `commit_id`, whose ratchet advanced.
    Ok {
        /// The decrypted message.
        message: Decrypted,
        /// The branch that held the epoch secrets.
        commit_id: [u8; 32],
    },
    /// No held branch is at the message's epoch; buffer it (§13.4).
    MissingState(u64),
    /// Malformed, or no branch at that epoch could decrypt it; the code is
    /// stable. Every held state is unchanged.
    Rejected(&'static str),
}

/// Decrypt by trying every held state at the ciphertext's epoch.
///
/// Sibling tips (and retained states) can share an epoch and only the one with
/// the right secrets succeeds. Each try runs on a copy, so a failed try leaves
/// its branch untouched, and only the branch that decrypts is replaced.
#[must_use]
pub fn decrypt_in(entry: &mut GroupEntry, content: &Value) -> DecryptOutcome {
    let group_id = entry.group_id();
    let parsed = match EncryptedContent::parse(content, &group_id) {
        Ok(parsed) => parsed,
        Err(error) => return DecryptOutcome::Rejected(error.code()),
    };
    let candidates: Vec<[u8; 32]> = entry
        .branches()
        .filter(|(_, branch)| branch.epoch() == parsed.mls_epoch)
        .map(|(id, _)| *id)
        .collect();
    if candidates.is_empty() {
        return DecryptOutcome::MissingState(parsed.mls_epoch);
    }
    for commit_id in candidates {
        let tried = entry.update(&commit_id, |group, provider| {
            decrypt(group, provider, &group_id, content)
                .map_err(|e| RegistryError::Mls(e.to_string()))
        });
        if let Ok(message) = tried {
            return DecryptOutcome::Ok { message, commit_id };
        }
    }
    DecryptOutcome::Rejected("decrypt_failed")
}

/// The output of a locally produced Commit.
#[derive(Debug)]
pub struct CommitOut {
    /// `m.dmls.commit` content, ready to send.
    pub content: Value,
    /// The Welcome bytes for an added member, to be bound to the Commit event.
    /// `None` for Remove and self-update, which add no one.
    pub welcome: Option<Vec<u8>>,
    /// The new extremity's commit id.
    pub commit_id: [u8; 32],
    /// The state the Commit produced.
    pub summary: GroupSummary,
}

/// The membership change a locally produced Commit makes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitOp {
    /// Add the owner of this serialized `KeyPackage`.
    Add(Vec<u8>),
    /// Remove every leaf of this member. Removing the caller is refused.
    Remove(MemberKey),
    /// Add several members, each by its own `KeyPackage`, in one Commit.
    AddAll(Vec<Vec<u8>>),
    /// Rotate the caller's own leaf and path secrets.
    SelfUpdate,
    /// Apply a merge plan's removals (possibly none) in one Commit.
    Merge(Vec<MemberKey>),
}

/// Commit an Add for `key_package` on top of `base`; see [`commit`].
///
/// # Errors
///
/// As [`commit`].
pub fn commit_add(
    entry: &mut GroupEntry,
    signer: &Signer,
    base: &ExtremityRef,
    key_package: &[u8],
) -> Result<CommitOut, EngineError> {
    commit(entry, signer, base, &CommitOp::Add(key_package.to_vec()))
}

/// Commit `op` on top of `base` and install the result as a new tip.
///
/// `base` must name a held state (the genesis reference for a fresh group). It
/// is retained as a non-tip, so a second Commit on the same base still applies
/// and the two can later be merged. On any error the entry is unchanged.
///
/// # Errors
///
/// [`EngineError`] for a missing base, a stale base epoch, an invalid key
/// package, a Remove naming no member (or the caller), or an `OpenMLS` failure.
#[allow(clippy::too_many_lines)]
pub fn commit(
    entry: &mut GroupEntry,
    signer: &Signer,
    base: &ExtremityRef,
    op: &CommitOp,
) -> Result<CommitOut, EngineError> {
    commit_inner(
        entry,
        signer,
        base,
        std::slice::from_ref(base),
        op,
        &PlanSummary::default(),
    )
}

#[allow(clippy::too_many_lines)]
fn commit_inner(
    entry: &mut GroupEntry,
    signer: &Signer,
    base: &ExtremityRef,
    merged: &[ExtremityRef],
    op: &CommitOp,
    plan: &PlanSummary,
) -> Result<CommitOut, EngineError> {
    let group_id = entry.group_id();
    let base_id = base.id.commit_id;
    let resolves: BTreeSet<[u8; 32]> = merged.iter().map(|r| r.id.commit_id).collect();
    let base_ref = base.clone();
    let merged = merged.to_vec();

    let (commit_id, content, welcome, summary) =
        entry.apply_with(&base_id, None, &resolves, |group, provider| {
            if group.epoch().as_u64() != base_ref.id.mls_epoch {
                return Err(RegistryError::Rejected("stale_epoch"));
            }
            let as_reg = |e: EngineError| RegistryError::Mls(e.to_string());
            verify_own_leaf(group, signer).map_err(as_reg)?;
            let (commit, welcome) = match op {
                CommitOp::Add(_) | CommitOp::AddAll(_) => {
                    let one;
                    let encoded: &[Vec<u8>] = match op {
                        CommitOp::Add(key_package) => {
                            one = [key_package.clone()];
                            &one
                        }
                        CommitOp::AddAll(all) => all,
                        _ => unreachable!(),
                    };
                    if encoded.is_empty() {
                        return Err(RegistryError::BadArgument("key_packages"));
                    }
                    let mut packages = Vec::with_capacity(encoded.len());
                    for key_package in encoded {
                        let mut bytes = key_package.as_slice();
                        packages.push(
                            KeyPackageIn::tls_deserialize(&mut bytes)
                                .map_err(mls)
                                .map_err(as_reg)?
                                .validate(provider.crypto(), ProtocolVersion::Mls10)
                                .map_err(mls)
                                .map_err(as_reg)?,
                        );
                    }
                    let (commit, welcome, _info) = group
                        .add_members(provider, &signer.pair, &packages)
                        .map_err(mls)
                        .map_err(as_reg)?;
                    (commit, Some(welcome))
                }
                CommitOp::Remove(target) => {
                    let leaves = leaves_of(group, signer, std::slice::from_ref(target))?;
                    let (commit, _welcome, _info) = group
                        .remove_members(provider, &signer.pair, &leaves)
                        .map_err(mls)
                        .map_err(as_reg)?;
                    (commit, None)
                }
                CommitOp::Merge(removes) if !removes.is_empty() => {
                    let leaves = leaves_of(group, signer, removes)?;
                    let (commit, _welcome, _info) = group
                        .remove_members(provider, &signer.pair, &leaves)
                        .map_err(mls)
                        .map_err(as_reg)?;
                    (commit, None)
                }
                CommitOp::SelfUpdate | CommitOp::Merge(_) => {
                    let bundle = group
                        .self_update(provider, &signer.pair, LeafNodeParameters::default())
                        .map_err(mls)
                        .map_err(as_reg)?;
                    (bundle.commit().clone(), None)
                }
            };
            group
                .merge_pending_commit(provider)
                .map_err(mls)
                .map_err(as_reg)?;
            let commit = commit.to_bytes().map_err(mls).map_err(as_reg)?;
            let welcome = welcome
                .map(|w| w.to_bytes())
                .transpose()
                .map_err(mls)
                .map_err(as_reg)?;
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
                base: base_ref,
                resolves: merged,
                commit,
                group_info,
                proposals: Vec::new(),
                plan: plan.clone(),
            }
            .to_value()
            .map_err(|e| RegistryError::Mls(e.to_string()))?;
            let summary = summarize(group, group_id, commit_id).map_err(as_reg)?;
            Ok((commit_id, (commit_id, content, welcome, summary)))
        })?;

    let encoded = {
        let branch = entry
            .branch(&commit_id)
            .ok_or(EngineError::BadArgument("state"))?;
        let mut meta =
            BranchMeta::decode(branch.meta()).map_err(|e| EngineError::Mls(e.to_string()))?;
        meta.after_local_commit(
            branch.group(),
            &group_id,
            branch.epoch(),
            &signer.member_key(),
            op,
        )
        .map_err(|e| EngineError::Mls(e.to_string()))?;
        meta.encode()
    };
    entry
        .branch_mut(&commit_id)
        .ok_or(EngineError::BadArgument("state"))?
        .set_meta(encoded);

    Ok(CommitOut {
        content,
        welcome,
        commit_id,
        summary,
    })
}

/// Leaf indices of every leaf owned by `targets`, refusing the caller.
fn leaves_of(
    group: &MlsGroup,
    signer: &Signer,
    targets: &[MemberKey],
) -> Result<Vec<LeafNodeIndex>, RegistryError> {
    let as_reg = |e: EngineError| RegistryError::Mls(e.to_string());
    if targets.contains(&signer.member_key()) {
        return Err(RegistryError::BadArgument("self_remove"));
    }
    let mut leaves = Vec::new();
    for target in targets {
        let before = leaves.len();
        for member in group.members() {
            if member_of(&member.credential).map_err(as_reg)? == *target {
                leaves.push(member.index);
            }
        }
        if leaves.len() == before {
            return Err(RegistryError::BadArgument("member"));
        }
    }
    Ok(leaves)
}

/// The outcome of [`merge`].
#[derive(Debug)]
pub enum MergeOutcome {
    /// The merge Commit was built and installed as the new tip.
    Merged(CommitOut),
    /// A requested state is not held; retry after more events. Entry unchanged.
    Deferred(&'static str),
    /// The merge cannot be built; the code is stable. Entry unchanged.
    Rejected(&'static str),
}

/// Plan a merge of `requested` and build the `m.dmls.merge` Commit.
///
/// The Commit is made on the plan's base state, applies the plan's Removes
/// (or a bare path update when there are none), and resolves every requested
/// extremity, so a single requested tip yields a plain `m.dmls.commit`. Plans
/// that need an Add are refused (`unsupported_add`): the merge input carries no
/// `KeyPackage`, so the member must rejoin. Required self-updates stay with the
/// named members; this never fabricates an `UpdateOther`.
///
/// # Errors
///
/// [`EngineError`] if stored metadata is corrupt or `OpenMLS` fails.
pub fn merge(
    entry: &mut GroupEntry,
    signer: &Signer,
    requested: &[ExtremityRef],
    registry: &DeviceRootRegistry,
) -> Result<MergeOutcome, EngineError> {
    let ids: Vec<[u8; 32]> = requested.iter().map(|r| r.id.commit_id).collect();
    let plan = match plan_merge(entry, &ids, registry)? {
        PlanOutcome::Planned(plan) => plan,
        PlanOutcome::Deferred(reason) => return Ok(MergeOutcome::Deferred(reason)),
        PlanOutcome::Rejected(reason) => return Ok(MergeOutcome::Rejected(reason)),
    };
    if !plan.adds.is_empty() {
        return Ok(MergeOutcome::Rejected("unsupported_add"));
    }
    let summary = PlanSummary::from_plan(&plan)?;
    if summary.removes.contains(&signer.member_key()) {
        return Ok(MergeOutcome::Rejected("self_removed"));
    }
    let mut resolved = requested.to_vec();
    resolved.sort_by_key(|r| r.id);
    resolved.dedup_by_key(|r| r.id);
    let Some(base) = resolved.iter().find(|r| r.id == plan.base).cloned() else {
        return Ok(MergeOutcome::Rejected("mismatch:base"));
    };
    let op = CommitOp::Merge(summary.removes.clone());
    match commit_inner(entry, signer, &base, &resolved, &op, &summary) {
        Ok(out) => Ok(MergeOutcome::Merged(out)),
        Err(EngineError::Registry(RegistryError::MissingBase)) => {
            Ok(MergeOutcome::Deferred("missing_base_state"))
        }
        Err(EngineError::Registry(RegistryError::MissingBranch)) => {
            Ok(MergeOutcome::Deferred("missing_branch"))
        }
        Err(error) => Err(error),
    }
}

/// The output of [`external_commit`].
#[derive(Debug)]
pub struct ExternalOut {
    /// `m.dmls.external_commit` content, ready to send.
    pub content: Value,
    /// The new extremity's commit id.
    pub commit_id: [u8; 32],
    /// The state the join produced.
    pub summary: GroupSummary,
}

/// Join a group by external Commit against the `GroupInfo` of `target`.
///
/// `group_info` is the TLS-serialized `GroupInfo` `MLSMessage` (with its
/// ratchet tree) taken from the target extremity's event, and `target` names
/// that extremity with its event id. The joiner must not already hold a leaf,
/// but `OpenMLS` resyncs a same-identity join by silently Removing the old leaf
/// and the Commit body is not inspectable here, so this cannot detect it:
/// receivers must reject an external Commit that carries a Remove (§8 rule 3).
/// The returned branch is a new root for the caller to install with
/// `GroupEntry::insert_root` (or a new entry), not a mutation of any entry.
/// An external Commit uses no `KeyPackage`, so the event has no
/// `key_package_id`; its `commit_id` is its identity.
///
/// # Errors
///
/// [`EngineError`] if the `GroupInfo` is malformed, is for another group or
/// epoch than `target`, the tree holds the joiner twice, or `OpenMLS` fails.
pub fn external_commit(
    signer: &Signer,
    group_id: &[u8; 32],
    target: &ExtremityRef,
    group_info: &[u8],
) -> Result<(HeldBranch, ExternalOut), EngineError> {
    let message = MlsMessageIn::tls_deserialize_exact(group_info).map_err(mls)?;
    let MlsMessageBodyIn::GroupInfo(verifiable) = message.extract() else {
        return Err(EngineError::UnexpectedMessage);
    };
    if verifiable.group_id().as_slice() != group_id.as_slice() {
        return Err(EngineError::BadArgument("group_id"));
    }
    if verifiable.epoch().as_u64() != target.id.mls_epoch {
        return Err(EngineError::BadArgument("target_epoch"));
    }
    let provider = OpenMlsRustCrypto::default();
    let config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let (group, bundle) = MlsGroup::external_commit_builder()
        .with_config(config)
        .build_group(&provider, verifiable, signer.credential.clone())
        .map_err(mls)?
        .load_psks(provider.storage())
        .map_err(mls)?
        .build(provider.rand(), provider.crypto(), &signer.pair, |_| true)
        .map_err(mls)?
        .finalize(&provider)
        .map_err(mls)?;

    let me = signer.member_key();
    let mine = group
        .members()
        .filter(|m| member_of(&m.credential).is_ok_and(|key| key == me))
        .count();
    if mine != 1 {
        return Err(EngineError::BadArgument("already_member"));
    }
    verify_own_leaf(&group, signer)?;

    let commit = bundle.commit().to_bytes().map_err(mls)?;
    let commit_id = wire::commit_id(&commit);
    let resulting_info = group
        .export_group_info(provider.crypto(), &signer.pair, true)
        .map_err(mls)?
        .to_bytes()
        .map_err(mls)?;
    let epoch = group.epoch().as_u64();
    let content = ExternalCommitContent {
        group_id: *group_id,
        target: target.clone(),
        commit,
        group_info: resulting_info,
        joiner: me.clone(),
    };
    if content.mls_epoch() != epoch {
        return Err(EngineError::BadArgument("target_epoch"));
    }
    let content = content.to_value()?;

    let mut meta =
        BranchMeta::from_group(&group, group_id).map_err(|e| EngineError::Mls(e.to_string()))?;
    meta.after_external_commit(&group, group_id, epoch, &me)
        .map_err(|e| EngineError::Mls(e.to_string()))?;
    let summary = summarize(&group, *group_id, commit_id)?;
    let mut branch = HeldBranch::new(provider, group);
    branch.set_meta(meta.encode());
    Ok((
        branch,
        ExternalOut {
            content,
            commit_id,
            summary,
        },
    ))
}

/// One recipient of a reboot's Welcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootRecipient {
    /// The member added to the replacement group.
    pub member: MemberKey,
    /// The consumed `KeyPackage`'s ID; the Welcome content names it.
    pub key_package_id: [u8; 32],
}

/// Output of [`reboot`].
#[derive(Debug)]
pub struct RebootOut {
    /// The `m.dmls.reboot` content, in the old group's room.
    pub reboot: Value,
    /// The replacement group's id.
    pub new_group_id: [u8; 32],
    /// The replacement group, holding the epoch-1 Commit as its only tip.
    pub entry: GroupEntry,
    /// The `m.dmls.commit` that adds every recipient (base: the new genesis).
    pub commit: CommitOut,
    /// Who the one Welcome in `commit.welcome` is for.
    pub recipients: Vec<RebootRecipient>,
}

/// The member a serialized `KeyPackage` belongs to, from its leaf credential.
///
/// # Errors
///
/// [`EngineError`] if the bytes are not a valid `KeyPackage` or its credential
/// is not a Cygnus member credential.
pub fn key_package_owner(bytes: &[u8]) -> Result<MemberKey, EngineError> {
    let mut slice = bytes;
    let package = KeyPackageIn::tls_deserialize(&mut slice)
        .map_err(mls)?
        .validate(
            OpenMlsRustCrypto::default().crypto(),
            ProtocolVersion::Mls10,
        )
        .map_err(mls)?;
    member_of(package.leaf_node().credential())
}

/// Start a replacement group from `base` after unrecoverable state loss
/// (00FD §11).
///
/// The caller must be an active member of `base`, which must be held. Each
/// `KeyPackage` names one member to carry over, and every such member must be
/// in `base` and appear once. The new group is
/// `reboot_group_id(old, base.commit_id)`; the caller creates it and adds the
/// members in a single Commit on its genesis. The old entry is left alone: a
/// reboot abandons old epochs, it does not resolve them.
///
/// # Errors
///
/// [`EngineError::BadArgument`] for an empty reason or member list, a base that
/// is not held, a caller or member that is not in `base`, or a `KeyPackage`
/// that is the caller's, a duplicate, or not for a `base` member.
pub fn reboot(
    old: &GroupEntry,
    signer: &Signer,
    reason: &str,
    base: &ExtremityRef,
    key_packages: &[Vec<u8>],
) -> Result<RebootOut, EngineError> {
    let old_group_id = old.group_id();
    let held = old
        .branch(&base.id.commit_id)
        .filter(|branch| branch.epoch() == base.id.mls_epoch)
        .ok_or(EngineError::BadArgument("base"))?;
    let old_members: BTreeSet<MemberKey> = held
        .group()
        .members()
        .map(|m| member_of(&m.credential))
        .collect::<Result<_, _>>()?;
    let me = signer.member_key();
    if !old_members.contains(&me) {
        return Err(EngineError::BadArgument("not_a_member"));
    }
    if key_packages.is_empty() {
        return Err(EngineError::BadArgument("members"));
    }
    let mut recipients = Vec::with_capacity(key_packages.len());
    let mut seen = BTreeSet::new();
    for package in key_packages {
        let member = key_package_owner(package)?;
        if member == me || !old_members.contains(&member) || !seen.insert(member.clone()) {
            return Err(EngineError::BadArgument("members"));
        }
        recipients.push(RebootRecipient {
            member,
            key_package_id: wire::key_package_id(package),
        });
    }
    let content = RebootContent {
        old_group_id,
        reason: reason.to_owned(),
        members: recipients.iter().map(|r| r.member.clone()).collect(),
        base: base.clone(),
    };
    let reboot_value = content.to_value()?;
    let new_group_id = content.new_group_id();

    let (branch, summary) = create_group(signer, new_group_id)?;
    let mut entry = GroupEntry::new(new_group_id);
    entry
        .insert_root(summary.commit_id, branch)
        .map_err(EngineError::Registry)?;
    let genesis = ExtremityRef::genesis(&new_group_id);
    let commit = commit(
        &mut entry,
        signer,
        &genesis,
        &CommitOp::AddAll(key_packages.to_vec()),
    )?;
    Ok(RebootOut {
        reboot: reboot_value,
        new_group_id,
        entry,
        commit,
        recipients,
    })
}

/// The outcome of checking a received `m.dmls.reboot`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebootCheck {
    /// The reboot is authorized; the replacement group is `new_group_id`.
    Accepted(RebootContent),
    /// `base` is not held, or its event is not a known ancestor. Retry later.
    Deferred(&'static str),
    /// Permanently invalid; the code is stable.
    Rejected(&'static str),
}

/// Check a received `m.dmls.reboot` against the old group (00FD §11): the
/// sender must be an active member of `base` and the listed members must all
/// be members of it. No state changes: a reboot abandons the old epochs.
#[must_use]
pub fn check_reboot(entry: &GroupEntry, content: &Value, ctx: &ApplyCtx) -> RebootCheck {
    let parsed = match RebootContent::parse(content, &entry.group_id()) {
        Ok(parsed) => parsed,
        Err(error) => return RebootCheck::Rejected(error.code()),
    };
    if let Some(event) = &parsed.base.event_id {
        if !ctx.ancestors.contains(event) {
            return RebootCheck::Deferred("unheld_ancestor");
        }
    }
    let Some(held) = entry.branch(&parsed.base.id.commit_id) else {
        return RebootCheck::Deferred("missing_base_state");
    };
    if held.epoch() != parsed.base.id.mls_epoch {
        return RebootCheck::Rejected("mismatch:base");
    }
    let Ok(members) = held
        .group()
        .members()
        .map(|m| member_of(&m.credential))
        .collect::<Result<BTreeSet<_>, _>>()
    else {
        return RebootCheck::Rejected("malformed:credential");
    };
    if !members.contains(&ctx.sender) {
        return RebootCheck::Rejected("mismatch:sender");
    }
    if parsed.members.is_empty() || !parsed.members.iter().all(|m| members.contains(m)) {
        return RebootCheck::Rejected("mismatch:members");
    }
    RebootCheck::Accepted(parsed)
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
    apply_event(entry, event_type, content, ctx, None)
}

/// Apply a received `m.dmls.merge`: everything [`apply_commit`] checks, plus a
/// recomputed [`PlanSummary`] and merged membership that must match the event.
///
/// `registry` is supplied per call and never cached (see §5.1). A merge whose
/// plan this device cannot reproduce is `rejected` with `mismatch:plan`; one
/// whose resolved states are not all held is `deferred`.
///
/// # Errors
///
/// [`EngineError::BadArgument`] if `event_type` is not `m.dmls.merge`, or
/// [`EngineError`] for corrupt stored metadata.
pub fn apply_merge(
    entry: &mut GroupEntry,
    event_type: &str,
    content: &Value,
    ctx: &ApplyCtx,
    registry: &DeviceRootRegistry,
) -> Result<ApplyOutcome, EngineError> {
    if event_type != wire::MERGE_EVENT {
        return Err(EngineError::BadArgument("event_type"));
    }
    apply_event(entry, event_type, content, ctx, Some(registry))
}

/// Apply a received `m.dmls.external_commit` (00FD §8).
///
/// The sender must be the `joiner`, and `target` must be a held state at epoch
/// `target.mls_epoch` whose event is a known ancestor. The Commit must carry no
/// proposals at all: a Remove is how `OpenMLS` silently resyncs a same-identity
/// join, so refusing every Remove enforces "no live leaf". The joiner must not
/// hold a leaf in the target state, the merged group must contain exactly one
/// more leaf, the joiner's, and `group_info` must be the joiner's signed
/// `GroupInfo` for this exact resulting state. The new state replaces `target` as
/// the tip.
///
/// # Errors
///
/// [`EngineError`] for corrupt stored metadata. Protocol failures are an
/// [`ApplyOutcome`].
#[allow(clippy::too_many_lines)]
pub fn apply_external_commit(
    entry: &mut GroupEntry,
    content: &Value,
    ctx: &ApplyCtx,
) -> Result<ApplyOutcome, EngineError> {
    let group_id = entry.group_id();
    let parsed = match ExternalCommitContent::parse(content, &ctx.sender, &group_id) {
        Ok(parsed) => parsed,
        Err(error) => return Ok(ApplyOutcome::Rejected(error.code())),
    };
    if let Some(event) = &parsed.target.event_id {
        if !ctx.ancestors.contains(event) {
            return Ok(ApplyOutcome::Deferred("unheld_ancestor"));
        }
    }
    let target_epoch = parsed.target.id.mls_epoch;
    let new_epoch = parsed.mls_epoch();
    let verifiable = match MlsMessageIn::tls_deserialize_exact(&parsed.group_info) {
        Ok(message) => match message.extract() {
            MlsMessageBodyIn::GroupInfo(info) => info,
            _ => return Ok(ApplyOutcome::Rejected("mismatch:group_info")),
        },
        Err(_) => return Ok(ApplyOutcome::Rejected("mismatch:group_info")),
    };
    if verifiable.group_id().as_slice() != group_id.as_slice()
        || verifiable.epoch().as_u64() != new_epoch
    {
        return Ok(ApplyOutcome::Rejected("mismatch:group_info"));
    }

    let base_id = parsed.target.id.commit_id;
    let new_id = parsed.commit_id();
    let resolves = BTreeSet::from([base_id]);
    let joiner = ctx.sender.clone();
    let commit = parsed.commit;

    let result = entry.apply(&base_id, new_id, &resolves, move |group, provider| {
        if group.epoch().as_u64() != target_epoch {
            return Err(RegistryError::Rejected("mismatch:base"));
        }
        let before = group.members().count();
        if group
            .members()
            .any(|m| member_of(&m.credential).is_ok_and(|key| key == joiner))
        {
            return Err(RegistryError::Rejected("joiner_has_leaf"));
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
        if committer != joiner {
            return Err(RegistryError::Rejected("mismatch:sender"));
        }
        let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content() else {
            return Err(RegistryError::Rejected("malformed:commit"));
        };
        if staged.remove_proposals().next().is_some() {
            return Err(RegistryError::Rejected("external_remove"));
        }
        if staged.add_proposals().next().is_some() || staged.update_proposals().next().is_some() {
            return Err(RegistryError::Rejected("malformed:commit"));
        }
        // `group_info` must be the GroupInfo for this Commit's resulting state,
        // not merely one for the same group and epoch.
        let path = staged
            .update_path_leaf_node()
            .ok_or(RegistryError::Rejected("mismatch:joiner"))?;
        let key = OpenMlsSignaturePublicKey::from_signature_key(
            path.signature_key().clone(),
            group.ciphersuite().signature_algorithm(),
        );
        let info = verifiable
            .verify(provider.crypto(), &key)
            .map_err(|_| RegistryError::Rejected("mismatch:group_info"))?;
        if info.group_context() != staged.group_context() {
            return Err(RegistryError::Rejected("mismatch:group_info"));
        }
        group
            .merge_staged_commit(provider, *staged)
            .map_err(|e| RegistryError::Mls(format!("{e:?}")))?;
        if group.epoch().as_u64() != new_epoch {
            return Err(RegistryError::Rejected("mismatch:mls_epoch"));
        }
        let mine = group
            .members()
            .filter(|m| member_of(&m.credential).is_ok_and(|key| key == joiner))
            .count();
        if mine != 1 || group.members().count() != before + 1 {
            return Err(RegistryError::Rejected("mismatch:joiner"));
        }
        summarize(group, group_id, new_id).map_err(|e| RegistryError::Mls(e.to_string()))
    });

    Ok(match result {
        Ok(summary) => {
            let encoded = {
                let branch = entry
                    .branch(&new_id)
                    .ok_or(EngineError::BadArgument("state"))?;
                let mut meta = BranchMeta::decode(branch.meta())
                    .map_err(|e| EngineError::Mls(e.to_string()))?;
                meta.after_external_commit(branch.group(), &group_id, new_epoch, &ctx.sender)
                    .map_err(|e| EngineError::Mls(e.to_string()))?;
                meta.encode()
            };
            entry
                .branch_mut(&new_id)
                .ok_or(EngineError::BadArgument("state"))?
                .set_meta(encoded);
            ApplyOutcome::Applied(summary)
        }
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

#[allow(clippy::too_many_lines)]
fn apply_event(
    entry: &mut GroupEntry,
    event_type: &str,
    content: &Value,
    ctx: &ApplyCtx,
    registry: Option<&DeviceRootRegistry>,
) -> Result<ApplyOutcome, EngineError> {
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
    let expected_members: Option<BTreeSet<MemberId>> = match registry {
        None => None,
        Some(registry) => {
            let ids: Vec<[u8; 32]> = resolves.iter().copied().collect();
            let plan = match plan_merge(entry, &ids, registry)? {
                PlanOutcome::Planned(plan) => plan,
                PlanOutcome::Deferred(reason) => return Ok(ApplyOutcome::Deferred(reason)),
                PlanOutcome::Rejected(reason) => return Ok(ApplyOutcome::Rejected(reason)),
            };
            let summary = PlanSummary::from_plan(&plan)?;
            if plan.base != parsed.base.id || summary != parsed.plan {
                return Ok(ApplyOutcome::Rejected("mismatch:plan"));
            }
            Some(plan.members.keys().cloned().collect())
        }
    };
    let base_epoch = parsed.base.id.mls_epoch;
    let target_epoch = parsed.mls_epoch();
    let commit = parsed.commit;
    let sender = ctx.sender.clone();
    let mut adds: Vec<KeyPackage> = Vec::new();
    let mut updates: Vec<LeafNode> = Vec::new();
    let mut removes: Vec<usize> = Vec::new();
    let mut update_path: Option<LeafNode> = None;

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
        adds.extend(
            staged
                .add_proposals()
                .map(|proposal| proposal.add_proposal().key_package().clone()),
        );
        updates.extend(
            staged
                .update_proposals()
                .map(|proposal| proposal.update_proposal().leaf_node().clone()),
        );
        removes.extend(
            staged
                .remove_proposals()
                .map(|proposal| proposal.remove_proposal().removed().usize()),
        );
        update_path = staged.update_path_leaf_node().cloned();
        group
            .merge_staged_commit(provider, *staged)
            .map_err(|e| RegistryError::Mls(format!("{e:?}")))?;
        if group.epoch().as_u64() != target_epoch {
            return Err(RegistryError::Rejected("mismatch:mls_epoch"));
        }
        let summary =
            summarize(group, group_id, new_id).map_err(|e| RegistryError::Mls(e.to_string()))?;
        if let Some(expected) = &expected_members {
            let actual: BTreeSet<MemberId> = summary
                .members
                .iter()
                .map(crate::branch_meta::member_id_from_key)
                .collect();
            if &actual != expected {
                return Err(RegistryError::Rejected("mismatch:plan"));
            }
        }
        Ok(summary)
    });

    Ok(match result {
        Ok(summary) => {
            let encoded = {
                let branch = entry
                    .branch(&new_id)
                    .ok_or(EngineError::BadArgument("state"))?;
                let mut meta = BranchMeta::decode(branch.meta())
                    .map_err(|e| EngineError::Mls(e.to_string()))?;
                meta.after_remote_commit(&crate::branch_meta::RemoteCommit {
                    group: branch.group(),
                    group_id: &group_id,
                    epoch: target_epoch,
                    sender: &sender,
                    adds: &adds,
                    updates: &updates,
                    removes: &removes,
                    update_path: update_path.as_ref(),
                })
                .map_err(|e| EngineError::Mls(e.to_string()))?;
                meta.encode()
            };
            entry
                .branch_mut(&new_id)
                .ok_or(EngineError::BadArgument("state"))?
                .set_meta(encoded);
            ApplyOutcome::Applied(summary)
        }
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

/// The result of planning a merge over locally held states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanOutcome {
    /// A plan was produced; `dmlsMerge` can build the Commit from it.
    Planned(MergePlan),
    /// At least one requested state is not held; retry after more events.
    Deferred(&'static str),
    /// The request cannot be planned; the code is stable.
    Rejected(&'static str),
}

/// Plan a merge over the held branches named by `requested` commit ids.
///
/// The device-root registry is supplied per call and is never cached. Leaf
/// signatures are not re-checked here because `OpenMLS` verified them when the
/// branches were received; the callback enforces the model's group and
/// update-source rules.
///
/// # Errors
///
/// [`EngineError`] if stored branch metadata is corrupt or the group is
/// malformed.
pub fn plan_merge(
    entry: &GroupEntry,
    requested: &[[u8; 32]],
    registry: &DeviceRootRegistry,
) -> Result<PlanOutcome, EngineError> {
    let group_id = entry.group_id();
    let mut held: BTreeMap<ExtremityId, Branch> = BTreeMap::new();
    for (commit_id, branch) in entry.branches() {
        let meta =
            BranchMeta::decode(branch.meta()).map_err(|e| EngineError::Mls(e.to_string()))?;
        held.insert(
            ExtremityId::new(branch.epoch(), *commit_id),
            meta.to_branch(*commit_id, branch.epoch(), branch.resolves().clone()),
        );
    }

    let mut requested_ids = Vec::with_capacity(requested.len());
    for commit_id in requested {
        match held.keys().find(|ext| ext.commit_id == *commit_id) {
            Some(ext) => requested_ids.push(*ext),
            None => return Ok(PlanOutcome::Deferred("missing_base_state")),
        }
    }

    let verify = |leaf: &crate::tree::LeafNode, _index: Option<usize>, for_update: bool| {
        leaf.group_id == group_id && !(for_update && leaf.source == LeafSource::KeyPackage)
    };
    match plan_with_device_roots(requested_ids, &held, &group_id, registry, &verify) {
        Ok(plan) => Ok(PlanOutcome::Planned(plan)),
        Err(MergeError::MissingBaseState { .. }) => Ok(PlanOutcome::Deferred("missing_base_state")),
        Err(MergeError::UncertifiedDevice(_)) => Ok(PlanOutcome::Rejected("uncertified_device")),
        Err(_) => Ok(PlanOutcome::Rejected("merge")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::EncryptedContent;
    use crate::device_root::DeviceRoot;
    use crate::merge::ExtremityId;
    use crate::registry::decode_secrets;
    use cygnus_core::DeviceCertificate;
    use ed25519_zebra::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from([seed; 32])
    }

    fn public(key: &SigningKey) -> [u8; 32] {
        <[u8; 32]>::from(key.verification_key())
    }

    /// Certify each (principal, signer seed, device id) under a generated root.
    fn device_registry(users: &[(&str, u8, &str)]) -> DeviceRootRegistry {
        let masters = users
            .iter()
            .map(|(principal, seed, _)| {
                ((*principal).to_owned(), public(&key(seed.wrapping_add(10))))
            })
            .collect::<Vec<_>>();
        let mut registry = DeviceRootRegistry::new(masters);
        for (principal, seed, device_id) in users {
            let master = key(seed.wrapping_add(10));
            let self_signing = key(seed.wrapping_add(20));
            registry
                .install_root(DeviceRoot {
                    principal: (*principal).to_owned(),
                    user_epoch_height: 1,
                    generation: 1,
                    self_signing_key: public(&self_signing),
                })
                .unwrap();
            let certificate =
                DeviceCertificate::issue(principal, &master, &self_signing, device_id, &key(*seed))
                    .unwrap();
            registry.certify(principal, &certificate).unwrap();
        }
        registry
    }

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
    fn decrypt_in_finds_the_branch_at_the_epoch_and_buffers_the_rest() {
        let (alice, bob, mut a, mut b, tip) = three_member_group();
        let content = encrypt_at(&mut a, &alice, None, b"hi").unwrap();
        let before = b.export();
        let DecryptOutcome::Ok { message, commit_id } = decrypt_in(&mut b, &content) else {
            panic!("expected ok");
        };
        assert_eq!(message.plaintext, b"hi");
        assert_eq!(message.sender, alice.member_key());
        assert_eq!(commit_id, tip.id.commit_id);
        assert_ne!(b.export(), before);

        // A replay cannot decrypt; nothing changes.
        let after = b.export();
        assert_eq!(
            decrypt_in(&mut b, &content),
            DecryptOutcome::Rejected("decrypt_failed")
        );
        assert_eq!(b.export(), after);

        // A later epoch is not held: buffer it.
        let next = commit(&mut a, &alice, &tip, &CommitOp::SelfUpdate).unwrap();
        let future = encrypt_at(&mut a, &alice, Some(&next.commit_id), b"later").unwrap();
        assert_eq!(decrypt_in(&mut b, &future), DecryptOutcome::MissingState(3));
        assert_eq!(b.export(), after);

        // Two tips: encrypting needs a named branch.
        commit(&mut a, &alice, &tip, &CommitOp::SelfUpdate).unwrap();
        assert!(matches!(
            encrypt_at(&mut a, &alice, None, b"x"),
            Err(EngineError::Registry(RegistryError::ForkUnresolved))
        ));
        let _ = bob;
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
            first.welcome.as_ref().unwrap(),
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
            first.welcome.as_ref().unwrap(),
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

    /// Alice adds Bob and Carol over two commits; returns Alice's and Bob's
    /// entries and the ref to the epoch-2 tip. Bob applies the second commit.
    fn three_member_group() -> (Signer, Signer, GroupEntry, GroupEntry, ExtremityRef) {
        let alice = signer(ALICE, "ALICE1", 1);
        let bob = signer(BOB, "BOB1", 2);
        let group_id = wire::group_id(ROOM);
        let mut a = alice_entry(&alice, group_id);
        let genesis = ExtremityRef::genesis(&group_id);
        let (bob_kp, bob_secrets) = package_bytes(&bob);
        let (carol_kp, _) = package_bytes(&signer(CAROL, "CAROL1", 3));
        let first = commit_add(&mut a, &alice, &genesis, &bob_kp).unwrap();
        let (bob_branch, _) = join_welcome(
            &bob,
            &bob_secrets,
            first.welcome.as_ref().unwrap(),
            &group_id,
            first.commit_id,
        )
        .unwrap();
        let mut b = GroupEntry::new(group_id);
        b.insert_root(first.commit_id, bob_branch).unwrap();
        let base1 = ExtremityRef::new(ExtremityId::new(1, first.commit_id), "$first");
        let second = commit_add(&mut a, &alice, &base1, &carol_kp).unwrap();
        let ctx = ApplyCtx {
            sender: alice.member_key(),
            ancestors: BTreeSet::from(["$first".to_owned()]),
        };
        assert!(matches!(
            apply_commit(&mut b, wire::COMMIT_EVENT, &second.content, &ctx).unwrap(),
            ApplyOutcome::Applied(_)
        ));
        let tip = ExtremityRef::new(ExtremityId::new(2, second.commit_id), "$second");
        (alice, bob, a, b, tip)
    }

    #[test]
    fn remove_drops_the_member_and_peers_apply_it() {
        let (alice, bob, mut a, mut b, tip) = three_member_group();
        let carol = MemberKey {
            principal: CAROL.to_owned(),
            device_id: "CAROL1".to_owned(),
        };
        let out = commit(&mut a, &alice, &tip, &CommitOp::Remove(carol.clone())).unwrap();
        assert!(out.welcome.is_none());
        assert_eq!(out.summary.mls_epoch, 3);
        assert!(!out.summary.members.contains(&carol));
        assert_eq!(out.summary.members.len(), 2);

        let ctx = ApplyCtx {
            sender: alice.member_key(),
            ancestors: BTreeSet::from(["$second".to_owned()]),
        };
        let ApplyOutcome::Applied(summary) =
            apply_commit(&mut b, wire::COMMIT_EVENT, &out.content, &ctx).unwrap()
        else {
            panic!("bob must apply the remove");
        };
        assert_eq!(summary, out.summary);
        assert!(summary.members.contains(&bob.member_key()));
    }

    #[test]
    fn self_update_rotates_without_changing_membership() {
        let (alice, _bob, mut a, mut b, tip) = three_member_group();
        let before = a
            .branch(&tip.id.commit_id)
            .unwrap()
            .group()
            .members()
            .count();
        let out = commit(&mut a, &alice, &tip, &CommitOp::SelfUpdate).unwrap();
        assert!(out.welcome.is_none());
        assert_eq!(out.summary.mls_epoch, 3);
        assert_eq!(out.summary.members.len(), before);

        let ctx = ApplyCtx {
            sender: alice.member_key(),
            ancestors: BTreeSet::from(["$second".to_owned()]),
        };
        assert!(matches!(
            apply_commit(&mut b, wire::COMMIT_EVENT, &out.content, &ctx).unwrap(),
            ApplyOutcome::Applied(s) if s == out.summary
        ));
    }

    #[test]
    fn branch_metadata_tracks_add_remove_and_self_update() {
        let (alice, _bob, mut a, _b, tip) = three_member_group();
        let meta_at = |entry: &GroupEntry, id: &[u8; 32]| {
            BranchMeta::decode(entry.branch(id).unwrap().meta()).unwrap()
        };

        let base = meta_at(&a, &tip.id.commit_id);
        assert_eq!(base.members.len(), 3);

        let carol = MemberKey {
            principal: CAROL.to_owned(),
            device_id: "CAROL1".to_owned(),
        };
        let removed = commit(&mut a, &alice, &tip, &CommitOp::Remove(carol)).unwrap();
        let after_remove = meta_at(&a, &removed.commit_id);
        assert_eq!(after_remove.members.len(), 2);
        assert_eq!(after_remove.removed.len(), 1);

        let base = ExtremityRef::new(
            ExtremityId::new(removed.summary.mls_epoch, removed.commit_id),
            "$removed",
        );
        let updated = commit(&mut a, &alice, &base, &CommitOp::SelfUpdate).unwrap();
        let after_update = meta_at(&a, &updated.commit_id);
        let own = crate::branch_meta::member_id_from_key(&alice.member_key());
        assert_eq!(after_update.members[&own].leaf.generation, 4);
        assert_eq!(after_update.members[&own].leaf.source, LeafSource::Update);
    }

    #[test]
    fn plan_merge_uses_the_held_branch_metadata() {
        let (_alice, _bob, a, _b, tip) = three_member_group();
        let unknown = [0xAA; 32];
        assert_eq!(
            plan_merge(&a, &[unknown], &DeviceRootRegistry::default()).unwrap(),
            PlanOutcome::Deferred("missing_base_state")
        );
        assert_eq!(
            plan_merge(&a, &[tip.id.commit_id], &DeviceRootRegistry::default()).unwrap(),
            PlanOutcome::Rejected("uncertified_device")
        );
    }

    #[test]
    fn plan_merge_accepts_certified_members_and_removes_revoked_ones() {
        let (alice, _bob, mut a, _b, tip) = three_member_group();
        let users = [
            (ALICE, 1_u8, "ALICE1"),
            (BOB, 2, "BOB1"),
            (CAROL, 3, "CAROL1"),
        ];
        let registry = device_registry(&users);

        let PlanOutcome::Planned(plan) = plan_merge(&a, &[tip.id.commit_id], &registry).unwrap()
        else {
            panic!("certified branches must plan");
        };
        assert_eq!(plan.members.len(), 3);
        assert!(plan.removes.is_empty());

        let carol = MemberKey {
            principal: CAROL.to_owned(),
            device_id: "CAROL1".to_owned(),
        };
        let removed = commit(&mut a, &alice, &tip, &CommitOp::Remove(carol)).unwrap();
        let PlanOutcome::Planned(plan) = plan_merge(&a, &[removed.commit_id], &registry).unwrap()
        else {
            panic!("the post-remove branch must plan");
        };
        assert_eq!(plan.members.len(), 2);

        // Revoking a still-present device turns the plan into a Remove.
        let mut registry = device_registry(&users);
        registry.revoke(&public(&key(2)));
        let PlanOutcome::Planned(plan) = plan_merge(&a, &[tip.id.commit_id], &registry).unwrap()
        else {
            panic!("a revoked member must still plan");
        };
        assert_eq!(
            plan.removes,
            vec![crate::branch_meta::member_id_from_key(&MemberKey {
                principal: BOB.to_owned(),
                device_id: "BOB1".to_owned(),
            })]
        );
    }

    #[test]
    fn bad_removes_leave_the_entry_byte_identical() {
        let (alice, _bob, mut a, _b, tip) = three_member_group();
        let before = a.export();
        let stranger = MemberKey {
            principal: CAROL.to_owned(),
            device_id: "NOPE".to_owned(),
        };
        for target in [alice.member_key(), stranger] {
            let error = commit(&mut a, &alice, &tip, &CommitOp::Remove(target)).unwrap_err();
            assert_eq!(error.code(), "bad_argument");
            assert_eq!(a.export(), before);
        }
    }

    fn carol_key() -> MemberKey {
        MemberKey {
            principal: CAROL.to_owned(),
            device_id: "CAROL1".to_owned(),
        }
    }

    #[test]
    fn merge_resolves_both_siblings_and_drops_the_removed_member() {
        let (alice, bob, mut a, mut b, tip) = three_member_group();
        let group_id = a.group_id();
        let registry =
            device_registry(&[(ALICE, 1, "ALICE1"), (BOB, 2, "BOB1"), (CAROL, 3, "CAROL1")]);
        // Bob rotates his leaf on the same base Alice removes Carol on.
        let s1 = commit(&mut b, &bob, &tip, &CommitOp::SelfUpdate).unwrap();
        let ctx = ApplyCtx {
            sender: bob.member_key(),
            ancestors: BTreeSet::from(["$second".to_owned()]),
        };
        assert!(matches!(
            apply_commit(&mut a, wire::COMMIT_EVENT, &s1.content, &ctx).unwrap(),
            ApplyOutcome::Applied(_)
        ));
        let s2 = commit(&mut a, &alice, &tip, &CommitOp::Remove(carol_key())).unwrap();
        assert_eq!(a.extremity_count(), 2);
        let r1 = ExtremityRef::new(ExtremityId::new(3, s1.commit_id), "$s1");
        let r2 = ExtremityRef::new(ExtremityId::new(3, s2.commit_id), "$s2");

        let outcome = merge(&mut a, &alice, &[r1, r2], &registry);
        let Ok(MergeOutcome::Merged(out)) = outcome else {
            panic!("certified siblings must merge: {outcome:?}");
        };
        assert!(out.welcome.is_none());
        assert_eq!(out.summary.mls_epoch, 4);
        assert_eq!(out.summary.members.len(), 2);
        assert!(!out.summary.members.contains(&carol_key()));
        assert_eq!(
            a.extremity_count(),
            1,
            "the merge retires both sibling tips"
        );

        let parsed = CommitContent::parse(wire::MERGE_EVENT, &out.content, &group_id).unwrap();
        assert_eq!(parsed.event_type(), wire::MERGE_EVENT);
        assert_eq!(parsed.resolves.len(), 2);
        assert_eq!(parsed.commit_id(), out.commit_id);
        // The merged branch carries metadata the next plan can use.
        assert!(matches!(
            plan_merge(&a, &[out.commit_id], &registry).unwrap(),
            PlanOutcome::Planned(plan) if plan.members.len() == 2
        ));
    }

    #[test]
    fn merge_of_one_tip_applies_a_revocation_as_a_remove() {
        let (alice, _bob, mut a, _b, tip) = three_member_group();
        let mut registry =
            device_registry(&[(ALICE, 1, "ALICE1"), (BOB, 2, "BOB1"), (CAROL, 3, "CAROL1")]);
        registry.revoke(&public(&key(3)));
        let MergeOutcome::Merged(out) =
            merge(&mut a, &alice, std::slice::from_ref(&tip), &registry).unwrap()
        else {
            panic!("a revoked member must be removable");
        };
        assert!(!out.summary.members.contains(&carol_key()));
        let parsed = CommitContent::parse(wire::COMMIT_EVENT, &out.content, &a.group_id()).unwrap();
        assert_eq!(parsed.plan.removes, vec![carol_key()]);
    }

    #[test]
    fn merge_defers_or_rejects_without_mutating() {
        let (alice, _bob, mut a, _b, tip) = three_member_group();
        let before = a.export();
        let unknown = ExtremityRef::new(ExtremityId::new(3, [0xAA; 32]), "$x");
        assert!(matches!(
            merge(&mut a, &alice, &[unknown], &DeviceRootRegistry::default()).unwrap(),
            MergeOutcome::Deferred("missing_base_state")
        ));
        assert!(matches!(
            merge(
                &mut a,
                &alice,
                std::slice::from_ref(&tip),
                &DeviceRootRegistry::default()
            )
            .unwrap(),
            MergeOutcome::Rejected("uncertified_device")
        ));
        // Revoking the committer would make the plan remove the caller.
        let mut registry =
            device_registry(&[(ALICE, 1, "ALICE1"), (BOB, 2, "BOB1"), (CAROL, 3, "CAROL1")]);
        registry.revoke(&public(&key(1)));
        let outcome = merge(&mut a, &alice, &[tip], &registry).unwrap();
        assert!(matches!(outcome, MergeOutcome::Rejected(_)), "{outcome:?}");
        assert_eq!(a.export(), before);
    }

    #[test]
    fn a_peer_applies_a_merge_only_when_it_reproduces_the_plan() {
        let (alice, bob, mut a, mut b, tip) = three_member_group();
        let registry =
            device_registry(&[(ALICE, 1, "ALICE1"), (BOB, 2, "BOB1"), (CAROL, 3, "CAROL1")]);
        let s1 = commit(&mut b, &bob, &tip, &CommitOp::SelfUpdate).unwrap();
        let ctx = |sender: &Signer, events: &[&str]| ApplyCtx {
            sender: sender.member_key(),
            ancestors: events.iter().map(|e| (*e).to_owned()).collect(),
        };
        apply_commit(
            &mut a,
            wire::COMMIT_EVENT,
            &s1.content,
            &ctx(&bob, &["$second"]),
        )
        .unwrap();
        let s2 = commit(&mut a, &alice, &tip, &CommitOp::Remove(carol_key())).unwrap();
        let r1 = ExtremityRef::new(ExtremityId::new(3, s1.commit_id), "$s1");
        let r2 = ExtremityRef::new(ExtremityId::new(3, s2.commit_id), "$s2");
        let MergeOutcome::Merged(out) = merge(&mut a, &alice, &[r1, r2], &registry).unwrap() else {
            panic!("alice must merge");
        };
        let merge_ctx = ctx(&alice, &["$s1", "$s2", "$second"]);

        // Bob lacks Alice's sibling state: deferred, nothing changes.
        assert_eq!(
            apply_merge(
                &mut b,
                wire::MERGE_EVENT,
                &out.content,
                &merge_ctx,
                &registry
            )
            .unwrap(),
            ApplyOutcome::Deferred("missing_base_state")
        );
        apply_commit(
            &mut b,
            wire::COMMIT_EVENT,
            &s2.content,
            &ctx(&alice, &["$second"]),
        )
        .unwrap();

        // A registry that revokes Bob yields a different plan: rejected, no change.
        let mut other =
            device_registry(&[(ALICE, 1, "ALICE1"), (BOB, 2, "BOB1"), (CAROL, 3, "CAROL1")]);
        other.revoke(&public(&key(2)));
        let before = b.export();
        assert_eq!(
            apply_merge(&mut b, wire::MERGE_EVENT, &out.content, &merge_ctx, &other).unwrap(),
            ApplyOutcome::Rejected("mismatch:plan")
        );
        assert_eq!(b.export(), before);
        // The plain commit entry point refuses a merge event outright.
        assert!(apply_commit(&mut b, wire::MERGE_EVENT, &out.content, &merge_ctx).is_err());

        let ApplyOutcome::Applied(summary) = apply_merge(
            &mut b,
            wire::MERGE_EVENT,
            &out.content,
            &merge_ctx,
            &registry,
        )
        .unwrap() else {
            panic!("bob must apply the merge");
        };
        assert_eq!(summary, out.summary);
        assert_eq!(b.extremity_count(), 1);
        assert!(matches!(
            plan_merge(&b, &[out.commit_id], &registry).unwrap(),
            PlanOutcome::Planned(plan) if plan.members.len() == 2
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn reboot_starts_a_replacement_group_and_receivers_check_it() {
        let (alice, bob, a, b, tip) = three_member_group();
        let old_id = a.group_id();
        let base = ExtremityRef::new(tip.id, "$second");
        let carol = signer(CAROL, "CAROL1", 3);
        let (bob_kp, bob_secrets) = package_bytes(&bob);
        let (carol_kp, carol_secrets) = package_bytes(&carol);
        let ctx = |sender: &MemberKey| ApplyCtx {
            sender: sender.clone(),
            ancestors: BTreeSet::from(["$second".to_owned()]),
        };

        let out = reboot(
            &a,
            &alice,
            "state-loss",
            &base,
            &[bob_kp.clone(), carol_kp.clone()],
        )
        .unwrap();
        assert_eq!(
            out.new_group_id,
            wire::reboot_group_id(&old_id, &tip.id.commit_id)
        );
        assert_eq!(out.entry.group_id(), out.new_group_id);
        assert_eq!(out.commit.summary.mls_epoch, 1);
        assert_eq!(out.commit.summary.members.len(), 3);
        assert_eq!(out.recipients.len(), 2);
        assert_eq!(a.group_id(), old_id);
        assert_eq!(a.branch(&tip.id.commit_id).unwrap().epoch(), 2);

        let welcome = out.commit.welcome.as_ref().unwrap();
        for (who, secrets) in [(&bob, &bob_secrets), (&carol, &carol_secrets)] {
            let (_, summary) = join_welcome(
                who,
                secrets,
                welcome,
                &out.new_group_id,
                out.commit.commit_id,
            )
            .unwrap();
            assert_eq!(summary.mls_epoch, 1);
            assert_eq!(summary.members.len(), 3);
        }

        let accepted = check_reboot(&b, &out.reboot, &ctx(&alice.member_key()));
        assert!(
            matches!(&accepted, RebootCheck::Accepted(c) if c.new_group_id() == out.new_group_id)
        );
        let no_ancestors = ApplyCtx {
            sender: alice.member_key(),
            ancestors: BTreeSet::new(),
        };
        assert_eq!(
            check_reboot(&b, &out.reboot, &no_ancestors),
            RebootCheck::Deferred("unheld_ancestor")
        );
        let stranger = MemberKey {
            principal: "@ggggggggggggggggggggggggggggggggggggggggggg".to_owned(),
            device_id: "DAVE1".to_owned(),
        };
        assert_eq!(
            check_reboot(&b, &out.reboot, &ctx(&stranger)),
            RebootCheck::Rejected("mismatch:sender")
        );

        let dave = signer(&stranger.principal, "DAVE1", 4);
        let (dave_kp, _) = package_bytes(&dave);
        let (alice_kp, _) = package_bytes(&alice);
        for bad in [
            vec![],
            vec![dave_kp],
            vec![alice_kp],
            vec![bob_kp.clone(), bob_kp],
        ] {
            assert!(matches!(
                reboot(&a, &alice, "state-loss", &base, &bad),
                Err(EngineError::BadArgument("members"))
            ));
        }
        assert!(reboot(&a, &alice, "", &base, std::slice::from_ref(&carol_kp)).is_err());
        let unheld = ExtremityRef::new(ExtremityId::new(2, [9; 32]), "$second");
        assert!(matches!(
            reboot(
                &a,
                &alice,
                "state-loss",
                &unheld,
                std::slice::from_ref(&carol_kp)
            ),
            Err(EngineError::BadArgument("base"))
        ));
        assert!(matches!(
            reboot(&a, &dave, "state-loss", &base, &[carol_kp]),
            Err(EngineError::BadArgument("not_a_member"))
        ));
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_peer_applies_an_external_commit_and_refuses_bad_ones() {
        let (alice, bob, mut a, mut b, tip) = three_member_group();
        let group_id = a.group_id();
        let s = commit(&mut a, &alice, &tip, &CommitOp::SelfUpdate).unwrap();
        let ctx = |sender: &MemberKey, events: &[&str]| ApplyCtx {
            sender: sender.clone(),
            ancestors: events.iter().map(|e| (*e).to_owned()).collect(),
        };
        assert!(matches!(
            apply_commit(
                &mut b,
                wire::COMMIT_EVENT,
                &s.content,
                &ctx(&alice.member_key(), &["$second"])
            )
            .unwrap(),
            ApplyOutcome::Applied(_)
        ));
        let info = CommitContent::parse(wire::COMMIT_EVENT, &s.content, &group_id)
            .unwrap()
            .group_info;
        let target = ExtremityRef::new(ExtremityId::new(3, s.commit_id), "$s");
        let dave_key = MemberKey {
            principal: "@ggggggggggggggggggggggggggggggggggggggggggg".to_owned(),
            device_id: "DAVE1".to_owned(),
        };
        let dave = signer(&dave_key.principal, "DAVE1", 4);
        let (_, out) = external_commit(&dave, &group_id, &target, &info).unwrap();

        let before = b.export();
        let other = alice.member_key();
        assert!(matches!(
            apply_external_commit(&mut b, &out.content, &ctx(&other, &["$s"])).unwrap(),
            ApplyOutcome::Rejected("mismatch")
        ));
        assert!(matches!(
            apply_external_commit(&mut b, &out.content, &ctx(&dave_key, &["$second"])).unwrap(),
            ApplyOutcome::Deferred("unheld_ancestor")
        ));
        assert_eq!(b.export(), before);

        // A GroupInfo for the same epoch but a different tree, signed by a
        // different member, is not the join's resulting state.
        let other_info = CommitContent::parse(wire::COMMIT_EVENT, &s.content, &group_id)
            .unwrap()
            .group_info;
        let mut wrong_info = out.content.clone();
        wrong_info.as_object_mut().unwrap().insert(
            "group_info".to_owned(),
            Value::from(crate::content::b64_encode(&other_info)),
        );
        assert!(matches!(
            apply_external_commit(&mut b, &wrong_info, &ctx(&dave_key, &["$s"])).unwrap(),
            ApplyOutcome::Rejected("mismatch:group_info")
        ));
        assert_eq!(b.export(), before);

        let applied = apply_external_commit(&mut b, &out.content, &ctx(&dave_key, &["$s"]));
        assert!(matches!(
            applied.unwrap(),
            ApplyOutcome::Applied(summary) if summary == out.summary
        ));
        let meta = BranchMeta::decode(b.branch(&out.commit_id).unwrap().meta()).unwrap();
        let dave_id = crate::branch_meta::member_id_from_key(&dave_key);
        assert!(meta.external_joiners.contains(&dave_id));
        assert_eq!(meta.members.len(), 4);
        assert!(matches!(
            apply_external_commit(&mut b, &out.content, &ctx(&dave_key, &["$s"])).unwrap(),
            ApplyOutcome::Applied(_)
        ));

        // A same-identity join makes OpenMLS Remove the old leaf; refused.
        let bob_key = bob.member_key();
        let bob_again = signer(BOB, "BOB1", 22);
        assert!(matches!(
            external_commit(&bob_again, &group_id, &target, &info),
            Err(EngineError::BadArgument("already_member"))
        ));
        // Build the same join past the sender-side check: the receiver refuses.
        let MlsMessageBodyIn::GroupInfo(verifiable) = MlsMessageIn::tls_deserialize_exact(&info)
            .unwrap()
            .extract()
        else {
            panic!("not a group info");
        };
        let provider = OpenMlsRustCrypto::default();
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let (joined, bundle) = MlsGroup::external_commit_builder()
            .with_config(config)
            .build_group(&provider, verifiable, bob_again.credential.clone())
            .unwrap()
            .load_psks(provider.storage())
            .unwrap()
            .build(provider.rand(), provider.crypto(), &bob_again.pair, |_| {
                true
            })
            .unwrap()
            .finalize(&provider)
            .unwrap();
        let forged = ExternalCommitContent {
            group_id,
            target: target.clone(),
            commit: bundle.commit().to_bytes().unwrap(),
            group_info: joined
                .export_group_info(provider.crypto(), &bob_again.pair, true)
                .unwrap()
                .to_bytes()
                .unwrap(),
            joiner: bob_key.clone(),
        }
        .to_value()
        .unwrap();
        let before = a.export();
        assert!(matches!(
            apply_external_commit(&mut a, &forged, &ctx(&bob_key, &["$s"])).unwrap(),
            ApplyOutcome::Rejected("joiner_has_leaf")
        ));
        assert_eq!(a.export(), before);
    }

    #[test]
    fn external_commit_joins_from_a_group_info_and_refuses_bad_targets() {
        let (alice, _bob, mut a, _b, tip) = three_member_group();
        let group_id = a.group_id();
        let s = commit(&mut a, &alice, &tip, &CommitOp::SelfUpdate).unwrap();
        let info = CommitContent::parse(wire::COMMIT_EVENT, &s.content, &group_id)
            .unwrap()
            .group_info;
        let target = ExtremityRef::new(ExtremityId::new(3, s.commit_id), "$s");
        let dave_key = MemberKey {
            principal: "@ggggggggggggggggggggggggggggggggggggggggggg".to_owned(),
            device_id: "DAVE1".to_owned(),
        };
        let dave = signer(&dave_key.principal, "DAVE1", 4);

        let (mut branch, out) = external_commit(&dave, &group_id, &target, &info).unwrap();
        assert_eq!(out.summary.mls_epoch, 4);
        assert_eq!(out.summary.members.len(), 4);
        assert!(out.summary.members.contains(&dave_key));
        let parsed = ExternalCommitContent::parse(&out.content, &dave_key, &group_id).unwrap();
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.commit_id(), out.commit_id);

        // The joiner is recorded as an external joiner and can encrypt at once.
        let meta = BranchMeta::decode(branch.meta()).unwrap();
        assert!(meta
            .external_joiners
            .contains(&crate::branch_meta::member_id_from_key(&dave_key)));
        let (group, provider) = branch.parts_mut();
        assert!(encrypt(&dave, group, provider, &group_id, b"hi").is_ok());

        // A wrong epoch and a wrong group are refused.
        let stale = ExtremityRef::new(ExtremityId::new(2, s.commit_id), "$s");
        assert!(external_commit(&dave, &group_id, &stale, &info).is_err());
        assert!(external_commit(&dave, &[9; 32], &target, &info).is_err());
    }
}
