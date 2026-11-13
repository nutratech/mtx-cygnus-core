//! Per-extremity group state, its persisted blob, and the held-extremity cap.
//!
//! MSC00FD §9.1 needs one MLS state per extremity. A [`GroupEntry`] holds one
//! [`HeldBranch`] (an `MlsGroup` plus its own `OpenMlsRustCrypto`) per held
//! tip. Every mutation runs on a *copy* of the branch and is installed only on
//! success, so a failed apply leaves the entry, and therefore its export,
//! byte-identical.
//!
//! The blob is our own versioned encoding of each provider's storage map. The
//! device signing seed is never written into that map: callers pass a
//! `SignatureKeyPair` per call and never `store` it.

use std::collections::{BTreeMap, BTreeSet};

use openmls::prelude::{GroupId, MlsGroup, OpenMlsProvider};
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::merge::ExtremityId;

/// Most extremities held per group. The cap applies to the *post-update* set.
pub const MAX_HELD_EXTREMITIES: usize = 8;

/// Most held states (tips plus retained ancestors) per group. Non-tip states
/// are kept so a late sibling commit can still apply. This is a bounded cache,
/// not a guarantee for arbitrarily late backfill: the oldest epoch (commit id
/// breaks ties) is evicted first, never a tip, and a commit whose base was
/// evicted defers as `missing_base_state`.
pub const MAX_RETAINED_STATES: usize = 16;

/// Blob magic.
const MAGIC: &[u8; 4] = b"CYDM";
/// Current blob version.
///
/// Nothing has been released, so the format evolves in place while it stays at
/// version 1. There is no compatibility contract for older encodings.
pub const BLOB_VERSION: u16 = 1;
/// Upper bound on one storage entry, to bound allocation from a hostile blob.
const MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;

/// Errors from the registry layer. [`RegistryError::code`] is the stable code
/// surfaced to JavaScript.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RegistryError {
    /// The blob is truncated, corrupt, or fails its integrity hash.
    #[error("bad_state: {0}")]
    BadState(&'static str),
    /// The blob version is not understood.
    #[error("unsupported_version: {0}")]
    UnsupportedVersion(u16),
    /// The group is not loaded.
    #[error("unknown_group")]
    UnknownGroup,
    /// The requested base branch is not held.
    #[error("missing_base_state")]
    MissingBase,
    /// A branch named in `resolves` is not held.
    #[error("missing_branch")]
    MissingBranch,
    /// The result would exceed [`MAX_HELD_EXTREMITIES`].
    #[error("extremity_cap: {0} extremities")]
    ExtremityCap(usize),
    /// Several tips are held and the caller named none.
    #[error("fork_unresolved")]
    ForkUnresolved,
    /// The incoming blob is older than the loaded entry.
    #[error("stale_state: loaded seq {loaded}, incoming seq {incoming}")]
    StaleState {
        /// Sequence number of the entry already in memory.
        loaded: u64,
        /// Sequence number of the blob being imported.
        incoming: u64,
    },
    /// `base` is not among `resolves`.
    #[error("mismatch:resolves")]
    BaseNotResolved,
    /// A branch's MLS group id is not the entry's group id.
    #[error("mismatch:group_id")]
    WrongGroup,
    /// The new commit is already held (idempotent re-apply).
    #[error("already_held")]
    AlreadyHeld,
    /// `OpenMLS` failed.
    #[error("crypto: {0}")]
    Mls(String),
    /// The caller supplied an unusable argument.
    #[error("bad_argument: {0}")]
    BadArgument(&'static str),
    /// The operation is permanently invalid; the payload is the stable code.
    #[error("{0}")]
    Rejected(&'static str),
}

impl RegistryError {
    /// The stable error code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadState(_) => "bad_state",
            Self::UnsupportedVersion(_) => "unsupported_version",
            Self::UnknownGroup => "unknown_group",
            Self::MissingBase => "missing_base_state",
            Self::MissingBranch => "missing_branch",
            Self::ExtremityCap(_) => "extremity_cap",
            Self::ForkUnresolved => "fork_unresolved",
            Self::StaleState { .. } => "stale_state",
            Self::BaseNotResolved => "mismatch:resolves",
            Self::WrongGroup => "mismatch:group_id",
            Self::AlreadyHeld => "already_held",
            Self::Mls(_) => "crypto",
            Self::BadArgument(_) => "bad_argument",
            Self::Rejected(code) => code,
        }
    }
}

type Snapshot = Vec<(Vec<u8>, Vec<u8>)>;

/// One held extremity: an MLS group and the provider that owns its storage.
pub struct HeldBranch {
    provider: OpenMlsRustCrypto,
    group: MlsGroup,
    resolves: BTreeSet<ExtremityId>,
    meta: Vec<u8>,
}

impl std::fmt::Debug for HeldBranch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HeldBranch")
            .field("epoch", &self.group.epoch().as_u64())
            .finish_non_exhaustive()
    }
}

fn snapshot(provider: &OpenMlsRustCrypto) -> Snapshot {
    let map = provider.storage().values.read().expect("storage lock");
    let mut entries: Snapshot = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    entries.sort();
    entries
}

fn restore(
    entries: Snapshot,
    group_id: &[u8; 32],
) -> Result<(OpenMlsRustCrypto, MlsGroup), RegistryError> {
    let provider = OpenMlsRustCrypto::default();
    provider
        .storage()
        .values
        .write()
        .expect("storage lock")
        .extend(entries);
    let group = MlsGroup::load(provider.storage(), &GroupId::from_slice(group_id))
        .map_err(|e| RegistryError::Mls(format!("{e:?}")))?
        .ok_or(RegistryError::BadState("group missing from storage"))?;
    Ok((provider, group))
}

impl HeldBranch {
    /// Wrap a freshly created or joined group.
    #[must_use]
    pub fn new(provider: OpenMlsRustCrypto, group: MlsGroup) -> Self {
        Self {
            provider,
            group,
            resolves: BTreeSet::new(),
            meta: Vec::new(),
        }
    }

    /// The branch's MLS epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// The group.
    #[must_use]
    pub fn group(&self) -> &MlsGroup {
        &self.group
    }

    /// Opaque per-branch metadata the apply layer persists beside the group:
    /// the parts of a merge `Branch` that cannot be derived from an `MlsGroup`
    /// (`parent_transcript_hash`, retained `removed` leaves, `external_joiners`).
    #[must_use]
    pub fn meta(&self) -> &[u8] {
        &self.meta
    }

    /// Set the metadata (see [`Self::meta`]).
    pub fn set_meta(&mut self, meta: Vec<u8>) {
        self.meta = meta;
    }

    /// The extremities this branch consumed.
    #[must_use]
    pub fn resolves(&self) -> &BTreeSet<ExtremityId> {
        &self.resolves
    }

    /// An independent copy, via a storage snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`RegistryError`] if the snapshot cannot be reloaded.
    pub fn fork(&self) -> Result<Self, RegistryError> {
        let id = group_id_of(&self.group)?;
        let (provider, group) = restore(snapshot(&self.provider), &id)?;
        Ok(Self {
            provider,
            group,
            resolves: self.resolves.clone(),
            meta: self.meta.clone(),
        })
    }

    /// Mutable access to the group and its provider, for the caller's closure.
    pub fn parts_mut(&mut self) -> (&mut MlsGroup, &OpenMlsRustCrypto) {
        (&mut self.group, &self.provider)
    }
}

fn group_id_of(group: &MlsGroup) -> Result<[u8; 32], RegistryError> {
    group
        .group_id()
        .as_slice()
        .try_into()
        .map_err(|_| RegistryError::BadState("group id is not 32 bytes"))
}

/// All held extremities for one group.
#[derive(Debug)]
pub struct GroupEntry {
    group_id: [u8; 32],
    seq: u64,
    tips: BTreeSet<[u8; 32]>,
    branches: BTreeMap<[u8; 32], HeldBranch>,
}

impl GroupEntry {
    /// An empty entry at `seq` 0.
    #[must_use]
    pub fn new(group_id: [u8; 32]) -> Self {
        Self {
            group_id,
            seq: 0,
            tips: BTreeSet::new(),
            branches: BTreeMap::new(),
        }
    }

    /// The group id.
    #[must_use]
    pub fn group_id(&self) -> [u8; 32] {
        self.group_id
    }

    /// Monotonic mutation counter. Every mutating call increments it, including
    /// decrypt; an export of unchanged state carries the same value.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Current extremity (tip) commit ids.
    #[must_use]
    pub fn extremities(&self) -> Vec<[u8; 32]> {
        self.tips.iter().copied().collect()
    }

    /// Number of extremities (tips).
    #[must_use]
    pub fn extremity_count(&self) -> usize {
        self.tips.len()
    }

    /// Number of held states, tips and retained ancestors.
    #[must_use]
    pub fn state_count(&self) -> usize {
        self.branches.len()
    }

    fn next_seq(&self) -> Result<u64, RegistryError> {
        self.seq
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(RegistryError::BadState("seq exhausted"))
    }

    fn install(&mut self, commit_id: [u8; 32], branch: HeldBranch, tip: bool) {
        self.branches.insert(commit_id, branch);
        if tip {
            self.tips.insert(commit_id);
        }
        while self.branches.len() > MAX_RETAINED_STATES {
            let oldest = self
                .branches
                .iter()
                .filter(|(id, _)| !self.tips.contains(*id))
                .min_by_key(|(id, b)| (b.epoch(), **id))
                .map(|(id, _)| *id);
            match oldest {
                Some(id) => {
                    self.branches.remove(&id);
                }
                None => break,
            }
        }
    }

    /// A held branch.
    #[must_use]
    pub fn branch(&self, commit_id: &[u8; 32]) -> Option<&HeldBranch> {
        self.branches.get(commit_id)
    }

    /// A held branch, for engine metadata updates after a successful mutation.
    pub(crate) fn branch_mut(&mut self, commit_id: &[u8; 32]) -> Option<&mut HeldBranch> {
        self.branches.get_mut(commit_id)
    }

    /// Every held state, tips and retained ancestors.
    pub(crate) fn branches(&self) -> impl Iterator<Item = (&[u8; 32], &HeldBranch)> {
        self.branches.iter()
    }

    /// Choose a branch: the named one, or the sole tip.
    ///
    /// # Errors
    ///
    /// [`RegistryError::MissingBase`] if the named branch is not held,
    /// [`RegistryError::ForkUnresolved`] if several tips are held and none is
    /// named, [`RegistryError::UnknownGroup`] if there are none.
    pub fn resolve_tip(&self, at: Option<&[u8; 32]>) -> Result<[u8; 32], RegistryError> {
        if let Some(id) = at {
            return if self.branches.contains_key(id) {
                Ok(*id)
            } else {
                Err(RegistryError::MissingBase)
            };
        }
        let mut keys = self.tips.iter();
        match (keys.next(), keys.next()) {
            (Some(id), None) => Ok(*id),
            (None, _) => Err(RegistryError::UnknownGroup),
            _ => Err(RegistryError::ForkUnresolved),
        }
    }

    /// Install a branch with no held parent (create, join, external commit).
    ///
    /// # Errors
    ///
    /// [`RegistryError::WrongGroup`] if the branch was built for another group,
    /// [`RegistryError::AlreadyHeld`] if the commit id is already held, or
    /// [`RegistryError::ExtremityCap`] if the cap would be exceeded.
    pub fn insert_root(
        &mut self,
        commit_id: [u8; 32],
        branch: HeldBranch,
    ) -> Result<(), RegistryError> {
        if group_id_of(&branch.group)? != self.group_id {
            return Err(RegistryError::WrongGroup);
        }
        if self.branches.contains_key(&commit_id) {
            return Err(RegistryError::AlreadyHeld);
        }
        if self.tips.len() + 1 > MAX_HELD_EXTREMITIES {
            return Err(RegistryError::ExtremityCap(self.tips.len() + 1));
        }
        let next_seq = self.next_seq()?;
        self.install(commit_id, branch, true);
        self.seq = next_seq;
        Ok(())
    }

    /// Apply `f` to a copy of `base` and, only on success, install the result
    /// as `new_commit_id`, dropping every branch in `resolves`.
    ///
    /// The cap is checked on the post-update set
    /// `(held − resolves) ∪ {new}`, so a merge that reduces the count is never
    /// blocked by the count it is reducing. `base` survives unless it is in
    /// `resolves`. On any error the entry is untouched.
    ///
    /// # Errors
    ///
    /// [`RegistryError::AlreadyHeld`], [`RegistryError::MissingBase`],
    /// [`RegistryError::MissingBranch`], [`RegistryError::ExtremityCap`], or
    /// whatever `f` returns.
    pub fn apply<T>(
        &mut self,
        base: &[u8; 32],
        new_commit_id: [u8; 32],
        resolves: &BTreeSet<[u8; 32]>,
        f: impl FnOnce(&mut MlsGroup, &OpenMlsRustCrypto) -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        self.apply_with(base, Some(new_commit_id), resolves, |g, p| {
            Ok((new_commit_id, f(g, p)?))
        })
    }

    /// Like [`Self::apply`] for a Commit this device produces: the new commit
    /// id is only known once `f` has built the Commit, so `f` returns it.
    ///
    /// # Errors
    ///
    /// As [`Self::apply`].
    pub fn apply_with<T>(
        &mut self,
        base: &[u8; 32],
        known_new: Option<[u8; 32]>,
        resolves: &BTreeSet<[u8; 32]>,
        f: impl FnOnce(&mut MlsGroup, &OpenMlsRustCrypto) -> Result<([u8; 32], T), RegistryError>,
    ) -> Result<T, RegistryError> {
        if known_new.is_some_and(|id| self.branches.contains_key(&id)) {
            return Err(RegistryError::AlreadyHeld);
        }
        let next_seq = self.next_seq()?;
        if !resolves.contains(base) {
            return Err(RegistryError::BaseNotResolved);
        }
        let base_branch = self.branches.get(base).ok_or(RegistryError::MissingBase)?;
        let mut consumed = BTreeSet::new();
        for id in resolves {
            let held = self.branches.get(id).ok_or(RegistryError::MissingBranch)?;
            consumed.insert(ExtremityId::new(held.epoch(), *id));
        }
        let next = self.tips.difference(resolves).count() + 1;
        if next > MAX_HELD_EXTREMITIES {
            return Err(RegistryError::ExtremityCap(next));
        }

        let mut copy = base_branch.fork()?;
        let (group, provider) = copy.parts_mut();
        let (new_commit_id, out) = f(group, provider)?;
        if self.branches.contains_key(&new_commit_id) {
            return Err(RegistryError::AlreadyHeld);
        }
        copy.resolves = consumed;

        for id in resolves {
            self.tips.remove(id);
        }
        self.install(new_commit_id, copy, true);
        self.seq = next_seq;
        Ok(out)
    }

    /// Mutate one branch in place (encrypt/decrypt ratchet), on a copy that
    /// replaces the original only on success.
    ///
    /// # Errors
    ///
    /// [`RegistryError::MissingBase`] if the branch is not held, or whatever
    /// `f` returns.
    pub fn update<T>(
        &mut self,
        commit_id: &[u8; 32],
        f: impl FnOnce(&mut MlsGroup, &OpenMlsRustCrypto) -> Result<T, RegistryError>,
    ) -> Result<T, RegistryError> {
        let next_seq = self.next_seq()?;
        let mut copy = self
            .branches
            .get(commit_id)
            .ok_or(RegistryError::MissingBase)?
            .fork()?;
        let (group, provider) = copy.parts_mut();
        let out = f(group, provider)?;
        self.branches.insert(*commit_id, copy);
        self.seq = next_seq;
        Ok(out)
    }

    /// Serialize to the versioned blob (not yet base64).
    #[must_use]
    pub fn export(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&BLOB_VERSION.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.group_id);
        put_len(&mut out, self.branches.len());
        for (commit_id, branch) in &self.branches {
            out.extend_from_slice(commit_id);
            put_bytes(&mut out, &branch.meta);
            out.push(u8::from(self.tips.contains(commit_id)));
            put_len(&mut out, branch.resolves.len());
            for r in &branch.resolves {
                out.extend_from_slice(&r.mls_epoch.to_be_bytes());
                out.extend_from_slice(&r.commit_id);
            }
            let entries = snapshot(&branch.provider);
            put_len(&mut out, entries.len());
            for (k, v) in entries {
                put_bytes(&mut out, &k);
                put_bytes(&mut out, &v);
            }
        }
        let digest = blake3::hash(&out);
        out.extend_from_slice(digest.as_bytes());
        out
    }

    /// Parse a blob into a new entry. Nothing is installed anywhere; the
    /// caller swaps the result in.
    ///
    /// # Errors
    ///
    /// [`RegistryError::BadState`] for truncation, a hash mismatch, or any
    /// structural problem; [`RegistryError::UnsupportedVersion`].
    pub fn import(blob: &[u8]) -> Result<Self, RegistryError> {
        if blob.len() < MAGIC.len() + 2 + 8 + 32 + 4 + 32 || blob.len() > MAX_BLOB_BYTES {
            return Err(RegistryError::BadState("bad length"));
        }
        let (body, hash) = blob.split_at(blob.len() - 32);
        if blake3::hash(body).as_bytes() != hash {
            return Err(RegistryError::BadState("integrity hash mismatch"));
        }
        let mut r = Reader { buf: body };
        if r.take(4)? != MAGIC {
            return Err(RegistryError::BadState("bad magic"));
        }
        let version = u16::from_be_bytes(r.array()?);
        if version != BLOB_VERSION {
            return Err(RegistryError::UnsupportedVersion(version));
        }
        let seq = u64::from_be_bytes(r.array()?);
        let group_id: [u8; 32] = r.array()?;

        let count = r.len(32 + 1 + 4 + 4 + 4)?;
        if count > MAX_RETAINED_STATES {
            return Err(RegistryError::BadState("too many branches"));
        }
        let mut branches = BTreeMap::new();
        let mut tips = BTreeSet::new();
        for _ in 0..count {
            let commit_id: [u8; 32] = r.array()?;
            let meta = r.bytes()?.to_vec();
            match r.array::<1>()?[0] {
                0 => {}
                1 => {
                    tips.insert(commit_id);
                }
                _ => return Err(RegistryError::BadState("bad tip flag")),
            }
            let n_resolves = r.len(8 + 32)?;
            let mut resolves = BTreeSet::new();
            for _ in 0..n_resolves {
                let epoch = u64::from_be_bytes(r.array()?);
                resolves.insert(ExtremityId::new(epoch, r.array()?));
            }
            let n_entries = r.len(8)?;
            let mut entries = Vec::new();
            for _ in 0..n_entries {
                let k = r.bytes()?.to_vec();
                let v = r.bytes()?.to_vec();
                entries.push((k, v));
            }
            let (provider, group) = restore(entries, &group_id)?;
            if branches.contains_key(&commit_id) {
                return Err(RegistryError::BadState("duplicate branch"));
            }
            branches.insert(
                commit_id,
                HeldBranch {
                    provider,
                    group,
                    resolves,
                    meta,
                },
            );
        }
        if !r.buf.is_empty() {
            return Err(RegistryError::BadState("trailing bytes"));
        }
        if seq == u64::MAX {
            return Err(RegistryError::BadState("seq exhausted"));
        }
        if tips.len() > MAX_HELD_EXTREMITIES {
            return Err(RegistryError::BadState("too many tips"));
        }
        Ok(Self {
            group_id,
            seq,
            tips,
            branches,
        })
    }
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    out.extend_from_slice(&u32::try_from(n).expect("length fits u32").to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_len(out, b.len());
    out.extend_from_slice(b);
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], RegistryError> {
        if self.buf.len() < n {
            return Err(RegistryError::BadState("truncated"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], RegistryError> {
        Ok(self.take(N)?.try_into().expect("length checked"))
    }

    /// Read a count of items that each occupy at least `min_item` bytes.
    fn len(&mut self, min_item: usize) -> Result<usize, RegistryError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        // A count beyond what the remaining input could hold is corrupt; this
        // bounds both the loop and the allocation.
        if n.saturating_mul(min_item) > self.buf.len() {
            return Err(RegistryError::BadState("count exceeds input"));
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Result<&'a [u8], RegistryError> {
        let n = u32::from_be_bytes(self.array()?) as usize;
        self.take(n)
    }
}

/// Magic for a key-package secrets blob.
const SECRETS_MAGIC: &[u8; 4] = b"CYKS";

/// Serialize a provider's storage (key-package private material) into the
/// versioned secrets blob Hydrogen persists per `key_package_id`.
#[must_use]
pub fn encode_secrets(provider: &OpenMlsRustCrypto) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SECRETS_MAGIC);
    out.extend_from_slice(&BLOB_VERSION.to_be_bytes());
    let entries = snapshot(provider);
    put_len(&mut out, entries.len());
    for (k, v) in entries {
        put_bytes(&mut out, &k);
        put_bytes(&mut out, &v);
    }
    let digest = blake3::hash(&out);
    out.extend_from_slice(digest.as_bytes());
    out
}

/// Rebuild a provider from [`encode_secrets`] output.
///
/// # Errors
///
/// [`RegistryError::BadState`] or [`RegistryError::UnsupportedVersion`].
pub fn decode_secrets(blob: &[u8]) -> Result<OpenMlsRustCrypto, RegistryError> {
    if blob.len() < 4 + 2 + 4 + 32 || blob.len() > MAX_BLOB_BYTES {
        return Err(RegistryError::BadState("bad length"));
    }
    let (body, hash) = blob.split_at(blob.len() - 32);
    if blake3::hash(body).as_bytes() != hash {
        return Err(RegistryError::BadState("integrity hash mismatch"));
    }
    let mut r = Reader { buf: body };
    if r.take(4)? != SECRETS_MAGIC {
        return Err(RegistryError::BadState("bad magic"));
    }
    let version = u16::from_be_bytes(r.array()?);
    if version != BLOB_VERSION {
        return Err(RegistryError::UnsupportedVersion(version));
    }
    let n = r.len(8)?;
    let mut entries = Vec::new();
    for _ in 0..n {
        let k = r.bytes()?.to_vec();
        let v = r.bytes()?.to_vec();
        entries.push((k, v));
    }
    if !r.buf.is_empty() {
        return Err(RegistryError::BadState("trailing bytes"));
    }
    let provider = OpenMlsRustCrypto::default();
    provider
        .storage()
        .values
        .write()
        .expect("storage lock")
        .extend(entries);
    Ok(provider)
}

/// What [`Registry::import`] reports about the entry it installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportInfo {
    /// The group id.
    pub group_id: [u8; 32],
    /// The blob's sequence number.
    pub seq: u64,
    /// Held extremity commit ids.
    pub extremities: Vec<[u8; 32]>,
}

/// The set of loaded groups.
#[derive(Debug, Default)]
pub struct Registry {
    groups: BTreeMap<[u8; 32], GroupEntry>,
}

impl Registry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a group is loaded.
    #[must_use]
    pub fn has(&self, group_id: &[u8; 32]) -> bool {
        self.groups.contains_key(group_id)
    }

    /// A loaded group.
    #[must_use]
    pub fn get(&self, group_id: &[u8; 32]) -> Option<&GroupEntry> {
        self.groups.get(group_id)
    }

    /// A loaded group, mutably.
    pub fn get_mut(&mut self, group_id: &[u8; 32]) -> Option<&mut GroupEntry> {
        self.groups.get_mut(group_id)
    }

    /// Install a newly created entry.
    pub fn insert(&mut self, entry: GroupEntry) {
        self.groups.insert(entry.group_id, entry);
    }

    /// Drop an entry from memory only.
    pub fn forget(&mut self, group_id: &[u8; 32]) {
        self.groups.remove(group_id);
    }

    /// Export a loaded group.
    ///
    /// # Errors
    ///
    /// [`RegistryError::UnknownGroup`].
    pub fn export(&self, group_id: &[u8; 32]) -> Result<Vec<u8>, RegistryError> {
        Ok(self
            .groups
            .get(group_id)
            .ok_or(RegistryError::UnknownGroup)?
            .export())
    }

    /// Import a blob, replacing a loaded entry atomically. An incoming `seq`
    /// lower than the loaded one is refused so a lock bug surfaces as an error
    /// instead of a ratchet fork.
    ///
    /// # Errors
    ///
    /// See [`GroupEntry::import`]; [`RegistryError::StaleState`].
    pub fn import(&mut self, blob: &[u8]) -> Result<ImportInfo, RegistryError> {
        let entry = GroupEntry::import(blob)?;
        if let Some(loaded) = self.groups.get(&entry.group_id) {
            // An equal seq is idempotent only if the content is identical; a
            // different blob at the same seq is two writers diverging.
            if entry.seq < loaded.seq || (entry.seq == loaded.seq && loaded.export() != blob) {
                return Err(RegistryError::StaleState {
                    loaded: loaded.seq,
                    incoming: entry.seq,
                });
            }
        }
        let info = ImportInfo {
            group_id: entry.group_id,
            seq: entry.seq,
            extremities: entry.extremities(),
        };
        self.groups.insert(entry.group_id, entry);
        Ok(info)
    }
}

#[cfg(test)]
mod tests {
    use openmls::prelude::{
        tls_codec::{Deserialize, Serialize},
        *,
    };
    use openmls_basic_credential::SignatureKeyPair;

    use super::*;
    use crate::CIPHERSUITE;

    const GID: [u8; 32] = [7; 32];

    fn signer(seed: [u8; 32]) -> (SignatureKeyPair, CredentialWithKey) {
        let pk = <[u8; 32]>::from(ed25519_zebra::SigningKey::from(seed).verification_key());
        let pair = SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), pk.to_vec());
        let cred = CredentialWithKey {
            credential: BasicCredential::new(format!("m{}", seed[0]).into_bytes()).into(),
            signature_key: pk.to_vec().into(),
        };
        (pair, cred)
    }

    fn new_group(seed: u8) -> (HeldBranch, SignatureKeyPair) {
        let (pair, cred) = signer([seed; 32]);
        let provider = OpenMlsRustCrypto::default();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let group =
            MlsGroup::new_with_group_id(&provider, &pair, &config, GroupId::from_slice(&GID), cred)
                .unwrap();
        (HeldBranch::new(provider, group), pair)
    }

    fn mls<E: std::fmt::Debug>(e: E) -> RegistryError {
        RegistryError::Mls(format!("{e:?}"))
    }

    /// Alice holds a group with Bob; returns Alice's branch, Bob's branch, and
    /// both signers.
    fn alice_and_bob() -> (HeldBranch, HeldBranch, SignatureKeyPair, SignatureKeyPair) {
        let (mut alice, a_sig) = new_group(1);
        let (b_sig, b_cred) = signer([2; 32]);
        let b_provider = OpenMlsRustCrypto::default();
        let kp = KeyPackage::builder()
            .build(CIPHERSUITE, &b_provider, &b_sig, b_cred)
            .unwrap();
        let kp_bytes = kp.key_package().tls_serialize_detached().unwrap();
        let kp_in = KeyPackageIn::tls_deserialize(&mut kp_bytes.as_slice())
            .unwrap()
            .validate(b_provider.crypto(), ProtocolVersion::Mls10)
            .unwrap();
        let (a_group, a_prov) = alice.parts_mut();
        let (_c, welcome, _gi) = a_group.add_members(a_prov, &a_sig, &[kp_in]).unwrap();
        a_group.merge_pending_commit(a_prov).unwrap();
        let MlsMessageBodyIn::Welcome(w) =
            MlsMessageIn::tls_deserialize_exact(welcome.to_bytes().unwrap())
                .unwrap()
                .extract()
        else {
            panic!("not a welcome")
        };
        let cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let bob_group = StagedWelcome::new_from_welcome(&b_provider, &cfg, w, None)
            .unwrap()
            .into_group(&b_provider)
            .unwrap();
        (alice, HeldBranch::new(b_provider, bob_group), a_sig, b_sig)
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn insert_root_refuses_a_branch_for_another_group() {
        let (branch, _) = new_group(0x11);
        let mut entry = GroupEntry::new([0x22; 32]);
        assert_eq!(
            entry.insert_root([1; 32], branch).unwrap_err(),
            RegistryError::WrongGroup
        );
        assert_eq!(entry.extremity_count(), 0);
        assert_eq!(entry.state_count(), 0);
    }

    #[test]
    fn export_import_export_is_byte_identical_and_seed_free() {
        let (branch, _) = new_group(0x5A);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([1; 32], branch).unwrap();
        let blob = entry.export();
        assert!(!contains(&blob, &[0x5A; 32]), "device seed leaked");
        let again = GroupEntry::import(&blob).unwrap();
        assert_eq!(again.export(), blob);
        assert_eq!(again.seq(), 1);
    }

    #[test]
    fn corrupt_and_truncated_blobs_are_bad_state() {
        let (branch, _) = new_group(3);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([1; 32], branch).unwrap();
        let blob = entry.export();
        for cut in [0, 10, blob.len() - 1] {
            let err = GroupEntry::import(&blob[..cut]).unwrap_err();
            assert_eq!(err.code(), "bad_state");
        }
        let mut flipped = blob.clone();
        flipped[blob.len() / 2] ^= 1;
        assert_eq!(
            GroupEntry::import(&flipped).unwrap_err().code(),
            "bad_state"
        );

        let mut future = blob[..blob.len() - 32].to_vec();
        future[4..6].copy_from_slice(&9_u16.to_be_bytes());
        let hash = blake3::hash(&future);
        future.extend_from_slice(hash.as_bytes());
        assert_eq!(
            GroupEntry::import(&future).unwrap_err(),
            RegistryError::UnsupportedVersion(9)
        );

        // Any version other than the current in-place format is refused.
        let mut old = blob[..blob.len() - 32].to_vec();
        old[4..6].copy_from_slice(&2_u16.to_be_bytes());
        let hash = blake3::hash(&old);
        old.extend_from_slice(hash.as_bytes());
        assert_eq!(
            GroupEntry::import(&old).unwrap_err(),
            RegistryError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn restored_member_processes_next_commit_and_decrypts() {
        let (mut alice, bob, a_sig, _b_sig) = alice_and_bob();
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([2; 32], bob).unwrap();
        let mut registry = Registry::new();
        registry.insert(entry);

        // Persist and restore Bob in a fresh registry.
        let saved = registry.export(&GID).unwrap();
        let mut restored = Registry::new();
        let info = restored.import(&saved).unwrap();
        assert_eq!((info.seq, info.extremities), (1, vec![[2; 32]]));

        // Alice commits, then sends an application message.
        let (a_group, a_prov) = alice.parts_mut();
        let commit = a_group
            .self_update(a_prov, &a_sig, LeafNodeParameters::default())
            .unwrap()
            .into_contents()
            .0
            .to_bytes()
            .unwrap();
        a_group.merge_pending_commit(a_prov).unwrap();
        let app = a_group
            .create_message(a_prov, &a_sig, b"after restore")
            .unwrap()
            .to_bytes()
            .unwrap();

        let entry = restored.get_mut(&GID).unwrap();
        entry
            .apply(&[2; 32], [3; 32], &BTreeSet::from([[2; 32]]), |g, p| {
                let msg = MlsMessageIn::tls_deserialize_exact(&commit)
                    .map_err(mls)?
                    .try_into_protocol_message()
                    .map_err(mls)?;
                let processed = g.process_message(p, msg).map_err(mls)?;
                let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
                else {
                    return Err(RegistryError::BadState("not a commit"));
                };
                g.merge_staged_commit(p, *staged).map_err(mls)
            })
            .unwrap();
        assert_eq!(entry.extremities(), vec![[3; 32]]);

        let plain = entry
            .update(&[3; 32], |g, p| {
                let msg = MlsMessageIn::tls_deserialize_exact(&app)
                    .map_err(mls)?
                    .try_into_protocol_message()
                    .map_err(mls)?;
                match g.process_message(p, msg).map_err(mls)?.into_content() {
                    ProcessedMessageContent::ApplicationMessage(m) => Ok(m.into_bytes()),
                    _ => Err(RegistryError::BadState("not application")),
                }
            })
            .unwrap();
        assert_eq!(plain, b"after restore");
    }

    #[test]
    fn failed_apply_leaves_export_byte_identical() {
        let (branch, _) = new_group(4);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([1; 32], branch).unwrap();
        let before = entry.export();

        let err = entry
            .apply(&[1; 32], [9; 32], &BTreeSet::from([[1; 32]]), |g, p| {
                // Mutate the copy, then fail: the original must not change.
                let (pair, _) = signer([4; 32]);
                g.self_update(p, &pair, LeafNodeParameters::default())
                    .map_err(mls)?;
                Err::<(), _>(RegistryError::BadState("boom"))
            })
            .unwrap_err();
        assert_eq!(err.code(), "bad_state");
        assert_eq!(entry.export(), before);

        // Structural failures also leave it untouched.
        assert_eq!(
            entry
                .apply(&[8; 32], [9; 32], &BTreeSet::from([[8; 32]]), |_, _| Ok(()))
                .unwrap_err(),
            RegistryError::MissingBase
        );
        assert_eq!(
            entry
                .apply(
                    &[1; 32],
                    [9; 32],
                    &BTreeSet::from([[1; 32], [5; 32]]),
                    |_, _| Ok(())
                )
                .unwrap_err(),
            RegistryError::MissingBranch
        );
        assert_eq!(
            entry
                .apply(&[1; 32], [9; 32], &BTreeSet::new(), |_, _| Ok(()))
                .unwrap_err(),
            RegistryError::BaseNotResolved
        );
        assert_eq!(entry.export(), before);
    }

    fn full_entry() -> GroupEntry {
        let (base, _) = new_group(6);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([0; 32], base).unwrap();
        for i in 1..MAX_HELD_EXTREMITIES {
            let fork = entry.branch(&[0; 32]).unwrap().fork().unwrap();
            entry
                .insert_root([u8::try_from(i).unwrap(); 32], fork)
                .unwrap();
        }
        entry
    }

    #[test]
    fn cap_is_checked_after_the_update() {
        let mut entry = full_entry();
        assert_eq!(entry.extremity_count(), MAX_HELD_EXTREMITIES);

        // A linear commit replaces its base tip: the count stays at the cap.
        entry
            .apply(&[0; 32], [0xEE; 32], &BTreeSet::from([[0; 32]]), |_, _| {
                Ok(())
            })
            .unwrap();
        assert_eq!(entry.extremity_count(), MAX_HELD_EXTREMITIES);
        assert!(entry.branch(&[0; 32]).is_some(), "parent state retained");

        // A sibling on the now-retired base would be a ninth tip: refused,
        // and nothing changes.
        let before = entry.export();
        assert_eq!(
            entry
                .apply(&[0; 32], [0xEF; 32], &BTreeSet::from([[0; 32]]), |_, _| Ok(
                    ()
                ))
                .unwrap_err(),
            RegistryError::ExtremityCap(MAX_HELD_EXTREMITIES + 1)
        );
        assert_eq!(
            entry
                .insert_root([0xEF; 32], new_group(6).0)
                .unwrap_err()
                .code(),
            "extremity_cap"
        );
        assert_eq!(entry.export(), before);

        // A merge that resolves six tips and adds one is accepted at the cap.
        let mut six: BTreeSet<[u8; 32]> = (2..7).map(|i| [i; 32]).collect();
        six.insert([0xEE; 32]);
        entry
            .apply(&[0xEE; 32], [0xDD; 32], &six, |_, _| Ok(()))
            .unwrap();
        assert_eq!(entry.extremity_count(), MAX_HELD_EXTREMITIES - 5);
    }

    #[test]
    fn seq_counts_mutations_and_stale_imports_are_refused() {
        let (branch, _) = new_group(7);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([1; 32], branch).unwrap();
        assert_eq!(entry.seq(), 1);
        assert_eq!(entry.export(), entry.export(), "export does not bump seq");
        entry.update(&[1; 32], |_, _| Ok(())).unwrap();
        assert_eq!(entry.seq(), 2);
        let newer = entry.export();
        entry.update(&[1; 32], |_, _| Ok(())).unwrap();
        let newest = entry.export();

        let mut registry = Registry::new();
        registry.insert(entry);
        // Re-importing a lower seq over the loaded entry is a visible error.
        assert_eq!(
            registry.import(&newer).unwrap_err(),
            RegistryError::StaleState {
                loaded: 3,
                incoming: 2
            }
        );
        // Equal seq is an idempotent replace.
        assert!(registry.import(&newest).is_ok());
        registry.forget(&GID);
        assert!(!registry.has(&GID));
        assert_eq!(
            registry.export(&GID).unwrap_err(),
            RegistryError::UnknownGroup
        );
    }

    #[test]
    fn resolve_tip_requires_a_name_when_forked() {
        let mut entry = full_entry();
        assert_eq!(
            entry.resolve_tip(None).unwrap_err(),
            RegistryError::ForkUnresolved
        );
        assert_eq!(entry.resolve_tip(Some(&[3; 32])).unwrap(), [3; 32]);
        assert_eq!(
            entry.resolve_tip(Some(&[0xAA; 32])).unwrap_err(),
            RegistryError::MissingBase
        );
        let all: BTreeSet<[u8; 32]> = (0..8).map(|i| [i; 32]).collect();
        entry
            .apply(&[0; 32], [0xDD; 32], &all, |_, _| Ok(()))
            .unwrap();
        assert_eq!(entry.resolve_tip(None).unwrap(), [0xDD; 32]);
    }

    #[test]
    fn sibling_commits_on_one_base_both_apply_and_old_states_are_bounded() {
        let (base, _) = new_group(8);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([0; 32], base).unwrap();
        // Two commits on the same base: each resolves the base, which stays
        // held as a non-tip so the second can still apply.
        let base_only = BTreeSet::from([[0; 32]]);
        entry
            .apply(&[0; 32], [1; 32], &base_only, |_, _| Ok(()))
            .unwrap();
        assert_eq!(entry.extremities(), vec![[1; 32]]);
        entry
            .apply(&[0; 32], [2; 32], &base_only, |_, _| Ok(()))
            .unwrap();
        assert_eq!(entry.extremities(), vec![[1; 32], [2; 32]]);
        assert_eq!(entry.state_count(), 3);
        // Export/import preserves the retained parent; then the siblings merge.
        let mut reloaded = GroupEntry::import(&entry.export()).unwrap();
        assert!(reloaded.branch(&[0; 32]).is_some());
        assert_eq!(reloaded.extremities(), vec![[1; 32], [2; 32]]);
        let both = BTreeSet::from([[1; 32], [2; 32]]);
        reloaded
            .apply(&[1; 32], [3; 32], &both, |_, _| Ok(()))
            .unwrap();
        assert_eq!(reloaded.extremities(), vec![[3; 32]]);

        // A long linear chain keeps only MAX_RETAINED_STATES, never evicting a tip.
        let mut tip = [2_u8; 32];
        for i in 10..40_u8 {
            entry
                .apply(&tip, [i; 32], &BTreeSet::from([tip]), |_, _| Ok(()))
                .unwrap();
            tip = [i; 32];
        }
        assert_eq!(entry.state_count(), MAX_RETAINED_STATES);
        assert!(entry.extremities().contains(&[1; 32]));
        assert!(entry.extremities().contains(&tip));
        // The evicted ancestor is a deferral, not a crash.
        assert_eq!(
            entry
                .apply(&[0; 32], [0x77; 32], &base_only, |_, _| Ok(()))
                .unwrap_err(),
            RegistryError::MissingBase
        );
        let blob = entry.export();
        assert_eq!(GroupEntry::import(&blob).unwrap().export(), blob);
    }

    #[test]
    fn hostile_blobs_and_conflicting_imports_are_refused() {
        let (branch, _) = new_group(9);
        let mut entry = GroupEntry::new(GID);
        entry.insert_root([1; 32], branch).unwrap();

        // A branch for another group cannot be installed.
        let other = {
            let (pair, cred) = signer([9; 32]);
            let provider = OpenMlsRustCrypto::default();
            let config = MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .build();
            let group = MlsGroup::new_with_group_id(
                &provider,
                &pair,
                &config,
                GroupId::from_slice(&[0xAB; 32]),
                cred,
            )
            .unwrap();
            HeldBranch::new(provider, group)
        };
        assert_eq!(
            entry.insert_root([2; 32], other).unwrap_err().code(),
            "mismatch:group_id"
        );

        // Same seq, different content: a conflict, not an idempotent replace.
        let blob = entry.export();
        let mut registry = Registry::new();
        registry.import(&blob).unwrap();
        assert!(
            registry.import(&blob).is_ok(),
            "identical blob is idempotent"
        );
        let mut diverged = GroupEntry::import(&blob).unwrap();
        diverged
            .apply(&[1; 32], [5; 32], &BTreeSet::from([[1; 32]]), |_, _| Ok(()))
            .unwrap();
        let mut forged = GroupEntry::import(&blob).unwrap();
        forged
            .apply(&[1; 32], [6; 32], &BTreeSet::from([[1; 32]]), |_, _| Ok(()))
            .unwrap();
        registry.import(&diverged.export()).unwrap();
        assert!(matches!(
            registry.import(&forged.export()),
            Err(RegistryError::StaleState { .. })
        ));

        // A count that cannot fit in the remaining input is rejected up front.
        let mut huge = blob[..blob.len() - 32].to_vec();
        let count_at = 4 + 2 + 8 + 32;
        huge[count_at..count_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let hash = blake3::hash(&huge);
        huge.extend_from_slice(hash.as_bytes());
        assert_eq!(GroupEntry::import(&huge).unwrap_err().code(), "bad_state");
    }
}
