//! Reference model for DMLS extremities and identity-keyed merge planning.
//!
//! The room/identity layer is injected through a `principal_of` callback. In a
//! combined MSC00FC/DMLS harness, that callback must validate the leaf's device
//! certificate against the resolved user chain and return its stable principal
//! and device ID. The MSC00FC device-root generation is retained as identity
//! metadata; it is not compared with the separate, group-scoped MLS leaf
//! generation.
//!
//! This is a state-machine model, not an MLS implementation. It does not create
//! commits, compute RFC transcript hashes, or implement `UpdatePath`
//! cryptography.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::tree::{LeafNode, LeafSource};

/// Invalid or incomplete DMLS merge input.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MergeError {
    /// A requested extremity is known but its group state is not held locally.
    #[error("missing local group state for {}", hex_lower(.commit_id))]
    MissingBaseState {
        /// The commit digest of the missing extremity.
        commit_id: [u8; 32],
    },
    /// An update candidate does not match the member identity.
    #[error("{0}")]
    IdentityMismatch(&'static str),
    /// A leaf signature key is not certified for the claimed device identity
    /// (a specialisation of an identity mismatch).
    #[error("{0}")]
    UncertifiedDevice(&'static str),
    /// An update candidate is stale or belongs to another MLS group.
    #[error("{0}")]
    Generation(&'static str),
    /// A `LeafNode` signature, source or position binding did not verify.
    #[error("{0}")]
    Signature(&'static str),
    /// Concurrent branches disagree on a member at the same MLS generation.
    #[error("{0}")]
    MembershipConflict(&'static str),
    /// Any other invalid merge input.
    #[error("{0}")]
    Invalid(&'static str),
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A member's stable certified identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberId {
    /// The principal (user) bytes.
    pub principal: Vec<u8>,
    /// The device ID.
    pub device_id: String,
}

impl MemberId {
    /// Create a member ID.
    #[must_use]
    pub fn new(principal: impl Into<Vec<u8>>, device_id: impl Into<String>) -> Self {
        Self {
            principal: principal.into(),
            device_id: device_id.into(),
        }
    }
}

/// The certified identity resolved from a leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalDevice {
    /// The principal (user) bytes.
    pub principal: Vec<u8>,
    /// The device ID.
    pub device_id: String,
    /// The user's epoch height.
    pub user_epoch_height: u64,
    /// The MSC00FC device-root generation (identity metadata only).
    pub device_root_generation: u64,
}

impl PrincipalDevice {
    /// The stable member ID.
    #[must_use]
    pub fn member_id(&self) -> MemberId {
        MemberId::new(self.principal.clone(), self.device_id.clone())
    }
}

/// Resolve a leaf's certified identity; injected so the model carries no
/// certificate logic.
pub type PrincipalOf<'a> = &'a dyn Fn(&LeafNode) -> Result<PrincipalDevice, MergeError>;

/// Verify a `LeafNode` at `leaf_index`; injected so the model carries no
/// signature scheme. The `bool` is `for_update`: when true the verifier MUST
/// also reject a `KeyPackage`-sourced leaf. It owns the whole leaf-validity
/// decision.
pub type LeafVerifier<'a> = &'a dyn Fn(&LeafNode, Option<usize>, bool) -> bool;

/// Stable identity for one DMLS commit extremity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtremityId {
    /// The MLS epoch.
    pub mls_epoch: u64,
    /// The 32-byte commit-message digest.
    pub commit_id: [u8; 32],
}

impl ExtremityId {
    /// Create an extremity ID.
    #[must_use]
    pub fn new(mls_epoch: u64, commit_id: [u8; 32]) -> Self {
        Self {
            mls_epoch,
            commit_id,
        }
    }
}

/// How a leaf entered a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeafOrigin {
    /// An existing member.
    #[default]
    Member,
    /// Added by a Commit.
    Add,
    /// Joined by an external commit.
    ExternalCommit,
}

/// A leaf as held by one branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafRecord {
    /// The leaf.
    pub leaf: LeafNode,
    /// How the leaf entered the branch.
    pub origin: LeafOrigin,
    /// Slot in this branch's tree. Existing members never move between
    /// branches; slots of members added on a losing branch are discarded by
    /// the merge.
    pub leaf_index: Option<usize>,
}

impl LeafRecord {
    /// An existing member's leaf with no known slot.
    #[must_use]
    pub fn new(leaf: LeafNode) -> Self {
        Self {
            leaf,
            origin: LeafOrigin::Member,
            leaf_index: None,
        }
    }

    /// Set the origin.
    #[must_use]
    pub fn with_origin(mut self, origin: LeafOrigin) -> Self {
        self.origin = origin;
        self
    }

    /// Set the slot.
    #[must_use]
    pub fn with_leaf_index(mut self, leaf_index: usize) -> Self {
        self.leaf_index = Some(leaf_index);
        self
    }
}

/// One held branch (extremity) and its membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    /// The extremity identity.
    pub extremity: ExtremityId,
    /// Retained to describe the common fork context; not a secret HMAC key.
    pub parent_transcript_hash: Vec<u8>,
    /// Current members.
    pub members: BTreeMap<MemberId, LeafRecord>,
    /// Evicted leaves, retained so concurrent removals can be compared with
    /// updates independently of which branch becomes the merge base.
    pub removed: BTreeMap<MemberId, LeafNode>,
    /// Members that joined on this branch by external commit.
    pub external_joiners: BTreeSet<MemberId>,
    /// Extremities this branch's merge consumed.
    pub resolves: BTreeSet<ExtremityId>,
}

impl Branch {
    /// Create a branch with no removals, external joiners or resolved set.
    #[must_use]
    pub fn new(
        extremity: ExtremityId,
        parent_transcript_hash: impl Into<Vec<u8>>,
        members: BTreeMap<MemberId, LeafRecord>,
    ) -> Self {
        Self {
            extremity,
            parent_transcript_hash: parent_transcript_hash.into(),
            members,
            removed: BTreeMap::new(),
            external_joiners: BTreeSet::new(),
            resolves: BTreeSet::new(),
        }
    }

    /// Set the retained removals.
    #[must_use]
    pub fn with_removed(mut self, removed: BTreeMap<MemberId, LeafNode>) -> Self {
        self.removed = removed;
        self
    }

    /// Set the external joiners.
    #[must_use]
    pub fn with_external_joiners(mut self, joiners: impl IntoIterator<Item = MemberId>) -> Self {
        self.external_joiners = joiners.into_iter().collect();
        self
    }

    /// Set the resolved extremities.
    #[must_use]
    pub fn with_resolves(mut self, resolves: impl IntoIterator<Item = ExtremityId>) -> Self {
        self.resolves = resolves.into_iter().collect();
        self
    }
}

/// The outcome of [`plan_merge`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergePlan {
    /// The selected base extremity.
    pub base: ExtremityId,
    /// The merged membership.
    pub members: BTreeMap<MemberId, LeafRecord>,
    /// Members that must issue their own Update after the base Commit.
    pub required_self_updates: Vec<MemberId>,
    /// Members to Add, with the leaf to add.
    pub adds: Vec<(MemberId, LeafNode)>,
    /// Members to Remove.
    pub removes: Vec<MemberId>,
    /// External joiners discarded by the merge, who must rejoin.
    pub orphaned_external_joiners: Vec<MemberId>,
}

/// Local knowledge about the fate of a pending external commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalJoinStatus {
    /// Every surviving tip contains the joiner.
    Accepted,
    /// Not yet decidable.
    Pending,
    /// Every surviving tip supersedes the join without the joiner.
    Orphaned,
}

/// Ascending sort key: higher epoch first, then deterministic digest order.
///
/// The commit digest is a grindable tie key, so it is deterministic rather than
/// fair.
#[must_use]
pub fn extremity_score(branch: &Branch) -> (Reverse<u64>, [u8; 32]) {
    (
        Reverse(branch.extremity.mls_epoch),
        branch.extremity.commit_id,
    )
}

/// Select the canonical base, deferring if any requested state is missing.
///
/// # Errors
///
/// Returns [`MergeError::Invalid`] for an empty request, or
/// [`MergeError::MissingBaseState`] naming the lowest missing extremity.
pub fn select_base(
    requested: impl IntoIterator<Item = ExtremityId>,
    held: &BTreeMap<ExtremityId, Branch>,
) -> Result<&Branch, MergeError> {
    let requested: BTreeSet<ExtremityId> = requested.into_iter().collect();
    if requested.is_empty() {
        return Err(MergeError::Invalid("cannot resolve an empty extremity set"));
    }
    if let Some(missing) = requested.iter().find(|ext| !held.contains_key(ext)) {
        return Err(MergeError::MissingBaseState {
            commit_id: missing.commit_id,
        });
    }
    requested
        .iter()
        .map(|ext| &held[ext])
        .min_by_key(|branch| extremity_score(branch))
        .ok_or(MergeError::Invalid("cannot resolve an empty extremity set"))
}

/// Validate device/group continuity and optionally a higher generation.
///
/// With `verify_leaf`, `new_leaf` must also pass the verifier at `leaf_index`.
///
/// # Errors
///
/// Returns a [`MergeError`] naming the failed check.
pub fn validate_update_candidate(
    old_leaf: &LeafNode,
    new_leaf: &LeafNode,
    group_id: &[u8],
    principal_of: PrincipalOf<'_>,
    require_newer: bool,
    leaf_index: Option<usize>,
    verify_leaf: Option<LeafVerifier<'_>>,
) -> Result<MemberId, MergeError> {
    let old_identity = principal_of(old_leaf)?.member_id();
    let new_identity = principal_of(new_leaf)?.member_id();
    if old_identity != new_identity {
        return Err(MergeError::IdentityMismatch(
            "other-branch update candidate changes the certified member identity",
        ));
    }
    if new_leaf.group_id != group_id || old_leaf.group_id != group_id {
        return Err(MergeError::Generation(
            "leaf generation extension has the wrong group_id",
        ));
    }
    if require_newer && new_leaf.generation <= old_leaf.generation {
        return Err(MergeError::Generation(
            "other-branch update candidate generation must strictly increase",
        ));
    }
    if let Some(verify) = verify_leaf {
        if new_leaf.source != LeafSource::KeyPackage && leaf_index.is_none() {
            return Err(MergeError::Signature(
                "leaf_index is required to verify this leaf",
            ));
        }
        if !verify(new_leaf, leaf_index, require_newer) {
            return Err(MergeError::Signature(
                "LeafNode does not verify at this position",
            ));
        }
    }
    Ok(old_identity)
}

fn validated_members<'a>(
    branch: &'a Branch,
    principal_of: PrincipalOf<'_>,
) -> Result<BTreeMap<MemberId, &'a LeafRecord>, MergeError> {
    let mut out = BTreeMap::new();
    for (member_id, record) in &branch.members {
        if &principal_of(&record.leaf)?.member_id() != member_id {
            return Err(MergeError::IdentityMismatch(
                "branch member key disagrees with certified leaf identity",
            ));
        }
        if out.insert(member_id.clone(), record).is_some() {
            return Err(MergeError::IdentityMismatch(
                "branch contains duplicate certified member identities",
            ));
        }
    }
    Ok(out)
}

fn validated_removed<'a>(
    branch: &'a Branch,
    group_id: &[u8],
    principal_of: PrincipalOf<'_>,
) -> Result<BTreeMap<MemberId, &'a LeafNode>, MergeError> {
    let mut out = BTreeMap::new();
    for (member_id, leaf) in &branch.removed {
        if &principal_of(leaf)?.member_id() != member_id {
            return Err(MergeError::IdentityMismatch(
                "branch removed key disagrees with certified leaf identity",
            ));
        }
        if leaf.group_id != group_id {
            return Err(MergeError::Generation(
                "removed leaf has the wrong group_id",
            ));
        }
        if branch.members.contains_key(member_id) {
            return Err(MergeError::Invalid(
                "member cannot be both present and removed in one branch",
            ));
        }
        out.insert(member_id.clone(), leaf);
    }
    Ok(out)
}

const SAME_GEN_CONFLICT: MergeError =
    MergeError::MembershipConflict("same member has different leaves at the same generation");

/// Plan identity-keyed membership reconciliation across held extremities.
///
/// The chosen base's membership and tree indexing are retained. A valid,
/// higher-generation leaf on another branch is checked as a candidate and
/// recorded as a requirement for that member to issue its own Update after
/// applying the base Commit; the candidate leaf is never installed by the
/// merge. Removals are compared symmetrically across all held branches,
/// including the base, using each branch's retained evicted leaf. External
/// joiners found only on non-base branches are orphaned and deliberately
/// omitted so callers can require a fresh external commit rather than reuse
/// their old `LeafNode`/`KeyPackage`.
///
/// # Errors
///
/// Returns a [`MergeError`] for missing state, identity or generation
/// violations, signature failures, or unresolvable membership conflicts.
#[allow(clippy::too_many_lines)]
pub fn plan_merge(
    requested: impl IntoIterator<Item = ExtremityId>,
    held: &BTreeMap<ExtremityId, Branch>,
    group_id: &[u8],
    principal_of: PrincipalOf<'_>,
    verify_leaf: Option<LeafVerifier<'_>>,
) -> Result<MergePlan, MergeError> {
    let requested: BTreeSet<ExtremityId> = requested.into_iter().collect();
    let base = select_base(requested.iter().copied(), held)?;
    let mut branches: Vec<&Branch> = requested.iter().map(|ext| &held[ext]).collect();
    branches.sort_by_key(|branch| extremity_score(branch));

    let mut members_by_extremity = BTreeMap::new();
    let mut removed_by_extremity = BTreeMap::new();
    for branch in &branches {
        members_by_extremity.insert(branch.extremity, validated_members(branch, principal_of)?);
    }
    for branch in &branches {
        removed_by_extremity.insert(
            branch.extremity,
            validated_removed(branch, group_id, principal_of)?,
        );
    }

    let base_members = &members_by_extremity[&base.extremity];
    let mut merged: BTreeMap<MemberId, LeafRecord> = base_members
        .iter()
        .map(|(id, record)| (id.clone(), (*record).clone()))
        .collect();
    let mut required_self_updates: BTreeSet<MemberId> = BTreeSet::new();
    let mut add_ops: BTreeMap<MemberId, LeafNode> = BTreeMap::new();
    let mut remove_ops: BTreeSet<MemberId> = BTreeSet::new();
    let mut orphaned: BTreeSet<MemberId> = BTreeSet::new();
    let mut evicted_members: BTreeSet<MemberId> = BTreeSet::new();

    // Compare every removal with every surviving copy, including removals on
    // the selected base branch. This makes remove/update conflicts symmetric.
    for branch in &branches {
        for (member_id, removed_leaf) in &removed_by_extremity[&branch.extremity] {
            for other in &branches {
                if other.extremity == branch.extremity {
                    continue;
                }
                let Some(other_record) = members_by_extremity[&other.extremity].get(member_id)
                else {
                    continue;
                };
                if other.external_joiners.contains(member_id)
                    || other_record.origin == LeafOrigin::ExternalCommit
                {
                    // External joins are discarded during merge; they are not
                    // competing updates to the removed member.
                    continue;
                }
                validate_update_candidate(
                    removed_leaf,
                    &other_record.leaf,
                    group_id,
                    principal_of,
                    false,
                    other_record.leaf_index,
                    verify_leaf,
                )?;
                if &other_record.leaf != *removed_leaf
                    && other_record.leaf.generation >= removed_leaf.generation
                {
                    return Err(MergeError::MembershipConflict(
                        "concurrent removal/update needs an explicit protocol rule",
                    ));
                }
            }
            evicted_members.insert(member_id.clone());
            if base_members.contains_key(member_id) {
                merged.remove(member_id);
                remove_ops.insert(member_id.clone());
                required_self_updates.remove(member_id);
            }
        }
    }

    for branch in &branches {
        if branch.extremity == base.extremity {
            continue;
        }
        for (member_id, record) in &members_by_extremity[&branch.extremity] {
            let record: &LeafRecord = record;
            let base_record = base_members.get(member_id).copied();
            let is_external_join = branch.external_joiners.contains(member_id)
                || record.origin == LeafOrigin::ExternalCommit;
            if is_external_join {
                if base_record.is_none() || evicted_members.contains(member_id) {
                    orphaned.insert(member_id.clone());
                }
                // The external commit's LeafNode is never copied into a merge.
                // If the base already has this identity, its base LeafNode wins.
                continue;
            }
            if evicted_members.contains(member_id) {
                continue;
            }
            let Some(base_record) = base_record else {
                if let Some(existing) = merged.get(member_id) {
                    if existing.leaf != record.leaf {
                        if existing.leaf.generation == record.leaf.generation {
                            return Err(SAME_GEN_CONFLICT);
                        }
                        if existing.leaf.generation > record.leaf.generation {
                            continue;
                        }
                    }
                }
                // The applier places the joiner at the leftmost blank leaf of
                // the merged tree, so a slot taken on this branch is dropped.
                let mut placed = record.clone();
                placed.leaf_index = None;
                merged.insert(member_id.clone(), placed);
                add_ops.insert(member_id.clone(), record.leaf.clone());
                continue;
            };

            if let (Some(index), Some(base_index)) = (record.leaf_index, base_record.leaf_index) {
                if index != base_index {
                    if base_record.origin != LeafOrigin::ExternalCommit {
                        return Err(MergeError::MembershipConflict(
                            "an existing member moved leaf index",
                        ));
                    }
                    // The base holds an RFC 9420 resync: the member rejoined at
                    // a new slot and removed its old leaf. A copy at the old
                    // slot is stale unless it is at least as new, and a signed
                    // update cannot be moved to another slot, so that case
                    // needs a fresh update.
                    validate_update_candidate(
                        &base_record.leaf,
                        &record.leaf,
                        group_id,
                        principal_of,
                        false,
                        record.leaf_index,
                        verify_leaf,
                    )?;
                    if record.leaf.generation >= base_record.leaf.generation {
                        return Err(MergeError::MembershipConflict(
                            "update authored on a pre-resync slot must be re-issued",
                        ));
                    }
                    continue;
                }
            }
            if record.leaf == base_record.leaf {
                continue;
            }
            if record.leaf.generation < base_record.leaf.generation {
                // A branch that never applied the newer update is stale, not
                // invalid. Verify its identity binding, then keep the base leaf.
                validate_update_candidate(
                    &base_record.leaf,
                    &record.leaf,
                    group_id,
                    principal_of,
                    false,
                    record.leaf_index,
                    verify_leaf,
                )?;
                continue;
            }
            if record.leaf.generation == base_record.leaf.generation {
                return Err(SAME_GEN_CONFLICT);
            }
            let from_update = validate_update_candidate(
                &base_record.leaf,
                &record.leaf,
                group_id,
                principal_of,
                true,
                record.leaf_index,
                verify_leaf,
            )?;
            if &from_update != member_id {
                return Err(MergeError::IdentityMismatch(
                    "other-branch update candidate identity mismatch",
                ));
            }
            let current = &merged
                .get(member_id)
                .ok_or(MergeError::Invalid("merged membership lost a base member"))?
                .leaf;
            if record.leaf.generation == current.generation {
                if &record.leaf != current {
                    return Err(SAME_GEN_CONFLICT);
                }
                continue;
            }
            if record.leaf.generation > current.generation {
                // The other branch's leaf is evidence that the member needs to
                // refresh, not a LeafNode this committer may install.
                required_self_updates.insert(member_id.clone());
                add_ops.remove(member_id);
            }
        }
    }

    Ok(MergePlan {
        base: base.extremity,
        members: merged,
        required_self_updates: required_self_updates.into_iter().collect(),
        adds: add_ops.into_iter().collect(),
        removes: remove_ops.into_iter().collect(),
        orphaned_external_joiners: orphaned.into_iter().collect(),
    })
}

/// Apply a merge's advertised consumed set idempotently to a local view.
#[must_use]
pub fn apply_resolved_set(
    local_extremities: impl IntoIterator<Item = ExtremityId>,
    merge_extremity: ExtremityId,
    resolves: &BTreeSet<ExtremityId>,
) -> BTreeSet<ExtremityId> {
    let mut remaining: BTreeSet<ExtremityId> = local_extremities.into_iter().collect();
    remaining.retain(|ext| !resolves.contains(ext));
    remaining.insert(merge_extremity);
    remaining
}

/// Check reachability in the locally held resolves graph.
///
/// `None` means at least one reachable parent is missing locally. A shared
/// visited set makes reconverging ancestry graphs linear in their reachable
/// vertices and edges.
#[must_use]
pub fn descends_from(
    extremity: ExtremityId,
    ancestor: ExtremityId,
    held: &BTreeMap<ExtremityId, Branch>,
) -> Option<bool> {
    if extremity == ancestor {
        return Some(true);
    }
    let mut pending = vec![extremity];
    let mut visited = BTreeSet::new();
    let mut incomplete = false;
    while let Some(current) = pending.pop() {
        if current == ancestor {
            return Some(true);
        }
        if !visited.insert(current) {
            continue;
        }
        match held.get(&current) {
            None => incomplete = true,
            Some(branch) => pending.extend(branch.resolves.iter().copied()),
        }
    }
    if incomplete {
        None
    } else {
        Some(false)
    }
}

/// Classify a join only after all known surviving tips supersede its branch.
///
/// A live external-commit extremity remains pending. An unrelated current tip
/// or incomplete local ancestry also keeps the result pending, preventing an
/// unrelated merge from causing a false orphan decision.
#[must_use]
pub fn external_join_status(
    joiner: &MemberId,
    commit: ExtremityId,
    state: &DmlsMergeState,
) -> ExternalJoinStatus {
    if state.extremities.contains(&commit) || state.extremities.is_empty() {
        return ExternalJoinStatus::Pending;
    }
    let mut membership = Vec::with_capacity(state.extremities.len());
    for extremity in &state.extremities {
        if descends_from(*extremity, commit, &state.held) != Some(true) {
            return ExternalJoinStatus::Pending;
        }
        let Some(branch) = state.held.get(extremity) else {
            return ExternalJoinStatus::Pending;
        };
        membership.push(branch.members.contains_key(joiner));
    }
    if membership.iter().all(|&present| present) {
        ExternalJoinStatus::Accepted
    } else if !membership.iter().any(|&present| present) {
        ExternalJoinStatus::Orphaned
    } else {
        ExternalJoinStatus::Pending
    }
}

/// Locally held group states and the currently known extremity set.
#[derive(Debug, Clone, Default)]
pub struct DmlsMergeState {
    /// Held branches by extremity.
    pub held: BTreeMap<ExtremityId, Branch>,
    /// The current extremity (tip) set.
    pub extremities: BTreeSet<ExtremityId>,
}

impl DmlsMergeState {
    /// An empty state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a newly observed branch as a live extremity.
    pub fn observe_branch(&mut self, branch: Branch) {
        self.extremities.insert(branch.extremity);
        self.held.insert(branch.extremity, branch);
    }

    /// Record a merge branch and drop the extremities it consumed.
    pub fn observe_merge(
        &mut self,
        mut branch: Branch,
        resolves: impl IntoIterator<Item = ExtremityId>,
    ) {
        let consumed: BTreeSet<ExtremityId> = resolves.into_iter().collect();
        branch.resolves.clone_from(&consumed);
        let extremity = branch.extremity;
        self.held.insert(extremity, branch);
        self.extremities =
            apply_resolved_set(self.extremities.iter().copied(), extremity, &consumed);
    }

    /// Plan a merge across the current extremity set.
    ///
    /// # Errors
    ///
    /// See [`plan_merge`].
    pub fn plan(
        &self,
        group_id: &[u8],
        principal_of: PrincipalOf<'_>,
        verify_leaf: Option<LeafVerifier<'_>>,
    ) -> Result<MergePlan, MergeError> {
        plan_merge(
            self.extremities.iter().copied(),
            &self.held,
            group_id,
            principal_of,
            verify_leaf,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GROUP: &[u8] = b"test-dmls-group";

    fn principal_of(leaf: &LeafNode) -> Result<PrincipalDevice, MergeError> {
        let text = std::str::from_utf8(&leaf.identity)
            .map_err(|_| MergeError::Invalid("identity is not utf-8"))?;
        let (user, device) = text
            .split_once(':')
            .ok_or(MergeError::Invalid("identity is not principal:device"))?;
        Ok(PrincipalDevice {
            principal: user.as_bytes().to_vec(),
            device_id: device.to_owned(),
            user_epoch_height: 1,
            device_root_generation: 1,
        })
    }

    fn leaf(identity: &str, key: &str, generation: u64) -> LeafNode {
        LeafNode::new(identity.as_bytes().to_vec(), key.as_bytes().to_vec())
            .with_generation(generation)
            .with_group_id(GROUP.to_vec())
    }

    fn id(leaf: &LeafNode) -> MemberId {
        principal_of(leaf).unwrap().member_id()
    }

    fn ext(epoch: u64, byte: u8) -> ExtremityId {
        ExtremityId::new(epoch, [byte; 32])
    }

    fn branch<const N: usize>(
        epoch: u64,
        byte: u8,
        members: [(MemberId, LeafRecord); N],
    ) -> Branch {
        Branch::new(
            ext(epoch, byte),
            vec![b'p'; 32],
            members.into_iter().collect(),
        )
    }

    fn held(branches: &[&Branch]) -> BTreeMap<ExtremityId, Branch> {
        branches
            .iter()
            .map(|b| (b.extremity, (*b).clone()))
            .collect()
    }

    fn plan(branches: &[&Branch]) -> Result<MergePlan, MergeError> {
        plan_merge(
            branches.iter().map(|b| b.extremity),
            &held(branches),
            GROUP,
            &principal_of,
            None,
        )
    }

    #[test]
    fn stale_generation_selects_the_base_and_requires_a_self_update() {
        let alice_old = leaf("alice:D1", "a1", 1);
        let alice_new = leaf("alice:D1", "a2", 2);
        let bob_old = leaf("bob:D1", "b1", 1);
        let bob_new = leaf("bob:D1", "b2", 2);
        let bob_newest = leaf("bob:D1", "b3", 3);
        let (alice, bob) = (id(&alice_old), id(&bob_old));

        let base = branch(
            2,
            1,
            [
                (alice.clone(), LeafRecord::new(alice_new.clone())),
                (bob.clone(), LeafRecord::new(bob_old.clone())),
            ],
        );
        let stale = branch(
            2,
            2,
            [
                (alice.clone(), LeafRecord::new(alice_old.clone())),
                (bob.clone(), LeafRecord::new(bob_new)),
            ],
        );
        let newer = branch(
            2,
            3,
            [
                (alice.clone(), LeafRecord::new(alice_new)),
                (bob.clone(), LeafRecord::new(bob_newest)),
            ],
        );

        let forward = plan(&[&newer, &stale, &base]).unwrap();
        let reverse = plan(&[&base, &stale, &newer]).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.base, base.extremity);
        assert_eq!(forward.members[&bob].leaf, bob_old);
        assert_eq!(forward.required_self_updates, vec![bob.clone()]);

        let known = held(&[&base]);
        let missing = ext(3, 4);
        assert_eq!(
            select_base([base.extremity, missing], &known).unwrap_err(),
            MergeError::MissingBaseState {
                commit_id: missing.commit_id
            }
        );

        let bob_new = leaf("bob:D1", "b2", 2);
        assert!(matches!(
            validate_update_candidate(&alice_old, &bob_new, GROUP, &principal_of, true, None, None),
            Err(MergeError::IdentityMismatch(_))
        ));
    }

    #[test]
    fn losing_external_join_is_orphaned_and_never_added() {
        let alice_new = leaf("alice:D1", "a2", 2);
        let bob_newest = leaf("bob:D1", "b3", 3);
        let carol_join = leaf("carol:D1", "c1", 1).with_source(LeafSource::Commit);
        let (alice, bob, carol) = (id(&alice_new), id(&bob_newest), id(&carol_join));

        let joined = branch(
            3,
            5,
            [
                (alice.clone(), LeafRecord::new(alice_new.clone())),
                (bob.clone(), LeafRecord::new(bob_newest.clone())),
                (
                    carol.clone(),
                    LeafRecord::new(carol_join).with_origin(LeafOrigin::ExternalCommit),
                ),
            ],
        )
        .with_external_joiners([carol.clone()]);
        let other = branch(
            3,
            4,
            [
                (alice.clone(), LeafRecord::new(alice_new.clone())),
                (bob, LeafRecord::new(bob_newest)),
            ],
        );
        let merged = plan(&[&other, &joined]).unwrap();
        assert!(merged.adds.is_empty());
        assert_eq!(merged.orphaned_external_joiners, vec![carol.clone()]);
        assert!(!merged.members.contains_key(&carol));

        // An unrelated merge leaves the join live, hence pending.
        let mut state = DmlsMergeState::new();
        state.observe_branch(joined.clone());
        let unrelated = branch(3, 6, [(alice.clone(), LeafRecord::new(alice_new.clone()))]);
        state.observe_branch(unrelated.clone());
        assert_eq!(
            external_join_status(&carol, joined.extremity, &state),
            ExternalJoinStatus::Pending
        );
        let unrelated_merge = branch(4, 7, [(alice.clone(), LeafRecord::new(alice_new.clone()))]);
        state.observe_merge(unrelated_merge.clone(), [unrelated.extremity]);
        assert_eq!(
            external_join_status(&carol, joined.extremity, &state),
            ExternalJoinStatus::Pending
        );
        let orphan_merge = branch(5, 8, [(alice, LeafRecord::new(alice_new))]);
        state.observe_merge(orphan_merge, [joined.extremity, unrelated_merge.extremity]);
        assert_eq!(
            external_join_status(&carol, joined.extremity, &state),
            ExternalJoinStatus::Orphaned
        );
    }

    #[test]
    fn remove_update_conflict_is_independent_of_base_order() {
        let gen1 = leaf("alice:D1", "alice-key-1", 1);
        let gen2 = leaf("alice:D1", "alice-key-2", 2);
        let alice = id(&gen1);
        let removed = || BTreeMap::from([(alice.clone(), gen1.clone())]);

        let remove_first = branch(4, 1, []).with_removed(removed());
        let update_second = branch(4, 2, [(alice.clone(), LeafRecord::new(gen2.clone()))]);
        let update_first = branch(4, 1, [(alice.clone(), LeafRecord::new(gen2))]);
        let remove_second = branch(4, 2, []).with_removed(removed());
        for pair in [
            [&remove_first, &update_second],
            [&update_first, &remove_second],
        ] {
            assert!(matches!(
                plan(&pair),
                Err(MergeError::MembershipConflict(_))
            ));
        }

        // A clean removal succeeds whichever branch supplies the base, without
        // resurrecting the member, and Remove is emitted only if the base held it.
        let unchanged_second = branch(4, 2, [(alice.clone(), LeafRecord::new(gen1.clone()))]);
        let unchanged_first = branch(4, 1, [(alice.clone(), LeafRecord::new(gen1))]);
        for (pair, base_has_member) in [
            ([&remove_first, &unchanged_second], false),
            ([&unchanged_first, &remove_second], true),
        ] {
            let clean = plan(&pair).unwrap();
            assert!(!clean.members.contains_key(&alice));
            assert!(clean.adds.is_empty());
            assert_eq!(clean.removes.contains(&alice), base_has_member);
        }
    }

    #[test]
    fn removed_member_external_rejoin_is_orphaned() {
        let gen1 = leaf("alice:D1", "alice-key-1", 1);
        let external = leaf("alice:D1", "alice-external-key", 2).with_source(LeafSource::Commit);
        let alice = id(&gen1);
        let removed = || BTreeMap::from([(alice.clone(), gen1.clone())]);
        let rejoin = |byte| {
            branch(
                4,
                byte,
                [(
                    alice.clone(),
                    LeafRecord::new(external.clone()).with_origin(LeafOrigin::ExternalCommit),
                )],
            )
            .with_external_joiners([alice.clone()])
        };

        let stable = branch(4, 1, [(alice.clone(), LeafRecord::new(gen1.clone()))]);
        let remove_branch = branch(4, 2, []).with_removed(removed());
        let result = plan(&[&stable, &remove_branch, &rejoin(3)]).unwrap();
        assert!(!result.members.contains_key(&alice));
        assert_eq!(result.removes, vec![alice.clone()]);
        assert!(result.adds.is_empty());
        assert_eq!(result.orphaned_external_joiners, vec![alice.clone()]);

        let removal_base = branch(4, 1, []).with_removed(removed());
        let result = plan(&[&removal_base, &rejoin(2)]).unwrap();
        assert!(!result.members.contains_key(&alice));
        assert!(result.removes.is_empty());
        assert_eq!(result.orphaned_external_joiners, vec![alice]);
    }

    #[test]
    fn concurrent_joins_are_added_and_slots_are_dropped() {
        let alice_leaf = leaf("alice:D1", "a1", 1);
        let yara_leaf = leaf("yara:D1", "y1", 1);
        let (alice, yara) = (id(&alice_leaf), id(&yara_leaf));
        let base = branch(
            2,
            1,
            [(
                alice.clone(),
                LeafRecord::new(alice_leaf.clone()).with_leaf_index(0),
            )],
        );
        let other = branch(
            2,
            2,
            [
                (
                    alice.clone(),
                    LeafRecord::new(alice_leaf).with_leaf_index(0),
                ),
                (
                    yara.clone(),
                    LeafRecord::new(yara_leaf.clone()).with_leaf_index(1),
                ),
            ],
        );
        let result = plan(&[&base, &other]).unwrap();
        assert_eq!(result.adds, vec![(yara.clone(), yara_leaf)]);
        assert_eq!(result.members[&yara].leaf_index, None);
        assert_eq!(result.members.len(), 2);
    }

    #[test]
    fn ancestry_diamond_terminates_and_incomplete_views_stay_unknown() {
        let alice_leaf = leaf("alice:D1", "alice-key", 0);
        let carol_leaf = leaf("carol:D1", "carol-key", 0).with_source(LeafSource::Commit);
        let (alice, carol) = (id(&alice_leaf), id(&carol_leaf));
        let member = || [(alice.clone(), LeafRecord::new(alice_leaf.clone()))];

        let join_root = branch(
            1,
            10,
            [(
                carol.clone(),
                LeafRecord::new(carol_leaf.clone()).with_origin(LeafOrigin::ExternalCommit),
            )],
        )
        .with_external_joiners([carol.clone()]);
        let other_root = branch(1, 11, member());
        let mut state = DmlsMergeState::new();
        state.observe_branch(join_root.clone());
        state.observe_branch(other_root.clone());

        let mut previous = vec![join_root.extremity, other_root.extremity];
        for layer in 2_u8..34 {
            let left = branch(u64::from(layer), layer * 2 + 1, member());
            let right = branch(u64::from(layer), layer * 2 + 2, member());
            state.observe_merge(left.clone(), previous.clone());
            state.observe_merge(right.clone(), previous);
            previous = vec![left.extremity, right.extremity];
        }
        let tip = branch(34, 250, member());
        state.observe_merge(tip.clone(), previous);
        assert_eq!(
            external_join_status(&carol, join_root.extremity, &state),
            ExternalJoinStatus::Orphaned
        );

        let absent = ExtremityId::new(99, [b'z'; 32]);
        let complete_tip = branch(35, 251, member()).with_resolves([tip.extremity]);
        let mut complete = state.held.clone();
        complete.insert(complete_tip.extremity, complete_tip.clone());
        assert_eq!(
            descends_from(complete_tip.extremity, absent, &complete),
            Some(false)
        );

        let missing_parent = ExtremityId::new(36, [b'y'; 32]);
        let incomplete_tip =
            branch(35, 252, member()).with_resolves([tip.extremity, missing_parent]);
        let mut incomplete = state.held.clone();
        incomplete.insert(incomplete_tip.extremity, incomplete_tip.clone());
        assert_eq!(
            descends_from(incomplete_tip.extremity, absent, &incomplete),
            None
        );

        let (a_id, b_id) = (ext(37, 1), ext(37, 2));
        let cycle_a = branch(37, 1, member()).with_resolves([b_id]);
        let cycle_b = branch(37, 2, member()).with_resolves([a_id, missing_parent]);
        let cycle = held(&[&cycle_a, &cycle_b]);
        assert_eq!(descends_from(a_id, absent, &cycle), None);
    }
}
