//! Merge-model metadata persisted beside one held MLS branch.
//!
//! An [`MlsGroup`] exposes its members but not the merge model's per-leaf
//! generation, origin or retained removals. Those are group-scoped facts this
//! crate maintains itself, so they travel in [`HeldBranch::meta`].
//!
//! The encoding is versioned and bounded like the group blob: every length is
//! checked against the remaining input before allocating. Metadata is internal
//! state, not an HTTP or event wire format.

use std::collections::{BTreeMap, BTreeSet};

use openmls::prelude::*;
use openmls::treesync::LeafNodeSource;

use crate::merge::{Branch, ExtremityId, LeafOrigin, LeafRecord, MemberId, MergeError};
use crate::tree::{LeafNode as ReducedLeaf, LeafSource};
use crate::wire::MemberKey;
use crate::MemberIdentity;

const VERSION: u16 = 1;

/// The merge facts for one held branch that `MlsGroup` cannot return.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BranchMeta {
    /// Current members, with the group-scoped generation merge planning uses.
    pub members: BTreeMap<MemberId, LeafRecord>,
    /// Leaves evicted on this branch, retained for concurrent-removal checks.
    pub removed: BTreeMap<MemberId, ReducedLeaf>,
    /// Members that joined this branch by external commit.
    pub external_joiners: BTreeSet<MemberId>,
    /// Carried for parity with the model; not used by planning.
    pub parent_transcript_hash: Vec<u8>,
}

/// The inputs gathered from one received Commit before it is merged.
pub(crate) struct RemoteCommit<'a> {
    /// The post-Commit group.
    pub group: &'a MlsGroup,
    /// The room-derived group id.
    pub group_id: &'a [u8; 32],
    /// The post-Commit MLS epoch.
    pub epoch: u64,
    /// The Commit sender, whose `UpdatePath` leaf must be recorded.
    pub sender: &'a MemberKey,
    /// Add proposals covered by the Commit.
    pub adds: &'a [KeyPackage],
    /// Update proposals covered by the Commit.
    pub updates: &'a [LeafNode],
    /// Removed leaf indices.
    pub removes: &'a [usize],
    /// The committer's new leaf from the `UpdatePath`.
    pub update_path: Option<&'a LeafNode>,
}

impl BranchMeta {
    /// Rebuild the metadata for a group whose leaves were all received.
    ///
    /// The MLS tree does not expose a per-leaf generation, so inherited leaves
    /// start at generation 0. Later Updates replace their records with the
    /// actual proposal leaf and the epoch that carried it.
    pub(crate) fn from_group(group: &MlsGroup, group_id: &[u8; 32]) -> Result<Self, MergeError> {
        let own = group.own_leaf_index();
        let mut members = BTreeMap::new();
        for member in group.members() {
            let (member_id, mut leaf) = leaf_from_member(&member, group_id)?;
            if member.index == own {
                if let Some(own_leaf) = group.own_leaf_node() {
                    leaf.source = source_of(own_leaf.leaf_node_source());
                    leaf.parent_hash = own_leaf.parent_hash().unwrap_or_default().to_vec();
                }
            }
            let record = LeafRecord::new(leaf)
                .with_origin(LeafOrigin::Member)
                .with_leaf_index(member.index.usize());
            members.insert(member_id, record);
        }
        Ok(Self {
            members,
            ..Self::default()
        })
    }

    /// Fold a locally produced Commit's effect into a copy of the base metadata.
    ///
    /// `group` is the post-Commit group and `epoch` is its MLS epoch.
    pub(crate) fn after_local_commit(
        &mut self,
        group: &MlsGroup,
        group_id: &[u8; 32],
        epoch: u64,
        signer: &MemberKey,
        op: &crate::engine::CommitOp,
    ) -> Result<(), MergeError> {
        match op {
            crate::engine::CommitOp::Add(_) => {
                // The post-Commit group has the new leaf with its real slot.
                for member in group.members() {
                    let (member_id, leaf) = leaf_from_member(&member, group_id)?;
                    if self.members.contains_key(&member_id) {
                        continue;
                    }
                    let mut leaf = leaf;
                    leaf.source = LeafSource::KeyPackage;
                    self.members.insert(
                        member_id,
                        LeafRecord::new(leaf)
                            .with_origin(LeafOrigin::Add)
                            .with_leaf_index(member.index.usize()),
                    );
                }
            }
            crate::engine::CommitOp::Remove(target) => {
                let target = member_id_from_key(target);
                if let Some(record) = self.members.remove(&target) {
                    self.removed.insert(target, record.leaf);
                }
            }
            crate::engine::CommitOp::SelfUpdate => {}
        }

        // Every Commit rotates its sender's own leaf through the UpdatePath.
        if let Some(own_leaf) = group.own_leaf_node() {
            self.replace_update(group, group_id, epoch, signer, own_leaf);
        }
        Ok(())
    }

    /// Fold a received Commit's proposals and `UpdatePath` into the base metadata.
    pub(crate) fn after_remote_commit(
        &mut self,
        commit: &RemoteCommit<'_>,
    ) -> Result<(), MergeError> {
        let group = commit.group;
        let group_id = commit.group_id;
        let epoch = commit.epoch;
        let sender = commit.sender;
        let adds = commit.adds;
        let updates = commit.updates;
        let removes = commit.removes;
        let update_path = commit.update_path;
        for package in adds {
            self.insert_added(group, group_id, package.leaf_node())?;
        }
        for leaf in updates {
            let identity = identity_of_leaf(leaf)?;
            self.replace_update(group, group_id, epoch, &identity, leaf);
        }
        for removed in removes {
            let target = self
                .members
                .iter()
                .find(|(_, record)| record.leaf_index == Some(*removed))
                .map(|(member_id, _)| member_id.clone());
            if let Some(target) = target {
                if let Some(record) = self.members.remove(&target) {
                    self.removed.insert(target, record.leaf);
                }
            }
        }
        if let Some(leaf) = update_path {
            self.replace_update(group, group_id, epoch, sender, leaf);
        }
        Ok(())
    }

    /// Build the merge model's branch view for this held state.
    pub(crate) fn to_branch(
        &self,
        commit_id: [u8; 32],
        mls_epoch: u64,
        resolves: BTreeSet<ExtremityId>,
    ) -> Branch {
        Branch::new(
            ExtremityId::new(mls_epoch, commit_id),
            self.parent_transcript_hash.clone(),
            self.members.clone(),
        )
        .with_removed(self.removed.clone())
        .with_external_joiners(self.external_joiners.iter().cloned())
        .with_resolves(resolves)
    }

    fn insert_added(
        &mut self,
        group: &MlsGroup,
        group_id: &[u8; 32],
        leaf: &LeafNode,
    ) -> Result<(), MergeError> {
        let identity = identity_of_leaf(leaf)?;
        let index = group
            .member_leaf_index(leaf.credential())
            .map(|index| index.usize());
        let (member_id, mut reduced) = reduced_leaf(&identity, leaf, group_id);
        reduced.source = LeafSource::KeyPackage;
        self.members.insert(
            member_id,
            LeafRecord::new(reduced)
                .with_origin(LeafOrigin::Add)
                .with_leaf_index_opt(index),
        );
        Ok(())
    }

    fn replace_update(
        &mut self,
        group: &MlsGroup,
        group_id: &[u8; 32],
        epoch: u64,
        identity: &MemberKey,
        leaf: &LeafNode,
    ) {
        let member_id = member_id_from_key(identity);
        let index = group
            .member_leaf_index(leaf.credential())
            .map(|index| index.usize());
        let (_, mut reduced) = reduced_leaf(identity, leaf, group_id);
        reduced.generation = epoch;
        reduced.source = LeafSource::Update;
        self.members.insert(
            member_id,
            LeafRecord::new(reduced)
                .with_origin(LeafOrigin::Member)
                .with_leaf_index_opt(index),
        );
    }

    /// Serialize with a version tag and explicit lengths.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&VERSION.to_be_bytes());
        put_records(&mut out, &self.members);
        put_leaves(&mut out, &self.removed);
        put_len(&mut out, self.external_joiners.len());
        for member_id in &self.external_joiners {
            put_member_id(&mut out, member_id);
        }
        put_bytes(&mut out, &self.parent_transcript_hash);
        out
    }

    /// Parse [`Self::encode`] output.
    ///
    /// # Errors
    ///
    /// Returns [`MergeError::Invalid`] for a bad version, truncation, a stale
    /// count, or trailing bytes.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, MergeError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        let mut r = Reader { buf: bytes };
        if u16::from_be_bytes(r.array()?) != VERSION {
            return Err(MergeError::Invalid("branch metadata version"));
        }
        let members = get_records(&mut r)?;
        let removed = get_leaves(&mut r)?;
        let count = r.len()?;
        let mut external_joiners = BTreeSet::new();
        for _ in 0..count {
            if !external_joiners.insert(r.member_id()?) {
                return Err(MergeError::Invalid("duplicate external joiner"));
            }
        }
        let parent_transcript_hash = r.bytes()?.to_vec();
        if !r.buf.is_empty() {
            return Err(MergeError::Invalid("trailing branch metadata"));
        }
        Ok(Self {
            members,
            removed,
            external_joiners,
            parent_transcript_hash,
        })
    }
}

/// The model member ID for a transport member key.
pub(crate) fn member_id_from_key(key: &MemberKey) -> MemberId {
    MemberId::new(key.principal.as_bytes().to_vec(), key.device_id.clone())
}

/// Parse the MLS basic credential into its Cygnus member key.
pub(crate) fn identity_of_leaf(leaf: &LeafNode) -> Result<MemberKey, MergeError> {
    let basic = BasicCredential::try_from(leaf.credential().clone())
        .map_err(|_| MergeError::Invalid("leaf is not a basic credential"))?;
    let identity = MemberIdentity::from_credential_bytes(basic.identity())
        .map_err(|_| MergeError::Invalid("leaf identity is not a Cygnus member"))?;
    Ok(MemberKey {
        principal: identity.principal,
        device_id: identity.device_id,
    })
}

fn leaf_from_member(
    member: &Member,
    group_id: &[u8; 32],
) -> Result<(MemberId, ReducedLeaf), MergeError> {
    let basic = BasicCredential::try_from(member.credential.clone())
        .map_err(|_| MergeError::Invalid("member is not a basic credential"))?;
    let identity = MemberIdentity::from_credential_bytes(basic.identity())
        .map_err(|_| MergeError::Invalid("member identity is not a Cygnus member"))?;
    let member_id = MemberId::new(
        identity.principal.as_bytes().to_vec(),
        identity.device_id.clone(),
    );
    Ok((
        member_id,
        ReducedLeaf {
            identity: format!("{}:{}", identity.principal, identity.device_id).into_bytes(),
            encryption_key: member.encryption_key.clone(),
            parent_hash: Vec::new(),
            source: LeafSource::KeyPackage,
            generation: 0,
            group_id: group_id.to_vec(),
            signature_key: member.signature_key.clone(),
            signature: Vec::new(),
        },
    ))
}

fn reduced_leaf(
    identity: &MemberKey,
    leaf: &LeafNode,
    group_id: &[u8; 32],
) -> (MemberId, ReducedLeaf) {
    (
        member_id_from_key(identity),
        ReducedLeaf {
            identity: format!("{}:{}", identity.principal, identity.device_id).into_bytes(),
            // OpenMLS does not expose these bytes publicly and the merge model
            // does not read them; identity, keys, generation and source decide
            // every check.
            encryption_key: Vec::new(),
            parent_hash: leaf.parent_hash().unwrap_or_default().to_vec(),
            source: source_of(leaf.leaf_node_source()),
            generation: 0,
            group_id: group_id.to_vec(),
            signature_key: leaf.signature_key().as_slice().to_vec(),
            signature: Vec::new(),
        },
    )
}

fn source_of(source: &LeafNodeSource) -> LeafSource {
    match source {
        LeafNodeSource::KeyPackage(_) => LeafSource::KeyPackage,
        LeafNodeSource::Update => LeafSource::Update,
        LeafNodeSource::Commit(_) => LeafSource::Commit,
    }
}

fn put_len(out: &mut Vec<u8>, n: usize) {
    let n = u32::try_from(n).expect("branch metadata length fits in u32");
    out.extend_from_slice(&n.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_len(out, bytes.len());
    out.extend_from_slice(bytes);
}

fn put_member_id(out: &mut Vec<u8>, member_id: &MemberId) {
    put_bytes(out, &member_id.principal);
    put_bytes(out, member_id.device_id.as_bytes());
}

fn put_leaf(out: &mut Vec<u8>, leaf: &ReducedLeaf) {
    put_bytes(out, &leaf.identity);
    put_bytes(out, &leaf.encryption_key);
    put_bytes(out, &leaf.parent_hash);
    out.push(match leaf.source {
        LeafSource::KeyPackage => 0,
        LeafSource::Update => 1,
        LeafSource::Commit => 2,
    });
    out.extend_from_slice(&leaf.generation.to_be_bytes());
    put_bytes(out, &leaf.group_id);
    put_bytes(out, &leaf.signature_key);
    put_bytes(out, &leaf.signature);
}

fn put_record(out: &mut Vec<u8>, record: &LeafRecord) {
    put_leaf(out, &record.leaf);
    out.push(match record.origin {
        LeafOrigin::Member => 0,
        LeafOrigin::Add => 1,
        LeafOrigin::ExternalCommit => 2,
    });
    match record.leaf_index {
        Some(index) => {
            out.push(1);
            put_len(out, index);
        }
        None => out.push(0),
    }
}

fn put_records(out: &mut Vec<u8>, records: &BTreeMap<MemberId, LeafRecord>) {
    put_len(out, records.len());
    for (member_id, record) in records {
        put_member_id(out, member_id);
        put_record(out, record);
    }
}

fn put_leaves(out: &mut Vec<u8>, leaves: &BTreeMap<MemberId, ReducedLeaf>) {
    put_len(out, leaves.len());
    for (member_id, leaf) in leaves {
        put_member_id(out, member_id);
        put_leaf(out, leaf);
    }
}

struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], MergeError> {
        if self.buf.len() < n {
            return Err(MergeError::Invalid("truncated branch metadata"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], MergeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| MergeError::Invalid("truncated branch metadata"))
    }

    fn len(&mut self) -> Result<usize, MergeError> {
        let n = usize::try_from(u32::from_be_bytes(self.array()?))
            .map_err(|_| MergeError::Invalid("branch metadata length"))?;
        // Every item takes at least one byte, so a count larger than the
        // remaining input is corrupt before any allocation happens.
        if n > self.buf.len() {
            return Err(MergeError::Invalid("branch metadata count exceeds input"));
        }
        Ok(n)
    }

    fn bytes(&mut self) -> Result<&'a [u8], MergeError> {
        let n = self.len()?;
        self.take(n)
    }

    fn member_id(&mut self) -> Result<MemberId, MergeError> {
        let principal = self.bytes()?.to_vec();
        let device_id = std::str::from_utf8(self.bytes()?)
            .map_err(|_| MergeError::Invalid("member device id"))?
            .to_owned();
        Ok(MemberId::new(principal, device_id))
    }

    fn leaf(&mut self) -> Result<ReducedLeaf, MergeError> {
        let identity = self.bytes()?.to_vec();
        let encryption_key = self.bytes()?.to_vec();
        let parent_hash = self.bytes()?.to_vec();
        let source = match self.take(1)?[0] {
            0 => LeafSource::KeyPackage,
            1 => LeafSource::Update,
            2 => LeafSource::Commit,
            _ => return Err(MergeError::Invalid("leaf source")),
        };
        let generation = u64::from_be_bytes(self.array()?);
        let group_id = self.bytes()?.to_vec();
        let signature_key = self.bytes()?.to_vec();
        let signature = self.bytes()?.to_vec();
        Ok(ReducedLeaf {
            identity,
            encryption_key,
            parent_hash,
            source,
            generation,
            group_id,
            signature_key,
            signature,
        })
    }

    fn record(&mut self) -> Result<LeafRecord, MergeError> {
        let leaf = self.leaf()?;
        let origin = match self.take(1)?[0] {
            0 => LeafOrigin::Member,
            1 => LeafOrigin::Add,
            2 => LeafOrigin::ExternalCommit,
            _ => return Err(MergeError::Invalid("leaf origin")),
        };
        let leaf_index = match self.take(1)?[0] {
            0 => None,
            1 => Some(self.len()?),
            _ => return Err(MergeError::Invalid("leaf index flag")),
        };
        Ok(LeafRecord {
            leaf,
            origin,
            leaf_index,
        })
    }
}

fn get_records(r: &mut Reader<'_>) -> Result<BTreeMap<MemberId, LeafRecord>, MergeError> {
    let count = r.len()?;
    let mut out = BTreeMap::new();
    for _ in 0..count {
        let member_id = r.member_id()?;
        if out.insert(member_id, r.record()?).is_some() {
            return Err(MergeError::Invalid("duplicate branch member"));
        }
    }
    Ok(out)
}

fn get_leaves(r: &mut Reader<'_>) -> Result<BTreeMap<MemberId, ReducedLeaf>, MergeError> {
    let count = r.len()?;
    let mut out = BTreeMap::new();
    for _ in 0..count {
        let member_id = r.member_id()?;
        if out.insert(member_id, r.leaf()?).is_some() {
            return Err(MergeError::Invalid("duplicate removed leaf"));
        }
    }
    Ok(out)
}

impl LeafRecord {
    fn with_leaf_index_opt(self, leaf_index: Option<usize>) -> Self {
        match leaf_index {
            Some(index) => self.with_leaf_index(index),
            None => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";

    fn member(device: &str) -> MemberId {
        MemberId::new(ALICE.as_bytes().to_vec(), device)
    }

    fn leaf(device: &str, generation: u64) -> ReducedLeaf {
        ReducedLeaf {
            identity: format!("{ALICE}:{device}").into_bytes(),
            encryption_key: b"enc".to_vec(),
            parent_hash: b"parent".to_vec(),
            source: LeafSource::Update,
            generation,
            group_id: b"group".to_vec(),
            signature_key: b"sigkey".to_vec(),
            signature: b"sig".to_vec(),
        }
    }

    #[test]
    fn metadata_round_trips_all_fields() {
        let mut meta = BranchMeta {
            parent_transcript_hash: b"transcript".to_vec(),
            ..BranchMeta::default()
        };
        meta.members.insert(
            member("D1"),
            LeafRecord::new(leaf("D1", 4))
                .with_origin(LeafOrigin::Add)
                .with_leaf_index(2),
        );
        meta.removed.insert(member("D2"), leaf("D2", 1));
        meta.external_joiners.insert(member("D3"));

        let encoded = meta.encode();
        assert_eq!(BranchMeta::decode(&encoded).unwrap(), meta);
    }

    #[test]
    fn empty_metadata_is_the_default() {
        assert_eq!(BranchMeta::decode(&[]).unwrap(), BranchMeta::default());
    }

    #[test]
    fn corrupt_metadata_is_rejected_without_panicking() {
        let encoded = BranchMeta::default().encode();
        assert!(BranchMeta::decode(&[]).is_ok());
        for cut in 1..encoded.len() {
            assert!(BranchMeta::decode(&encoded[..cut]).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(BranchMeta::decode(&trailing).is_err());
    }

    #[test]
    fn branch_view_carries_members_removed_and_resolves() {
        let mut meta = BranchMeta::default();
        meta.members
            .insert(member("D1"), LeafRecord::new(leaf("D1", 0)));
        meta.removed.insert(member("D2"), leaf("D2", 1));
        let resolves = BTreeSet::from([ExtremityId::new(1, [9; 32])]);
        let branch = meta.to_branch([7; 32], 2, resolves.clone());
        assert_eq!(branch.extremity, ExtremityId::new(2, [7; 32]));
        assert_eq!(branch.members.len(), 1);
        assert_eq!(branch.removed.len(), 1);
        assert_eq!(branch.resolves, resolves);
    }
}
