//! Structural reference model for the MLS ratchet tree used by DMLS.
//!
//! Two shapes are modelled because they are not the same tree:
//!
//! * [`RatchetTree`] is the draft-11 left-balanced shape for an arbitrary leaf
//!   count (`2 * n - 1` nodes). Leaf depth varies, and for `n = 2^k + 1` the
//!   right-most leaf is a direct child of the root.
//! * [`Rfc9420Tree`] is the RFC 9420 §4.1 perfect tree: leaf capacity is the
//!   next power of two, unused leaves are blank, and every populated leaf has
//!   the same depth. The two coincide at power-of-two leaf counts.
//!
//! Blank nodes, direct paths, copaths, resolutions, tree hashes, and
//! parent-hash relationships are modelled here. This is not a wire-compatible
//! MLS implementation: leaf and parent values are reduced to the fields needed
//! for structural experiments, and the hash encodings are model encodings
//! rather than MLS TLS encoding.

use std::collections::{HashMap, HashSet};

use blake3::Hasher;
use thiserror::Error;

/// The tree shape or a requested tree operation is invalid.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct InvalidTree(String);

fn invalid(message: impl Into<String>) -> InvalidTree {
    InvalidTree(message.into())
}

/// Where a leaf's signature came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LeafSource {
    /// The leaf was carried in a `KeyPackage` before its slot was known.
    #[default]
    KeyPackage,
    /// The leaf was committed by its own device as an Update.
    Update,
    /// The leaf was committed as part of a Commit.
    Commit,
}

impl LeafSource {
    /// The source name used by the model encoding.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KeyPackage => "key_package",
            Self::Update => "update",
            Self::Commit => "commit",
        }
    }
}

/// A reduced `LeafNode` carrying the fields DMLS needs for structural checks.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeafNode {
    /// The credential identity bytes.
    pub identity: Vec<u8>,
    /// The leaf's HPKE encryption key.
    pub encryption_key: Vec<u8>,
    /// The leaf's parent hash.
    pub parent_hash: Vec<u8>,
    /// The source of the signature.
    pub source: LeafSource,
    /// The leaf generation.
    pub generation: u64,
    /// The group the leaf was committed in.
    pub group_id: Vec<u8>,
    /// The RFC 9420 signature key, kept distinct from the HPKE key.
    pub signature_key: Vec<u8>,
    /// The signature over the leaf TBS.
    pub signature: Vec<u8>,
}

impl LeafNode {
    /// Create a leaf from its identity and encryption key.
    #[must_use]
    pub fn new(identity: impl Into<Vec<u8>>, encryption_key: impl Into<Vec<u8>>) -> Self {
        Self {
            identity: identity.into(),
            encryption_key: encryption_key.into(),
            ..Self::default()
        }
    }

    /// Set the leaf generation.
    #[must_use]
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }

    /// Set the group the leaf is bound to.
    #[must_use]
    pub fn with_group_id(mut self, group_id: impl Into<Vec<u8>>) -> Self {
        self.group_id = group_id.into();
        self
    }

    /// Set the leaf source.
    #[must_use]
    pub fn with_source(mut self, source: LeafSource) -> Self {
        self.source = source;
        self
    }
}

/// A reduced `ParentNode` carrying the fields DMLS needs.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ParentNode {
    /// The parent's HPKE encryption key.
    pub encryption_key: Vec<u8>,
    /// The parent's parent hash.
    pub parent_hash: Vec<u8>,
    /// Leaves whose paths have not been merged into this node.
    pub unmerged_leaves: Vec<usize>,
}

impl ParentNode {
    /// Create a parent from its encryption key.
    #[must_use]
    pub fn new(encryption_key: impl Into<Vec<u8>>) -> Self {
        Self {
            encryption_key: encryption_key.into(),
            ..Self::default()
        }
    }

    /// Set the unmerged leaves.
    #[must_use]
    pub fn with_unmerged_leaves(mut self, leaves: impl IntoIterator<Item = usize>) -> Self {
        self.unmerged_leaves = leaves.into_iter().collect();
        self
    }
}

/// A node in the ratchet tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeNode {
    /// An even-indexed leaf node.
    Leaf(LeafNode),
    /// An odd-indexed parent node.
    Parent(ParentNode),
}

impl From<LeafNode> for TreeNode {
    fn from(value: LeafNode) -> Self {
        Self::Leaf(value)
    }
}

impl From<ParentNode> for TreeNode {
    fn from(value: ParentNode) -> Self {
        Self::Parent(value)
    }
}

/// Return the largest power of two strictly less than `value`.
fn largest_power_of_two_below(value: usize) -> Result<usize, InvalidTree> {
    if value < 2 {
        return Err(invalid("a split needs at least two leaves"));
    }
    Ok(1 << ((value - 1).ilog2()))
}

fn lp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(
        &u32::try_from(data.len())
            .expect("model length fits in u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(data);
    out
}

fn digest(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(tag);
    for part in parts {
        hasher.update(&lp(part));
    }
    hasher.finalize().as_bytes().to_vec()
}

/// Model of RFC 9420 §7.2 `LeafNodeTBS` (model encoding, not TLS).
///
/// A `key_package` leaf is signed before its slot is known, so `group_id` and
/// `leaf_index` are omitted; `update` and `commit` leaves bind both, so a
/// valid signed leaf cannot be replanted at another position or group.
///
/// # Errors
///
/// Returns [`InvalidTree`] if an update/commit leaf has no `leaf_index`.
pub fn leaf_tbs(leaf: &LeafNode, leaf_index: Option<usize>) -> Result<Vec<u8>, InvalidTree> {
    let generation = leaf.generation.to_be_bytes();
    let mut parts: Vec<&[u8]> = vec![
        leaf.source.as_str().as_bytes(),
        &leaf.identity,
        &leaf.encryption_key,
        &leaf.signature_key,
        &generation,
    ];
    let index_bytes;
    if leaf.source != LeafSource::KeyPackage {
        let index = leaf_index
            .ok_or_else(|| invalid("update/commit leaves are signed with a leaf_index"))?;
        index_bytes = u32::try_from(index)
            .map_err(|_| invalid("leaf index exceeds u32"))?
            .to_be_bytes();
        parts.push(&leaf.group_id);
        parts.push(&index_bytes);
    }
    Ok(digest(b"DMLS-model-leaf-tbs-v1", &parts))
}

/// Flat-array model of the left-balanced ratchet-tree topology.
///
/// Leaves use even node indices (`2 * leaf_index`); parent nodes use odd
/// indices. For `n` leaves, the backing array has `2 * n - 1` slots. A subtree
/// with a non-power-of-two leaf count splits at the largest power of two below
/// that count.
#[derive(Debug, Clone)]
pub struct RatchetTree {
    leaf_count: usize,
    nodes: Vec<Option<TreeNode>>,
    children: HashMap<usize, (usize, usize)>,
    parent_of: HashMap<usize, usize>,
}

impl RatchetTree {
    /// Create an empty tree with `leaf_count` leaves.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `leaf_count` is zero.
    pub fn new(leaf_count: usize) -> Result<Self, InvalidTree> {
        Self::build(leaf_count, None)
    }

    /// Create a tree whose nodes are supplied directly.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the node count or node kinds are wrong.
    pub fn with_nodes(
        leaf_count: usize,
        nodes: Vec<Option<TreeNode>>,
    ) -> Result<Self, InvalidTree> {
        Self::build(leaf_count, Some(nodes))
    }

    fn build(leaf_count: usize, nodes: Option<Vec<Option<TreeNode>>>) -> Result<Self, InvalidTree> {
        if leaf_count == 0 {
            return Err(invalid("a ratchet tree must have at least one leaf"));
        }
        let mut tree = Self {
            leaf_count,
            nodes: vec![None; 2 * leaf_count - 1],
            children: HashMap::new(),
            parent_of: HashMap::new(),
        };
        tree.build_shape(0, leaf_count)?;
        if let Some(supplied) = nodes {
            if supplied.len() != tree.nodes.len() {
                return Err(invalid("node array length must be 2 * leaf_count - 1"));
            }
            tree.nodes = supplied;
            tree.validate_node_kinds()?;
        }
        Ok(tree)
    }

    fn build_shape(&mut self, first_leaf: usize, count: usize) -> Result<usize, InvalidTree> {
        if count == 1 {
            return Ok(2 * first_leaf);
        }
        let left_count = largest_power_of_two_below(count)?;
        let left_root = self.build_shape(first_leaf, left_count)?;
        let right_root = self.build_shape(first_leaf + left_count, count - left_count)?;
        let root = 2 * first_leaf + 2 * left_count - 1;
        self.children.insert(root, (left_root, right_root));
        self.parent_of.insert(left_root, root);
        self.parent_of.insert(right_root, root);
        Ok(root)
    }

    /// The number of leaves in the tree.
    #[must_use]
    pub fn leaf_count(&self) -> usize {
        self.leaf_count
    }

    /// The backing node array.
    #[must_use]
    pub fn nodes(&self) -> &[Option<TreeNode>] {
        &self.nodes
    }

    /// The root node index.
    #[must_use]
    pub fn root(&self) -> usize {
        Self::root_for(0, self.leaf_count)
    }

    fn root_for(first_leaf: usize, count: usize) -> usize {
        if count == 1 {
            return 2 * first_leaf;
        }
        let left_count = 1 << ((count - 1).ilog2());
        2 * first_leaf + 2 * left_count - 1
    }

    fn validate_node_kinds(&self) -> Result<(), InvalidTree> {
        for (index, node) in self.nodes.iter().enumerate() {
            let Some(node) = node else { continue };
            match (index % 2, node) {
                (0, TreeNode::Leaf(_)) | (1, TreeNode::Parent(_)) => {}
                (0, TreeNode::Parent(_)) => {
                    return Err(invalid(format!(
                        "even node index {index} must contain a leaf"
                    )));
                }
                (1, TreeNode::Leaf(_)) => {
                    return Err(invalid(format!(
                        "odd node index {index} must contain a parent"
                    )));
                }
                _ => unreachable!("index modulo two is either zero or one"),
            }
        }
        Ok(())
    }

    /// The backing node index for a leaf index.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn leaf_node_index(&self, leaf_index: usize) -> Result<usize, InvalidTree> {
        if leaf_index >= self.leaf_count {
            return Err(invalid(format!("leaf index {leaf_index} is out of range")));
        }
        Ok(2 * leaf_index)
    }

    /// The leaf at `leaf_index`, if the slot is populated.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn leaf(&self, leaf_index: usize) -> Result<Option<&LeafNode>, InvalidTree> {
        let node_index = self.leaf_node_index(leaf_index)?;
        Ok(match self.nodes.get(node_index) {
            Some(Some(TreeNode::Leaf(leaf))) => Some(leaf),
            _ => None,
        })
    }

    /// Set or clear a leaf slot. Parent nodes are rejected at even indices.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn set_leaf(
        &mut self,
        leaf_index: usize,
        node: Option<LeafNode>,
    ) -> Result<(), InvalidTree> {
        let node_index = self.leaf_node_index(leaf_index)?;
        self.nodes[node_index] = node.map(TreeNode::Leaf);
        Ok(())
    }

    /// Set or clear a parent node.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `node_index` is not a parent.
    pub fn set_parent(
        &mut self,
        node_index: usize,
        node: Option<ParentNode>,
    ) -> Result<(), InvalidTree> {
        if !self.children.contains_key(&node_index) {
            return Err(invalid(format!("node index {node_index} is not a parent")));
        }
        self.nodes[node_index] = node.map(TreeNode::Parent);
        Ok(())
    }

    /// The children of a parent node.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `node_index` is not a parent.
    pub fn children(&self, node_index: usize) -> Result<(usize, usize), InvalidTree> {
        self.children
            .get(&node_index)
            .copied()
            .ok_or_else(|| invalid(format!("node index {node_index} is not a parent")))
    }

    /// The parent of a node, if it has one.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `node_index` is out of range.
    pub fn parent(&self, node_index: usize) -> Result<Option<usize>, InvalidTree> {
        if node_index >= self.nodes.len() {
            return Err(invalid(format!("node index {node_index} is out of range")));
        }
        Ok(self.parent_of.get(&node_index).copied())
    }

    /// Parent node indices from the leaf's parent up to the root.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn direct_path(&self, leaf_index: usize) -> Result<Vec<usize>, InvalidTree> {
        let mut current = self.leaf_node_index(leaf_index)?;
        let mut path = Vec::new();
        while let Some(parent) = self.parent(current)? {
            path.push(parent);
            current = parent;
        }
        Ok(path)
    }

    /// A leaf's structural depth, regardless of blank nodes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn leaf_depth(&self, leaf_index: usize) -> Result<usize, InvalidTree> {
        Ok(self.direct_path(leaf_index)?.len())
    }

    /// Sibling subtree roots corresponding to [`Self::direct_path`].
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn copath(&self, leaf_index: usize) -> Result<Vec<usize>, InvalidTree> {
        let mut current = self.leaf_node_index(leaf_index)?;
        let mut siblings = Vec::new();
        while let Some(parent) = self.parent(current)? {
            let (left, right) = self.children(parent)?;
            siblings.push(if current == left { right } else { left });
            current = parent;
        }
        Ok(siblings)
    }

    /// The filtered direct path: each nonblank-parent node whose copath
    /// resolution is nonempty.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn filtered_direct_path(&self, leaf_index: usize) -> Result<Vec<usize>, InvalidTree> {
        Ok(self
            .update_path_resolutions(leaf_index)?
            .into_iter()
            .map(|(parent, _)| parent)
            .collect())
    }

    /// Each filtered direct-path node and its copath recipients.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn update_path_resolutions(
        &self,
        leaf_index: usize,
    ) -> Result<Vec<(usize, Vec<usize>)>, InvalidTree> {
        let path = self.direct_path(leaf_index)?;
        let copath = self.copath(leaf_index)?;
        let mut out = Vec::new();
        for (parent, sibling) in path.into_iter().zip(copath) {
            let resolution = self.resolution(sibling, &HashSet::new())?;
            if !resolution.is_empty() {
                out.push((parent, resolution));
            }
        }
        Ok(out)
    }

    /// Nonblank key-bearing nodes resolving a subtree.
    ///
    /// A nonblank parent contributes itself and its unmerged leaves. A blank
    /// parent is recursively resolved through its children.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `node_index` is out of range.
    pub fn resolution(
        &self,
        node_index: usize,
        excluded_leaves: &HashSet<usize>,
    ) -> Result<Vec<usize>, InvalidTree> {
        if node_index >= self.nodes.len() {
            return Err(invalid(format!("node index {node_index} is out of range")));
        }
        match &self.nodes[node_index] {
            Some(TreeNode::Leaf(_)) => {
                if excluded_leaves.contains(&(node_index / 2)) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![node_index])
                }
            }
            Some(TreeNode::Parent(parent)) => {
                let mut out = vec![node_index];
                for &leaf_index in &parent.unmerged_leaves {
                    if !excluded_leaves.contains(&leaf_index) && self.leaf(leaf_index)?.is_some() {
                        out.push(self.leaf_node_index(leaf_index)?);
                    }
                }
                Ok(out)
            }
            None => {
                let Some(&(left, right)) = self.children.get(&node_index) else {
                    return Ok(Vec::new());
                };
                let mut out = self.resolution(left, excluded_leaves)?;
                out.extend(self.resolution(right, excluded_leaves)?);
                Ok(out)
            }
        }
    }

    /// The highest nonblank leaf index, or `None` if all are blank.
    #[must_use]
    pub fn highest_occupied_leaf(&self) -> Option<usize> {
        (0..self.leaf_count)
            .rev()
            .find(|&leaf_index| matches!(self.leaf(leaf_index), Ok(Some(_))))
    }

    /// RFC 9420 §7.7 Add placement: leftmost blank leaf, else extend.
    ///
    /// A return value of `leaf_count` means the tree must grow.
    #[must_use]
    pub fn first_blank_or_extend(&self) -> usize {
        (0..self.leaf_count)
            .find(|&leaf_index| matches!(self.leaf(leaf_index), Ok(None)))
            .unwrap_or(self.leaf_count)
    }

    /// Blank a leaf and its direct path (RFC 9420 §7.7 Remove).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn remove_leaf(&mut self, leaf_index: usize) -> Result<(), InvalidTree> {
        self.set_leaf(leaf_index, None)?;
        for parent in self.direct_path(leaf_index)? {
            self.nodes[parent] = None;
        }
        Ok(())
    }

    /// Shrink past trailing blank leaves; return whether the tree shrank.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if a parent spanning a truncated leaf is not
    /// blank.
    pub fn truncate_trailing_blanks(&mut self) -> Result<bool, InvalidTree> {
        let top = self.highest_occupied_leaf();
        self.shrink_to(top.map_or(1, |top| top + 1))
    }

    fn shrink_to(&mut self, new_count: usize) -> Result<bool, InvalidTree> {
        if new_count >= self.leaf_count {
            return Ok(false);
        }
        let keep = 2 * new_count - 1;
        for leaf_index in new_count..self.leaf_count {
            for parent in self.direct_path(leaf_index)? {
                if parent < keep && self.nodes[parent].is_some() {
                    return Err(invalid(format!(
                        "parent {parent} spans a truncated leaf but is not blank"
                    )));
                }
            }
        }
        self.nodes.truncate(keep);
        self.leaf_count = new_count;
        self.children.clear();
        self.parent_of.clear();
        self.build_shape(0, new_count)?;
        Ok(true)
    }

    /// Count blank leaf and parent slots for diagnostics only.
    #[must_use]
    pub fn blank_count(&self) -> usize {
        self.nodes.iter().filter(|node| node.is_none()).count()
    }

    /// Count model HPKE recipients for one leaf's `UpdatePath`.
    ///
    /// This is the sum of the resolutions of the leaf's copath nodes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn wire_cost(&self, leaf_index: usize) -> Result<usize, InvalidTree> {
        Ok(self
            .update_path_resolutions(leaf_index)?
            .into_iter()
            .map(|(_, resolution)| resolution.len())
            .sum())
    }

    fn tree_hash_node(
        &self,
        node_index: usize,
        excluded_leaves: &HashSet<usize>,
    ) -> Result<Vec<u8>, InvalidTree> {
        if node_index % 2 == 0 {
            let leaf_index = node_index / 2;
            if excluded_leaves.contains(&leaf_index) {
                return Ok(digest(b"DMLS-model-blank-leaf-v1", &[]));
            }
            let Some(Some(TreeNode::Leaf(node))) = self.nodes.get(node_index) else {
                return Ok(digest(b"DMLS-model-blank-leaf-v1", &[]));
            };
            let generation = node.generation.to_be_bytes();
            return Ok(digest(
                b"DMLS-model-leaf-v1",
                &[
                    &node.identity,
                    &node.encryption_key,
                    &node.signature_key,
                    &node.parent_hash,
                    node.source.as_str().as_bytes(),
                    &generation,
                    &node.group_id,
                ],
            ));
        }

        let (left, right) = self.children(node_index)?;
        match self.nodes.get(node_index) {
            Some(Some(TreeNode::Parent(node))) => {
                let mut excluded = excluded_leaves.clone();
                excluded.extend(node.unmerged_leaves.iter().copied());
                Ok(digest(
                    b"DMLS-model-parent-v1",
                    &[
                        &node.encryption_key,
                        &node.parent_hash,
                        &self.tree_hash_node(left, &excluded)?,
                        &self.tree_hash_node(right, &excluded)?,
                    ],
                ))
            }
            _ => Ok(digest(
                b"DMLS-model-blank-parent-v1",
                &[
                    &self.tree_hash_node(left, excluded_leaves)?,
                    &self.tree_hash_node(right, excluded_leaves)?,
                ],
            )),
        }
    }

    /// Return a deterministic model hash of this tree (not MLS `TreeHash`).
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the tree shape is inconsistent.
    pub fn tree_hash(&self) -> Result<Vec<u8>, InvalidTree> {
        self.tree_hash_node(self.root(), &HashSet::new())
    }

    fn parent_hash_value(
        &self,
        parent_index: usize,
        ancestor_hash: &[u8],
        direct_child: usize,
    ) -> Result<Vec<u8>, InvalidTree> {
        let Some(Some(TreeNode::Parent(node))) = self.nodes.get(parent_index) else {
            return Err(invalid(format!(
                "node index {parent_index} is blank or not a parent"
            )));
        };
        let (left, right) = self.children(parent_index)?;
        let sibling = if direct_child == left { right } else { left };
        let excluded: HashSet<usize> = node.unmerged_leaves.iter().copied().collect();
        let sibling_hash = self.tree_hash_node(sibling, &excluded)?;
        Ok(digest(
            b"DMLS-model-parent-hash-v1",
            &[&node.encryption_key, ancestor_hash, &sibling_hash],
        ))
    }

    /// Check model-encoded leaf and parent hash links on one path.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range or the tree is
    /// inconsistent.
    pub fn verify_model_parent_hash_chain(&self, leaf_index: usize) -> Result<bool, InvalidTree> {
        let Some(leaf) = self.leaf(leaf_index)? else {
            return Ok(false);
        };
        if leaf.source != LeafSource::Commit {
            return Ok(leaf.parent_hash.is_empty());
        }
        let path = self.filtered_direct_path(leaf_index)?;
        if path.is_empty() {
            return Ok(leaf.parent_hash.is_empty());
        }

        let mut child_by_parent = HashMap::new();
        let mut child = self.leaf_node_index(leaf_index)?;
        for parent_index in self.direct_path(leaf_index)? {
            child_by_parent.insert(parent_index, child);
            child = parent_index;
        }

        let mut expected_by_parent = HashMap::new();
        let mut ancestor_hash: Vec<u8> = Vec::new();
        for &parent_index in path.iter().rev() {
            let Some(Some(TreeNode::Parent(node))) = self.nodes.get(parent_index) else {
                return Ok(false);
            };
            if node.parent_hash != ancestor_hash {
                return Ok(false);
            }
            let child = *child_by_parent
                .get(&parent_index)
                .ok_or_else(|| invalid("direct path is missing a child link"))?;
            let value = self.parent_hash_value(parent_index, &ancestor_hash, child)?;
            expected_by_parent.insert(parent_index, value.clone());
            ancestor_hash = value;
        }

        let last = *path
            .last()
            .ok_or_else(|| invalid("filtered direct path is empty"))?;
        Ok(leaf.parent_hash == expected_by_parent[&last])
    }
}

/// Return `2^d`, the smallest power-of-two leaf capacity for `member_count`.
///
/// # Errors
///
/// Returns [`InvalidTree`] if `member_count` is zero.
pub fn rfc9420_capacity(member_count: usize) -> Result<usize, InvalidTree> {
    if member_count == 0 {
        return Err(invalid("a ratchet tree must have at least one leaf"));
    }
    let shift = usize::BITS - (member_count - 1).leading_zeros();
    1usize
        .checked_shl(shift)
        .ok_or_else(|| invalid("member count exceeds the addressable tree size"))
}

/// RFC 9420 §4.1 perfect binary tree with blank padding.
///
/// The protocol tree always has `2^d` leaves; members occupy leaves
/// `0 .. member_count` and the remainder are blank. Every populated leaf has
/// the same structural depth `d`.
#[derive(Debug, Clone)]
pub struct Rfc9420Tree {
    tree: RatchetTree,
    member_count: usize,
    capacity: usize,
}

impl Rfc9420Tree {
    /// Create a tree for `member_count` members.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `member_count` is zero.
    pub fn new(member_count: usize) -> Result<Self, InvalidTree> {
        Self::with_nodes(member_count, None)
    }

    /// Create a tree with supplied nodes.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `member_count` is zero or the nodes are
    /// invalid for the padded capacity.
    pub fn with_nodes(
        member_count: usize,
        nodes: Option<Vec<Option<TreeNode>>>,
    ) -> Result<Self, InvalidTree> {
        if member_count == 0 {
            return Err(invalid("a ratchet tree must have at least one leaf"));
        }
        let capacity = rfc9420_capacity(member_count)?;
        let tree = match nodes {
            Some(nodes) => RatchetTree::with_nodes(capacity, nodes)?,
            None => RatchetTree::new(capacity)?,
        };
        for leaf_index in member_count..capacity {
            if tree.leaf(leaf_index)?.is_some() {
                return Err(invalid(format!("padding leaf {leaf_index} must be blank")));
            }
        }
        Ok(Self {
            tree,
            member_count,
            capacity,
        })
    }

    /// The number of actual members.
    #[must_use]
    pub fn member_count(&self) -> usize {
        self.member_count
    }

    /// The padded leaf capacity.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Structural depth of every populated leaf.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.capacity.ilog2() as usize
    }

    /// Leaf indices reserved as padding (all blank).
    #[must_use]
    pub fn blank_leaf_indices(&self) -> Vec<usize> {
        (self.member_count..self.capacity).collect()
    }

    /// Shrink to the smallest power-of-two capacity holding `new_count`.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `new_count` is zero or exceeds the current
    /// member count (this type never grows), or if a retained parent or a
    /// leaf past `new_count` is not blank. Nothing changes on error.
    pub fn shrink_to(&mut self, new_count: usize) -> Result<bool, InvalidTree> {
        if new_count > self.member_count {
            return Err(invalid("cannot shrink to more members than the tree holds"));
        }
        let capacity = rfc9420_capacity(new_count)?;
        for leaf_index in new_count..self.member_count {
            if self.tree.leaf(leaf_index)?.is_some() {
                return Err(invalid(format!(
                    "leaf {leaf_index} past the new member count is not blank"
                )));
            }
        }
        // Validates spanning parents before mutating; a no-op when the
        // capacity does not drop.
        let shrank = self.tree.shrink_to(capacity)?;
        self.member_count = new_count;
        self.capacity = capacity;
        Ok(shrank)
    }

    /// Set or clear a leaf. Populating a padding leaf is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the index is out of range or is padding
    /// and `node` is `Some`.
    pub fn set_leaf(
        &mut self,
        leaf_index: usize,
        node: Option<LeafNode>,
    ) -> Result<(), InvalidTree> {
        if node.is_some() && leaf_index >= self.member_count {
            return Err(invalid(format!(
                "leaf {leaf_index} is padding and must stay blank"
            )));
        }
        self.tree.set_leaf(leaf_index, node)
    }

    /// Set or clear a parent node.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if `node_index` is not a parent.
    pub fn set_parent(
        &mut self,
        node_index: usize,
        node: Option<ParentNode>,
    ) -> Result<(), InvalidTree> {
        self.tree.set_parent(node_index, node)
    }

    /// Blank a leaf and its direct path.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the leaf index is out of range.
    pub fn remove_leaf(&mut self, leaf_index: usize) -> Result<(), InvalidTree> {
        self.tree.remove_leaf(leaf_index)
    }

    /// Shrink past trailing blank members.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTree`] if the tree shape is inconsistent.
    pub fn truncate_trailing_blanks(&mut self) -> Result<bool, InvalidTree> {
        let top = self.tree.highest_occupied_leaf();
        let new_count = top.map_or(1, |top| top + 1).min(self.member_count);
        self.shrink_to(new_count)
    }
}

impl std::ops::Deref for Rfc9420Tree {
    type Target = RatchetTree;

    fn deref(&self) -> &Self::Target {
        &self.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filled_tree(leaf_count: usize) -> RatchetTree {
        let mut tree = RatchetTree::new(leaf_count).unwrap();
        for leaf_index in 0..leaf_count {
            tree.set_leaf(
                leaf_index,
                Some(LeafNode::new(
                    format!("u{leaf_index}").into_bytes(),
                    format!("k{leaf_index}").into_bytes(),
                )),
            )
            .unwrap();
        }
        tree
    }

    #[test]
    fn draft11_depth_distribution_matches_the_model() {
        let expected = [
            (2_usize, 1_u32, 1_usize, 1_usize),
            (3, 2, 1, 2),
            (4, 2, 2, 2),
            (5, 3, 1, 3),
            (6, 3, 2, 3),
            (9, 4, 1, 4),
            (16, 4, 4, 4),
        ];
        for (leaf_count, height, low, high) in expected {
            let tree = RatchetTree::new(leaf_count).unwrap();
            let depths: Vec<_> = (0..leaf_count)
                .map(|leaf| tree.leaf_depth(leaf).unwrap())
                .collect();
            assert_eq!(usize::BITS - (leaf_count - 1).leading_zeros(), height);
            assert_eq!(*depths.iter().min().unwrap(), low);
            assert_eq!(*depths.iter().max().unwrap(), high);
        }

        for exponent in 1..10 {
            let leaf_count = (1 << exponent) + 1;
            let tree = RatchetTree::new(leaf_count).unwrap();
            let depths: Vec<_> = (0..leaf_count)
                .map(|leaf| tree.leaf_depth(leaf).unwrap())
                .collect();
            assert_eq!(depths.last().copied(), Some(1));
            assert!(depths[..leaf_count - 1]
                .iter()
                .all(|&depth| depth == exponent + 1));
        }
    }

    #[test]
    fn rfc9420_tree_pads_to_the_next_power_of_two() {
        for member_count in 1..=512 {
            let tree = Rfc9420Tree::new(member_count).unwrap();
            let capacity = rfc9420_capacity(member_count).unwrap();
            assert_eq!(tree.capacity(), capacity);
            assert_eq!(tree.leaf_count(), capacity);
            assert_eq!(tree.depth(), capacity.ilog2() as usize);
            assert!(tree
                .blank_leaf_indices()
                .iter()
                .all(|&leaf| tree.leaf(leaf).unwrap().is_none()));
            for leaf in 0..capacity {
                assert_eq!(tree.leaf_depth(leaf).unwrap(), tree.depth());
            }
        }
    }

    #[test]
    fn resolution_and_wire_cost_follow_exclusion_rules() {
        let mut tree = RatchetTree::new(4).unwrap();
        for leaf_index in 0..4 {
            tree.set_leaf(
                leaf_index,
                Some(LeafNode::new(
                    format!("u{leaf_index}").into_bytes(),
                    format!("k{leaf_index}").into_bytes(),
                )),
            )
            .unwrap();
        }
        tree.set_parent(
            1,
            Some(ParentNode::new(b"p1".to_vec()).with_unmerged_leaves([1])),
        )
        .unwrap();
        assert_eq!(tree.resolution(1, &HashSet::new()).unwrap(), vec![1, 2]);
        assert_eq!(tree.resolution(1, &HashSet::from([1])).unwrap(), vec![1]);

        let mut sparse = filled_tree(9);
        for node_index in (1..sparse.nodes().len()).step_by(2) {
            sparse
                .set_parent(node_index, Some(ParentNode::new(format!("p{node_index}"))))
                .unwrap();
        }
        assert_eq!(sparse.wire_cost(0).unwrap(), 4);
        assert_eq!(sparse.wire_cost(8).unwrap(), 1);

        for node_index in sparse.direct_path(0).unwrap() {
            sparse.set_parent(node_index, None).unwrap();
        }
        assert_eq!(sparse.wire_cost(8).unwrap(), 4);
        assert_eq!(sparse.filtered_direct_path(0).unwrap(), vec![1, 3, 7, 15]);
    }

    #[test]
    fn removal_blanks_the_direct_path_and_truncation_shrinks() {
        let mut tree = filled_tree(3);
        assert_eq!(tree.highest_occupied_leaf(), Some(2));
        tree.remove_leaf(2).unwrap();
        assert_eq!(tree.highest_occupied_leaf(), Some(1));
        assert!(tree.truncate_trailing_blanks().unwrap());
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.root(), 1);
    }

    #[test]
    fn add_placement_uses_the_leftmost_blank() {
        let mut tree = filled_tree(4);
        assert_eq!(tree.first_blank_or_extend(), 4);
        tree.remove_leaf(1).unwrap();
        assert_eq!(tree.first_blank_or_extend(), 1);
    }

    fn populated(leaf_count: usize) -> RatchetTree {
        let mut tree = filled_tree(leaf_count);
        for node_index in (1..tree.nodes().len()).step_by(2) {
            tree.set_parent(node_index, Some(ParentNode::new(format!("p{node_index}"))))
                .unwrap();
        }
        tree
    }

    #[test]
    fn wire_cost_513_and_truncation_match_the_model() {
        let mut tree = populated(513);
        assert_eq!(tree.copath(512).unwrap(), vec![511]);
        assert_eq!(
            (tree.wire_cost(0).unwrap(), tree.wire_cost(512).unwrap()),
            (10, 1)
        );
        tree.remove_leaf(5).unwrap();
        assert_eq!(
            (tree.wire_cost(0).unwrap(), tree.wire_cost(512).unwrap()),
            (11, 9)
        );
        assert_eq!(tree.first_blank_or_extend(), 5);

        let mut draft = populated(600);
        for leaf_index in 500..600 {
            draft.remove_leaf(leaf_index).unwrap();
        }
        assert!(draft.truncate_trailing_blanks().unwrap());
        assert_eq!(draft.leaf_count(), 500);
        assert_eq!(draft.nodes().len(), 999);

        let mut skipped = populated(600);
        for leaf_index in 500..600 {
            skipped.set_leaf(leaf_index, None).unwrap();
        }
        assert!(skipped.truncate_trailing_blanks().is_err());
        assert_eq!(skipped.leaf_count(), 600);

        let mut rfc = Rfc9420Tree::new(600).unwrap();
        for leaf_index in 0..rfc.member_count() {
            rfc.set_leaf(
                leaf_index,
                Some(LeafNode::new(
                    format!("u{leaf_index}").into_bytes(),
                    format!("k{leaf_index}").into_bytes(),
                )),
            )
            .unwrap();
        }
        for node_index in (1..rfc.nodes().len()).step_by(2) {
            rfc.set_parent(node_index, Some(ParentNode::new(format!("p{node_index}"))))
                .unwrap();
        }
        for leaf_index in 300..rfc.leaf_count() {
            rfc.remove_leaf(leaf_index).unwrap();
        }
        let keep = 2 * 512 - 1;
        let left = rfc.nodes()[..keep].to_vec();
        assert!(rfc.truncate_trailing_blanks().unwrap());
        assert_eq!(rfc.capacity(), 512);
        assert_eq!(rfc.member_count(), 300);
        assert_eq!(&rfc.nodes()[..keep], &left[..]);
    }

    #[test]
    fn rfc_tree_rejects_padding_and_invalid_shrinks_without_mutating() {
        let mut rfc = Rfc9420Tree::new(5).unwrap();
        assert_eq!((rfc.member_count(), rfc.capacity()), (5, 8));
        let leaf = LeafNode::new(b"x".to_vec(), b"k".to_vec());
        assert!(rfc.set_leaf(6, Some(leaf.clone())).is_err());
        assert!(rfc.shrink_to(9).is_err());
        assert_eq!((rfc.member_count(), rfc.capacity()), (5, 8));

        let mut nodes = vec![None; 15];
        nodes[12] = Some(TreeNode::Leaf(leaf));
        assert!(Rfc9420Tree::with_nodes(5, Some(nodes)).is_err());
    }

    #[test]
    fn model_digests_match_the_python_reference() {
        let mut tree = filled_tree(4);
        tree.set_parent(
            1,
            Some(ParentNode::new(b"p1".to_vec()).with_unmerged_leaves([1])),
        )
        .unwrap();
        assert_eq!(
            hex::encode(tree.tree_hash().unwrap()),
            "ca447eed1df77e716a71218aaa7fad75f626981b4d5d043a22376bf8cf26d210"
        );

        let key_package = LeafNode::new(b"alice".to_vec(), b"key".to_vec());
        assert_eq!(
            hex::encode(leaf_tbs(&key_package, None).unwrap()),
            "830aa7928a192c74fbabd3303d8bad485496d10ad7382f8455f9b40a31a6582c"
        );

        let update = key_package
            .with_source(LeafSource::Update)
            .with_group_id(b"g".to_vec());
        assert_eq!(
            hex::encode(leaf_tbs(&update, Some(0)).unwrap()),
            "638fd9ffeb659afbeb467f6dc66aa28af259e19bd970070c59bb8cd5ae2cd59a"
        );
    }

    #[test]
    fn leaf_tbs_binds_slot_for_update_and_commit_leaves() {
        let key_package = LeafNode::new(b"alice".to_vec(), b"key".to_vec());
        let update = key_package.clone().with_source(LeafSource::Update);
        assert!(leaf_tbs(&key_package, None).is_ok());
        assert!(leaf_tbs(&update, None).is_err());
        assert_ne!(
            leaf_tbs(&update, Some(0)).unwrap(),
            leaf_tbs(&update, Some(1)).unwrap()
        );
    }
}
