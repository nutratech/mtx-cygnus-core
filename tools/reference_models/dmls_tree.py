#!/usr/bin/env python3
"""Structural reference model for the MLS ratchet tree used by DMLS.

Two shapes are modelled because they are not the same tree:

* ``RatchetTree`` is the draft-11 left-balanced shape for an arbitrary leaf
  count (``2*n - 1`` nodes). Leaf depth varies, and for ``n = 2^k + 1`` the
  right-most leaf is a direct child of the root.
* ``Rfc9420Tree`` is the RFC 9420 §4.1 perfect tree: leaf capacity is the next
  power of two, unused leaves are blank, and every populated leaf has the same
  depth. The two coincide at power-of-two leaf counts, which is why the
  official tree-math vectors (all powers of two) cannot distinguish them.

Blank nodes, direct paths, copaths, resolutions, tree hashes, and parent-hash
relationships are modelled here. This is not a wire-compatible MLS
implementation: LeafNode and ParentNode values are reduced to the fields needed
for structural experiments, and the hash encodings below are model encodings
rather than MLS TLS encoding.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set, Tuple, Union

import blake3


class InvalidTree(ValueError):
    """The tree shape or a requested tree operation is invalid."""


U64_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class LeafNode:
    identity: bytes
    encryption_key: bytes
    parent_hash: bytes = b""
    source: str = "key_package"
    generation: int = 0
    group_id: bytes = b""
    # RFC 9420 LeafNode.signature_key, kept distinct from the HPKE key above.
    signature_key: bytes = b""
    # RFC 9420 LeafNode.signature over ``leaf_tbs``; ``source`` is
    # leaf_node_source ("key_package", "update" or "commit").
    signature: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.generation <= U64_MAX:
            raise InvalidTree("leaf generation must fit in an unsigned 64-bit integer")


@dataclass(frozen=True)
class ParentNode:
    encryption_key: bytes
    parent_hash: bytes = b""
    unmerged_leaves: Tuple[int, ...] = ()


TreeNode = Union[LeafNode, ParentNode]


def _largest_power_of_two_below(value: int) -> int:
    """Return the largest power of two strictly less than ``value``."""
    if value < 2:
        raise InvalidTree("a split needs at least two leaves")
    return 1 << ((value - 1).bit_length() - 1)


def _lp(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _digest(tag: bytes, *parts: bytes) -> bytes:
    h = blake3.blake3()
    h.update(tag)
    for part in parts:
        h.update(_lp(part))
    return h.digest()


def leaf_tbs(leaf: LeafNode, leaf_index: Optional[int] = None) -> bytes:
    """Model of RFC 9420 §7.2 LeafNodeTBS (model encoding, not TLS).

    A "key_package" leaf is signed before its slot is known, so ``group_id`` and
    ``leaf_index`` are omitted; "update" and "commit" leaves bind both, so a
    valid signed leaf cannot be replanted at another position or group.
    """
    parts = [
        leaf.source.encode(),
        leaf.identity,
        leaf.encryption_key,
        leaf.signature_key,
        leaf.generation.to_bytes(8, "big"),
    ]
    if leaf.source != "key_package":
        if leaf_index is None:
            raise InvalidTree("update/commit leaves are signed with a leaf_index")
        parts += [leaf.group_id, leaf_index.to_bytes(4, "big")]
    return _digest(b"DMLS-model-leaf-tbs-v1", *parts)


class RatchetTree:
    """Flat-array model of the RFC's left-balanced ratchet-tree topology.

    Leaves use even node indices (``2 * leaf_index``); parent nodes use odd
    indices. For ``n`` leaves, the backing array has ``2*n - 1`` slots. A
    subtree with a non-power-of-two leaf count splits at the largest power of
    two below that count, matching the MLS left-balanced shape.
    """

    def __init__(
        self, leaf_count: int, nodes: Optional[Iterable[Optional[TreeNode]]] = None
    ):
        if leaf_count < 1:
            raise InvalidTree("a ratchet tree must have at least one leaf")
        self.leaf_count = leaf_count
        self.nodes: List[Optional[TreeNode]] = [None] * (2 * leaf_count - 1)
        self._children: Dict[int, Tuple[int, int]] = {}
        self._parent: Dict[int, int] = {}
        self._build_shape(0, leaf_count)
        if nodes is not None:
            supplied = list(nodes)
            if len(supplied) != len(self.nodes):
                raise InvalidTree("node array length must be 2 * leaf_count - 1")
            self.nodes = supplied
            self._validate_node_kinds()

    def _build_shape(self, first_leaf: int, count: int) -> int:
        if count == 1:
            return 2 * first_leaf
        left_count = _largest_power_of_two_below(count)
        left_root = self._build_shape(first_leaf, left_count)
        right_root = self._build_shape(first_leaf + left_count, count - left_count)
        root = 2 * first_leaf + 2 * left_count - 1
        self._children[root] = (left_root, right_root)
        self._parent[left_root] = root
        self._parent[right_root] = root
        return root

    @property
    def root(self) -> int:
        return self._root_for(0, self.leaf_count)

    @staticmethod
    def _root_for(first_leaf: int, count: int) -> int:
        if count == 1:
            return 2 * first_leaf
        left_count = _largest_power_of_two_below(count)
        return 2 * first_leaf + 2 * left_count - 1

    def _validate_node_kinds(self) -> None:
        for index, node in enumerate(self.nodes):
            if node is None:
                continue
            if index % 2 == 0 and not isinstance(node, LeafNode):
                raise InvalidTree(f"even node index {index} must contain a leaf")
            if index % 2 == 1 and not isinstance(node, ParentNode):
                raise InvalidTree(f"odd node index {index} must contain a parent")

    def leaf_node_index(self, leaf_index: int) -> int:
        if not 0 <= leaf_index < self.leaf_count:
            raise InvalidTree(f"leaf index {leaf_index} is out of range")
        return 2 * leaf_index

    def leaf(self, leaf_index: int) -> Optional[LeafNode]:
        node = self.nodes[self.leaf_node_index(leaf_index)]
        return node if isinstance(node, LeafNode) else None

    def set_leaf(self, leaf_index: int, node: Optional[LeafNode]) -> None:
        """Set a leaf slot, rejecting parent nodes at even indices."""
        if node is not None and not isinstance(node, LeafNode):
            raise InvalidTree("leaf slots can only contain LeafNode values")
        self.nodes[self.leaf_node_index(leaf_index)] = node

    def set_parent(self, node_index: int, node: Optional[ParentNode]) -> None:
        if node_index not in self._children:
            raise InvalidTree(f"node index {node_index} is not a parent")
        if node is not None and not isinstance(node, ParentNode):
            raise InvalidTree("parent slots can only contain ParentNode values")
        self.nodes[node_index] = node

    def children(self, node_index: int) -> Tuple[int, int]:
        try:
            return self._children[node_index]
        except KeyError as exc:
            raise InvalidTree(f"node index {node_index} is not a parent") from exc

    def parent(self, node_index: int) -> Optional[int]:
        if not 0 <= node_index < len(self.nodes):
            raise InvalidTree(f"node index {node_index} is out of range")
        return self._parent.get(node_index)

    def direct_path(self, leaf_index: int) -> List[int]:
        """Return parent node indices from the leaf's parent up to the root."""
        current = self.leaf_node_index(leaf_index)
        path: List[int] = []
        parent = self.parent(current)
        while parent is not None:
            path.append(parent)
            current = parent
            parent = self.parent(current)
        return path

    def leaf_depth(self, leaf_index: int) -> int:
        """Return a leaf's structural depth, regardless of blank nodes."""
        return len(self.direct_path(leaf_index))

    def copath(self, leaf_index: int) -> List[int]:
        """Return sibling subtree roots corresponding to ``direct_path``."""
        current = self.leaf_node_index(leaf_index)
        siblings: List[int] = []
        while (parent := self.parent(current)) is not None:
            left, right = self.children(parent)
            siblings.append(right if current == left else left)
            current = parent
        return siblings

    def filtered_direct_path(self, leaf_index: int) -> List[int]:
        return [parent for parent, _ in self.update_path_resolutions(leaf_index)]

    def update_path_resolutions(self, leaf_index: int) -> List[Tuple[int, List[int]]]:
        """Return each filtered direct-path node and its copath recipients."""
        return [
            (parent, resolution)
            for parent, sibling in zip(
                self.direct_path(leaf_index), self.copath(leaf_index)
            )
            if (resolution := self.resolution(sibling))
        ]

    def resolution(
        self, node_index: int, excluded_leaves: Optional[Set[int]] = None
    ) -> List[int]:
        """Return nonblank key-bearing nodes resolving a subtree.

        A nonblank parent contributes itself and its unmerged leaves. A blank
        parent is recursively resolved through its children. ``excluded_leaves``
        contains leaf indices omitted from this resolution, as required when
        resolving copaths for an UpdatePath.
        """
        if not 0 <= node_index < len(self.nodes):
            raise InvalidTree(f"node index {node_index} is out of range")
        if excluded_leaves is None:
            excluded_leaves = set()
        node = self.nodes[node_index]
        if isinstance(node, LeafNode):
            return [] if node_index // 2 in excluded_leaves else [node_index]
        if isinstance(node, ParentNode):
            out = [node_index]
            for leaf_index in node.unmerged_leaves:
                leaf_node_index = self.leaf_node_index(leaf_index)
                if (
                    leaf_index not in excluded_leaves
                    and self.leaf(leaf_index) is not None
                ):
                    out.append(leaf_node_index)
            return out
        if node_index not in self._children:
            return []
        left, right = self.children(node_index)
        return self.resolution(left, excluded_leaves) + self.resolution(
            right, excluded_leaves
        )

    def highest_occupied_leaf(self) -> Optional[int]:
        """Return the highest nonblank leaf index, or None if all are blank."""
        for leaf_index in range(self.leaf_count - 1, -1, -1):
            if self.leaf(leaf_index) is not None:
                return leaf_index
        return None

    def first_blank_or_extend(self) -> int:
        """RFC 9420 §7.7 Add placement: leftmost blank leaf, else extend.

        Every member derives the same slot, so joiners never choose one. A
        return value of ``leaf_count`` means the tree must grow.
        """
        for leaf_index in range(self.leaf_count):
            if self.leaf(leaf_index) is None:
                return leaf_index
        return self.leaf_count

    def remove_leaf(self, leaf_index: int) -> None:
        """Blank a leaf and its direct path (RFC 9420 §7.7 Remove)."""
        self.set_leaf(leaf_index, None)
        for parent in self.direct_path(leaf_index):
            self.nodes[parent] = None

    def truncate_trailing_blanks(self) -> bool:
        """Shrink past trailing blank leaves; return whether the tree shrank.

        Truncation only drops array slots. ``remove_leaf`` has already blanked
        the direct path of every removed leaf, so no surviving parent can have a
        changed span; a nonblank one means the caller skipped Remove, and the
        tree is left untouched.
        """
        top = self.highest_occupied_leaf()
        return self._shrink_to(1 if top is None else top + 1)

    def _shrink_to(self, new_count: int) -> bool:
        if new_count >= self.leaf_count:
            return False
        keep = 2 * new_count - 1
        for leaf_index in range(new_count, self.leaf_count):
            for parent in self.direct_path(leaf_index):
                if parent < keep and self.nodes[parent] is not None:
                    raise InvalidTree(
                        f"parent {parent} spans a truncated leaf but is not blank"
                    )
        self.nodes = self.nodes[:keep]
        self.leaf_count = new_count
        self._children = {}
        self._parent = {}
        self._build_shape(0, new_count)
        return True

    def blank_count(self) -> int:
        """Count blank leaf and parent slots for diagnostics only."""
        return sum(node is None for node in self.nodes)

    def wire_cost(self, leaf_index: int) -> int:
        """Count model HPKE recipients for one leaf's UpdatePath.

        This is the sum of the resolutions of the leaf's copath nodes, i.e. the
        number of ciphertexts an UpdatePath from this leaf would carry. It is
        positional: it depends on which copath subtrees are blank, not only on
        structural depth.
        """
        return sum(
            len(resolution)
            for _, resolution in self.update_path_resolutions(leaf_index)
        )

    def _tree_hash(
        self, node_index: int, excluded_leaves: Optional[Set[int]] = None
    ) -> bytes:
        if excluded_leaves is None:
            excluded_leaves = set()
        if node_index % 2 == 0:
            leaf_index = node_index // 2
            node = None if leaf_index in excluded_leaves else self.nodes[node_index]
            if not isinstance(node, LeafNode):
                return _digest(b"DMLS-model-blank-leaf-v1")
            return _digest(
                b"DMLS-model-leaf-v1",
                node.identity,
                node.encryption_key,
                node.signature_key,
                node.parent_hash,
                node.source.encode("utf-8"),
                node.generation.to_bytes(8, "big", signed=False),
                node.group_id,
            )

        node = self.nodes[node_index]
        if not isinstance(node, ParentNode):
            return _digest(
                b"DMLS-model-blank-parent-v1",
                self._tree_hash(self._children[node_index][0], excluded_leaves),
                self._tree_hash(self._children[node_index][1], excluded_leaves),
            )
        excluded = set(excluded_leaves)
        excluded.update(node.unmerged_leaves)
        left, right = self._children[node_index]
        return _digest(
            b"DMLS-model-parent-v1",
            node.encryption_key,
            node.parent_hash,
            self._tree_hash(left, excluded),
            self._tree_hash(right, excluded),
        )

    def tree_hash(self) -> bytes:
        """Return a deterministic model hash of this tree (not MLS TreeHash)."""
        return self._tree_hash(self.root)

    def _parent_hash_value(
        self, parent_index: int, ancestor_hash: bytes, direct_child: int
    ) -> bytes:
        node = self.nodes[parent_index]
        if not isinstance(node, ParentNode):
            raise InvalidTree(f"node index {parent_index} is blank or not a parent")
        left, right = self.children(parent_index)
        sibling = right if direct_child == left else left
        sibling_hash = self._tree_hash(sibling, set(node.unmerged_leaves))
        return _digest(
            b"DMLS-model-parent-hash-v1",
            node.encryption_key,
            ancestor_hash,
            sibling_hash,
        )

    def verify_model_parent_hash_chain(self, leaf_index: int) -> bool:
        """Check model-encoded LeafNode and ParentNode hash links on one path.

        The hash inputs are the model encodings documented in this module's
        docstring. This validates structural chaining for vectors; MLS wire
        interoperability requires the RFC's TLS encodings and signature checks.
        """
        leaf = self.leaf(leaf_index)
        if leaf is None:
            return False
        if leaf.source != "commit":
            return leaf.parent_hash == b""
        path = self.filtered_direct_path(leaf_index)
        if not path:
            return leaf.parent_hash == b""

        child_by_parent: Dict[int, int] = {}
        child = self.leaf_node_index(leaf_index)
        for parent_index in self.direct_path(leaf_index):
            child_by_parent[parent_index] = child
            child = parent_index

        expected_by_parent: Dict[int, bytes] = {}
        ancestor_hash = b""
        # Compute parent-hash values from root down toward the leaf.
        for parent_index in reversed(path):
            node = self.nodes[parent_index]
            assert isinstance(node, ParentNode)
            if node.parent_hash != ancestor_hash:
                return False
            value = self._parent_hash_value(
                parent_index, ancestor_hash, child_by_parent[parent_index]
            )
            expected_by_parent[parent_index] = value
            ancestor_hash = value

        return leaf.parent_hash == expected_by_parent[path[-1]]


def rfc9420_capacity(member_count: int) -> int:
    """Return ``2^d``, the smallest power-of-two leaf capacity for members."""
    if member_count < 1:
        raise InvalidTree("a ratchet tree must have at least one leaf")
    return 1 << (member_count - 1).bit_length()


class Rfc9420Tree(RatchetTree):
    """RFC 9420 §4.1 perfect binary tree with blank padding.

    The protocol tree always has ``2^d`` leaves; members occupy leaves
    ``0 .. member_count-1`` and the remainder are blank. Every populated leaf
    therefore has the same structural depth ``d``. Use ``RatchetTree`` only
    when deliberately modelling the draft-11 arbitrary-leaf-count shape.
    """

    def __init__(
        self,
        member_count: int,
        nodes: Optional[Iterable[Optional[TreeNode]]] = None,
    ):
        if member_count < 1:
            raise InvalidTree("a ratchet tree must have at least one leaf")
        self.member_count = member_count
        self.capacity = rfc9420_capacity(member_count)
        super().__init__(self.capacity, nodes)

    @property
    def depth(self) -> int:
        """Structural depth of every populated leaf."""
        return self.capacity.bit_length() - 1

    def blank_leaf_indices(self) -> List[int]:
        """Leaf indices reserved as padding (all blank)."""
        return list(range(self.member_count, self.capacity))

    def _shrink_to(self, new_count: int) -> bool:
        """Shrink to the smallest power-of-two capacity holding ``new_count``.

        The kept left subtree keeps its node indices and spans; the old root and
        right half are dropped, so nothing is blanked.
        """
        capacity = rfc9420_capacity(new_count)
        self.member_count = new_count
        if capacity >= self.capacity:
            return False
        self.nodes = self.nodes[: 2 * capacity - 1]
        self.capacity = capacity
        self.leaf_count = capacity
        self._children = {}
        self._parent = {}
        self._build_shape(0, capacity)
        return True


if __name__ == "__main__":
    # A tiny smoke demonstration; protocol vectors belong in a separate module.
    tree = RatchetTree(3)
    tree.set_leaf(0, LeafNode(b"alice", b"alice-key"))
    tree.set_leaf(1, LeafNode(b"bob", b"bob-key"))
    tree.set_leaf(2, LeafNode(b"carol", b"carol-key"))
    print(tree.tree_hash().hex())
