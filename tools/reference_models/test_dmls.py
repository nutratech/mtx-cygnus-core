#!/usr/bin/env python3
"""Conformance checks and vector generation for the DMLS reference models.

Run from any directory with ``python3 proposals/test_dmls.py`` (the model
digests require the ``blake3`` package). The vendored upstream tree-math
fixture is the conformance oracle; ``dmls_vectors.json`` stores compact derived
metadata, fixture provenance, and DMLS scenarios.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import blake3
import pid_ref as pid_crypto
from dmls_00fc import (
    DeviceRoot,
    DeviceRootRegistry,
    UncertifiedDevice,
    plan_with_device_roots,
)
from dmls_merge import (
    Branch,
    DmlsMergeState,
    ExternalJoinStatus,
    ExtremityId,
    IdentityMismatch,
    LeafRecord,
    MemberId,
    MembershipConflict,
    MissingBaseState,
    PrincipalDevice,
    _descends_from,
    external_join_status,
    plan_merge,
    select_base,
    validate_update_candidate,
)
from dmls_tree import InvalidTree, LeafNode, ParentNode, RatchetTree, Rfc9420Tree
from pid_cutover import Event as CutoverEvent
from pid_cutover import resolve_root
from pid_pdu import device_bundle

HERE = Path(__file__).resolve().parent
OFFICIAL_TREE_MATH = HERE / "dmls_tree_math_vectors.json"
OUTPUT_VECTORS = HERE / "dmls_vectors.json"
# The sizes covered by the upstream mlswg/mls-implementations fixture.
OFFICIAL_SIZES = tuple(1 << exponent for exponent in range(10))


def _lbbt_level(node_index: int) -> int:
    """Return trailing-one count used by draft-11 LBBT tree math."""
    return (~node_index & (node_index + 1)).bit_length() - 1


def _lbbt_root(leaf_count: int) -> int:
    width = 2 * leaf_count - 1
    return (1 << (width.bit_length() - 1)) - 1


def _lbbt_left(node_index: int) -> int:
    level = _lbbt_level(node_index)
    assert level > 0
    return node_index ^ (1 << (level - 1))


def _lbbt_right(node_index: int, leaf_count: int) -> int:
    level = _lbbt_level(node_index)
    assert level > 0
    right = node_index ^ (3 << (level - 1))
    while right >= 2 * leaf_count - 1:
        right = _lbbt_left(right)
    return right


def _accept_all_leaves(
    leaf: LeafNode, leaf_index: Optional[int], for_update: bool
) -> bool:
    """Stub verifier for structural tests whose leaves are unsigned."""
    return True


def _mock_principal_of(leaf: LeafNode) -> PrincipalDevice:
    """Decode test-only ``principal:device`` identities."""
    user, device = leaf.identity.decode("utf-8").split(":", maxsplit=1)
    return PrincipalDevice(
        principal=user.encode("utf-8"),
        device_id=device,
        user_epoch_height=1,
        device_root_generation=1,
    )


def _make_branch(
    epoch: int,
    digest_byte: int,
    members: Dict[MemberId, LeafRecord],
    **kwargs,
) -> Branch:
    return Branch(
        extremity=ExtremityId(epoch, bytes([digest_byte]) * 32),
        parent_transcript_hash=b"p" * 32,
        members=members,
        **kwargs,
    )


def _json_digest(value: object) -> str:
    """Hash canonical compact JSON with BLAKE3 for reproducible vector records."""
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return blake3.blake3(encoded).hexdigest()


def build_official_tree_math_vectors() -> List[dict]:
    """Check the vendored official vectors and closed-form tree math."""
    vectors = json.loads(OFFICIAL_TREE_MATH.read_text(encoding="utf-8"))
    generated: List[dict] = []
    assert tuple(vector["n_leaves"] for vector in vectors) == OFFICIAL_SIZES
    for vector in vectors:
        leaf_count = vector["n_leaves"]
        tree = Rfc9420Tree(leaf_count)
        assert tree.capacity == leaf_count
        assert tree.root == _lbbt_root(leaf_count) == leaf_count - 1
        assert len(tree.nodes) == vector["n_nodes"] == 2 * leaf_count - 1
        parents: Dict[int, Optional[int]] = {
            index: None for index in range(2 * leaf_count - 1)
        }
        siblings: Dict[int, Optional[int]] = {
            index: None for index in range(2 * leaf_count - 1)
        }
        for node_index in range(1, 2 * leaf_count - 1, 2):
            left = _lbbt_left(node_index)
            right = _lbbt_right(node_index, leaf_count)
            assert tree.children(node_index) == (left, right)
            parents[left] = node_index
            parents[right] = node_index
            siblings[left] = right
            siblings[right] = left

        shape = []
        for node_index in range(2 * leaf_count - 1):
            assert tree.parent(node_index) == parents[node_index]
            assert tree.parent(node_index) == vector["parent"][node_index]
            children = list(tree.children(node_index)) if node_index % 2 == 1 else None
            if children is None:
                assert vector["left"][node_index] is None
            else:
                assert children == [
                    vector["left"][node_index],
                    vector["right"][node_index],
                ]
            parent = tree.parent(node_index)
            sibling = None
            if parent is not None:
                left_child, right_child = tree.children(parent)
                sibling = right_child if node_index == left_child else left_child
            assert sibling == vector["sibling"][node_index]
            shape.append(
                {
                    "node": node_index,
                    "parent": parents[node_index],
                    "children": children,
                }
            )
        paths = []
        for leaf_index in range(leaf_count):
            expected_path: List[int] = []
            current = 2 * leaf_index
            while parents[current] is not None:
                parent = parents[current]
                assert parent is not None
                current = parent
                expected_path.append(parent)
            expected_copath = (
                []
                if leaf_count == 1
                else [siblings[node] for node in [2 * leaf_index] + expected_path[:-1]]
            )
            assert tree.direct_path(leaf_index) == expected_path
            assert tree.copath(leaf_index) == expected_copath
            paths.append(
                {
                    "leaf": leaf_index,
                    "direct_path": expected_path,
                    "copath": expected_copath,
                }
            )

        generated.append(
            {
                "leaf_capacity": leaf_count,
                "node_count": len(tree.nodes),
                "root": tree.root,
                "tree_blake3": _json_digest(shape),
                "paths_blake3": _json_digest(paths),
                "vector_blake3": _json_digest(vector),
            }
        )
    return generated


def build_draft11_tree_math_vectors() -> List[dict]:
    """Check exact-size draft-11 LBBT math separately from RFC capacities."""
    generated = []
    for leaf_count in range(1, 129):
        tree = RatchetTree(leaf_count)
        assert tree.root == _lbbt_root(leaf_count)
        parents: Dict[int, Optional[int]] = {
            index: None for index in range(2 * leaf_count - 1)
        }
        siblings: Dict[int, Optional[int]] = {
            index: None for index in range(2 * leaf_count - 1)
        }
        for node_index in range(1, 2 * leaf_count - 1, 2):
            left = _lbbt_left(node_index)
            right = _lbbt_right(node_index, leaf_count)
            assert tree.children(node_index) == (left, right)
            parents[left] = node_index
            parents[right] = node_index
            siblings[left] = right
            siblings[right] = left
        for node_index in range(2 * leaf_count - 1):
            assert tree.parent(node_index) == parents[node_index]
        for leaf_index in range(leaf_count):
            expected_path: List[int] = []
            current = 2 * leaf_index
            while parents[current] is not None:
                parent = parents[current]
                assert parent is not None
                current = parent
                expected_path.append(parent)
            expected_copath = (
                []
                if leaf_count == 1
                else [siblings[node] for node in [2 * leaf_index] + expected_path[:-1]]
            )
            assert tree.direct_path(leaf_index) == expected_path
            assert tree.copath(leaf_index) == expected_copath
        generated.append(
            {
                "leaf_count": leaf_count,
                "root": tree.root,
                "node_count": len(tree.nodes),
                "topology_blake3": _json_digest(
                    [
                        {
                            "node": node,
                            "parent": parents[node],
                            "children": (
                                list(tree.children(node)) if node % 2 == 1 else None
                            ),
                        }
                        for node in range(len(tree.nodes))
                    ]
                ),
            }
        )
    return generated


def build_member_count_vectors() -> List[dict]:
    """Check all requested member counts through 512 against RFC capacity rules.

    The tree shape for a member count is fully described by its power-of-two
    ``leaf_capacity``; the per-size digest lives in ``official_tree_math``, so
    it is not repeated on every row here.
    """
    generated = []
    for member_count in range(1, 513):
        tree = Rfc9420Tree(member_count)
        depth = tree.capacity.bit_length() - 1
        assert tree.leaf_count == tree.capacity
        assert all(tree.leaf_depth(i) == depth for i in range(tree.capacity))
        assert tree.blank_leaf_indices() == list(range(member_count, tree.capacity))
        generated.append(
            {
                "member_count": member_count,
                "leaf_capacity": tree.capacity,
                "structural_depth": depth,
                "blank_leaf_count": tree.capacity - member_count,
            }
        )
    return generated


def check_draft11_depth_distribution() -> dict:
    """Keep historical positional-depth claims separate from RFC tree math."""
    expected: Dict[int, Tuple[int, int, int, float, List[int]]] = {
        2: (1, 1, 1, 1.0, [0, 1]),
        3: (2, 1, 2, 5 / 3, [2]),
        4: (2, 2, 2, 2.0, [0, 1, 2, 3]),
        5: (3, 1, 3, 2.6, [4]),
        6: (3, 2, 3, 8 / 3, [4, 5]),
        9: (4, 1, 4, 11 / 3, [8]),
        16: (4, 4, 4, 4.0, list(range(16))),
    }
    results = {}
    for leaf_count, (height, low, high, mean, shallow) in expected.items():
        tree = RatchetTree(leaf_count)
        depths = [tree.leaf_depth(i) for i in range(leaf_count)]
        assert math.ceil(math.log2(leaf_count)) == height
        assert (min(depths), max(depths)) == (low, high)
        assert math.isclose(sum(depths) / leaf_count, mean, rel_tol=1e-9)
        assert [i for i, value in enumerate(depths) if value == low] == shallow
        results[str(leaf_count)] = depths

    for exponent in range(1, 10):
        leaf_count = (1 << exponent) + 1
        tree = RatchetTree(leaf_count)
        depths = [tree.leaf_depth(i) for i in range(leaf_count)]
        assert depths[-1] == 1
        assert all(value == exponent + 1 for value in depths[:-1])
    return results


def check_resolution_and_wire_cost() -> dict:
    """Check exclusion semantics and the effect of blanking a direct path."""
    tree = RatchetTree(4)
    for leaf_index in range(4):
        tree.set_leaf(
            leaf_index,
            LeafNode(f"u{leaf_index}".encode(), f"k{leaf_index}".encode()),
        )
    tree.set_parent(1, ParentNode(b"p1", unmerged_leaves=(1,)))
    assert tree.resolution(1) == [1, 2]
    assert tree.resolution(1, excluded_leaves={1}) == [1]

    try:
        tree.set_leaf(0, ParentNode(b"wrong type"))  # type: ignore[arg-type]
    except InvalidTree:
        pass
    else:
        raise AssertionError("set_leaf accepted a ParentNode")

    sparse = RatchetTree(9)
    for leaf_index in range(9):
        sparse.set_leaf(
            leaf_index,
            LeafNode(f"u{leaf_index}".encode(), f"k{leaf_index}".encode()),
        )
    for node_index in range(1, len(sparse.nodes), 2):
        sparse.set_parent(node_index, ParentNode(f"p{node_index}".encode()))
    clean_left = sparse.wire_cost(0)
    clean_right = sparse.wire_cost(8)
    assert clean_left == 4
    assert clean_right == 1

    # Updating leaf 0 blanks its full direct path. The right-edge leaf's
    # copath resolution expands through the now-blank left-subtree root.
    for node_index in sparse.direct_path(0):
        sparse.set_parent(node_index, None)
    blanked_right = sparse.wire_cost(8)
    assert blanked_right == 4
    assert sparse.filtered_direct_path(0) == [1, 3, 7, 15]
    return {
        "clean_cost_left": clean_left,
        "clean_cost_right": clean_right,
        "blanked_cost_right": blanked_right,
    }


def check_merge_invariants() -> dict:
    """Check stale generations, equivocation retention, and join outcomes."""
    group_id = b"test-dmls-group"
    alice_old = LeafNode(b"alice:D1", b"a1", generation=1, group_id=group_id)
    alice_new = LeafNode(b"alice:D1", b"a2", generation=2, group_id=group_id)
    bob_old = LeafNode(b"bob:D1", b"b1", generation=1, group_id=group_id)
    bob_new = LeafNode(b"bob:D1", b"b2", generation=2, group_id=group_id)
    bob_newest = LeafNode(b"bob:D1", b"b3", generation=3, group_id=group_id)
    carol_join = LeafNode(
        b"carol:D1", b"c1", source="commit", generation=1, group_id=group_id
    )

    alice_id = _mock_principal_of(alice_old).member_id
    bob_id = _mock_principal_of(bob_old).member_id
    carol_id = _mock_principal_of(carol_join).member_id

    ext_base = ExtremityId(2, b"\x01" * 32)
    ext_stale = ExtremityId(2, b"\x02" * 32)
    ext_newer = ExtremityId(2, b"\x03" * 32)
    base = _make_branch(
        2,
        1,
        {
            alice_id: LeafRecord(alice_new),
            bob_id: LeafRecord(bob_old),
        },
    )
    stale = _make_branch(
        2,
        2,
        {
            alice_id: LeafRecord(alice_old),
            bob_id: LeafRecord(bob_new),
        },
    )
    newer = _make_branch(
        2,
        3,
        {
            alice_id: LeafRecord(alice_new),
            bob_id: LeafRecord(bob_newest),
        },
    )
    # Keep keys explicit so fixture construction errors are caught.
    assert base.extremity == ext_base
    assert stale.extremity == ext_stale
    assert newer.extremity == ext_newer

    state = DmlsMergeState()
    for branch in (base, stale, newer):
        state.observe_branch(branch)
    assert len(state.extremities) == 3  # same epoch does not collapse commits

    plan = plan_merge(
        [ext_newer, ext_stale, ext_base],
        state.held,
        group_id,
        _mock_principal_of,
    )
    reverse_plan = plan_merge(
        [ext_base, ext_stale, ext_newer],
        state.held,
        group_id,
        _mock_principal_of,
    )
    assert plan == reverse_plan
    assert plan.base == ext_base
    assert plan.members[bob_id].leaf == bob_old
    assert plan.required_self_updates == (bob_id,)

    # A requested but unheld extremity defers instead of selecting a partial base.
    missing = ExtremityId(3, b"\x04" * 32)
    try:
        select_base([ext_base, missing], state.held)
    except MissingBaseState as error:
        assert error.commit_id == missing.commit_id
    else:
        raise AssertionError("select_base did not defer for missing local state")

    try:
        validate_update_candidate(
            alice_old,
            bob_new,
            group_id,
            _mock_principal_of,
        )
    except IdentityMismatch:
        pass
    else:
        raise AssertionError(
            "other-branch update candidate accepted a different device identity"
        )

    # The losing external-commit LeafNode is reported as orphaned, never added.
    ext_join = ExtremityId(3, b"\x05" * 32)
    joined_branch = _make_branch(
        3,
        5,
        {
            alice_id: LeafRecord(alice_new),
            bob_id: LeafRecord(bob_newest),
            carol_id: LeafRecord(carol_join, "external_commit"),
        },
        external_joiners=frozenset({carol_id}),
    )
    ext_other_join = ExtremityId(3, b"\x04" * 32)
    other_join_branch = _make_branch(
        3,
        4,
        {alice_id: LeafRecord(alice_new), bob_id: LeafRecord(bob_newest)},
    )
    merge_plan = plan_merge(
        [ext_other_join, ext_join],
        {ext_other_join: other_join_branch, ext_join: joined_branch},
        group_id,
        _mock_principal_of,
    )
    assert merge_plan.adds == ()
    assert merge_plan.orphaned_external_joiners == (carol_id,)
    assert carol_id not in merge_plan.members

    # An unrelated merge leaves the join branch live and therefore pending.
    join_state = DmlsMergeState()
    join_state.observe_branch(joined_branch)
    unrelated = _make_branch(
        3,
        6,
        {alice_id: LeafRecord(alice_new)},
    )
    join_state.observe_branch(unrelated)
    assert external_join_status(carol_id, ext_join, join_state) == (
        ExternalJoinStatus.PENDING
    )

    unrelated_merge = _make_branch(4, 7, {alice_id: LeafRecord(alice_new)})
    join_state.observe_merge(unrelated_merge, [unrelated.extremity])
    assert external_join_status(carol_id, ext_join, join_state) == (
        ExternalJoinStatus.PENDING
    )

    orphan_merge = _make_branch(5, 8, {alice_id: LeafRecord(alice_new)})
    join_state.observe_merge(orphan_merge, [ext_join, unrelated_merge.extremity])
    assert external_join_status(carol_id, ext_join, join_state) == (
        ExternalJoinStatus.ORPHANED
    )

    # Remove/update conflicts are symmetric, including when the remover is
    # selected as the base. The removed leaf is retained for comparison.
    alice_gen1 = LeafNode(b"alice:D1", b"alice-key-1", generation=1, group_id=group_id)
    alice_gen2 = LeafNode(b"alice:D1", b"alice-key-2", generation=2, group_id=group_id)
    alice_member = _mock_principal_of(alice_gen1).member_id
    remove_first = _make_branch(4, 1, {}, removed={alice_member: alice_gen1})
    update_second = _make_branch(4, 2, {alice_member: LeafRecord(alice_gen2)})
    update_first = _make_branch(4, 1, {alice_member: LeafRecord(alice_gen2)})
    remove_second = _make_branch(4, 2, {}, removed={alice_member: alice_gen1})
    for first, second in (
        (remove_first, update_second),  # base is the remover
        (update_first, remove_second),  # base is the updater
    ):
        try:
            plan_merge(
                [first.extremity, second.extremity],
                {first.extremity: first, second.extremity: second},
                group_id,
                _mock_principal_of,
            )
        except MembershipConflict:
            pass
        else:
            raise AssertionError("remove/update conflict depended on base ordering")

    # A clean removal against the unchanged prior leaf succeeds whichever
    # branch supplies the base, without resurrecting the member as an Add.
    # Remove is only emitted when the selected base still holds the member.
    remove_first = _make_branch(4, 1, {}, removed={alice_member: alice_gen1})
    unchanged_second = _make_branch(4, 2, {alice_member: LeafRecord(alice_gen1)})
    unchanged_first = _make_branch(4, 1, {alice_member: LeafRecord(alice_gen1)})
    remove_second = _make_branch(4, 2, {}, removed={alice_member: alice_gen1})
    for branches, base_has_member in (
        ((remove_first, unchanged_second), False),
        ((unchanged_first, remove_second), True),
    ):
        clean_remove = plan_merge(
            [branch.extremity for branch in branches],
            {branch.extremity: branch for branch in branches},
            group_id,
            _mock_principal_of,
        )
        assert alice_member not in clean_remove.members
        assert clean_remove.adds == ()
        assert (alice_member in clean_remove.removes) is base_has_member

    # A sibling external re-join is not a concurrent UpdateOther. The removal
    # wins, while the discarded joiner is reported so it can retry at the tip.
    external_alice = LeafNode(
        b"alice:D1",
        b"alice-external-key",
        source="commit",
        generation=2,
        group_id=group_id,
    )
    stable_base = _make_branch(4, 1, {alice_member: LeafRecord(alice_gen1)})
    remove_branch = _make_branch(4, 2, {}, removed={alice_member: alice_gen1})
    external_rejoin = _make_branch(
        4,
        3,
        {alice_member: LeafRecord(external_alice, "external_commit")},
        external_joiners=frozenset({alice_member}),
    )
    rejoin_plan = plan_merge(
        [stable_base.extremity, remove_branch.extremity, external_rejoin.extremity],
        {
            stable_base.extremity: stable_base,
            remove_branch.extremity: remove_branch,
            external_rejoin.extremity: external_rejoin,
        },
        group_id,
        _mock_principal_of,
    )
    assert alice_member not in rejoin_plan.members
    assert rejoin_plan.removes == (alice_member,)
    assert rejoin_plan.adds == ()
    assert rejoin_plan.orphaned_external_joiners == (alice_member,)

    # With the remover selected as the base, the external re-join is still
    # orphaned and no Remove targets a member the base no longer holds.
    removal_base = _make_branch(4, 1, {}, removed={alice_member: alice_gen1})
    external_second = _make_branch(
        4,
        2,
        {alice_member: LeafRecord(external_alice, "external_commit")},
        external_joiners=frozenset({alice_member}),
    )
    removal_plan = plan_merge(
        [removal_base.extremity, external_second.extremity],
        {
            removal_base.extremity: removal_base,
            external_second.extremity: external_second,
        },
        group_id,
        _mock_principal_of,
    )
    assert alice_member not in removal_plan.members
    assert removal_plan.removes == ()
    assert removal_plan.orphaned_external_joiners == (alice_member,)

    return {
        "equivocated_extremities": len(state.extremities),
        "selected_base": plan.base.commit_id.hex(),
        "bob_base_generation": plan.members[bob_id].leaf.generation,
        "bob_self_update_required": bob_id in plan.required_self_updates,
        "losing_external_joiner": "orphaned_without_add",
        "unrelated_merge_status": ExternalJoinStatus.PENDING.value,
        "consuming_merge_status": ExternalJoinStatus.ORPHANED.value,
        "remove_update_conflict_order_independent": True,
        "removed_member_not_resurrected": True,
        "removed_external_rejoin_orphaned": True,
    }


def check_ancestry_diamond() -> dict:
    """Exercise ancestry lookup on reconverging graphs and incomplete views."""
    group_id = b"ancestry-diamond-test"
    alice_leaf = LeafNode(b"alice:D1", b"alice-key", group_id=group_id)
    carol_leaf = LeafNode(b"carol:D1", b"carol-key", source="commit", group_id=group_id)
    alice_id = _mock_principal_of(alice_leaf).member_id
    carol_id = _mock_principal_of(carol_leaf).member_id

    join_root = _make_branch(
        1,
        10,
        {carol_id: LeafRecord(carol_leaf, "external_commit")},
        external_joiners=frozenset({carol_id}),
    )
    other_root = _make_branch(1, 11, {alice_id: LeafRecord(alice_leaf)})
    state = DmlsMergeState()
    state.observe_branch(join_root)
    state.observe_branch(other_root)

    previous = [join_root.extremity, other_root.extremity]
    for layer in range(2, 34):
        left_digest = layer * 2 + 1
        right_digest = layer * 2 + 2
        left = _make_branch(layer, left_digest, {alice_id: LeafRecord(alice_leaf)})
        right = _make_branch(layer, right_digest, {alice_id: LeafRecord(alice_leaf)})
        state.observe_merge(left, previous)
        state.observe_merge(right, previous)
        previous = [left.extremity, right.extremity]

    tip = _make_branch(34, 250, {alice_id: LeafRecord(alice_leaf)})
    state.observe_merge(tip, previous)
    status = external_join_status(carol_id, join_root.extremity, state)
    assert status is ExternalJoinStatus.ORPHANED

    absent_ancestor = ExtremityId(99, b"z" * 32)
    complete_tip = _make_branch(
        35, 251, {alice_id: LeafRecord(alice_leaf)}, resolves=frozenset({tip.extremity})
    )
    complete_held = dict(state.held)
    complete_held[complete_tip.extremity] = complete_tip
    assert (
        _descends_from(complete_tip.extremity, absent_ancestor, complete_held) is False
    )

    missing_parent = ExtremityId(36, b"y" * 32)
    incomplete_tip = _make_branch(
        35,
        252,
        {alice_id: LeafRecord(alice_leaf)},
        resolves=frozenset({tip.extremity, missing_parent}),
    )
    incomplete_held = dict(state.held)
    incomplete_held[incomplete_tip.extremity] = incomplete_tip
    assert (
        _descends_from(incomplete_tip.extremity, absent_ancestor, incomplete_held)
        is None
    )

    # A cycle is finite to traverse; an unresolved parent still makes the
    # ancestry result incomplete rather than falsely proving non-descent.
    cycle_a_id = ExtremityId(37, bytes([1]) * 32)
    cycle_b_id = ExtremityId(37, bytes([2]) * 32)
    cycle_a = _make_branch(
        37, 1, {alice_id: LeafRecord(alice_leaf)}, resolves=frozenset({cycle_b_id})
    )
    cycle_b = _make_branch(
        37,
        2,
        {alice_id: LeafRecord(alice_leaf)},
        resolves=frozenset({cycle_a_id, missing_parent}),
    )
    cycle_held = {cycle_a_id: cycle_a, cycle_b_id: cycle_b}
    assert _descends_from(cycle_a_id, absent_ancestor, cycle_held) is None

    return {
        "diamond_depth": 32,
        "diamond_join_status": status.value,
        "incomplete_ancestry_remains_unknown": True,
        "cycles_terminate": True,
    }


def check_00fc_leaf_binding() -> dict:
    """Require active 00FC identity and plan removal after device revocation."""
    principal = "@alice:example.org"
    master_sk = pid_crypto.sk_from_seed(b"m" * 32)
    self_signing_sk = pid_crypto.sk_from_seed(b"s" * 32)
    device_sk = pid_crypto.sk_from_seed(b"d" * 32)
    certificate = device_bundle(principal, master_sk, self_signing_sk, device_sk, "D1")
    identity = f"{principal}:D1".encode("utf-8")
    group_id = b"dmls-00fc-test"
    registry = DeviceRootRegistry(master_keys={principal: pid_crypto.pub(master_sk)})
    registry.install_root(
        DeviceRoot(
            principal=principal,
            user_epoch_height=4,
            generation=1,
            self_signing_key=pid_crypto.pub(self_signing_sk),
        )
    )
    registry.certify(principal, certificate)
    leaf = LeafNode(
        identity,
        b"hpke-public-key",
        group_id=group_id,
        signature_key=pid_crypto.pub(device_sk),
    )
    resolved = registry(leaf)
    assert resolved.principal == principal.encode("utf-8")
    assert resolved.device_id == "D1"

    wrong_key_leaf = LeafNode(
        identity,
        b"hpke-public-key",
        group_id=group_id,
        signature_key=b"x" * 32,
    )
    try:
        registry(wrong_key_leaf)
    except UncertifiedDevice:
        pass
    else:
        raise AssertionError("00FC resolver accepted an uncertified LeafNode key")

    member_id = resolved.member_id
    branch = Branch(
        extremity=ExtremityId(1, b"r" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(leaf)},
    )
    next_self_signing_sk = pid_crypto.sk_from_seed(b"n" * 32)
    registry.install_root(
        DeviceRoot(
            principal=principal,
            user_epoch_height=4,
            generation=2,
            self_signing_key=pid_crypto.pub(next_self_signing_sk),
        )
    )
    assert not registry.is_active(leaf)
    plan = plan_with_device_roots(
        [branch.extremity],
        {branch.extremity: branch},
        group_id,
        registry,
        verify_leaf=_accept_all_leaves,
    )
    assert plan.removes == (member_id,)
    assert member_id not in plan.members
    return {
        "principal": principal,
        "device_id": "D1",
        "wrong_key_rejected": True,
        "revoked_leaf_removed": True,
    }


def check_00fc_rotation_rejects_update() -> dict:
    """Exercise re-certification, stale-update ordering, and revocation."""
    principal = "@alice:example.org"
    master_sk = pid_crypto.sk_from_seed(b"m" * 32)
    old_ss = pid_crypto.sk_from_seed(b"s" * 32)
    old_dev = pid_crypto.sk_from_seed(b"d" * 32)
    new_ss = pid_crypto.sk_from_seed(b"R" * 32)
    new_dev = pid_crypto.sk_from_seed(b"E" * 32)
    identity = f"{principal}:D1".encode("utf-8")
    group_id = b"dmls-00fc-test"
    registry = DeviceRootRegistry(master_keys={principal: pid_crypto.pub(master_sk)})
    registry.install_root(
        DeviceRoot(
            principal,
            user_epoch_height=4,
            generation=1,
            self_signing_key=pid_crypto.pub(old_ss),
        )
    )
    registry.certify(
        principal, device_bundle(principal, master_sk, old_ss, old_dev, "D1")
    )
    registry.install_root(
        DeviceRoot(
            principal,
            user_epoch_height=4,
            generation=2,
            self_signing_key=pid_crypto.pub(new_ss),
        )
    )
    registry.certify(
        principal, device_bundle(principal, master_sk, new_ss, new_dev, "D1")
    )

    stale_leaf = LeafNode(
        identity,
        b"hpke-old",
        group_id=group_id,
        generation=2,
        signature_key=pid_crypto.pub(old_dev),
    )
    active_leaf = LeafNode(
        identity,
        b"hpke-new",
        group_id=group_id,
        generation=1,
        signature_key=pid_crypto.pub(new_dev),
    )
    assert not registry.is_active(stale_leaf)
    assert registry.is_active(active_leaf)
    try:
        registry(stale_leaf)
    except UncertifiedDevice:
        pass
    else:
        raise AssertionError("resolver accepted a stale certificate after rotation")

    member_id = registry(active_leaf).member_id
    stale_base_leaf = LeafNode(
        identity,
        b"hpke-old-base",
        group_id=group_id,
        generation=1,
        signature_key=pid_crypto.pub(old_dev),
    )
    active_update_leaf = LeafNode(
        identity,
        b"hpke-new-update",
        group_id=group_id,
        generation=2,
        signature_key=pid_crypto.pub(new_dev),
    )

    # An inactive base leaf cannot be replaced with another branch's active
    # leaf. The merge must stop rather than install that leaf as UpdateOther.
    stale_base = Branch(
        extremity=ExtremityId(1, b"a" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(stale_base_leaf)},
    )
    active_update = Branch(
        extremity=ExtremityId(1, b"b" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(active_update_leaf)},
    )
    try:
        plan_with_device_roots(
            [stale_base.extremity, active_update.extremity],
            {stale_base.extremity: stale_base, active_update.extremity: active_update},
            group_id,
            registry,
            verify_leaf=_accept_all_leaves,
        )
    except UncertifiedDevice:
        pass
    else:
        raise AssertionError(
            "inactive base leaf was replaced by another branch's active leaf"
        )

    # A stale higher-generation leaf never replaces an active leaf, and never
    # justifies a self-update requirement. With the stale leaf as base, the
    # active leaf on the other branch cannot be installed, so the plan aborts.
    for first_leaf, second_leaf, aborts in (
        (active_leaf, stale_leaf, False),
        (stale_leaf, active_leaf, True),
    ):
        first = Branch(
            extremity=ExtremityId(1, b"a" * 32),
            parent_transcript_hash=b"p" * 32,
            members={member_id: LeafRecord(first_leaf)},
        )
        second = Branch(
            extremity=ExtremityId(1, b"b" * 32),
            parent_transcript_hash=b"p" * 32,
            members={member_id: LeafRecord(second_leaf)},
        )
        try:
            ordered = plan_with_device_roots(
                [first.extremity, second.extremity],
                {first.extremity: first, second.extremity: second},
                group_id,
                registry,
                verify_leaf=_accept_all_leaves,
            )
        except UncertifiedDevice:
            assert aborts, "active base leaf was rejected"
        else:
            assert not aborts, "stale base leaf superseded an active leaf"
            assert ordered.members[member_id].leaf == active_leaf
            assert member_id not in ordered.required_self_updates

    # If all branches hold stale certificates, remove the resolved stale leaf.
    stale_gen1 = stale_base_leaf
    stale_gen2 = stale_leaf
    stale_branch1 = Branch(
        extremity=ExtremityId(1, b"c" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(stale_gen1)},
    )
    stale_branch2 = Branch(
        extremity=ExtremityId(1, b"d" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(stale_gen2)},
    )
    revoked = plan_with_device_roots(
        [stale_branch1.extremity, stale_branch2.extremity],
        {
            stale_branch1.extremity: stale_branch1,
            stale_branch2.extremity: stale_branch2,
        },
        group_id,
        registry,
        verify_leaf=_accept_all_leaves,
    )
    assert revoked.removes == (member_id,)
    assert member_id not in revoked.members
    assert not revoked.required_self_updates

    # A stale leaf present only as a losing-branch Add is dropped without a
    # Remove targeting a leaf that never existed in the selected base.
    empty_base = Branch(
        extremity=ExtremityId(1, b"e" * 32),
        parent_transcript_hash=b"p" * 32,
        members={},
    )
    stale_add_branch = Branch(
        extremity=ExtremityId(1, b"f" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(stale_gen2, "add")},
    )
    stale_add_plan = plan_with_device_roots(
        [empty_base.extremity, stale_add_branch.extremity],
        {
            empty_base.extremity: empty_base,
            stale_add_branch.extremity: stale_add_branch,
        },
        group_id,
        registry,
        verify_leaf=_accept_all_leaves,
    )
    assert stale_add_plan.members == {}
    assert stale_add_plan.adds == ()
    assert stale_add_plan.removes == ()
    return {
        "stale_key_rejected_symmetrically": True,
        "recertification_update_preserved": True,
        "revoked_member_removed": True,
        "stale_nonbase_add_dropped_without_remove": True,
    }


def check_device_root_resolution_boundary() -> dict:
    """Apply resolved device roots and preserve the cutover freeze rules."""
    principal = "@alice:example.org"
    root11 = CutoverEvent(
        "root-h1-g1",
        (),
        principal,
        1,
        user_epoch_height=1,
        generation=1,
    )
    root12 = CutoverEvent(
        "root-h1-g2",
        (root11.eid,),
        principal,
        1,
        user_epoch_height=1,
        generation=2,
        previous_root=root11.eid,
    )
    conflict_a = CutoverEvent(
        "root-h1-g3-a",
        (root12.eid,),
        principal,
        1,
        user_epoch_height=1,
        generation=3,
        previous_root=root12.eid,
    )
    conflict_b = CutoverEvent(
        "root-h1-g3-b",
        (root12.eid,),
        principal,
        1,
        user_epoch_height=1,
        generation=3,
        previous_root=root12.eid,
    )
    reanchor = CutoverEvent(
        "root-h2-g1",
        (root12.eid,),
        principal,
        2,
        user_epoch_height=2,
        generation=1,
        previous_root=root12.eid,
    )
    events = {
        event.eid: event for event in (root11, root12, conflict_a, conflict_b, reanchor)
    }
    roots = (root11, root12, conflict_a, conflict_b, reanchor)
    self_signing_a = pid_crypto.sk_from_seed(b"A" * 32)
    self_signing_b = pid_crypto.sk_from_seed(b"B" * 32)
    master_sk = pid_crypto.sk_from_seed(b"m" * 32)
    device_sk = pid_crypto.sk_from_seed(b"d" * 32)
    signing_keys = {
        root11.eid: pid_crypto.pub(self_signing_a),
        root12.eid: pid_crypto.pub(self_signing_a),
        reanchor.eid: pid_crypto.pub(self_signing_b),
    }
    registry = DeviceRootRegistry(master_keys={principal: pid_crypto.pub(master_sk)})

    def install_resolved(event: CutoverEvent) -> DeviceRoot:
        assert event.user_epoch_height is not None
        assert event.generation is not None
        return registry.install_root(
            DeviceRoot(
                principal=principal,
                user_epoch_height=event.user_epoch_height,
                generation=event.generation,
                self_signing_key=signing_keys[event.eid],
            )
        )

    resolved_g1 = resolve_root((root11,), events, max_user_epoch_height=1)
    assert resolved_g1 is root11
    install_resolved(resolved_g1)
    registry.certify(
        principal,
        device_bundle(principal, master_sk, self_signing_a, device_sk, "D1"),
    )
    leaf = LeafNode(
        f"{principal}:D1".encode(),
        b"hpke-A",
        group_id=b"device-root-transition-test",
        signature_key=pid_crypto.pub(device_sk),
    )
    assert registry(leaf).device_id == "D1"

    resolved_g2 = resolve_root((root11, root12), events, max_user_epoch_height=1)
    assert resolved_g2 is root12
    active_g2 = install_resolved(resolved_g2)
    assert active_g2.generation == 2
    assert registry(leaf).device_id == "D1"

    # The conflict at g3 falls back to g2; neither conflicted event is installed.
    resolved_conflict = resolve_root(roots[:4], events, max_user_epoch_height=1)
    assert resolved_conflict is root12
    assert install_resolved(resolved_conflict) == active_g2
    try:
        registry.install_root(
            DeviceRoot(
                principal,
                user_epoch_height=1,
                generation=2,
                self_signing_key=b"x" * 32,
            )
        )
    except UncertifiedDevice:
        pass
    else:
        raise AssertionError("registry accepted a conflicting same-generation root")
    assert registry.roots[principal] == active_g2

    # A K_rot re-anchor at (h + 1, 1) changes the active self-signing key.
    resolved_reanchor = resolve_root(roots, events, max_user_epoch_height=2)
    assert resolved_reanchor is reanchor
    installed_reanchor = install_resolved(resolved_reanchor)
    assert installed_reanchor.user_epoch_height == 2
    assert installed_reanchor.generation == 1
    assert installed_reanchor.self_signing_key == signing_keys[reanchor.eid]
    assert not registry.is_active(leaf)
    try:
        registry(leaf)
    except UncertifiedDevice:
        pass
    else:
        raise AssertionError("re-anchor did not stale the old device certificate")

    member_id = registry.identity_of(leaf).member_id
    branch = Branch(
        extremity=ExtremityId(2, b"z" * 32),
        parent_transcript_hash=b"p" * 32,
        members={member_id: LeafRecord(leaf)},
    )
    plan = plan_with_device_roots(
        [branch.extremity],
        {branch.extremity: branch},
        leaf.group_id,
        registry,
        verify_leaf=_accept_all_leaves,
    )
    assert plan.removes == (member_id,)
    return {
        "linear_generation_2_installed": True,
        "conflict_falls_back_to": root12.eid,
        "same_generation_conflict_rejected": True,
        "reanchor_installed": reanchor.eid,
        "stale_device_remove_planned": True,
    }


def _populated(tree):
    for i in range(tree.leaf_count):
        tree.set_leaf(i, LeafNode(b"u%d" % i, b"k%d" % i))
    for ni in list(tree._children):
        tree.set_parent(ni, ParentNode(b"p%d" % ni))
    return tree


def check_513_wire_cost_and_truncation():
    # Independent derivation of the clean case: leaf 0 sits at depth
    # ceil(log2 513) = 10, one copath node per level, all intact. Leaf 512 is a
    # direct child of the root, so its only copath node is the intact left
    # subtree root (node 511) and it needs one ciphertext.
    assert (513 - 1).bit_length() == 10
    tree = _populated(RatchetTree(513))
    assert tree.copath(512) == [511]
    assert (tree.wire_cost(0), tree.wire_cost(512)) == (10, 1)
    # Regression snapshot of this model's output, not an oracle: blanking one
    # left-subtree path raises the left fringe to 11 and the right fringe to 9.
    # The right fringe does not become costlier than the left.
    tree.remove_leaf(5)
    after = (tree.wire_cost(0), tree.wire_cost(512))
    assert after == (11, 9)
    # RFC 9420 §7.7 placement is deterministic: leftmost blank, else extend.
    assert tree.first_blank_or_extend() == 5
    assert _populated(RatchetTree(4)).first_blank_or_extend() == 4

    # Draft-11 truncation only drops slots; Remove has already blanked paths.
    t2 = _populated(RatchetTree(600))
    for i in range(500, 600):
        t2.remove_leaf(i)
    assert t2.truncate_trailing_blanks() and t2.leaf_count == 500
    assert len(t2.nodes) == 999
    # Skipping Remove leaves a nonblank parent over a dropped leaf: refuse.
    t2b = _populated(RatchetTree(600))
    for i in range(500, 600):
        t2b.set_leaf(i, None)
    try:
        t2b.truncate_trailing_blanks()
    except InvalidTree:
        assert t2b.leaf_count == 600
    else:
        raise AssertionError("truncated over a nonblank parent")

    # RFC 9420: the surviving left subtree is untouched, nothing is blanked.
    t3 = _populated(Rfc9420Tree(600))
    for i in range(300, 1024):
        t3.remove_leaf(i)
    left = list(t3.nodes[: 2 * 512 - 1])
    left_before = [n for i, n in enumerate(left)]
    t3.truncate_trailing_blanks()
    assert t3.capacity == 512 and t3.member_count == 300
    assert t3.nodes[: 2 * 512 - 1] == left_before
    return {"clean": [10, 1], "blank_one_snapshot": list(after)}


def test_513_wire_cost_and_truncation() -> None:
    check_513_wire_cost_and_truncation()


def check_concurrent_join_same_slot():
    """Two identities joining the same leftmost-blank slot on two branches."""
    group_id = b"g" * 8
    common = LeafNode(b"alice:D1", b"a", group_id=group_id)
    x = LeafNode(b"xavier:D1", b"x", source="key_package", group_id=group_id)
    y = LeafNode(b"yara:D1", b"y", source="key_package", group_id=group_id)
    alice_id = MemberId(b"alice", "D1")
    x_id, y_id = MemberId(b"xavier", "D1"), MemberId(b"yara", "D1")
    base = _make_branch(
        2,
        1,
        {
            alice_id: LeafRecord(common, leaf_index=0),
            x_id: LeafRecord(x, origin="add", leaf_index=1),
        },
    )
    other = _make_branch(
        2,
        2,
        {
            alice_id: LeafRecord(common, leaf_index=0),
            y_id: LeafRecord(y, origin="add", leaf_index=1),
        },
    )
    held = {base.extremity: base, other.extremity: other}
    plan = plan_merge(held, held, group_id, _mock_principal_of)
    assert plan.base == base.extremity
    assert set(plan.members) == {alice_id, x_id, y_id}
    assert [m for m, _ in plan.adds] == [y_id]
    assert plan.members[x_id].leaf_index == 1
    assert plan.members[y_id].leaf_index is None  # applier reassigns the slot
    return {"members": 3, "adds": ["yara:D1"]}


def test_concurrent_join_same_slot() -> None:
    check_concurrent_join_same_slot()


def check_resync_and_device_isolation():
    """Resync at a new slot must not wedge the merge; sibling devices stay apart."""
    g = b"g" * 8
    a1_old = LeafNode(b"alice:D1", b"a1", generation=1, group_id=g)
    a1_resync = LeafNode(b"alice:D1", b"a1r", source="commit", generation=2, group_id=g)
    a2 = LeafNode(b"alice:D2", b"b1", generation=1, group_id=g)
    a2_new = LeafNode(b"alice:D2", b"b2", source="update", generation=2, group_id=g)
    d1, d2 = MemberId(b"alice", "D1"), MemberId(b"alice", "D2")

    # Base: D1 resynced via external commit at slot 5 (old slot 1 removed).
    base = _make_branch(
        3,
        1,
        {
            d1: LeafRecord(a1_resync, origin="external_commit", leaf_index=5),
            d2: LeafRecord(a2, leaf_index=2),
        },
    )
    # Other branch still has the pre-resync D1 at slot 1 and updates D2 only.
    other = _make_branch(
        3,
        2,
        {
            d1: LeafRecord(a1_old, leaf_index=1),
            d2: LeafRecord(a2_new, leaf_index=2),
        },
    )
    held = {base.extremity: base, other.extremity: other}
    plan = plan_merge(held, held, g, _mock_principal_of)
    assert plan.members[d1].leaf == a1_resync and plan.members[d1].leaf_index == 5
    assert plan.required_self_updates == (d2,)  # D2 must self-update; D1 untouched
    assert plan.members[d2].leaf == a2

    # A genuine move of an ordinary member (no resync) is still a conflict.
    moved = _make_branch(
        3,
        3,
        {d1: LeafRecord(a1_old, leaf_index=9), d2: LeafRecord(a2, leaf_index=2)},
    )
    plain = _make_branch(
        3,
        4,
        {d1: LeafRecord(a1_old, leaf_index=1), d2: LeafRecord(a2, leaf_index=2)},
    )
    held2 = {moved.extremity: moved, plain.extremity: plain}
    try:
        plan_merge(held2, held2, g, _mock_principal_of)
    except MembershipConflict:
        pass
    else:
        raise AssertionError("unexplained leaf index move accepted")

    # An update authored on the pre-resync slot cannot be moved: conflict.
    stale_update = LeafNode(
        b"alice:D1", b"a1u", source="update", generation=3, group_id=g
    )
    other2 = _make_branch(
        3,
        5,
        {d1: LeafRecord(stale_update, leaf_index=1), d2: LeafRecord(a2, leaf_index=2)},
    )
    held3 = {base.extremity: base, other2.extremity: other2}
    try:
        plan_merge(held3, held3, g, _mock_principal_of)
    except MembershipConflict:
        pass
    else:
        raise AssertionError("update on a pre-resync slot was merged")
    # Resync on the incoming branch only: the base keeps its own leaf and the
    # external-commit copy is discarded, not orphaned (the base has the member).
    base_plain = _make_branch(
        3,
        6,
        {d1: LeafRecord(a1_old, leaf_index=1), d2: LeafRecord(a2, leaf_index=2)},
    )
    incoming_resync = _make_branch(
        3,
        7,
        {
            d1: LeafRecord(a1_resync, origin="external_commit", leaf_index=5),
            d2: LeafRecord(a2, leaf_index=2),
        },
    )
    held4 = {
        base_plain.extremity: base_plain,
        incoming_resync.extremity: incoming_resync,
    }
    p4 = plan_merge(held4, held4, g, _mock_principal_of)
    assert p4.members[d1].leaf == a1_old and p4.members[d1].leaf_index == 1
    assert not p4.orphaned_external_joiners and not p4.required_self_updates

    # The same member resyncs on both branches to different slots: the base's
    # resync wins and the other is discarded.
    other_resync = LeafNode(
        b"alice:D1", b"a1s", source="commit", generation=2, group_id=g
    )
    left = _make_branch(
        3,
        8,
        {
            d1: LeafRecord(a1_resync, origin="external_commit", leaf_index=5),
            d2: LeafRecord(a2, leaf_index=2),
        },
    )
    right = _make_branch(
        3,
        9,
        {
            d1: LeafRecord(other_resync, origin="external_commit", leaf_index=6),
            d2: LeafRecord(a2, leaf_index=2),
        },
    )
    held5 = {left.extremity: left, right.extremity: right}
    p5 = plan_merge(held5, held5, g, _mock_principal_of)
    assert p5.members[d1].leaf == a1_resync and p5.members[d1].leaf_index == 5

    # A resync that restarts the generation sequence is not silently dropped in
    # favour of the stale copy: the old-slot copy is at least as new, so abort.
    restarted = LeafNode(b"alice:D1", b"a1x", source="commit", generation=0, group_id=g)
    base_restart = _make_branch(
        3,
        10,
        {
            d1: LeafRecord(restarted, origin="external_commit", leaf_index=5),
            d2: LeafRecord(a2, leaf_index=2),
        },
    )
    old_copy = _make_branch(
        3,
        11,
        {d1: LeafRecord(a1_old, leaf_index=1), d2: LeafRecord(a2, leaf_index=2)},
    )
    held6 = {base_restart.extremity: base_restart, old_copy.extremity: old_copy}
    try:
        plan_merge(held6, held6, g, _mock_principal_of)
    except MembershipConflict:
        pass
    else:
        raise AssertionError("restarted resync generation was merged silently")

    # Identical leaves at different slots are a conflict, with or without a
    # verifier: the signature binds the slot, so one copy cannot be valid.
    for verifier in (None, _ed25519_verifier):
        try:
            plan_merge(held2, held2, g, _mock_principal_of, verifier)
        except MembershipConflict:
            pass
        else:
            raise AssertionError("identical leaf at two slots accepted")

    # The 00FC path refuses to run without a verifier.
    try:
        plan_with_device_roots([], {}, g, DeviceRootRegistry(master_keys={}), None)
    except ValueError:
        pass
    else:
        raise AssertionError("plan_with_device_roots ran without a verifier")
    return {"resync_ok": True}


def test_resync_and_device_isolation() -> None:
    check_resync_and_device_isolation()


def _signed_leaf(sk, identity, enc, generation, group_id, leaf_index, source="update"):
    from dataclasses import replace

    from dmls_tree import leaf_tbs

    leaf = LeafNode(
        identity,
        enc,
        source=source,
        generation=generation,
        group_id=group_id,
        signature_key=pid_crypto.pub(sk),
    )
    return replace(leaf, signature=sk.sign(leaf_tbs(leaf, leaf_index)))


def _ed25519_verifier(leaf, leaf_index, for_update=False):
    from dmls_tree import leaf_tbs

    if for_update and leaf.source not in ("update", "commit"):
        return False
    try:
        msg = leaf_tbs(leaf, leaf_index)
    except InvalidTree:
        return False
    return pid_crypto.verify_sig(leaf.signature_key, msg, leaf.signature)


def check_leaf_signature_guards():
    from dataclasses import replace

    from dmls_merge import GenerationError, SignatureError

    g = b"g" * 8
    sk, other_sk = (
        pid_crypto.sk_from_seed(b"\x01" * 32),
        pid_crypto.sk_from_seed(b"\x02" * 32),
    )
    old = _signed_leaf(sk, b"alice:D1", b"a1", 1, g, 3)
    new = _signed_leaf(sk, b"alice:D1", b"a2", 2, g, 3)
    args = (old, new, g, _mock_principal_of)
    kw = dict(leaf_index=3, verify_leaf=_ed25519_verifier)
    assert validate_update_candidate(*args, **kw) == MemberId(b"alice", "D1")

    def expect(exc, *a, **k):
        try:
            validate_update_candidate(*a, **k)
        except exc:
            return
        raise AssertionError(f"expected {exc.__name__}")

    # (a) bad signature
    expect(
        SignatureError,
        old,
        replace(new, signature=b"\0" * 64),
        g,
        _mock_principal_of,
        **kw,
    )
    # (b) replayed old generation, validly signed
    expect(GenerationError, new, old, g, _mock_principal_of, **kw)
    # (c) signature by a key other than the leaf's signature_key
    forged = replace(
        new, signature=other_sk.sign(__import__("dmls_tree").leaf_tbs(new, 3))
    )
    expect(SignatureError, old, forged, g, _mock_principal_of, **kw)
    # (d) valid signed leaf replayed at a different leaf_index
    expect(
        SignatureError,
        old,
        new,
        g,
        _mock_principal_of,
        leaf_index=7,
        verify_leaf=_ed25519_verifier,
    )
    # (e) another certified device of the same user cannot update D1's leaf
    d2 = _signed_leaf(other_sk, b"alice:D2", b"b1", 2, g, 3)
    expect(IdentityMismatch, old, d2, g, _mock_principal_of, **kw)
    # key_package-sourced leaves cannot serve as update candidates
    kp = _signed_leaf(sk, b"alice:D1", b"a3", 3, g, 3, source="key_package")
    expect(SignatureError, old, kp, g, _mock_principal_of, **kw)
    # generation is a u64
    for bad in (-1, 1 << 64):
        try:
            LeafNode(b"alice:D1", b"k", generation=bad)
        except InvalidTree:
            pass
        else:
            raise AssertionError("out-of-range generation accepted")
    return {"negative_cases": 7}


def test_leaf_signature_guards() -> None:
    check_leaf_signature_guards()


def test_official_tree_math() -> None:
    build_official_tree_math_vectors()


def test_draft11_tree_math() -> None:
    build_draft11_tree_math_vectors()


def test_member_counts_use_padded_capacity() -> None:
    build_member_count_vectors()


def test_draft11_depth_distribution() -> None:
    check_draft11_depth_distribution()


def test_resolution_and_wire_cost() -> None:
    check_resolution_and_wire_cost()


def test_merge_invariants() -> None:
    check_merge_invariants()


def test_ancestry_diamond() -> None:
    check_ancestry_diamond()


def test_00fc_leaf_binding() -> None:
    check_00fc_leaf_binding()


def test_00fc_rotation_rejects_update() -> None:
    check_00fc_rotation_rejects_update()


def test_device_root_resolution_boundary() -> None:
    check_device_root_resolution_boundary()


def build_daggraph_trace() -> List[dict]:
    """Build a daggraph.py-compatible JSONL trace of the verified scenarios.

    The trace is a companion narrative for ``daggraph.py``; the corresponding
    assertions live in ``check_merge_invariants`` and
    ``check_device_root_resolution_boundary``. Each event carries the usual
    ``event_id``/``prev_events``/``depth`` graph fields plus DMLS metadata.
    ``alias`` is the short status label rendered by ``daggraph.py``.
    """
    merge_result = check_merge_invariants()
    cutover_result = check_device_root_resolution_boundary()
    assert merge_result["remove_update_conflict_order_independent"]
    assert merge_result["removed_external_rejoin_orphaned"]
    assert cutover_result["same_generation_conflict_rejected"]
    assert cutover_result["stale_device_remove_planned"]

    events: List[dict] = []

    def add_ev(
        event_id: str,
        prev: Sequence[str],
        event_type: str,
        depth: int,
        sender: str,
        alias: str,
        status: str,
        **extra: object,
    ) -> None:
        detail = str(extra.get("label", alias))
        events.append(
            {
                "event_id": event_id,
                "prev_events": list(prev),
                "type": event_type,
                "depth": depth,
                "sender": sender,
                "origin": sender.rsplit(":", 1)[-1],
                "alias": f"{status}: {detail}",
                "status": status,
                **extra,
            }
        )

    # DMLS fork: three same-epoch commits, base selection and self-update need.
    add_ev(
        "$d1_init",
        [],
        "m.dmls.commit",
        1,
        "@alice:example.org",
        "INIT",
        "ACCEPTED",
        mls_epoch=1,
        label="epoch 1: alice:D1 g1, bob:D1 g1",
    )
    add_ev(
        "$d2_base",
        ["$d1_init"],
        "m.dmls.commit",
        2,
        "@alice:example.org",
        "BASE",
        "BASE_SELECTED",
        mls_epoch=2,
        commit_id="01" * 32,
        label="epoch 2 0x01..: base, alice:D1 g2",
    )
    add_ev(
        "$d2_stale",
        ["$d1_init"],
        "m.dmls.commit",
        2,
        "@bob:example.org",
        "STALE",
        "STALE_VIEW_DROPPED",
        mls_epoch=2,
        commit_id="02" * 32,
        label="epoch 2 0x02..: alice:D1 g1 is stale, bob:D1 g2",
    )
    add_ev(
        "$d2_new",
        ["$d1_init"],
        "m.dmls.commit",
        2,
        "@bob:example.org",
        "NEWER",
        "UPDATE_CANDIDATE",
        mls_epoch=2,
        commit_id="03" * 32,
        label="epoch 2 0x03..: bob:D1 g3 candidate",
    )
    add_ev(
        "$d3_merge",
        ["$d2_base", "$d2_stale", "$d2_new"],
        "m.dmls.merge",
        3,
        "@alice:example.org",
        "MERGE",
        "MERGED",
        mls_epoch=3,
        resolves=["$d2_base", "$d2_stale", "$d2_new"],
        required_self_updates=["bob:D1"],
        label="epoch 3: base 0x01.., retain bob:D1 g1; self-update required",
    )

    # External join on a losing branch stays PENDING, then is ORPHANED.
    add_ev(
        "$d3_join",
        ["$d1_init"],
        "m.dmls.external_commit",
        3,
        "@carol:example.org",
        "EXT_JOIN",
        "PENDING",
        mls_epoch=3,
        commit_id="05" * 32,
        label="epoch 3 0x05..: carol:D1 external commit",
    )
    add_ev(
        "$d4_sib",
        ["$d3_merge"],
        "m.dmls.commit",
        4,
        "@alice:example.org",
        "SIBLING",
        "PENDING",
        mls_epoch=4,
        commit_id="07" * 32,
        label="epoch 4 0x07..: unrelated merge, carol still pending",
    )
    add_ev(
        "$d5_orph",
        ["$d4_sib", "$d3_join"],
        "m.dmls.merge",
        5,
        "@alice:example.org",
        "ORPHAN",
        "ORPHANED_EXTERNAL_JOINER",
        mls_epoch=5,
        commit_id="08" * 32,
        orphaned_external_joiners=["carol:D1"],
        label="epoch 5 0x08..: consumes 0x05.. without carol",
    )

    # MSC00FC device-root cutover: linear advance, freeze, re-anchor.
    add_ev(
        "$r1_g1",
        [],
        "m.room.device_root",
        1,
        "@alice:example.org",
        "ROOT h1g1",
        "ACTIVE_ROOT",
        user_epoch_height=1,
        generation=1,
        label="device_root (h=1, g=1, SSK_A)",
    )
    add_ev(
        "$r1_g2",
        ["$r1_g1"],
        "m.room.device_root",
        2,
        "@alice:example.org",
        "ROOT h1g2",
        "ACTIVE_ROOT",
        user_epoch_height=1,
        generation=2,
        label="device_root (h=1, g=2, SSK_A)",
    )
    add_ev(
        "$r1_g3a",
        ["$r1_g2"],
        "m.room.device_root",
        3,
        "@alice:example.org",
        "CONFLICT A",
        "FROZEN_FALLBACK_TO_G2",
        user_epoch_height=1,
        generation=3,
        label="device_root conflict A (h=1, g=3)",
    )
    add_ev(
        "$r1_g3b",
        ["$r1_g2"],
        "m.room.device_root",
        3,
        "@alice:example.org",
        "CONFLICT B",
        "FROZEN_FALLBACK_TO_G2",
        user_epoch_height=1,
        generation=3,
        label="device_root conflict B (h=1, g=3)",
    )
    add_ev(
        "$r2_g1",
        ["$r1_g2"],
        "m.room.device_root",
        4,
        "@alice:example.org",
        "REANCHOR",
        "REANCHORED_ACTIVE",
        user_epoch_height=2,
        generation=1,
        label="re-anchor (h=2, g=1, SSK_B) stales SSK_A",
    )
    add_ev(
        "$d6_remove",
        ["$d5_orph", "$r2_g1"],
        "m.dmls.merge",
        6,
        "@alice:example.org",
        "REMOVE",
        "REVOKED_LEAF_REMOVED",
        removes=["@alice:example.org:D1"],
        label="plan_with_device_roots: Remove stale alice:D1",
    )
    return events


def write_jsonl_trace(path: Path, records: Iterable[dict]) -> None:
    """Write one compact JSON object per line for daggraph.py."""
    lines = [
        json.dumps(record, sort_keys=True, separators=(",", ":")) for record in records
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_daggraph_trace_invariants() -> None:
    trace = build_daggraph_trace()
    by_id = {event["event_id"]: event for event in trace}
    assert len(by_id) == len(trace)
    for event in trace:
        assert event["alias"]
        assert event["status"]
        assert event["type"].startswith(("m.dmls.", "m.room."))
        for parent in event["prev_events"]:
            assert parent in by_id
            assert by_id[parent]["depth"] < event["depth"]
    assert "carol:D1" in by_id["$d5_orph"]["orphaned_external_joiners"]
    assert by_id["$d6_remove"]["removes"] == ["@alice:example.org:D1"]


def write_vectors(vectors: dict) -> None:
    OUTPUT_VECTORS.write_text(
        json.dumps(vectors, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    prettier = shutil.which("prettier")
    if prettier is None:
        return
    try:
        subprocess.run(
            [
                prettier,
                "--prose-wrap",
                "always",
                "--print-width",
                "80",
                "--write",
                "--",
                str(OUTPUT_VECTORS),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


def main(argv: Optional[Sequence[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--emit-jsonl",
        type=Path,
        default=None,
        help="Write a daggraph.py-compatible DMLS and MSC00FC trace.",
    )
    args = parser.parse_args(argv)

    result = {
        "version": 1,
        "tree_math_source": "mlswg/mls-implementations tree-math vectors",
        "tree_math_fixture": {
            "file": OFFICIAL_TREE_MATH.name,
            "blake3": blake3.blake3(OFFICIAL_TREE_MATH.read_bytes()).hexdigest(),
        },
        "official_tree_math": build_official_tree_math_vectors(),
        "draft11_tree_math": build_draft11_tree_math_vectors(),
        "rfc_member_counts": build_member_count_vectors(),
        "draft11_depths": check_draft11_depth_distribution(),
        "resolution_cost": check_resolution_and_wire_cost(),
        "wire_cost_513_and_truncation": check_513_wire_cost_and_truncation(),
        "concurrent_join_same_slot": check_concurrent_join_same_slot(),
        "leaf_signature_guards": check_leaf_signature_guards(),
        "resync_and_device_isolation": check_resync_and_device_isolation(),
        "merge_invariants": check_merge_invariants(),
        "ancestry_diamond": check_ancestry_diamond(),
        "00fc_leaf_binding": check_00fc_leaf_binding(),
        "00fc_rotation_rejects_update": check_00fc_rotation_rejects_update(),
        "device_root_resolution_boundary": check_device_root_resolution_boundary(),
    }
    write_vectors(result)
    if args.emit_jsonl is not None:
        trace = build_daggraph_trace()
        write_jsonl_trace(args.emit_jsonl, trace)
        print(f"Wrote {len(trace)} DAG trace events to {args.emit_jsonl}")
    print(f"DMLS checks passed; wrote {OUTPUT_VECTORS.name}")


if __name__ == "__main__":
    main(sys.argv[1:])
