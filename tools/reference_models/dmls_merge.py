#!/usr/bin/env python3
"""Reference model for DMLS extremities and identity-keyed merge planning.

The room/identity layer is intentionally injected through ``principal_of``.
In a combined MSC00FC/DMLS harness, that callback must validate the leaf's
device certificate against the resolved user chain and return its stable
principal and device ID. The MSC00FC device-root generation is retained as
identity metadata; it is not compared with the separate, group-scoped MLS leaf
generation.

This is a state-machine model, not an MLS implementation. It does not create
commits, compute RFC transcript hashes, or implement UpdatePath cryptography.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import (
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Set,
    Tuple,
)

from dmls_tree import LeafNode


class MergeError(ValueError):
    """Invalid or incomplete DMLS merge input."""


class MissingBaseState(MergeError):
    """A requested extremity is known but its group state is not held locally."""

    def __init__(self, commit_id: bytes):
        self.commit_id = commit_id
        super().__init__(f"missing local group state for {commit_id.hex()}")


class IdentityMismatch(MergeError):
    """An update candidate does not match the member identity."""


class GenerationError(MergeError):
    """An update candidate is stale or belongs to another MLS group."""


class SignatureError(MergeError):
    """A LeafNode signature, source or position binding did not verify."""


class MembershipConflict(MergeError):
    """Concurrent branches disagree on a member at the same MLS generation."""


@dataclass(frozen=True, order=True)
class MemberId:
    principal: bytes
    device_id: str


@dataclass(frozen=True)
class PrincipalDevice:
    principal: bytes
    device_id: str
    user_epoch_height: int
    device_root_generation: int

    @property
    def member_id(self) -> MemberId:
        return MemberId(self.principal, self.device_id)


PrincipalOf = Callable[[LeafNode], PrincipalDevice]
# Verifies a LeafNode at ``leaf_index``; injected so the model carries no
# signature scheme. ``for_update`` is True when the leaf is checked as an
# update candidate, where the verifier MUST also reject a "key_package"-sourced
# leaf. It owns the whole leaf-validity decision.
LeafVerifier = Callable[[LeafNode, Optional[int], bool], bool]


@dataclass(frozen=True)
class ExtremityId:
    """Stable identity for one DMLS commit extremity."""

    mls_epoch: int
    commit_id: bytes

    def __post_init__(self) -> None:
        if self.mls_epoch < 0:
            raise MergeError("MLS epoch must be non-negative")
        if len(self.commit_id) != 32:
            raise MergeError("commit_id must be a 32-byte commit-message digest")


@dataclass(frozen=True)
class LeafRecord:
    leaf: LeafNode
    origin: str = "member"
    # Slot in this branch's tree. Existing members never move between branches;
    # slots of members added on a losing branch are discarded by the merge.
    leaf_index: Optional[int] = None

    def __post_init__(self) -> None:
        if self.origin not in {"member", "add", "external_commit"}:
            raise MergeError(f"unsupported leaf origin: {self.origin}")


@dataclass(frozen=True)
class Branch:
    extremity: ExtremityId
    # Retained to describe the common fork context; it is not a secret HMAC key.
    parent_transcript_hash: bytes
    members: Mapping[MemberId, LeafRecord]
    # Retain the evicted leaf so concurrent removals can be compared with
    # updates independently of which branch becomes the merge base.
    removed: Mapping[MemberId, LeafNode] = field(default_factory=dict)
    external_joiners: FrozenSet[MemberId] = frozenset()
    resolves: FrozenSet[ExtremityId] = frozenset()


@dataclass(frozen=True)
class MergePlan:
    base: ExtremityId
    members: Mapping[MemberId, LeafRecord]
    required_self_updates: Tuple[MemberId, ...]
    adds: Tuple[Tuple[MemberId, LeafNode], ...]
    removes: Tuple[MemberId, ...]
    orphaned_external_joiners: Tuple[MemberId, ...]


class ExternalJoinStatus(str, Enum):
    """Local knowledge about the fate of a pending external commit."""

    ACCEPTED = "accepted"
    PENDING = "pending"
    ORPHANED = "orphaned"


def extremity_tie_breaker(branch: Branch) -> bytes:
    """Return the commit digest as a deterministic, grindable tie key."""
    return branch.extremity.commit_id


def extremity_score(branch: Branch) -> Tuple[int, bytes]:
    """Ascending sort key: higher epoch first, then deterministic digest order."""
    return (-branch.extremity.mls_epoch, extremity_tie_breaker(branch))


def select_base(
    requested: Iterable[ExtremityId], held: Mapping[ExtremityId, Branch]
) -> Branch:
    """Select the canonical base, deferring if any requested state is missing."""
    requested_set = set(requested)
    if not requested_set:
        raise MergeError("cannot resolve an empty extremity set")
    missing = sorted(
        requested_set - set(held), key=lambda e: (e.mls_epoch, e.commit_id)
    )
    if missing:
        raise MissingBaseState(missing[0].commit_id)
    return min((held[ext] for ext in requested_set), key=extremity_score)


def validate_update_candidate(
    old_leaf: LeafNode,
    new_leaf: LeafNode,
    group_id: bytes,
    principal_of: PrincipalOf,
    require_newer: bool = True,
    leaf_index: Optional[int] = None,
    verify_leaf: Optional[LeafVerifier] = None,
) -> MemberId:
    """Validate device/group continuity and optionally a higher generation.

    With ``verify_leaf``, ``new_leaf`` must also pass the verifier at
    ``leaf_index``; see ``LeafVerifier``.
    """
    old_identity = principal_of(old_leaf)
    new_identity = principal_of(new_leaf)
    if old_identity.member_id != new_identity.member_id:
        raise IdentityMismatch(
            "other-branch update candidate changes the certified member identity"
        )
    if new_leaf.group_id != group_id or old_leaf.group_id != group_id:
        raise GenerationError("leaf generation extension has the wrong group_id")
    if require_newer and new_leaf.generation <= old_leaf.generation:
        raise GenerationError(
            "other-branch update candidate generation must strictly increase"
        )
    if verify_leaf is not None:
        if new_leaf.source != "key_package" and leaf_index is None:
            raise SignatureError("leaf_index is required to verify this leaf")
        if not verify_leaf(new_leaf, leaf_index, require_newer):
            raise SignatureError("LeafNode does not verify at this position")
    return old_identity.member_id


def _validated_members(
    branch: Branch, principal_of: PrincipalOf
) -> Dict[MemberId, LeafRecord]:
    out: Dict[MemberId, LeafRecord] = {}
    for member_id, record in branch.members.items():
        resolved = principal_of(record.leaf).member_id
        if resolved != member_id:
            raise IdentityMismatch(
                "branch member key disagrees with certified leaf identity"
            )
        if member_id in out:
            raise IdentityMismatch(
                "branch contains duplicate certified member identities"
            )
        out[member_id] = record
    return out


def _validated_removed(
    branch: Branch, group_id: bytes, principal_of: PrincipalOf
) -> Dict[MemberId, LeafNode]:
    out: Dict[MemberId, LeafNode] = {}
    for member_id, leaf in branch.removed.items():
        if principal_of(leaf).member_id != member_id:
            raise IdentityMismatch(
                "branch removed key disagrees with certified leaf identity"
            )
        if leaf.group_id != group_id:
            raise GenerationError("removed leaf has the wrong group_id")
        if member_id in branch.members:
            raise MergeError("member cannot be both present and removed in one branch")
        out[member_id] = leaf
    return out


def plan_merge(
    requested: Iterable[ExtremityId],
    held: Mapping[ExtremityId, Branch],
    group_id: bytes,
    principal_of: PrincipalOf,
    verify_leaf: Optional[LeafVerifier] = None,
) -> MergePlan:
    """Plan identity-keyed membership reconciliation across held extremities.

    The chosen base's membership and tree indexing are retained. A valid,
    higher-generation leaf on another branch is checked as a candidate and
    recorded as a requirement for that member to issue its own Update after
    applying the base Commit; the candidate leaf is never installed by the
    merge. Removals are compared symmetrically across all held branches,
    including the base, using each branch's retained evicted leaf. External
    joiners found only on non-base branches are orphaned and deliberately
    omitted so callers can require a fresh external commit rather than reuse
    their old LeafNode/KeyPackage.
    """
    requested_ids = tuple(set(requested))
    base = select_base(requested_ids, held)
    branches = sorted((held[ext] for ext in requested_ids), key=extremity_score)
    members_by_extremity = {
        branch.extremity: _validated_members(branch, principal_of)
        for branch in branches
    }
    removed_by_extremity = {
        branch.extremity: _validated_removed(branch, group_id, principal_of)
        for branch in branches
    }
    base_members = members_by_extremity[base.extremity]
    merged = dict(base_members)
    required_self_updates: Set[MemberId] = set()
    add_ops: Dict[MemberId, LeafNode] = {}
    remove_ops: Set[MemberId] = set()
    orphaned: Set[MemberId] = set()
    evicted_members: Set[MemberId] = set()

    # Compare every removal with every surviving copy, including removals on
    # the selected base branch. This makes remove/update conflicts symmetric.
    for branch in branches:
        for member_id, removed_leaf in removed_by_extremity[branch.extremity].items():
            for other in branches:
                if other.extremity == branch.extremity:
                    continue
                other_record = members_by_extremity[other.extremity].get(member_id)
                if other_record is None:
                    continue
                if (
                    member_id in other.external_joiners
                    or other_record.origin == "external_commit"
                ):
                    # External joins are discarded during merge; they are not
                    # competing updates to the removed member.
                    continue
                validate_update_candidate(
                    removed_leaf,
                    other_record.leaf,
                    group_id,
                    principal_of,
                    require_newer=False,
                    leaf_index=other_record.leaf_index,
                    verify_leaf=verify_leaf,
                )
                if (
                    other_record.leaf != removed_leaf
                    and other_record.leaf.generation >= removed_leaf.generation
                ):
                    raise MembershipConflict(
                        "concurrent removal/update needs an explicit protocol rule"
                    )
            evicted_members.add(member_id)
            if member_id in base_members:
                merged.pop(member_id, None)
                remove_ops.add(member_id)
                required_self_updates.discard(member_id)

    for branch in branches:
        if branch.extremity == base.extremity:
            continue
        branch_members = members_by_extremity[branch.extremity]

        for member_id, record in branch_members.items():
            base_record = base_members.get(member_id)
            is_external_join = (
                member_id in branch.external_joiners
                or record.origin == "external_commit"
            )
            if is_external_join:
                if base_record is None or member_id in evicted_members:
                    orphaned.add(member_id)
                # The external commit's LeafNode is never copied into a merge.
                # If the base already has this identity, its base LeafNode wins.
                continue
            if member_id in evicted_members:
                continue
            if base_record is None:
                existing = merged.get(member_id)
                if existing is not None and existing.leaf != record.leaf:
                    if existing.leaf.generation == record.leaf.generation:
                        raise MembershipConflict(
                            "same member has different leaves at the same generation"
                        )
                    if existing.leaf.generation > record.leaf.generation:
                        continue
                # The applier places the joiner at the leftmost blank leaf of the
                # merged tree, so a slot taken on this branch is dropped.
                merged[member_id] = replace(record, leaf_index=None)
                add_ops[member_id] = record.leaf
                continue

            if (
                record.leaf_index is not None
                and base_record.leaf_index is not None
                and record.leaf_index != base_record.leaf_index
            ):
                if base_record.origin != "external_commit":
                    raise MembershipConflict("an existing member moved leaf index")
                # The base holds an RFC 9420 resync: the member rejoined at a new
                # slot and removed its old leaf. A copy at the old slot is stale
                # unless it is at least as new, and a signed update cannot be
                # moved to another slot, so that case needs a fresh update.
                validate_update_candidate(
                    base_record.leaf,
                    record.leaf,
                    group_id,
                    principal_of,
                    require_newer=False,
                    leaf_index=record.leaf_index,
                    verify_leaf=verify_leaf,
                )
                if record.leaf.generation >= base_record.leaf.generation:
                    raise MembershipConflict(
                        "update authored on a pre-resync slot must be re-issued"
                    )
                continue
            if record.leaf == base_record.leaf:
                continue
            if record.leaf.generation < base_record.leaf.generation:
                # A branch that never applied the newer update is stale, not
                # invalid. Verify its identity binding, then keep the base leaf.
                validate_update_candidate(
                    base_record.leaf,
                    record.leaf,
                    group_id,
                    principal_of,
                    require_newer=False,
                    leaf_index=record.leaf_index,
                    verify_leaf=verify_leaf,
                )
                continue
            if record.leaf.generation == base_record.leaf.generation:
                raise MembershipConflict(
                    "same member has different leaves at the same generation"
                )
            member_id_from_update = validate_update_candidate(
                base_record.leaf,
                record.leaf,
                group_id,
                principal_of,
                leaf_index=record.leaf_index,
                verify_leaf=verify_leaf,
            )
            if member_id_from_update != member_id:
                raise IdentityMismatch(
                    "other-branch update candidate identity mismatch"
                )
            current = merged[member_id].leaf
            if record.leaf.generation == current.generation:
                if record.leaf != current:
                    raise MembershipConflict(
                        "same member has different leaves at the same generation"
                    )
                continue
            if record.leaf.generation > current.generation:
                # The other branch's leaf is evidence that the member needs
                # to refresh, not a LeafNode this committer may install.
                required_self_updates.add(member_id)
                add_ops.pop(member_id, None)

    return MergePlan(
        base=base.extremity,
        members=merged,
        required_self_updates=tuple(sorted(required_self_updates)),
        adds=tuple(sorted(add_ops.items())),
        removes=tuple(sorted(remove_ops)),
        orphaned_external_joiners=tuple(sorted(orphaned)),
    )


def apply_resolved_set(
    local_extremities: Iterable[ExtremityId],
    merge_extremity: ExtremityId,
    resolves: Iterable[ExtremityId],
) -> FrozenSet[ExtremityId]:
    """Apply a merge's advertised consumed set idempotently to a local view."""
    remaining = set(local_extremities)
    remaining.difference_update(resolves)
    remaining.add(merge_extremity)
    return frozenset(remaining)


def _descends_from(
    extremity: ExtremityId,
    ancestor: ExtremityId,
    held: Mapping[ExtremityId, Branch],
) -> Optional[bool]:
    """Check reachability in the locally held resolves graph.

    ``None`` means at least one reachable parent is missing locally. A shared
    visited set makes reconverging ancestry graphs linear in their reachable
    vertices and edges, without caching results that depend on a DFS stack.
    """
    if extremity == ancestor:
        return True
    pending = [extremity]
    visited: Set[ExtremityId] = set()
    incomplete = False
    while pending:
        current = pending.pop()
        if current == ancestor:
            return True
        if current in visited:
            continue
        visited.add(current)
        branch = held.get(current)
        if branch is None:
            incomplete = True
            continue
        pending.extend(branch.resolves)
    return None if incomplete else False


def external_join_status(
    joiner: MemberId, commit: ExtremityId, state: "DmlsMergeState"
) -> ExternalJoinStatus:
    """Classify a join only after all known surviving tips supersede its branch.

    A live external-commit extremity remains pending. An unrelated current tip
    or incomplete local ancestry also keeps the result pending, preventing an
    unrelated merge from causing a false orphan decision.
    """
    if commit in state.extremities or not state.extremities:
        return ExternalJoinStatus.PENDING

    descendants: List[Branch] = []
    for extremity in state.extremities:
        if _descends_from(extremity, commit, state.held) is not True:
            return ExternalJoinStatus.PENDING
        branch = state.held.get(extremity)
        if branch is None:
            return ExternalJoinStatus.PENDING
        descendants.append(branch)

    membership = [joiner in branch.members for branch in descendants]
    if all(membership):
        return ExternalJoinStatus.ACCEPTED
    if not any(membership):
        return ExternalJoinStatus.ORPHANED
    return ExternalJoinStatus.PENDING


@dataclass
class DmlsMergeState:
    """Locally held group states and the currently known extremity set."""

    held: Dict[ExtremityId, Branch] = field(default_factory=dict)
    extremities: Set[ExtremityId] = field(default_factory=set)

    def observe_branch(self, branch: Branch) -> None:
        self.held[branch.extremity] = branch
        self.extremities.add(branch.extremity)

    def observe_merge(self, branch: Branch, resolves: Iterable[ExtremityId]) -> None:
        resolved = frozenset(resolves)
        self.held[branch.extremity] = replace(branch, resolves=resolved)
        self.extremities = set(
            apply_resolved_set(self.extremities, branch.extremity, resolved)
        )

    def plan(
        self,
        group_id: bytes,
        principal_of: PrincipalOf,
        verify_leaf: Optional[LeafVerifier] = None,
    ) -> MergePlan:
        return plan_merge(
            self.extremities, self.held, group_id, principal_of, verify_leaf
        )
