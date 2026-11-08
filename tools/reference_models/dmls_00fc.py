#!/usr/bin/env python3
"""Bridge MSC00FC device certificates and device roots into DMLS identities.

The DMLS merge model deliberately takes identity resolution as an injected
callback (``dmls_merge.PrincipalOf``); it knows nothing about certificates. This
module supplies that callback from room-level MSC00FC state:

* ``DeviceRootRegistry`` holds the unambiguous ``m.room.device_root`` for each
  principal (as produced by ``pid_cutover.resolve_root``) and the device
  certificates that were verified against a master key.
* ``DeviceRootRegistry.__call__`` is the strict resolver: the leaf's
  ``signature_key`` must be a certified device key, the leaf identity must name
  that device, and the certificate's self-signing key must equal the active
  root's self-signing key.
* ``DeviceRootRegistry.identity_of`` resolves identity without requiring the
  certificate to still be active. Merge planning needs this so it can *plan a
  removal* for a device that has been revoked or rotated.
* ``plan_with_device_roots`` turns inactive devices into Remove operations,
  refuses a stale base leaf when another branch has an active leaf for that
  device, and filters self-update requirements for removed devices.

MLS leaf generation and ``device_root.generation`` remain separate: the former
is group-scoped and advances on a re-join, the latter is room identity state.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Dict, Iterable, Mapping, Set, Tuple

import pid_pdu
from dmls_merge import (
    Branch,
    ExtremityId,
    IdentityMismatch,
    LeafVerifier,
    MemberId,
    MergePlan,
    PrincipalDevice,
    plan_merge,
)
from dmls_tree import LeafNode


class UncertifiedDevice(IdentityMismatch):
    """A leaf signature key is not certified for the claimed device identity."""


@dataclass(frozen=True)
class DeviceRoot:
    """The active, unambiguous MSC00FC device root for one principal."""

    principal: str
    user_epoch_height: int
    generation: int
    self_signing_key: bytes


@dataclass(frozen=True)
class CertifiedDevice:
    """One device key that was verified against a master key."""

    principal: str
    device_id: str
    device_key: bytes
    self_signing_key: bytes


@dataclass
class DeviceRootRegistry:
    """Certified devices plus the active device roots for one room view."""

    master_keys: Mapping[str, bytes]
    roots: Dict[str, DeviceRoot] = field(default_factory=dict)
    devices: Dict[bytes, CertifiedDevice] = field(default_factory=dict)
    revoked: Set[bytes] = field(default_factory=set)

    def install_root(self, root: DeviceRoot) -> DeviceRoot:
        """Install a root already resolved by ``pid_cutover.resolve_root``.

        The strict ``+1`` check is repeated here so a caller cannot silently
        install two unrelated roots at the same epoch height and generation.
        """
        current = self.roots.get(root.principal)
        if current is None:
            if root.generation != 1:
                raise UncertifiedDevice("first device_root must be generation 1")
        elif root.user_epoch_height < current.user_epoch_height:
            raise UncertifiedDevice("device_root epoch height moved backwards")
        elif root.user_epoch_height == current.user_epoch_height:
            if root.generation == current.generation:
                if root == current:
                    return current
                raise UncertifiedDevice(
                    "conflicting device_roots at the same epoch and generation"
                )
            if root.generation != current.generation + 1:
                raise UncertifiedDevice(
                    "device_root generation must advance by exactly one"
                )
        elif root.generation != 1:
            raise UncertifiedDevice(
                "first device_root at a new epoch height must be generation 1"
            )
        self.roots[root.principal] = root
        return root

    def certify(self, principal: str, cert: Mapping[str, object]) -> CertifiedDevice:
        """Verify the certificate chain and record the device key."""
        master_key = self.master_keys.get(principal)
        if master_key is None:
            raise UncertifiedDevice("no master key for principal")
        device_key = pid_pdu.verify_device_certificate(
            dict(cert), principal, master_key
        )
        device_id = str(cert["device_id"])
        self_signing_key = pid_pdu.unb64(str(cert["self_signing_key"]))
        root = self.roots.get(principal)
        if root is None:
            raise UncertifiedDevice("principal has no device_root")
        device = CertifiedDevice(principal, device_id, device_key, self_signing_key)
        # Keep stale certificates so merge planning can still recognise the
        # member and propose a Remove; ``is_active`` decides whether it may
        # continue as a live leaf.
        self.devices[device_key] = device
        return device

    def revoke(self, device_key: bytes) -> None:
        self.revoked.add(device_key)

    def is_active(self, leaf: LeafNode) -> bool:
        """Whether this leaf's device key is certified by the active root."""
        device = self.devices.get(leaf.signature_key)
        if device is None or leaf.signature_key in self.revoked:
            return False
        root = self.roots.get(device.principal)
        if root is None or device.self_signing_key != root.self_signing_key:
            return False
        try:
            principal, device_id = _identity_parts(leaf)
        except UncertifiedDevice:
            return False
        return device.principal == principal and device.device_id == device_id

    def identity_of(self, leaf: LeafNode) -> PrincipalDevice:
        """Resolve identity from a once-certified device, active or not."""
        principal, device_id = _identity_parts(leaf)
        device = self.devices.get(leaf.signature_key)
        if device is None:
            raise UncertifiedDevice("leaf signature key was never certified")
        if device.principal != principal or device.device_id != device_id:
            raise UncertifiedDevice(
                "leaf signature key is certified for a different device"
            )
        root = self.roots.get(principal)
        if root is None:
            raise UncertifiedDevice("principal has no device_root")
        return PrincipalDevice(
            principal=principal.encode("utf-8"),
            device_id=device_id,
            user_epoch_height=root.user_epoch_height,
            device_root_generation=root.generation,
        )

    def __call__(self, leaf: LeafNode) -> PrincipalDevice:
        """Strict resolver: the certificate must still chain to the active root."""
        identity = self.identity_of(leaf)
        if not self.is_active(leaf):
            raise UncertifiedDevice(
                "device certificate is revoked or stale for the active device_root"
            )
        return identity

    def require_active(self, leaf: LeafNode) -> None:
        if not self.is_active(leaf):
            raise UncertifiedDevice(
                "device certificate is revoked or stale for the active device_root"
            )

    def inactive_members(self, branch: Branch) -> Tuple[MemberId, ...]:
        """Members whose current leaf cannot be certified by the active root."""
        return tuple(
            sorted(
                member_id
                for member_id, record in branch.members.items()
                if not self.is_active(record.leaf)
            )
        )


def _identity_parts(leaf: LeafNode) -> Tuple[str, str]:
    """Decode the model's ``principal:device_id`` identity convention."""
    try:
        principal, device_id = leaf.identity.decode("utf-8").rsplit(":", 1)
    except (UnicodeDecodeError, ValueError) as error:
        raise UncertifiedDevice("leaf identity is not principal:device") from error
    return principal, device_id


def plan_with_device_roots(
    requested: Iterable[ExtremityId],
    held: Mapping[ExtremityId, Branch],
    group_id: bytes,
    registry: DeviceRootRegistry,
    verify_leaf: LeafVerifier,
) -> MergePlan:
    """Plan a merge while reconciling active certificates and stale leaves.

    A stale leaf cannot supersede an active leaf for the same device, whichever
    branch wins base selection. A stale leaf is removed only when the resolved
    member state is inactive; stale historical leaves do not evict a valid
    re-certification from another branch.

    ``verify_leaf`` is mandatory on this path: the device-root bridge never
    plans without LeafNode signature checks.
    """
    if verify_leaf is None:
        raise ValueError("plan_with_device_roots requires a LeafNode verifier")
    requested_ids = tuple(requested)
    plan = plan_merge(requested_ids, held, group_id, registry.identity_of, verify_leaf)

    active_anywhere: Set[MemberId] = set()
    for extremity in requested_ids:
        branch = held.get(extremity)
        if branch is None:
            continue
        active_anywhere.update(
            member_id
            for member_id, record in branch.members.items()
            if registry.is_active(record.leaf)
        )

    for member_id, record in plan.members.items():
        if not registry.is_active(record.leaf) and member_id in active_anywhere:
            raise UncertifiedDevice(
                "stale or revoked leaf supersedes an active certificate for the same device"
            )

    # A self-update is only worth requiring when some branch holds an active,
    # newer leaf for the member; a stale or revoked candidate never justifies it.
    def _has_active_newer(member_id: MemberId) -> bool:
        base_gen = plan.members[member_id].leaf.generation
        for extremity in requested_ids:
            record = held[extremity].members.get(member_id)
            if (
                record is not None
                and registry.is_active(record.leaf)
                and record.leaf.generation > base_gen
            ):
                return True
        return False

    plan = replace(
        plan,
        required_self_updates=tuple(
            m for m in plan.required_self_updates if _has_active_newer(m)
        ),
    )

    removed = set(plan.removes)
    inactive = {
        member_id
        for member_id, record in plan.members.items()
        if not registry.is_active(record.leaf)
    }
    if not inactive:
        return plan
    base_members = held[plan.base].members
    removed.update(inactive & set(base_members))
    return replace(
        plan,
        members={
            member_id: record
            for member_id, record in plan.members.items()
            if member_id not in inactive
        },
        required_self_updates=tuple(
            member_id
            for member_id in plan.required_self_updates
            if member_id not in inactive
        ),
        adds=tuple(
            (member_id, leaf)
            for member_id, leaf in plan.adds
            if member_id not in inactive
        ),
        removes=tuple(sorted(removed)),
    )
