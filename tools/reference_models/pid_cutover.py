#!/usr/bin/env python3
"""Prototype of the causal cutover predicates in Open Problem 2.

This is not room-version N authorization. It models only the graph predicates
the proposal would need with a separate m.room.server_seal state event:

  - only the server may send a seal, signed under an epoch at least as high;
  - Pass 0 resolves the highest unambiguous seal height first; a same-height
    conflict falls back without tainting event ancestry;
  - an event signed by that server below the seal's sealed_height contributes
    only if it is in the seal's causal past;
  - a relay advancement neither seals nor erases an existing seal;
  - device roots resolve at the highest user epoch height first, then by
    generation; a same-generation conflict retains the last unambiguous parent.

Running the file checks those predicates. It does not model event auth, state
resolution, or signatures.
"""

from typing import Dict, Iterable, List, Optional, Set, Tuple


class Event:
    def __init__(
        self,
        eid: str,
        prev: Tuple[str, ...],
        signer: str,
        signer_height: int,
        sealed_height: Optional[int] = None,
        seal: bool = False,
        previous_seal: Optional[str] = None,
        user_epoch_height: Optional[int] = None,
        generation: Optional[int] = None,
        previous_root: Optional[str] = None,
        signatures: Optional[Iterable[str]] = None,
    ) -> None:
        self.eid = eid
        self.prev = prev
        self.signer = signer
        self.signer_height = signer_height
        self.sealed_height = sealed_height
        self.seal = seal
        self.previous_seal = previous_seal
        self.user_epoch_height = user_epoch_height
        self.generation = generation
        self.previous_root = previous_root
        self.signatures = (
            frozenset(signatures) if signatures is not None else frozenset({signer})
        )


def ancestors(eid: str, events: Dict[str, Event]) -> Set[str]:
    seen: Set[str] = set()
    stack: List[str] = [eid]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        ev = events.get(cur)
        if ev is not None:
            stack.extend(ev.prev)
    return seen


def is_ancestor(ancestor: str, event: Event, events: Dict[str, Event]) -> bool:
    return ancestor in ancestors(event.eid, events)


def seal_auth_ok(seal: Event, events: Dict[str, Event]) -> bool:
    """Signed at or above its height and descending from a lower same-server seal."""
    if (
        not seal.seal
        or seal.sealed_height is None
        or seal.sealed_height < 1
        or seal.signer_height < seal.sealed_height
    ):
        return False
    if seal.sealed_height == 1:
        return True
    for aid in ancestors(seal.eid, events):
        prev = events.get(aid)
        if (
            prev is not None
            and prev.seal
            and prev.signer == seal.signer
            and prev.sealed_height is not None
            and 1 <= prev.sealed_height < seal.sealed_height
            and prev.signer_height >= prev.sealed_height
        ):
            return True
    return False


def resolve_seal(seals: Iterable[Event], events: Dict[str, Event]) -> Optional[Event]:
    """Top-down; a conflict falls back only through common ancestry."""
    by_height: Dict[int, Dict[str, Event]] = {}
    for ev in seals:
        if ev.seal and ev.sealed_height is not None:
            by_height.setdefault(ev.sealed_height, {})[ev.eid] = ev
    allowed: Optional[Set[str]] = None
    for height in sorted(by_height, reverse=True):
        candidates = by_height[height].values()
        if allowed is None:
            valid = [ev for ev in candidates if seal_auth_ok(ev, events)]
        else:
            valid = [
                ev
                for ev in candidates
                if ev.eid in allowed and seal_auth_ok(ev, events)
            ]
        if len(valid) == 1:
            return valid[0]
        if len(valid) > 1:
            common = set.intersection(*(ancestors(ev.eid, events) for ev in valid))
            allowed = common if allowed is None else (allowed & common)
    return None


def resolve_root(
    roots: Iterable[Event],
    events: Dict[str, Event],
    max_user_epoch_height: int,
    allowed: Optional[Set[str]] = None,
) -> Optional[Event]:
    """Top-down by epoch; within an epoch, generation advances by exactly one."""
    roots = tuple(roots)
    by_epoch: Dict[int, Dict[int, Dict[str, Event]]] = {}
    for ev in roots:
        if (
            ev.user_epoch_height is not None
            and ev.generation is not None
            and 0 <= ev.user_epoch_height <= max_user_epoch_height
            and (allowed is None or ev.eid in allowed)
        ):
            by_epoch.setdefault(ev.user_epoch_height, {}).setdefault(ev.generation, {})[
                ev.eid
            ] = ev

    def root_is_unambiguous(root_id: str, visiting: Set[str]) -> bool:
        root = events.get(root_id)
        if root is None or root.user_epoch_height is None or root.generation is None:
            return False
        slot = by_epoch.get(root.user_epoch_height, {}).get(root.generation, {})
        if len(slot) != 1 or root_id in visiting:
            return False
        if root.previous_root is None:
            return root.generation == 1
        parent = events.get(root.previous_root)
        if (
            parent is None
            or parent.user_epoch_height is None
            or parent.generation is None
        ):
            return False
        if root.generation == 1:
            parent_step = parent.user_epoch_height < root.user_epoch_height
        else:
            parent_step = (
                parent.user_epoch_height == root.user_epoch_height
                and parent.generation == root.generation - 1
            )
        return (
            parent_step
            and is_ancestor(parent.eid, root, events)
            and root_is_unambiguous(parent.eid, visiting | {root_id})
        )

    for epoch_height in sorted(by_epoch, reverse=True):
        current: Optional[Event] = None
        for generation in sorted(by_epoch[epoch_height]):
            if current is None and generation != 1:
                break
            if current is not None and generation != (current.generation or 0) + 1:
                break
            valid: List[Event] = []
            for ev in by_epoch[epoch_height][generation].values():
                if generation == 1:
                    if ev.previous_root is None:
                        valid.append(ev)
                        continue
                    parent = events.get(ev.previous_root)
                    if (
                        parent is not None
                        and parent.user_epoch_height is not None
                        and parent.user_epoch_height < epoch_height
                        and is_ancestor(parent.eid, ev, events)
                        and root_is_unambiguous(parent.eid, set())
                    ):
                        valid.append(ev)
                elif (
                    current is not None
                    and ev.previous_root == current.eid
                    and is_ancestor(current.eid, ev, events)
                ):
                    valid.append(ev)
            if len(valid) == 1:
                current = valid[0]
            elif len(valid) > 1 and generation == 1:
                common = set.intersection(*(ancestors(ev.eid, events) for ev in valid))
                if allowed is not None:
                    common &= allowed
                return resolve_root(roots, events, epoch_height - 1, common)
            else:
                break
        if current is not None:
            return current
    return None


def cutover_allows(ev: Event, seal: Optional[Event], events: Dict[str, Event]) -> bool:
    """Whether `ev` may contribute once `seal` is accepted in the room."""
    if seal is None or seal.sealed_height is None:
        return True
    if ev.signer != seal.signer:
        return True
    if ev.signer_height >= seal.sealed_height:
        return True
    return is_ancestor(ev.eid, seal, events)


def cert_allows(
    cert_generation: int,
    cert_ssk: str,
    epoch_generation: int,
    epoch_ssk: str,
) -> bool:
    """A certificate is valid only at the device root that committed its key."""
    return cert_generation == epoch_generation and cert_ssk == epoch_ssk


def generation_bump(previous: int, new: int) -> bool:
    return new == previous + 1


def run() -> int:
    e0 = Event("$e0", (), "S", 0)
    m0 = Event("$m0", ("$e0",), "S", 0)
    seal1 = Event("$seal1", ("$m0",), "S", 1, sealed_height=1, seal=True)
    m1_clean = Event("$m1clean", ("$seal1",), "S", 1)
    evil = Event("$evil", ("$e0",), "S", 0)
    other = Event("$other", ("$e0",), "T", 0)
    relay1 = Event("$relay1", ("$e0",), "R", 1)
    relay2 = Event("$relay2", ("$relay1",), "R", 2)
    seal2 = Event("$seal2", ("$m1clean",), "S", 2, sealed_height=2, seal=True)
    branch2b = Event("$b2b", ("$e0",), "S", 1)
    otherpost = Event("$otherpost", ("$e0",), "T", 0)
    alice_msg = Event("$alicemsg", ("$e0",), "U", 0, signatures=("U", "S"))
    seal2b = Event(
        "$seal2b",
        ("$m1clean", "$b2b", "$otherpost", "$alicemsg"),
        "S",
        2,
        sealed_height=2,
        seal=True,
    )
    seal2_sameheight = Event(
        "$seal2same", ("$seal2",), "S", 2, sealed_height=2, seal=True
    )
    seal3_bad = Event("$seal3bad", ("$seal2b",), "S", 3, sealed_height=3, seal=True)
    seal3_smuggle = Event(
        "$seal3smuggle",
        ("$seal1", "$seal2b"),
        "S",
        3,
        sealed_height=3,
        seal=True,
    )
    seal3_branch = Event(
        "$seal3branch", ("$seal1", "$b2b"), "S", 3, sealed_height=3, seal=True
    )
    seal3_clean = Event(
        "$seal3clean",
        ("$m1clean", "$otherpost"),
        "S",
        3,
        sealed_height=3,
        seal=True,
    )
    seal3_alice = Event(
        "$seal3alice",
        ("$m1clean", "$alicemsg"),
        "S",
        3,
        sealed_height=3,
        seal=True,
    )
    seal3_recover = Event(
        "$seal3recover",
        ("$seal2", "$m1clean"),
        "S",
        3,
        sealed_height=3,
        seal=True,
    )
    seal1_late = Event("$seal1late", ("$e0",), "S", 1, sealed_height=1, seal=True)
    seal2_late = Event(
        "$seal2late", ("$seal1", "$evil"), "S", 2, sealed_height=2, seal=True
    )
    seal3_conflict_a = Event(
        "$seal3conflicta", ("$seal1", "$m1clean"), "S", 3, sealed_height=3, seal=True
    )
    seal3_conflict_b = Event(
        "$seal3conflictb", ("$seal1", "$b2b"), "S", 3, sealed_height=3, seal=True
    )
    seal_low = Event("$seallow", ("$m0",), "S", 0, sealed_height=1, seal=True)

    root1 = Event("$root1", ("$m0",), "U", 0, user_epoch_height=1, generation=1)
    root0 = Event("$root0", ("$m0",), "U", 0, user_epoch_height=0, generation=1)
    root0a = Event("$root0a", ("$m0",), "U", 0, user_epoch_height=0, generation=1)
    root0b = Event(
        "$root0b", ("$m0", "$otherpost"), "U", 0, user_epoch_height=0, generation=1
    )
    root1_after_initial_conflict = Event(
        "$root1afterconflict",
        ("$m0",),
        "U",
        0,
        user_epoch_height=1,
        generation=1,
    )
    root1_bad_reanchor = Event(
        "$root1bad",
        ("$root0a",),
        "U",
        0,
        user_epoch_height=1,
        generation=1,
        previous_root="$root0a",
    )
    root2_initial = Event(
        "$root2initial",
        ("$m0",),
        "U",
        0,
        user_epoch_height=2,
        generation=1,
    )
    root2a = Event(
        "$root2a",
        ("$root1",),
        "U",
        0,
        user_epoch_height=1,
        generation=2,
        previous_root="$root1",
    )
    root2b = Event(
        "$root2b",
        ("$root1", "$otherpost"),
        "U",
        0,
        user_epoch_height=1,
        generation=2,
        previous_root="$root1",
    )
    root3skip = Event(
        "$root3skip",
        ("$root1",),
        "U",
        0,
        user_epoch_height=1,
        generation=3,
        previous_root="$root1",
    )
    root2at2 = Event(
        "$root2at2",
        ("$root1", "$otherpost"),
        "U",
        0,
        user_epoch_height=2,
        generation=1,
        previous_root="$root1",
    )
    root2at2b = Event(
        "$root2at2b",
        ("$root1",),
        "U",
        0,
        user_epoch_height=2,
        generation=1,
        previous_root="$root1",
    )
    root1gen2late = Event(
        "$root1gen2late",
        ("$root1",),
        "U",
        0,
        user_epoch_height=1,
        generation=2,
        previous_root="$root1",
    )
    root3at3 = Event(
        "$root3at3",
        ("$root1",),
        "U",
        0,
        user_epoch_height=3,
        generation=1,
        previous_root="$root1",
    )
    root3a = Event(
        "$root3a",
        ("$root1",),
        "U",
        0,
        user_epoch_height=3,
        generation=1,
        previous_root="$root1",
    )
    root3b = Event(
        "$root3b",
        ("$root1", "$otherpost"),
        "U",
        0,
        user_epoch_height=3,
        generation=1,
        previous_root="$root1",
    )

    events = {
        ev.eid: ev
        for ev in (
            e0,
            m0,
            seal1,
            m1_clean,
            evil,
            other,
            relay1,
            relay2,
            seal2,
            branch2b,
            otherpost,
            alice_msg,
            seal2b,
            seal2_sameheight,
            seal3_bad,
            seal3_smuggle,
            seal3_branch,
            seal3_clean,
            seal3_alice,
            seal3_recover,
            seal1_late,
            seal2_late,
            seal3_conflict_a,
            seal3_conflict_b,
            seal_low,
            root0,
            root0a,
            root0b,
            root1,
            root1_after_initial_conflict,
            root1_bad_reanchor,
            root2_initial,
            root2a,
            root2b,
            root3skip,
            root2at2,
            root2at2b,
            root1gen2late,
            root3at3,
            root3a,
            root3b,
        )
    }

    checks = [
        (
            "sealed rotation rejects an old-height sibling",
            not cutover_allows(evil, seal1, events),
        ),
        (
            "honest old-height ancestor survives",
            cutover_allows(m0, seal1, events),
        ),
        (
            "other signers are not filtered by this seal",
            cutover_allows(other, seal1, events),
        ),
        (
            "a relay advancement does not seal",
            cutover_allows(evil, relay1, events),
        ),
        (
            "a later relay does not erase the seal",
            resolve_seal((seal1,), events) is seal1
            and not cutover_allows(evil, seal1, events),
        ),
        (
            "a new seal descends from a lower seal",
            is_ancestor(seal1.eid, seal2, events),
        ),
        (
            "two seals at one height conflict and fall back",
            resolve_seal((seal1, seal2, seal2_sameheight), events) is seal1,
        ),
        (
            "the highest unambiguous seal wins",
            resolve_seal((seal1, seal2), events) is seal2,
        ),
        (
            "a seal under a lower epoch is rejected",
            not seal_auth_ok(seal_low, events),
        ),
        (
            "a same-height conflict retains the previous seal",
            resolve_seal((seal1, seal2, seal2b), events) is seal1,
        ),
        (
            "conflict resolution is order-independent",
            resolve_seal((seal1, seal2, seal2b), events)
            is resolve_seal((seal2b, seal2, seal1), events),
        ),
        (
            "duplicate seal event IDs are idempotent",
            resolve_seal((seal1, seal2, seal2), events) is seal2,
        ),
        (
            "a later seal may advance from the last unambiguous seal",
            resolve_seal((seal1, seal2, seal2b, seal3_clean), events) is seal3_clean,
        ),
        (
            "a later seal may descend through a conflicted lower height",
            resolve_seal((seal1, seal2b, seal3_bad), events) is seal3_bad,
        ),
        (
            "a later seal may merge a lower conflict",
            resolve_seal((seal1, seal2b, seal3_smuggle), events) is seal3_smuggle,
        ),
        (
            "a higher seal's ancestry determines which old events survive",
            resolve_seal((seal1, seal2b, seal3_branch), events) is seal3_branch
            and cutover_allows(branch2b, seal3_branch, events)
            and not cutover_allows(m1_clean, seal3_branch, events),
        ),
        (
            "a countersigned user event survives a lower conflict",
            resolve_seal((seal1, seal2b, seal3_alice), events) is seal3_alice,
        ),
        (
            "a higher seal recovers without tainting honest events",
            resolve_seal((seal1, seal2, seal2b, seal3_clean), events) is seal3_clean
            and cutover_allows(m1_clean, seal3_clean, events)
            and not cutover_allows(branch2b, seal3_clean, events),
        ),
        (
            "third-party events do not poison recovery",
            cutover_allows(otherpost, seal3_clean, events),
        ),
        (
            "siblings citing the honest tip do not erase it",
            resolve_seal((seal1, seal2, seal2b, seal3_recover), events) is seal3_recover
            and cutover_allows(m1_clean, seal3_recover, events),
        ),
        (
            "a retired seal at a lower height does not displace the current seal",
            resolve_seal((seal1_late, seal2), events) is seal2,
        ),
        (
            "seal conflict falls back only to a seal in every candidate's ancestry",
            resolve_seal(
                (seal1, seal2_late, seal3_conflict_a, seal3_conflict_b), events
            )
            is seal1,
        ),
        (
            "an initial device root is valid at genesis height zero",
            resolve_root((root0,), events, 0) is root0,
        ),
        (
            "an initial device root may first appear at a later resolved epoch",
            resolve_root((root2_initial,), events, 2) is root2_initial,
        ),
        (
            "an initial-root conflict can re-anchor later",
            resolve_root((root0a, root0b, root1_after_initial_conflict), events, 1)
            is root1_after_initial_conflict,
        ),
        (
            "a root cannot name an ambiguous root as its predecessor",
            resolve_root((root0a, root0b, root1_bad_reanchor), events, 1) is None,
        ),
        (
            "a same-generation root conflict freezes at the previous root",
            resolve_root((root1, root2a, root2b), events, 2) is root1,
        ),
        (
            "a root cannot skip a frozen generation at the same epoch height",
            resolve_root((root1, root2a, root2b, root3skip), events, 2) is root1,
        ),
        (
            "a user-epoch advance re-anchors a frozen root",
            resolve_root((root1, root2a, root2b, root2at2), events, 2) is root2at2,
        ),
        (
            "a device root cannot claim an epoch above resolved room state",
            resolve_root((root1, root2at2), events, 1) is root1,
        ),
        (
            "a master-key thief can freeze the re-anchored epoch too",
            resolve_root((root1, root2a, root2b, root2at2, root2at2b), events, 2)
            is root1,
        ),
        (
            "an old-epoch insertion does not displace a higher re-anchor",
            resolve_root((root1, root1gen2late, root3at3), events, 3) is root3at3,
        ),
        (
            "root conflict falls back only to a root in every candidate's ancestry",
            resolve_root((root1, root1gen2late, root3a, root3b), events, 3) is root1,
        ),
        (
            "an old certificate is rejected at the new generation",
            not cert_allows(1, "ssk1", 2, "ssk2"),
        ),
        (
            "the current certificate is accepted",
            cert_allows(2, "ssk2", 2, "ssk2"),
        ),
        (
            "a generation bump advances by exactly one",
            generation_bump(1, 2)
            and not generation_bump(2, 2)
            and not generation_bump(1, 3),
        ),
    ]
    failed = 0
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        if not ok:
            failed += 1
    print(f"\n{len(checks) - failed}/{len(checks)} cutover prototype checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(run())
