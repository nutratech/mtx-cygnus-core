#!/usr/bin/env python3
"""Reference model for MSCxxxx: self-certifying server and portable user identities.

Scope: the link layer (serialization, digests, verify_link), the auth rules for
active and burn epoch events, Pass 0 resolution, and pure §8 name-binding and
ingress policy models. Running the file regenerates
the Appendix A test vectors (pid_vectors.json) and checks the threat-model
scenarios, including two attacks that succeed against the previous draft's rules
(height inflation in Pass 0, and burns built on a chain the room never accepted).

Out of scope: PDU hashing/redaction, Passes 1-2, federation. Those are unchanged
v2.1 machinery plus the small consultation rules described in the MSC.

Signature verification uses OpenSSL via `cryptography`. The MSC mandates ZIP-215
verification; the two agree on every canonical signature, and all vectors here
are canonical.
"""

import base64
import hashlib
import json
import random
import re
import shutil
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TypedDict

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

VERSION = 1
KIND_SERVER = 1
KIND_USER = 2
TAG_COMMIT = b"matrix-cygnus-rot-v1\x00"
TAG_LINK = b"matrix-cygnus-link-v1\x00"
ZERO32 = bytes(32)
COMMON = struct.Struct(">BB32sQ32s32s")  # 106 bytes

SERVER_NAME_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
    r"|\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-f:.]+\])(?::\d{1,5})?$"
)
MXID_RE = re.compile(r"^@[a-z0-9._=\-/+]+:(.+)$")


class Invalid(Exception):
    pass


# --------------------------------------------------------------------------- helpers


def sha256(b: bytes) -> bytes:
    """PDU-layer hashing. 00FC link digests use ``blake3_digest`` below."""
    return hashlib.sha256(b).digest()


def blake3_digest(b: bytes) -> bytes:
    return blake3.blake3(b).digest()


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def write_json(filename: str, value: object) -> None:
    """Write generated JSON beside this script, formatted if Prettier is present.

    The file is always written next to the script, so the working directory
    cannot produce stray copies. Formatting is best-effort: a machine without
    Node still runs the reference model and gets equivalent JSON.
    """
    path = Path(__file__).with_name(filename)
    with open(path, "w") as fh:
        json.dump(value, fh, indent=2)
        fh.write("\n")
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
                str(path),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass


def sk_from_seed(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def pub(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def commitment(rot_pub: bytes) -> bytes:
    return blake3_digest(TAG_COMMIT + rot_pub)


def verify_sig(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------- links


@dataclass(frozen=True)
class Link:
    kind: int
    root: bytes
    height: int
    prev: bytes
    next_commit: bytes
    body: bytes
    trailer: bytes
    # server payload
    online_key: Optional[bytes] = None
    server_name: Optional[str] = None
    # user payload
    custodian: Optional[bytes] = None
    msk: Optional[bytes] = None
    mxid: Optional[str] = None

    @property
    def digest(self) -> bytes:
        return blake3_digest(self.body)

    @property
    def raw(self) -> bytes:
        return self.body + self.trailer

    @property
    def principal(self) -> bytes:
        """Raw 32-byte principal digest this link belongs to."""
        return self.digest if self.height == 0 else self.root

    @property
    def rot_pub(self) -> Optional[bytes]:
        return self.trailer[:32] if self.height > 0 else None


def _common(kind, root, height, prev, nc) -> bytes:
    return COMMON.pack(VERSION, kind, root, height, prev, nc)


def server_body(root, height, prev, nc, online_key, server_name) -> bytes:
    n = server_name.encode("ascii")
    return (
        _common(KIND_SERVER, root, height, prev, nc)
        + online_key
        + struct.pack(">H", len(n))
        + n
    )


def user_body(root, height, prev, nc, custodian, msk, mxid) -> bytes:
    m = mxid.encode("ascii")
    flag = b"\x01" + msk if msk is not None else b"\x00"
    return (
        _common(KIND_USER, root, height, prev, nc)
        + custodian
        + flag
        + struct.pack(">H", len(m))
        + m
    )


def parse_body(raw: bytes):
    """Parse a link body from the front of `raw`. Returns (fields, body_len)."""
    if len(raw) < COMMON.size:
        raise Invalid("short body")
    ver, kind, root, height, prev, nc = COMMON.unpack_from(raw, 0)
    if ver != VERSION:
        raise Invalid("bad version")
    off = COMMON.size
    f = dict(kind=kind, root=root, height=height, prev=prev, next_commit=nc)
    if kind == KIND_SERVER:
        if len(raw) < off + 34:
            raise Invalid("short server payload")
        f["online_key"] = raw[off : off + 32]
        (n,) = struct.unpack_from(">H", raw, off + 32)
        off += 34
        name = raw[off : off + n]
        if len(name) != n or not 1 <= n <= 255:
            raise Invalid("bad server_name length")
        try:
            s = name.decode("ascii")
        except UnicodeDecodeError:
            raise Invalid("server_name not ascii")
        if not SERVER_NAME_RE.match(s):
            raise Invalid("server_name not canonical")
        f["server_name"] = s
        off += n
    elif kind == KIND_USER:
        if len(raw) < off + 33:
            raise Invalid("short user payload")
        f["custodian"] = raw[off : off + 32]
        flag = raw[off + 32]
        off += 33
        if flag == 1:
            f["msk"] = raw[off : off + 32]
            if len(f["msk"]) != 32:
                raise Invalid("short msk")
            off += 32
        elif flag != 0:
            raise Invalid("bad msk flag")
        (m,) = struct.unpack_from(">H", raw, off)
        off += 2
        mx = raw[off : off + m]
        if len(mx) != m or not 4 <= m <= 255:
            raise Invalid("bad mxid length")
        try:
            s = mx.decode("ascii")
        except UnicodeDecodeError:
            raise Invalid("mxid not ascii")
        mm = MXID_RE.match(s)
        if not mm or not SERVER_NAME_RE.match(mm.group(1)):
            raise Invalid("mxid malformed")
        f["mxid"] = s
        off += m
    else:
        raise Invalid("bad kind")
    if height == 0 and (root != ZERO32 or prev != ZERO32):
        raise Invalid("genesis must have zero root and prev")
    if height > 0 and (root == ZERO32 or prev == ZERO32):
        raise Invalid("non-genesis needs root and prev")
    return f, off


def trailer_len(kind: int, height: int) -> int:
    if height > 0:
        return 96
    return 64 if kind == KIND_SERVER else 0


def parse_link(raw: bytes) -> Link:
    f, blen = parse_body(raw)
    tl = trailer_len(f["kind"], f["height"])
    if len(raw) != blen + tl:
        raise Invalid("bad trailer length")
    return Link(body=raw[:blen], trailer=raw[blen:], **f)


def parse_body_only(body: bytes) -> Link:
    f, blen = parse_body(body)
    if blen != len(body):
        raise Invalid("trailing bytes after body")
    return Link(body=body, trailer=b"", **f)


def verify_link(link: Link, parent: Optional[Link]) -> None:
    """Raises Invalid unless `link` is a valid successor of `parent` (or a valid genesis)."""
    if link.height == 0:
        if parent is not None:
            raise Invalid("genesis cannot have a parent")
        if link.kind == KIND_SERVER:
            assert link.online_key is not None
            if not verify_sig(link.online_key, TAG_LINK + link.body, link.trailer):
                raise Invalid("bad server genesis signature")
        return
    if parent is None:
        raise Invalid("rotation needs parent")
    if link.kind != parent.kind:
        raise Invalid("kind mismatch")
    if link.kind == KIND_USER and link.msk != parent.msk:
        raise Invalid("user master key changed")
    if link.height != parent.height + 1:
        raise Invalid("height must increment")
    if link.root != parent.principal:
        raise Invalid("root mismatch")
    if link.prev != parent.digest:
        raise Invalid("prev mismatch")
    rp = link.rot_pub
    assert rp is not None
    if commitment(rp) != parent.next_commit:
        raise Invalid("revealed rotation key does not match commitment")
    if not verify_sig(rp, TAG_LINK + link.body + rp, link.trailer[32:]):
        raise Invalid("bad rotation signature")


def verify_slice(links: List[Link], parent: Optional[Link]) -> None:
    p = parent
    for lnk in links:
        verify_link(lnk, p)
        p = lnk


# --------------------------------------------------------------------------- link builders


def make_server_genesis(online_sk, next_rot_pub, server_name) -> Link:
    body = server_body(
        ZERO32, 0, ZERO32, commitment(next_rot_pub), pub(online_sk), server_name
    )
    return parse_link(body + online_sk.sign(TAG_LINK + body))


def make_user_genesis(
    custodian: bytes, next_commit: bytes, mxid: str, msk: Optional[bytes]
) -> Link:
    # The client supplies only next_commit; the custodian never sees the rotation key.
    return parse_link(user_body(ZERO32, 0, ZERO32, next_commit, custodian, msk, mxid))


def make_rotation(parent: Link, rot_sk, next_commit: bytes, **payload) -> Link:
    root, h, prev = parent.principal, parent.height + 1, parent.digest
    if parent.kind == KIND_SERVER:
        body = server_body(
            root, h, prev, next_commit, payload["online_key"], payload["server_name"]
        )
    else:
        body = user_body(
            root,
            h,
            prev,
            next_commit,
            payload["custodian"],
            payload.get("msk"),
            payload["mxid"],
        )
    rp = pub(rot_sk)
    return parse_link(body + rp + rot_sk.sign(TAG_LINK + body + rp))


# --------------------------------------------------------------------------- epoch events


@dataclass
class EpochEvent:
    event_id: str
    key: bytes  # principal digest (state_key, decoded)
    status: str  # "active" | "burned"
    prev: Optional["EpochEvent"]  # same-key epoch event cited in auth_events
    slice: List[Link] = field(default_factory=list)  # active only
    # burn only
    fork_height: int = 0
    parent_body: bytes = b""
    bridge: List[Link] = field(default_factory=list)
    branch_a: Optional[Link] = None
    branch_b: Optional[Link] = None

    @property
    def chain(self) -> List[Link]:
        """Full chain from genesis that this event establishes (burns: their anchor's chain)."""
        if self.status == "burned":
            assert self.prev is not None
            return self.prev.chain
        return (self.prev.chain if self.prev else []) + self.slice

    @property
    def height(self) -> int:
        return self.chain[-1].height

    @property
    def tip(self) -> Link:
        return self.chain[-1]

    def claimed_digests(self) -> List[bytes]:
        """Burn only: digests of the chain the proof stands on, heights 0..f-1."""
        assert self.prev is not None
        base = [lnk.digest for lnk in self.prev.chain]
        f, g = self.fork_height, self.prev.height
        if f == g:
            return base[:f]
        return base + [lnk.digest for lnk in self.bridge]


def auth_active(e: EpochEvent) -> None:
    if not e.slice:
        raise Invalid("empty slice")
    if e.prev is None:
        # Genesis-only first introduction: guarantees every fork has a common epoch event.
        if len(e.slice) != 1 or e.slice[0].height != 0 or e.slice[0].digest != e.key:
            raise Invalid(
                "first introduction must carry exactly this principal's genesis link"
            )
        verify_slice(e.slice, None)
    else:
        if e.prev.status != "active":
            raise Invalid("principal is burned")
        verify_slice(
            e.slice, e.prev.tip
        )  # strictly extends the cited tip, so height increases


def auth_burn(e: EpochEvent) -> None:
    """Tip-anchored duplicity proof (MSC section 5.4)."""
    if e.prev is None or e.prev.status != "active":
        raise Invalid("burn needs an active anchor in auth_events")
    assert e.prev is not None and e.branch_a is not None and e.branch_b is not None
    T, g, f = e.prev.tip, e.prev.height, e.fork_height
    if f < 1:
        raise Invalid("cannot fork genesis")
    if f < g:
        raise Invalid("stale: fork below the room's established tip")
    parent = parse_body_only(e.parent_body)
    if f == g:
        if e.bridge:
            raise Invalid("bridge must be empty when forking at the tip")
        if parent.digest != T.prev:
            raise Invalid("parent is not the tip's parent")
        if e.branch_a.digest != T.digest:
            raise Invalid("branch_a must be the room's tip link")
    else:
        if len(e.bridge) != f - 1 - g:
            raise Invalid("bridge must cover heights g+1..f-1")
        verify_slice(e.bridge, T)
        expect = e.bridge[-1] if e.bridge else T
        if parent.digest != expect.digest:
            raise Invalid("parent does not continue the room's chain")
    verify_link(e.branch_a, parent)
    verify_link(e.branch_b, parent)
    if e.branch_a.digest == e.branch_b.digest:
        raise Invalid("branches identical")
    if e.branch_a.height != f:
        raise Invalid("branch height != fork_height")


def auth_epoch(e: EpochEvent) -> None:
    (auth_active if e.status == "active" else auth_burn)(e)


# --------------------------------------------------------------------------- Pass 0


def _is_prefix(a: List[bytes], b: List[bytes]) -> bool:
    return len(a) <= len(b) and b[: len(a)] == a


def _divergence(chains: List[List[bytes]]):
    """First height at which two maximal chains differ, and the common prefix below it."""
    maximal = [
        c for c in chains if not any(c != o and _is_prefix(c, o) for o in chains)
    ]
    d = 0
    while all(len(c) > d for c in maximal) and len({c[d] for c in maximal}) == 1:
        d += 1
    return maximal[0][:d], d


def resolve_pass0(V: List[EpochEvent]) -> Optional[EpochEvent]:
    """MSC section 6.2. V: all valid epoch events for one key in the full conflicted set."""
    actives = [e for e in V if e.status == "active"]
    burns = [e for e in V if e.status == "burned"]
    chains = [[lnk.digest for lnk in e.chain] for e in actives]
    if not actives:
        return min(burns, key=lambda b: (b.fork_height, b.event_id)) if burns else None
    longest = max(chains, key=len)
    linear = all(_is_prefix(c, longest) for c in chains)
    if linear:
        J, threshold = longest, len(longest) - 1  # tip height H
    else:
        J, threshold = _divergence(chains)  # common prefix 0..d-1; divergence at d

    def non_stale(b: EpochEvent) -> bool:
        f = b.fork_height
        if f < threshold:
            return False
        assert b.branch_a is not None and b.branch_b is not None
        claim = b.claimed_digests()
        overlap = min(f, len(J))  # heights 0..min(f-1, |J|-1)
        if claim[:overlap] != J[:overlap]:
            return False
        if (
            linear
            and f == threshold
            and b.branch_a.digest != J[f]
            and b.branch_b.digest != J[f]
        ):
            return False
        return True

    live = [b for b in burns if non_stale(b)]
    if live:
        return min(live, key=lambda b: (b.fork_height, b.event_id))
    if linear:
        H = len(longest)
        return min((e for e in actives if len(e.chain) == H), key=lambda e: e.event_id)
    # Forked with no live burn: freeze at the greatest common epoch event.
    # Candidates include active events in V and in their auth chains (ancestors).
    maximal = [
        c for c in chains if not any(c != o and _is_prefix(c, o) for o in chains)
    ]
    candidates: Dict[str, EpochEvent] = {}
    for e in actives:
        curr: Optional[EpochEvent] = e
        while curr is not None:
            if curr.status == "active":
                candidates[curr.event_id] = curr
            curr = curr.prev
    common = [
        e
        for e in candidates.values()
        if all(_is_prefix([lnk.digest for lnk in e.chain], c) for c in maximal)
    ]
    if not common:
        return None
    top = max(len(e.chain) for e in common)
    return min((e for e in common if len(e.chain) == top), key=lambda e: e.event_id)


# --------------------------------------------------------------------------- previous draft's rules (for the regression checks)


def auth_burn_draft(e: EpochEvent) -> None:
    """Gemini draft (doc 10) section 4.3.3: fork_height >= prev.height, parent only needs root == key."""
    if e.prev is None or e.prev.status != "active":
        raise Invalid("no anchor")
    if e.fork_height < e.prev.height:
        raise Invalid("stale")
    assert e.branch_a is not None and e.branch_b is not None
    parent = parse_body_only(e.parent_body)
    if parent.height != e.fork_height - 1 or parent.principal != e.key:
        raise Invalid("bad parent")
    verify_link(e.branch_a, parent)
    verify_link(e.branch_b, parent)
    if e.branch_a.digest == e.branch_b.digest:
        raise Invalid("identical")


def resolve_pass0_draft(V: List[EpochEvent]) -> Optional[EpochEvent]:
    """Gemini draft (doc 10) section 5.1: stale test against h_max over all active candidates."""
    actives = [e for e in V if e.status == "active"]
    burns = [e for e in V if e.status == "burned"]
    h_max = max((e.height for e in actives), default=0)
    live = [b for b in burns if b.fork_height >= h_max]
    if live:
        return min(live, key=lambda b: (b.fork_height, b.event_id))
    chains = [[lnk.digest for lnk in e.chain] for e in actives]
    longest = max(chains, key=len)
    if all(_is_prefix(c, longest) for c in chains):
        return min((e for e in actives if e.height == h_max), key=lambda e: e.event_id)
    _, d = _divergence(chains)
    best = min({c[d] for c in chains if len(c) > d})
    on_branch = [e for e, c in zip(actives, chains) if len(c) > d and c[d] == best]
    return max(on_branch, key=lambda e: (e.height, e.event_id))


# --------------------------------------------------------------------------- fixtures


def seed(n: int) -> bytes:
    return bytes([n]) * 32


SRV_A_ONLINE0, SRV_A_ROT1, SRV_A_ONLINE1, SRV_A_ROT2 = (
    sk_from_seed(seed(n)) for n in (0x01, 0x02, 0x03, 0x04)
)
SRV_B_ONLINE0, SRV_B_ROT1 = (sk_from_seed(seed(n)) for n in (0x11, 0x12))
USR_ROT1, USR_ROT2, USR_MSK = (sk_from_seed(seed(n)) for n in (0x21, 0x22, 0x2F))


def build_fixtures():
    A0 = make_server_genesis(SRV_A_ONLINE0, pub(SRV_A_ROT1), "chat.example.org")
    A1 = make_rotation(
        A0,
        SRV_A_ROT1,
        commitment(pub(SRV_A_ROT2)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="chat.example.org",
    )
    B0 = make_server_genesis(SRV_B_ONLINE0, pub(SRV_B_ROT1), "second.example.net")
    U0 = make_user_genesis(
        A0.digest, commitment(pub(USR_ROT1)), "@alice:chat.example.org", pub(USR_MSK)
    )
    U1 = make_rotation(
        U0,
        USR_ROT1,
        commitment(pub(USR_ROT2)),
        custodian=B0.digest,
        msk=pub(USR_MSK),
        mxid="@alice:second.example.net",
    )
    return A0, A1, B0, U0, U1


def link_json(lnk: Link) -> dict:
    d = {
        "height": lnk.height,
        "body_len": len(lnk.body),
        "trailer_len": len(lnk.trailer),
        "body_hex": lnk.body.hex(),
        "trailer_hex": lnk.trailer.hex(),
        "link_b64u": b64u(lnk.raw),
        "digest_hex": lnk.digest.hex(),
        "next_commit_hex": lnk.next_commit.hex(),
    }
    if lnk.height == 0:
        d["principal"] = b64u(lnk.digest)
    return d


# --------------------------------------------------------------------------- scenarios


GAP_LABELS = {True: "KNOWN", False: "FAIL ", None: "SPEC "}


class GapRecord(TypedDict, total=False):
    """One known gap. `reproduced` is True, False, or None (see Checks.gap)."""

    name: str
    reproduced: Optional[bool]
    detail: str
    problem: str


class Checks:
    """Conformance results plus known-gap records.

    `expect` is for behaviour the proposal promises. `gap` records behaviour it
    does not prevent yet, so that the hole is executable rather than prose.
    """

    def __init__(self) -> None:
        self.results: List[Tuple[str, bool, str]] = []
        self.gaps: List[GapRecord] = []

    def expect(self, name, ok, detail=""):
        self.results.append((name, ok, detail))

    def gap(
        self,
        name: str,
        reproduced: Optional[bool],
        detail: str = "",
        problem: str = "",
    ) -> None:
        """Record a current failure.

        `reproduced` is True while the harness demonstrates the behaviour: an
        expected current failure, reported as KNOWN and not counted against the
        run. False means it no longer reproduces, which fails the run: promote
        the vector to a conformance check and update the MSC. None means the
        behaviour is not executable here (no finality or cross-room machinery);
        reported as SPEC and never fails.
        """
        rec: GapRecord = {"name": name, "reproduced": reproduced, "detail": detail}
        if problem:
            rec["problem"] = problem
        self.gaps.append(rec)

    def gap_failures(self) -> List[str]:
        return [g["name"] for g in self.gaps if g["reproduced"] is False]

    def rejects(self, name, fn, *a):
        try:
            fn(*a)
            self.expect(name, False, "accepted, expected rejection")
        except Invalid as ex:
            self.expect(name, True, f"rejected: {ex}")

    def accepts(self, name, fn, *a):
        try:
            fn(*a)
            self.expect(name, True, "accepted")
        except Invalid as ex:
            self.expect(name, False, f"rejected: {ex}")


class NameBindingModel:
    """Pure §8 name-binding transitions; DNS and lookup transport are external."""

    def __init__(self) -> None:
        self.states: Dict[Tuple[str, str], str] = {}
        self.seen: Dict[str, set] = {}

    def state(self, name: str, principal: str) -> str:
        return self.states.get((name, principal), "unverified")

    def observe(self, name: str, principal: Optional[str]) -> None:
        pairs = self.seen.setdefault(name, set())
        if principal is None:
            for pair in pairs:
                if self.states.get((name, pair)) == "verified":
                    self.states[(name, pair)] = "formerly verified"
            return
        pairs.add(principal)
        for pair in pairs:
            self.states[(name, pair)] = "verified" if pair == principal else "contested"

    def needs_reverification(self, name: str) -> bool:
        return any(
            self.states.get((name, pair)) in {"contested", "formerly verified"}
            for pair in self.seen.get(name, set())
        )

    def admits_name_allow(self, name: str, principal: str) -> bool:
        return self.state(name, principal) in {"verified", "formerly verified"}


def _acl_name_matches(pattern: str, name: str) -> bool:
    regex = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char)
        for char in pattern
    )
    return re.fullmatch(regex, name, re.S) is not None


def _complete_server_branch(branch: List[Link], principal: bytes) -> bool:
    """Check the shape of a complete branch already validated cryptographically."""
    if (
        not branch
        or branch[0].kind != KIND_SERVER
        or branch[0].height != 0
        or branch[0].root != ZERO32
        or branch[0].prev != ZERO32
        or branch[0].principal != principal
    ):
        return False
    for parent, link in zip(branch, branch[1:]):
        if (
            link.kind != KIND_SERVER
            or link.height != parent.height + 1
            or link.prev != parent.digest
            or link.principal != principal
        ):
            return False
    return True


def admit(
    acl: dict,
    principal: bytes,
    origin_name: str,
    room_tip: Optional[Link],
    known_branches: Optional[List[List[Link]]],
    bindings: NameBindingModel,
) -> str:
    """Model §8 ingress policy over complete, cryptographically validated chains.

    `known_branches` contains complete, validated branches from genesis; None
    denotes true first contact with no complete history available or supplied.
    The result is `admit`, `reject`, or `defer` for that first-contact case.
    """
    principal_id = "~" + b64u(principal)
    deny = acl.get("deny", [])
    allow = acl.get("allow", [])

    def matches_entry(entry: str, names: List[str]) -> bool:
        if entry.startswith("~"):
            return entry == principal_id
        return any(_acl_name_matches(entry, name) for name in names)

    # Direct denies do not need chain history.
    if any(matches_entry(entry, [origin_name]) for entry in deny):
        return "reject"

    branches = [
        branch
        for branch in (known_branches or [])
        if _complete_server_branch(branch, principal)
    ]
    if not branches:
        return "defer"

    # The origin must be named on a branch that extends the room's accepted tip.
    origin_is_on_accepted_branch = False
    for branch in branches:
        if room_tip is None:
            # With no room epoch, only the tip of the validated origin branch is T.
            origin_is_on_accepted_branch |= branch[-1].server_name == origin_name
            continue
        if room_tip.principal != principal:
            continue
        tip_index = next(
            (
                i
                for i, link in enumerate(branch)
                if link.height == room_tip.height and link.digest == room_tip.digest
            ),
            None,
        )
        if tip_index is None:
            continue
        origin_is_on_accepted_branch |= any(
            link.height >= room_tip.height and link.server_name == origin_name
            for link in branch[tip_index:]
        )
    if not origin_is_on_accepted_branch:
        return "reject"

    historical_names = [
        link.server_name
        for branch in branches
        for link in branch
        if link.server_name is not None
    ]
    if any(matches_entry(entry, [origin_name, *historical_names]) for entry in deny):
        return "reject"

    for entry in allow:
        if entry.startswith("~"):
            if entry == principal_id:
                return "admit"
        elif _acl_name_matches(entry, origin_name) and bindings.admits_name_allow(
            origin_name, principal_id
        ):
            return "admit"
    return "reject"


def report(checks: Checks) -> int:
    """Print results and known gaps; return the process exit status."""
    rows = [("PASS" if ok else "FAIL", n, d) for n, ok, d in checks.results]
    rows += [(GAP_LABELS[g["reproduced"]], g["name"], g["detail"]) for g in checks.gaps]
    width = max((len(n) for _, n, _ in rows), default=0)
    for label, n, d in rows:
        print(f"{label}  {n.ljust(width)}  {d}")
    failed = [n for n, ok, _ in checks.results if not ok] + checks.gap_failures()
    passed = sum(1 for _, ok, _ in checks.results if ok)
    print(f"\n{passed}/{len(checks.results)} checks passed")
    if checks.gaps:
        known = sum(1 for g in checks.gaps if g["reproduced"])
        spec = sum(1 for g in checks.gaps if g["reproduced"] is None)
        print(
            f"{known} known gaps reproduced (expected current failures), {spec} spec-level"
        )
    return 1 if failed else 0


def introduce(prefix: str, key: bytes, links: List[Link]):
    """Genesis-only introduction, then one advancement event carrying the rest."""
    g = EpochEvent(prefix + "g", key, "active", None, links[:1])
    if len(links) == 1:
        return g, [g]
    a = EpochEvent(prefix, key, "active", g, links[1:])
    return a, [g, a]


def user_chain(
    custodian: bytes, n: int, base_seed: int, mxid="@carol:chat.example.org"
):
    """Honest user chain of length n+1 with rotation keys seed(base_seed+i)."""
    keys = [sk_from_seed(seed(base_seed + i)) for i in range(n + 1)]
    links = [make_user_genesis(custodian, commitment(pub(keys[0])), mxid, None)]
    for i in range(1, n + 1):
        links.append(
            make_rotation(
                links[-1],
                keys[i - 1],
                commitment(pub(keys[i])),
                custodian=custodian,
                mxid=mxid,
            )
        )
    return links, keys


def attacker_link(
    parent: Link, rot_sk, custodian: bytes, mxid: str, nonce: int
) -> Tuple[Link, Ed25519PrivateKey]:
    """A forged successor; the attacker commits to a key of its own choosing (varied by nonce)."""
    nxt = sk_from_seed(sha256(b"attacker" + nonce.to_bytes(8, "big")))
    return (
        make_rotation(
            parent, rot_sk, commitment(pub(nxt)), custodian=custodian, mxid=mxid
        ),
        nxt,
    )


def run_checks(A0, A1, B0, U0, U1) -> Checks:
    C = Checks()

    bindings = NameBindingModel()
    bindings.observe("old.example", "P1")
    bindings.observe("old.example", "P2")
    C.expect(
        "name-binding lookup takeover contests the earlier principal",
        bindings.state("old.example", "P1") == "contested"
        and bindings.state("old.example", "P2") == "verified",
    )
    bindings.observe("old.example", None)
    C.expect(
        "name-binding outage preserves contested and retries formerly verified",
        bindings.state("old.example", "P1") == "contested"
        and bindings.state("old.example", "P2") == "formerly verified"
        and bindings.needs_reverification("old.example")
        and not bindings.admits_name_allow("old.example", "P1")
        and bindings.admits_name_allow("old.example", "P2"),
    )
    bindings.observe("old.example", "P1")
    C.expect(
        "name-binding successful recovery restores the earlier principal",
        bindings.state("old.example", "P1") == "verified"
        and bindings.state("old.example", "P2") == "contested"
        and bindings.admits_name_allow("old.example", "P1")
        and not bindings.admits_name_allow("old.example", "P2"),
    )

    single = NameBindingModel()
    single.observe("single.example", "P3")
    single.observe("single.example", None)
    C.expect(
        "name-binding single-pair outage preserves formerly-verified admission",
        single.state("single.example", "P3") == "formerly verified"
        and single.needs_reverification("single.example")
        and single.admits_name_allow("single.example", "P3"),
    )
    single.observe("single.example", "P3")
    C.expect(
        "name-binding formerly verified pair recovers to verified on same result",
        single.state("single.example", "P3") == "verified"
        and single.admits_name_allow("single.example", "P3"),
    )

    # §8 ingress decisions over complete validated branches.
    principal_id = "~" + b64u(A0.principal)
    new_name = "new.example.org"
    renamed = make_rotation(
        A0,
        SRV_A_ROT1,
        commitment(pub(SRV_A_ROT2)),
        online_key=pub(SRV_A_ONLINE1),
        server_name=new_name,
    )
    verify_link(renamed, A0)
    known_rename = [[A0, renamed]]
    ingress_bindings = NameBindingModel()
    ingress_bindings.observe(new_name, principal_id)
    C.expect(
        "ingress admits rename before room processes epoch advancement",
        admit(
            {"allow": ["*"], "deny": []},
            A0.principal,
            new_name,
            A0,
            known_rename,
            ingress_bindings,
        )
        == "admit",
    )
    ingress_bindings.observe("chat.example.org", principal_id)
    C.expect(
        "ingress rejects alias from before the room epoch tip",
        admit(
            {"allow": ["*"], "deny": []},
            A0.principal,
            "chat.example.org",
            renamed,
            known_rename,
            ingress_bindings,
        )
        == "reject",
    )

    fork_key = sk_from_seed(seed(0x61))
    fork_a = make_rotation(
        renamed,
        SRV_A_ROT2,
        commitment(pub(fork_key)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="current.example.org",
    )
    fork_b = make_rotation(
        renamed,
        SRV_A_ROT2,
        commitment(pub(fork_key)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="forked-deny.example.org",
    )
    verify_link(fork_a, renamed)
    verify_link(fork_b, renamed)
    fork_branches = [[A0, renamed, fork_a], [A0, renamed, fork_b]]
    ingress_bindings.observe("current.example.org", principal_id)
    C.expect(
        "ingress deny matches a name on another validated fork branch",
        admit(
            {"allow": ["*"], "deny": ["forked-deny.example.org"]},
            A0.principal,
            "current.example.org",
            renamed,
            fork_branches,
            ingress_bindings,
        )
        == "reject",
    )

    # A branch sharing a prefix with the room tip but not containing it cannot
    # supply the origin name, even though the name is on a validated branch.
    divergent = make_rotation(
        A0,
        SRV_A_ROT1,
        commitment(pub(SRV_A_ROT2)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="divergent.example.org",
    )
    verify_link(divergent, A0)
    assert divergent.digest != renamed.digest
    ingress_bindings.observe("divergent.example.org", principal_id)
    C.expect(
        "ingress rejects a name on a branch that does not contain the room tip",
        admit(
            {"allow": ["*"], "deny": []},
            A0.principal,
            "divergent.example.org",
            renamed,
            [[A0, divergent]],
            ingress_bindings,
        )
        == "reject",
    )
    C.expect(
        "ingress still rejects it when the tip branch is also supplied",
        admit(
            {"allow": ["*"], "deny": []},
            A0.principal,
            "divergent.example.org",
            renamed,
            [[A0, renamed], [A0, divergent]],
            ingress_bindings,
        )
        == "reject",
    )

    alias_rot_3 = sk_from_seed(seed(0x63))
    alias_rot_4 = sk_from_seed(seed(0x64))
    alias_3 = make_rotation(
        renamed,
        SRV_A_ROT2,
        commitment(pub(alias_rot_3)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="third.example.org",
    )
    alias_4 = make_rotation(
        alias_3,
        alias_rot_3,
        commitment(pub(alias_rot_4)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="fourth.example.org",
    )
    verify_link(alias_3, renamed)
    verify_link(alias_4, alias_3)
    ingress_bindings.observe("fourth.example.org", principal_id)
    C.expect(
        "ingress historical deny finds the oldest of multiple prior aliases",
        admit(
            {"allow": ["*"], "deny": ["chat.example.org"]},
            A0.principal,
            "fourth.example.org",
            alias_4,
            [[A0, renamed, alias_3, alias_4]],
            ingress_bindings,
        )
        == "reject",
    )

    first_contact_acl = {"allow": ["*"], "deny": ["blocked.example.org"]}
    C.expect(
        "first contact with complete supplied links evaluates ingress",
        admit(
            first_contact_acl,
            A0.principal,
            new_name,
            None,
            known_rename,
            ingress_bindings,
        )
        == "admit",
    )
    C.expect(
        "first contact without complete links defers ingress",
        admit(
            first_contact_acl,
            A0.principal,
            new_name,
            None,
            None,
            ingress_bindings,
        )
        == "defer",
    )

    # --- link layer --------------------------------------------------------
    C.accepts("server genesis verifies", verify_link, A0, None)
    C.accepts("server rotation verifies", verify_link, A1, A0)
    C.accepts(
        "user genesis (unsigned, client commitment) verifies", verify_link, U0, None
    )
    C.accepts("user migration link verifies", verify_link, U1, U0)
    changed_msk = make_rotation(
        U0,
        USR_ROT1,
        commitment(pub(USR_ROT2)),
        custodian=B0.digest,
        msk=pub(USR_ROT2),
        mxid="@alice:second.example.net",
    )
    C.rejects(
        "user rotation cannot replace its committed master key",
        verify_link,
        changed_msk,
        U0,
    )
    stolen_online = make_rotation(
        A0,
        SRV_A_ONLINE0,
        commitment(pub(SRV_A_ROT2)),
        online_key=pub(SRV_A_ONLINE1),
        server_name="evil.example",
    )
    C.rejects("online key cannot sign a rotation", verify_link, stolen_online, A0)
    tampered = parse_link(A1.body[:-1] + b"x" + A1.trailer)
    C.rejects("tampered body fails rotation signature", verify_link, tampered, A0)

    custodian = A0.digest
    mx = "@carol:chat.example.org"

    # --- T1: consumed key held by an ex-custodian --------------------------
    # Custodial genesis: custodian holds K_rot,1 (seed 0x41). Handover link h=1 commits to the
    # user's key (0x42); the user immediately rotates to h=2 (commits 0x43).
    k1, k2, k3 = (sk_from_seed(seed(n)) for n in (0x41, 0x42, 0x43))
    g0 = make_user_genesis(custodian, commitment(pub(k1)), mx, None)
    h1 = make_rotation(g0, k1, commitment(pub(k2)), custodian=custodian, mxid=mx)
    h2 = make_rotation(h1, k2, commitment(pub(k3)), custodian=custodian, mxid=mx)
    forged1, _ = attacker_link(g0, k1, custodian, mx, 1)
    key = g0.digest
    e0 = EpochEvent("$e0", key, "active", None, [g0])
    e1 = EpochEvent("$e1", key, "active", e0, [h1])
    e2 = EpochEvent("$e2", key, "active", e1, [h2])
    for ev in (e0, e1, e2):
        auth_epoch(ev)
    burn_vs_h2 = EpochEvent(
        "$b_stale",
        key,
        "burned",
        e2,
        fork_height=1,
        parent_body=g0.body,
        branch_a=h1,
        branch_b=forged1,
    )
    C.rejects(
        "T1 ex-custodian burn below an up-to-date tip is stale", auth_burn, burn_vs_h2
    )
    burn_vs_h1 = EpochEvent(
        "$b_lag",
        key,
        "burned",
        e1,
        fork_height=1,
        parent_body=g0.body,
        branch_a=h1,
        branch_b=forged1,
    )
    C.accepts(
        "T1 residual: same burn in a room still at the handover tip",
        auth_burn,
        burn_vs_h1,
    )
    r = resolve_pass0([e0, e1, e2, burn_vs_h1])
    C.expect(
        "T1 Pass 0: lagging-branch burn is stale once h=2 is in the merge",
        r is e2,
        f"resolved {r.event_id if r else None}",
    )

    # --- T2: height inflation in Pass 0 ------------------------------------
    # Room knows the user at h=1. Attacker holds K_rot,2 (stolen before use). Branch X: attacker
    # extends 2'..6'. Branch Y: honest 2..3. An honest server burns, anchored on the common h=1.
    links, keys = user_chain(custodian, 3, 0x50, mx)  # honest 0..3
    key = links[0].digest
    c0, c0_evs = introduce("$c0", key, links[:2])  # common: heights 0..1
    y = EpochEvent("$y", key, "active", c0, links[2:4])  # honest 2..3
    # Attacker grinds its height-2 link until its digest sorts below the honest one,
    # which is what the draft's lexicographic tie-break rewards.
    nonce = 0
    while True:
        f2, nxt = attacker_link(links[1], keys[1], custodian, mx, nonce)
        if f2.digest < links[2].digest:
            break
        nonce += 1
    xs = [f2]
    for i in range(4):
        n2 = sk_from_seed(sha256(b"atk-chain" + bytes([i])))
        xs.append(
            make_rotation(
                xs[-1], nxt, commitment(pub(n2)), custodian=custodian, mxid=mx
            )
        )
        nxt = n2
    x = EpochEvent("$x", key, "active", c0, xs)  # attacker 2'..6'
    for ev in (*c0_evs, y, x):
        auth_epoch(ev)
    honest_burn = EpochEvent(
        "$hb",
        key,
        "burned",
        c0,
        fork_height=2,
        parent_body=links[1].body,
        branch_a=links[2],
        branch_b=f2,
    )
    C.accepts(
        "T2 honest burn anchored on the common tip passes auth", auth_burn, honest_burn
    )
    V = [*c0_evs, y, x, honest_burn]
    rd = resolve_pass0_draft(V)
    C.expect(
        "T2 draft rule: attacker wins (burn ignored as 'stale', grind wins tie-break)",
        rd is x,
        f"draft resolved {rd.event_id if rd else None}; grind took {nonce + 1} tries",
    )
    rn = resolve_pass0(V)
    C.expect(
        "T2 this MSC: burn is live, principal burned",
        rn is honest_burn,
        f"resolved {rn.event_id if rn else None}",
    )
    rn2 = resolve_pass0([*c0_evs, y, x])
    C.expect(
        "T2 this MSC, before any burn: freeze at common epoch",
        rn2 is c0,
        f"resolved {rn2.event_id if rn2 else None}",
    )
    rn3 = resolve_pass0([y, x])
    C.expect(
        "T2 freeze with only branch tips in conflicted set resolves to common ancestor",
        rn3 is c0,
        f"resolved {rn3.event_id if rn3 else None}",
    )
    rd2 = resolve_pass0_draft([*c0_evs, y, x])
    C.expect(
        "T2 draft, before any burn: attacker branch selected",
        rd2 is x,
        f"draft resolved {rd2.event_id if rd2 else None}",
    )
    # After the freeze, the honest burn anchored on the frozen state is accepted.
    C.accepts(
        "T2 burn anchored on the frozen common epoch passes auth",
        auth_burn,
        honest_burn,
    )

    # --- T3: burn built on a chain the room never accepted -----------------
    # Room is linear at h=3 (honest). Attacker holds consumed K_rot,2, forges 2', then two
    # siblings at height 3 from 2' using its own key, and claims a fork at f=3 >= tip height.
    links, keys = user_chain(custodian, 3, 0x60, mx)
    key = links[0].digest
    r0, r0_evs = introduce("$r0", key, links)
    for ev in r0_evs:
        auth_epoch(ev)
    alt2, ak = attacker_link(links[1], keys[1], custodian, mx, 99)
    sa, _ = attacker_link(alt2, ak, custodian, mx, 100)
    sb, _ = attacker_link(alt2, ak, custodian, mx, 101)
    off_chain = EpochEvent(
        "$oc",
        key,
        "burned",
        r0,
        fork_height=3,
        parent_body=alt2.body,
        branch_a=sa,
        branch_b=sb,
    )
    C.accepts(
        "T3 draft auth accepts an off-chain burn (kill with a consumed key)",
        auth_burn_draft,
        off_chain,
    )
    C.rejects(
        "T3 this MSC rejects it (branch_a must be the room tip)", auth_burn, off_chain
    )

    # --- T4: live equivocation above the tip -------------------------------
    links, keys = user_chain(custodian, 2, 0x70, mx)
    key = links[0].digest
    t0, t0_evs = introduce("$t0", key, links)
    a3, _ = attacker_link(links[2], keys[2], custodian, mx, 7)
    b3, _ = attacker_link(links[2], keys[2], custodian, mx, 8)
    live = EpochEvent(
        "$live",
        key,
        "burned",
        t0,
        fork_height=3,
        parent_body=links[2].body,
        branch_a=a3,
        branch_b=b3,
    )
    C.accepts(
        "T4 two children of the tip (unused key used twice) burn", auth_burn, live
    )
    C.expect("T4 Pass 0 selects the burn", resolve_pass0([*t0_evs, live]) is live)
    sib, _ = attacker_link(links[1], keys[1], custodian, mx, 9)
    at_tip = EpochEvent(
        "$tip",
        key,
        "burned",
        t0,
        fork_height=2,
        parent_body=links[1].body,
        branch_a=links[2],
        branch_b=sib,
    )
    C.accepts(
        "T4 sibling of the tip burns (consumed tip key; room cannot tell)",
        auth_burn,
        at_tip,
    )
    C.expect(
        "T4 burn-only conflict with empty actives selects earliest fork height",
        resolve_pass0([live, at_tip]) is at_tip,
    )

    # --- T5: linear advancement and tie-break ------------------------------
    links, keys = user_chain(custodian, 2, 0x80, mx)
    key = links[0].digest
    p0 = EpochEvent("$p0", key, "active", None, links[:1])
    p1 = EpochEvent("$p1", key, "active", p0, links[1:2])
    p2a = EpochEvent("$p2b", key, "active", p1, links[2:3])
    p2b = EpochEvent("$p2a", key, "active", p1, links[2:3])
    C.expect(
        "T5 linear: highest tip wins, identical tips broken by event_id",
        resolve_pass0([p0, p1, p2a, p2b]) is p2b,
    )
    C.rejects(
        "T5 re-posting the same height fails auth",
        auth_active,
        EpochEvent("$dup", key, "active", p2a, links[2:3]),
    )

    # --- T6: first introductions are genesis-only --------------------------
    # Two concurrent first introductions that fork at h=1. With multi-link introductions there
    # is no common epoch event, Pass 0 resolves to nothing, and no burn can anchor.
    links, keys = user_chain(custodian, 1, 0x90, mx)
    key = links[0].digest
    f1, _ = attacker_link(links[0], keys[0], custodian, mx, 3)
    C.rejects(
        "T6 first introduction carrying more than genesis fails auth",
        auth_active,
        EpochEvent("$multi", key, "active", None, links),
    )
    ga = EpochEvent("$ga", key, "active", None, links[:1])
    gb = EpochEvent("$gb", key, "active", None, links[:1])
    a1 = EpochEvent("$a1", key, "active", ga, links[1:])
    b1 = EpochEvent("$b1", key, "active", gb, [f1])
    for ev in (ga, gb, a1, b1):
        auth_epoch(ev)
    fr = resolve_pass0([ga, gb, a1, b1])
    C.expect(
        "T6 concurrent introductions that fork freeze at a genesis event",
        fr is ga,
        f"resolved {fr.event_id if fr else None}",
    )
    burn = EpochEvent(
        "$burn6",
        key,
        "burned",
        fr,
        fork_height=1,
        parent_body=links[0].body,
        branch_a=links[1],
        branch_b=f1,
    )
    C.accepts("T6 burn anchored on the frozen genesis passes auth", auth_burn, burn)
    C.expect(
        "T6 Pass 0 then selects the burn", resolve_pass0([ga, gb, a1, b1, burn]) is burn
    )

    # --- T7: randomized permutation and fork-height sweep ------------------
    sweep_ok = True
    sweep_links, sweep_keys = user_chain(custodian, 15, 0x30, mx)
    sweep_key = sweep_links[0].digest
    base_evs = [EpochEvent("$sw_e0", sweep_key, "active", None, sweep_links[:1])]
    for i in range(1, len(sweep_links)):
        base_evs.append(
            EpochEvent(f"$sw_e{i}", sweep_key, "active", base_evs[-1], [sweep_links[i]])
        )

    rnd = random.Random(42)
    for h in range(1, 11):
        parent_ev = base_evs[h - 1]
        y1 = EpochEvent(f"$y1_{h}", sweep_key, "active", parent_ev, [sweep_links[h]])
        y2 = EpochEvent(f"$y2_{h}", sweep_key, "active", y1, [sweep_links[h + 1]])

        f1, k1 = attacker_link(
            sweep_links[h - 1], sweep_keys[h - 1], custodian, mx, h * 10
        )
        f2, _ = attacker_link(f1, k1, custodian, mx, h * 10 + 1)
        x1 = EpochEvent(f"$x1_{h}", sweep_key, "active", parent_ev, [f1])
        x2 = EpochEvent(f"$x2_{h}", sweep_key, "active", x1, [f2])

        cands = [y1, y2, x1, x2]
        for _ in range(10):
            shuffled = list(cands)
            rnd.shuffle(shuffled)
            res = resolve_pass0(shuffled)
            if res is not parent_ev:
                sweep_ok = False
                break
        if not sweep_ok:
            break

    C.expect(
        "T7 freeze across sweep heights 1..10 is order-independent and finds common ancestor",
        sweep_ok,
    )
    return C


def main():
    A0, A1, B0, U0, U1 = build_fixtures()
    fixtures = {
        "seeds": {
            "srv_a_online_0": "01" * 32,
            "srv_a_rot_1": "02" * 32,
            "srv_a_online_1": "03" * 32,
            "srv_a_rot_2": "04" * 32,
            "srv_b_online_0": "11" * 32,
            "srv_b_rot_1": "12" * 32,
            "usr_rot_1": "21" * 32,
            "usr_rot_2": "22" * 32,
            "usr_msk": "2f" * 32,
        },
        "public_keys": {
            k: pub(sk).hex()
            for k, sk in {
                "srv_a_online_0": SRV_A_ONLINE0,
                "srv_a_rot_1": SRV_A_ROT1,
                "srv_a_online_1": SRV_A_ONLINE1,
                "srv_a_rot_2": SRV_A_ROT2,
                "srv_b_online_0": SRV_B_ONLINE0,
                "srv_b_rot_1": SRV_B_ROT1,
                "usr_rot_1": USR_ROT1,
                "usr_rot_2": USR_ROT2,
                "usr_msk": USR_MSK,
            }.items()
        },
        "commitments": {
            "C(srv_a_rot_1)": commitment(pub(SRV_A_ROT1)).hex(),
            "C(srv_a_rot_2)": commitment(pub(SRV_A_ROT2)).hex(),
            "C(srv_b_rot_1)": commitment(pub(SRV_B_ROT1)).hex(),
            "C(usr_rot_1)": commitment(pub(USR_ROT1)).hex(),
            "C(usr_rot_2)": commitment(pub(USR_ROT2)).hex(),
        },
        "links": {
            "A0_server_genesis": link_json(A0),
            "A1_server_rotation": link_json(A1),
            "B0_server_genesis": link_json(B0),
            "U0_user_genesis": link_json(U0),
            "U1_user_migration": link_json(U1),
        },
        "principals": {
            "server_A": "~" + b64u(A0.digest),
            "server_B": "~" + b64u(B0.digest),
            "user_U": "@" + b64u(U0.digest),
        },
    }
    checks = run_checks(A0, A1, B0, U0, U1)
    fixtures["checks"] = [
        {"name": n, "pass": ok, "detail": d} for n, ok, d in checks.results
    ]
    if checks.gaps:
        fixtures["known_gaps"] = checks.gaps
    write_json("pid_vectors.json", fixtures)
    sys.exit(report(checks))


if __name__ == "__main__":
    main()
