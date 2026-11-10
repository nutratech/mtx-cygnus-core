#!/usr/bin/env python3
"""PDU layer and event-auth harness for MSCxxxx (room version tk.nutra.cygnus.1).

Implements: canonical JSON, room v12 redaction plus this MSC's additions (section 4.3),
content hashes, reference hashes, event and room IDs, PDU signing, signer resolution
(section 5.2), epoch event auth including relay (5.3), burns (5.4), and the custodian
binding and rebinding rules for all other events (5.5).

Most scenarios model one linear room at a time: an event's auth events must be the
current state for their keys, which stands in for the state-before check. The G7
candidate scenario merges two accepted branches and applies the proposed seal filter;
it is not full Matrix state resolution. Standard v12 auth (power levels, join rules
for ordinary joins) is assumed and not re-implemented; every check here is one this
MSC adds or a documented candidate rule.

Running the file checks the flows from the MSC and writes pid_pdu_vectors.json.
"""

import copy
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, TypedDict, TypeVar

import pid_ref as p
from pid_ref import Invalid

ROOM_VERSION = "tk.nutra.cygnus.1"
SERVER_EPOCH = "m.room.server_epoch"
USER_EPOCH = "m.room.user_epoch"
SERVER_SEAL = "m.room.server_seal"
EPOCHS = (SERVER_EPOCH, USER_EPOCH)
DEVICE_CERT_TAG = b"matrix-cygnus-device-cert-v1\x00"
DEVICE_EVENT_TAG = b"matrix-cygnus-device-event-v1\x00"


class DeviceCredentials(TypedDict):
    master: p.SigningKey
    self_signing: p.SigningKey
    device: p.SigningKey
    device_id: str


DEVICE_CREDENTIALS: Dict[str, DeviceCredentials] = {}

# Room v11/v12 redaction, plus section 4.3 of this MSC.
KEEP_TOP = {
    "event_id",
    "type",
    "room_id",
    "sender",
    "state_key",
    "content",
    "hashes",
    "signatures",
    "depth",
    "prev_events",
    "auth_events",
    "origin_server_ts",
    "device_certificate",
}
FULL_CONTENT = {"m.room.create", SERVER_EPOCH, USER_EPOCH, SERVER_SEAL}
KEEP_CONTENT = {
    "m.room.member": {
        "membership",
        "join_authorised_via_users_server",
        "third_party_invite",
        "custodian",
    },
    "m.room.join_rules": {"join_rule", "allow"},
    "m.room.power_levels": {
        "ban",
        "events",
        "events_default",
        "invite",
        "kick",
        "redact",
        "state_default",
        "users",
        "users_default",
    },
    "m.room.history_visibility": {"history_visibility"},
    "m.room.redaction": {"redacts"},
    "m.room.server_acl": {
        "allow",
        "deny",
        "allow_ip_literals",
    },  # this MSC: now an auth input
}


# --------------------------------------------------------------------------- encoding


def cjson(obj) -> bytes:
    def check(o):
        if isinstance(o, float):
            raise ValueError("canonical JSON forbids floats")
        if isinstance(o, dict):
            for v in o.values():
                check(v)
        elif isinstance(o, list):
            for v in o:
                check(v)

    check(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def redact(ev: dict) -> dict:
    out = {k: copy.deepcopy(v) for k, v in ev.items() if k in KEEP_TOP}
    t = out.get("type")
    content = out.get("content", {})
    if t in FULL_CONTENT:
        return out
    kept = {k: v for k, v in content.items() if k in KEEP_CONTENT.get(t or "", set())}
    if t == "m.room.member" and "third_party_invite" in kept:
        tpi = kept["third_party_invite"]
        if isinstance(tpi, dict) and "signed" in tpi:
            kept["third_party_invite"] = {"signed": tpi["signed"]}
        else:
            del kept["third_party_invite"]
    out["content"] = kept
    return out


def content_hash(ev: dict) -> str:
    e = {k: v for k, v in ev.items() if k not in ("unsigned", "signatures", "hashes")}
    return p.b64u(p.sha256(cjson(e)))


def signing_input(ev: dict) -> bytes:
    r = redact(ev)
    r.pop("signatures", None)
    r.pop("unsigned", None)
    return cjson(r)


def reference_hash(ev: dict) -> bytes:
    return p.sha256(signing_input(ev))  # redacted, without signatures/unsigned


def event_id(ev: dict) -> str:
    return "$" + p.b64u(reference_hash(ev))


def sign(ev: dict, server: str, height: int, sk) -> dict:
    e = copy.deepcopy(ev)
    e.pop("unsigned", None)
    e["hashes"] = {"sha256": content_hash(e)}
    sigs = e.setdefault("signatures", {})
    sigs[server] = {f"{p.pid_sig.KEY_ALGORITHM}:{height}": p.b64u(sk.sign(signing_input(e)))}
    return e


def device_bundle(principal: str, master_sk, self_signing_sk, device_sk, device_id):
    self_signing_key = p.b64u(p.pub(self_signing_sk))
    device_key = p.b64u(p.pub(device_sk))
    self_cert = {
        "principal": principal,
        "purpose": "self_signing",
        "key": self_signing_key,
    }
    device_cert = {
        "principal": principal,
        "device_id": device_id,
        "key": device_key,
    }
    return {
        "version": 1,
        "device_id": device_id,
        "device_key": device_key,
        "self_signing_key": self_signing_key,
        "self_signing_signature": p.b64u(
            master_sk.sign(DEVICE_CERT_TAG + cjson(self_cert))
        ),
        "device_key_signature": p.b64u(
            self_signing_sk.sign(DEVICE_CERT_TAG + cjson(device_cert))
        ),
    }


def verify_device_certificate(cert: object, principal: str, master_key: bytes) -> bytes:
    """Verify the MSC00FC master → self-signing → device certificate chain.

    This deliberately does not verify a room-event signature. Callers that
    authenticate a PDU must separately verify its DEVICE_EVENT_TAG signature.
    """
    required = {
        "version",
        "device_id",
        "device_key",
        "self_signing_key",
        "self_signing_signature",
        "device_key_signature",
    }
    if not isinstance(cert, dict) or not required <= set(cert):
        raise Invalid("missing or malformed device certificate")
    version = cert["version"]
    if type(version) is not int or version != 1:
        raise Invalid("device certificate version must be the integer 1")
    device_id = cert["device_id"]
    if not isinstance(device_id, str) or not re.fullmatch(
        r"[A-Za-z0-9._-]{1,255}", device_id
    ):
        raise Invalid("bad device_id")
    device_key = unb64(cert["device_key"])
    self_signing_key = unb64(cert["self_signing_key"])
    if len(device_key) != 32 or len(self_signing_key) != 32:
        raise Invalid("bad device certificate key length")
    self_cert = {
        "principal": principal,
        "purpose": "self_signing",
        "key": cert["self_signing_key"],
    }
    device_cert = {
        "principal": principal,
        "device_id": device_id,
        "key": cert["device_key"],
    }
    if not p.verify_sig(
        master_key,
        DEVICE_CERT_TAG + cjson(self_cert),
        unb64(cert["self_signing_signature"]),
    ):
        raise Invalid("self-signing key is not certified by master key")
    if not p.verify_sig(
        self_signing_key,
        DEVICE_CERT_TAG + cjson(device_cert),
        unb64(cert["device_key_signature"]),
    ):
        raise Invalid("device key is not certified by self-signing key")
    return device_key


def add_device_signature(ev: dict, principal: str, credentials: dict) -> dict:
    e = copy.deepcopy(ev)
    e["device_certificate"] = device_bundle(
        principal,
        credentials["master"],
        credentials["self_signing"],
        credentials["device"],
        credentials["device_id"],
    )
    e["hashes"] = {"sha256": content_hash(e)}
    sig = credentials["device"].sign(DEVICE_EVENT_TAG + signing_input(e))
    e["signatures"] = {
        principal: {
            f"{p.pid_sig.KEY_ALGORITHM}:{credentials['device_id']}": p.b64u(sig),
        }
    }
    return e


T = TypeVar("T")


def req(x: Optional[T], what: str) -> T:
    """Unwrap a link field that the link's kind guarantees is present."""
    if x is None:
        raise Invalid(f"missing {what}")
    return x


def unb64(s: str) -> bytes:
    import base64
    import binascii

    if not isinstance(s, str):
        raise Invalid("base64url value is not a string")
    try:
        decoded = base64.b64decode(
            s + "=" * (-len(s) % 4), altchars=b"-_", validate=True
        )
    except (binascii.Error, ValueError) as ex:
        raise Invalid("invalid base64url encoding") from ex
    if p.b64u(decoded) != s:
        raise Invalid("non-canonical base64url encoding")
    return decoded


def principal_digest(s: str) -> bytes:
    if len(s) != 44 or s[0] not in "~@":
        raise Invalid(f"not a principal: {s}")
    return unb64(s[1:])


def srv_id(link: p.Link) -> str:
    return "~" + p.b64u(link.principal)


def usr_id(link: p.Link) -> str:
    return "@" + p.b64u(link.principal)


GLOB_CACHE = {}


def glob(pattern: str, s: str) -> bool:
    if pattern not in GLOB_CACHE:
        rx = "".join(
            ".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern
        )
        GLOB_CACHE[pattern] = re.compile(rx + r"\Z", re.S)
    return bool(GLOB_CACHE[pattern].match(s))


def acl_denies(acl: dict, names: List[str]) -> bool:
    if any(glob(g, n) for g in acl.get("deny", []) for n in names):
        return True
    return not any(glob(g, n) for g in acl.get("allow", []) for n in names)


def validate_server_acl(content: dict) -> None:
    for field in ("allow", "deny"):
        entries = content.get(field, [])
        if not isinstance(entries, list) or any(
            not isinstance(x, str) for x in entries
        ):
            raise Invalid(f"server ACL {field} must be a list of strings")
        for entry in entries:
            if entry.startswith("~"):
                digest = principal_digest(entry)
                if len(digest) != 32 or "~" + p.b64u(digest) != entry:
                    raise Invalid("server ACL principal is not a canonical encoding")


# --------------------------------------------------------------------------- room harness


class Room:
    def __init__(self, label: str):
        self.label = label
        self.events: Dict[str, dict] = {}
        self.order: List[str] = []
        self.state: Dict[Tuple[str, str], str] = {}
        self.chains: Dict[str, List[p.Link]] = {}  # active epoch event id -> full chain
        self.room_id: Optional[str] = None
        self.creators: set = set()
        self.ts = 1792860000000

    # -- branches -----------------------------------------------------------
    def snapshot(self) -> dict:
        """The room's state, order and chain map at this point."""
        return {
            "state": dict(self.state),
            "order": list(self.order),
            "chains": dict(self.chains),
            "creators": set(self.creators),
            "ts": self.ts,
        }

    def branch_at(self, snap: dict) -> "Room":
        """A disjoint branch attached at an earlier snapshot.

        Used by the known-gap vectors to model a point in the room's history
        that an event can still be constructed against. Stored events are
        shared for auth lookup; state, order and chains are copied, so the
        branch never merges back into this room.
        """
        b = Room(self.label + "/branch")
        b.events = dict(self.events)
        b.state = dict(snap["state"])
        b.order = list(snap["order"])
        b.chains = dict(snap["chains"])
        b.creators = set(snap["creators"])
        b.ts = snap["ts"]
        b.room_id = self.room_id
        return b

    # -- helpers ------------------------------------------------------------
    def get(self, A: dict, t: str, sk: str) -> Optional[dict]:
        return A.get((t, sk))

    def tip(self, ev: dict) -> p.Link:
        return self.chains[ev["event_id_"]][-1]

    def custodian_of(self, A: dict, user: str) -> Optional[str]:
        ue = A.get((USER_EPOCH, user))
        if ue is None or ue["content"]["status"] != "active":
            return None
        return ue["content"]["custodian"]

    def joined(self, A: dict, user: str) -> bool:
        m = A.get(("m.room.member", user))
        return m is not None and m["content"].get("membership") == "join"

    def admitted(self, A: dict, user: str) -> bool:
        if user in self.creators:
            return True
        m = A.get(("m.room.member", user))
        if m is not None and m["content"].get("membership") in (
            "join",
            "invite",
            "knock",
        ):
            return True
        jr = A.get(("m.room.join_rules", ""))
        return jr is not None and jr["content"].get("join_rule") in (
            "public",
            "knock",
            "restricted",
            "knock_restricted",
        )

    def chain_from_genesis(self, raws: List[str], server: str) -> List[p.Link]:
        links = [p.parse_link(unb64(r)) for r in raws]
        p.verify_slice(links, None)
        if links[0].kind != p.KIND_SERVER or links[0].digest != principal_digest(
            server
        ):
            raise Invalid("signer_links is not this server's chain")
        return links

    def signer_key(self, ev: dict, A: dict, server: str) -> bytes:
        """Section 5.2: online key for `server` as a signer of `ev`."""
        c = ev["content"]
        if (
            ev["type"] == SERVER_EPOCH
            and ev["state_key"] == server
            and c.get("status") == "active"
            and A.get((SERVER_EPOCH, server)) is not None
        ):
            prev = A[(SERVER_EPOCH, server)]
            links = [p.parse_link(unb64(r)) for r in c["links"]]
            p.verify_slice(links, self.tip(prev))
            return req(
                links[-1].online_key, "online_key"
            )  # (a) the server advancing itself
        se = A.get((SERVER_EPOCH, server))
        if se is not None:
            if se["content"]["status"] != "active":
                raise Invalid("signer is burned")
            return req(
                self.tip(se).online_key, "online_key"
            )  # (b) the room's view of the signer
        if "signer_links" in c:
            return req(
                self.chain_from_genesis(c["signer_links"], server)[-1].online_key,
                "online_key",
            )  # (c)
        raise Invalid("no key available for signer")

    def signed_by(self, ev: dict, A: dict, server: str) -> bool:
        sigs = ev.get("signatures", {}).get(server, {})
        if not sigs:
            return False
        pk = self.signer_key(ev, A, server)
        return any(p.verify_sig(pk, signing_input(ev), unb64(s)) for s in sigs.values())

    def auth_device_signature(self, ev: dict, principal: str, master_key: bytes):
        cert = ev.get("device_certificate")
        if not isinstance(cert, dict):
            raise Invalid("missing or malformed device certificate")
        device_key = verify_device_certificate(cert, principal, master_key)
        device_id = cert["device_id"]
        sig = ev.get("signatures", {}).get(principal, {}).get(f"{p.pid_sig.KEY_ALGORITHM}:{device_id}")
        if sig is None or not p.verify_sig(
            device_key,
            DEVICE_EVENT_TAG + signing_input(ev),
            unb64(sig),
        ):
            raise Invalid("bad user-device event signature")

    # -- auth ---------------------------------------------------------------
    def auth_create(self, ev: dict):
        c = ev["content"]
        if c.get("room_version") != ROOM_VERSION:
            raise Invalid("wrong room version")
        srv = [p.parse_link(unb64(r)) for r in c["creator_links"]["server"]]
        usr = [p.parse_link(unb64(r)) for r in c["creator_links"]["user"]]
        p.verify_slice(srv, None)
        p.verify_slice(usr, None)
        if srv[0].kind != p.KIND_SERVER or usr[0].kind != p.KIND_USER:
            raise Invalid("creator_links kinds")
        if usr_id(usr[0]) != ev["sender"]:
            raise Invalid("user chain is not the sender's")
        if usr[-1].custodian != srv[0].digest:
            raise Invalid("creator's custodian is not the creating server")
        if req(usr[-1].mxid, "mxid").split(":", 1)[1] != srv[-1].server_name:
            raise Invalid("display_user_id does not match server_name")
        server = srv_id(srv[0])
        sigs = ev.get("signatures", {}).get(server, {})
        if not any(
            p.verify_sig(
                req(srv[-1].online_key, "online_key"), signing_input(ev), unb64(s)
            )
            for s in sigs.values()
        ):
            raise Invalid("create not signed by creating server's current key")
        master_key = req(usr[-1].msk, "creator master_key")
        if any(link.msk != master_key for link in usr):
            raise Invalid("creator master_key changed or was omitted")
        self.auth_device_signature(ev, ev["sender"], master_key)

    def auth_epoch_active(self, ev: dict, A: dict):
        t, sk, c, sender = ev["type"], ev["state_key"], ev["content"], ev["sender"]
        links = [p.parse_link(unb64(r)) for r in c["links"]]
        kind = p.KIND_SERVER if t == SERVER_EPOCH else p.KIND_USER
        prev = A.get((t, sk))
        if prev is None:
            if (
                len(links) != 1
                or links[0].height != 0
                or links[0].digest != principal_digest(sk)
            ):
                raise Invalid("first introduction must carry exactly the genesis link")
            p.verify_link(links[0], None)
        else:
            if prev["content"]["status"] != "active":
                raise Invalid("principal is burned")
            p.verify_slice(links, self.tip(prev))
        if kind == p.KIND_USER:
            master_key = req(links[0].msk, "user master_key")
            if any(link.msk != master_key for link in links):
                raise Invalid("user master_key is absent or changed")
        tip = links[-1]
        if tip.kind != kind:
            raise Invalid("link kind does not match event type")
        expect = {"height": tip.height, "tip": p.b64u(tip.digest)}
        if kind == p.KIND_SERVER:
            expect.update(
                online_key=p.b64u(req(tip.online_key, "online_key")),
                server_name=tip.server_name,
            )
        else:
            expect.update(
                custodian="~" + p.b64u(req(tip.custodian, "custodian")),
                display_user_id=tip.mxid,
            )
            if tip.msk is not None:
                expect["master_key"] = p.b64u(tip.msk)
        for k, v in expect.items():
            if c.get(k) != v:
                raise Invalid(f"restated field {k} does not match the tip")
        if kind == p.KIND_USER and tip.msk is None and "master_key" in c:
            raise Invalid("master_key present without one in the link")

        # Sender (5.3 rule 2) and permitted signers (5.2).
        own_signer = sk if t == SERVER_EPOCH else c["custodian"]
        principal_sends = (
            (sender == sk) if t == USER_EPOCH else (self.custodian_of(A, sender) == sk)
        )
        relay = prev is not None and self.joined(A, sender)
        if not (principal_sends or relay):
            raise Invalid("sender may not send this epoch event")
        if not self.admitted(A, sender):
            raise Invalid("sender not admitted")
        signers = [own_signer] if principal_sends else []
        if relay:
            rc = self.custodian_of(A, sender)
            if rc:
                signers.append(rc)
        if not any(
            self.signed_by(ev, A, s) for s in signers if s in ev.get("signatures", {})
        ):
            raise Invalid("not signed by a permitted signer")
        return links

    def auth_burn(self, ev: dict, A: dict):
        t, sk, c = ev["type"], ev["state_key"], ev["content"]
        prev = A.get((t, sk))
        if prev is None or prev["content"]["status"] != "active":
            raise Invalid("burn needs an active anchor")
        anchor = p.EpochEvent(
            prev["event_id_"],
            principal_digest(sk),
            "active",
            None,
            self.chains[prev["event_id_"]],
        )
        anchor.prev = None  # chain is complete already
        b = p.EpochEvent(
            "$burn",
            principal_digest(sk),
            "burned",
            anchor,
            fork_height=c["fork_height"],
            parent_body=unb64(c["parent"]),
            bridge=[p.parse_link(unb64(r)) for r in c["bridge"]],
            branch_a=p.parse_link(unb64(c["branch_a"])),
            branch_b=p.parse_link(unb64(c["branch_b"])),
        )
        p.auth_burn(b)
        if not self.joined(A, ev["sender"]):
            raise Invalid("burn sender must be joined")
        self.auth_signed_by_custodian(ev, A)

    def auth_signed_by_custodian(self, ev: dict, A: dict) -> str:
        C = self.custodian_of(A, ev["sender"])
        if C is None:
            raise Invalid("sender has no active user epoch")
        se = A.get((SERVER_EPOCH, C))
        if se is None or se["content"]["status"] != "active":
            raise Invalid("custodian has no active server epoch")
        if not self.signed_by(ev, A, C):
            raise Invalid("not signed by the sender's custodian")
        return C

    def auth_other(self, ev: dict, A: dict):
        if ev["type"] == "m.room.server_acl":
            validate_server_acl(ev["content"])
        C = self.auth_signed_by_custodian(ev, A)  # 5.5 rule 1
        u = ev["sender"]
        ue = A.get((USER_EPOCH, u))
        if ue is None or ue["content"].get("status") != "active":
            raise Invalid("sender has no active user epoch")
        master_key = req(self.tip(ue).msk, "user master_key")
        self.auth_device_signature(ev, u, master_key)
        self_member = ev["type"] == "m.room.member" and ev.get("state_key") == u
        m = A.get(("m.room.member", u))
        if not self_member and m is not None and m["content"].get("custodian") != C:
            raise Invalid("membership is bound to a different custodian")  # rule 2
        if self_member:
            if ev["content"].get("custodian") != C:
                raise Invalid(
                    "member event custodian must be the sender's custodian"
                )  # rule 3
            if (
                ev["content"].get("membership") == "join"
                and m is not None
                and m["content"].get("membership") == "join"
                and m["content"].get("custodian") != C
            ):
                old = m["content"]["custodian"]  # rule 4: rebinding
                acl = A.get(("m.room.server_acl", ""))
                jr = A.get(("m.room.join_rules", ""))
                if acl is not None and (
                    jr is None or jr["content"].get("join_rule") != "public"
                ):
                    names = [old]
                    ose = A.get((SERVER_EPOCH, old))
                    if ose is not None:
                        names.append(ose["content"]["server_name"])
                    if acl_denies(acl["content"], names):
                        raise Invalid(
                            "rebinding refused: previous custodian denied by server ACL"
                        )

    # -- submission ---------------------------------------------------------
    def select_auth(
        self, t: str, sender: str, sk: Optional[str], content: dict
    ) -> List[str]:
        keys = [
            ("m.room.join_rules", ""),
            ("m.room.power_levels", ""),
            ("m.room.member", sender),
            (USER_EPOCH, sender),
        ]
        st = {k: self.events[v] for k, v in self.state.items()}
        C = self.custodian_of(st, sender)
        if C:
            keys.append((SERVER_EPOCH, C))
        if t in EPOCHS:
            keys.append((t, req(sk, "state_key")))
            if t == USER_EPOCH and content.get("custodian"):
                keys.append((SERVER_EPOCH, content["custodian"]))
        if t == "m.room.member":
            sk = req(sk, "state_key")
            keys += [("m.room.member", sk), ("m.room.server_acl", "")]
            m = st.get(("m.room.member", sk))
            if m is not None and m["content"].get("custodian"):
                keys.append((SERVER_EPOCH, m["content"]["custodian"]))
        out = []
        for k in keys:
            if k in self.state and self.state[k] not in out:
                out.append(self.state[k])
        return out

    def build(
        self,
        t,
        sender,
        content,
        signer,
        height,
        sk_,
        state_key=None,
        auth=None,
        device_sign=True,
    ):
        self.ts += 1
        ev = {
            "type": t,
            "sender": sender,
            "content": content,
            "origin_server_ts": self.ts,
            "depth": len(self.order) + 1,
            "prev_events": self.order[-1:],
            "auth_events": (
                auth
                if auth is not None
                else (
                    []
                    if t == "m.room.create"
                    else self.select_auth(t, sender, state_key, content)
                )
            ),
        }
        if state_key is not None:
            ev["state_key"] = state_key
        if t != "m.room.create":
            ev["room_id"] = self.room_id
        if sender.startswith("@") and t not in EPOCHS and device_sign:
            credentials = DEVICE_CREDENTIALS.get(sender)
            if credentials is None:
                raise Invalid("test fixture has no device credentials for sender")
            ev = add_device_signature(ev, sender, credentials)
        return sign(ev, signer, height, sk_)

    def submit(self, ev: dict) -> str:
        if ev["hashes"]["sha256"] != content_hash(ev):
            raise Invalid("content hash mismatch")
        eid = event_id(ev)
        t = ev["type"]
        if t == "m.room.create":
            if self.order:
                raise Invalid("second create")
            self.auth_create(ev)
            self.room_id = "!" + eid[1:]
            self.creators = {
                ev["sender"],
                *ev["content"].get("additional_creators", []),
            }
        else:
            if ev.get("room_id") != self.room_id:
                raise Invalid("wrong room")
            A = {}
            for aid in ev["auth_events"]:
                a = self.events.get(aid)
                if a is None:
                    raise Invalid("unknown auth event")
                if "state_key" not in a:
                    raise Invalid("auth event is not a state event")
                key = (a["type"], a["state_key"])
                if self.state.get(key) != aid:
                    raise Invalid(
                        "auth event is not current state (state-before check)"
                    )
                A[key] = a
            if t in EPOCHS and ev["content"].get("status") == "active":
                links = self.auth_epoch_active(ev, A)
                prev = A.get((t, ev["state_key"]))
                self.chains[eid] = (
                    self.chains[prev["event_id_"]] if prev else []
                ) + links
            elif t in EPOCHS:
                self.auth_burn(ev, A)
            else:
                self.auth_other(ev, A)
        stored = dict(ev, event_id_=eid)
        self.events[eid] = stored
        self.order.append(eid)
        if "state_key" in ev:
            self.state[(t, ev["state_key"])] = eid
        return eid


def pdu_ancestors(ev: dict, events: Dict[str, dict]) -> Set[str]:
    """Return the transitive prev_events ancestry of a PDU."""
    seen: Set[str] = set()
    stack = list(ev.get("prev_events", []))
    while stack:
        eid = stack.pop()
        if eid in seen:
            continue
        seen.add(eid)
        parent = events.get(eid)
        if parent is not None:
            stack.extend(parent.get("prev_events", []))
    return seen


def server_signing_height(
    ev: dict, server: str, events: Dict[str, dict]
) -> Optional[int]:
    """Resolve the server signing height from the event's authorization view."""
    if not ev.get("signatures", {}).get(server):
        return None

    target = principal_digest(server)

    def chain_height(raw_links) -> Optional[int]:
        if not isinstance(raw_links, list) or not raw_links:
            return None
        links = [p.parse_link(unb64(raw)) for raw in raw_links]
        if links[0].digest != target:
            return None
        return links[-1].height

    content = ev.get("content", {})
    if ev.get("type") == "m.room.create":
        creator_links = content.get("creator_links", {})
        return chain_height(creator_links.get("server"))

    if ev.get("type") == SERVER_EPOCH and ev.get("state_key") == server:
        active_epoch_in_auth = any(
            (auth_ev := events.get(aid)) is not None
            and auth_ev.get("type") == SERVER_EPOCH
            and auth_ev.get("state_key") == server
            and auth_ev.get("content", {}).get("status") == "active"
            for aid in ev.get("auth_events", [])
        )
        if active_epoch_in_auth:
            height = content.get("height")
            return height if type(height) is int else None

    for aid in ev.get("auth_events", []):
        auth_ev = events.get(aid)
        if (
            auth_ev is not None
            and auth_ev.get("type") == SERVER_EPOCH
            and auth_ev.get("state_key") == server
            and auth_ev.get("content", {}).get("status") == "active"
        ):
            height = auth_ev["content"].get("height")
            return height if type(height) is int else None
    # Section 5.2's introduction fallback signs with the tip in signer_links;
    # the event's own subject chain may be at a different height.
    return chain_height(content.get("signer_links"))


def candidate_g7_merge(
    branches: List[Room], seal: dict, server: str, verifier: Room
) -> Tuple[Set[str], Set[str]]:
    """Merge branch events under the proposed seal ancestry rule.

    Branch events were individually accepted by Room.submit, which validates
    their ordinary event and device signatures against their branch state. This
    merge pass rechecks the candidate G7 rule against the merged DAG and the
    active server epoch used to sign the seal. It is not full Matrix state
    resolution or normative room-version authorization.
    """
    seal_height = seal.get("content", {}).get("sealed_height")
    state_key = seal.get("state_key")
    if (
        seal.get("type") != SERVER_SEAL
        or state_key != server
        or type(seal_height) is not int
    ):
        raise Invalid("malformed candidate server seal")

    graph: Dict[str, dict] = {}
    for branch in branches:
        for eid, ev in branch.events.items():
            prior = graph.get(eid)
            if prior is not None and prior != ev:
                raise Invalid("branches disagree on an event ID")
            graph[eid] = ev
    graph[event_id(seal)] = seal

    auth_state = {}
    for aid in seal.get("auth_events", []):
        auth_ev = graph.get(aid)
        if auth_ev is None or "state_key" not in auth_ev:
            raise Invalid("seal has an unknown or non-state auth event")
        auth_state[(auth_ev["type"], auth_ev["state_key"])] = auth_ev
    epoch = auth_state.get((SERVER_EPOCH, server))
    if epoch is None or epoch["content"].get("status") != "active":
        raise Invalid("seal lacks an active server epoch")
    sender_epoch = auth_state.get((USER_EPOCH, seal.get("sender")))
    if (
        sender_epoch is None
        or sender_epoch["content"].get("status") != "active"
        or sender_epoch["content"].get("custodian") != server
    ):
        raise Invalid("seal sender is not custodied by the subject server")
    sender_member = auth_state.get(("m.room.member", seal.get("sender")))
    if sender_member is None or sender_member["content"].get("membership") != "join":
        raise Invalid("seal sender is not joined")
    if epoch["content"].get("height", -1) < seal_height:
        raise Invalid("seal height exceeds its signing epoch")
    if not verifier.signed_by(seal, auth_state, server):
        raise Invalid("seal is not signed by the subject server")

    seal_ancestry = pdu_ancestors(seal, graph)
    accepted: Set[str] = set()
    rejected: Set[str] = set()
    for eid, ev in graph.items():
        if ev.get("signatures", {}).get(server):
            signer_height = server_signing_height(ev, server, graph)
            if signer_height is None:
                raise Invalid("cannot resolve signing height for server signature")
            if signer_height < seal_height and eid not in seal_ancestry:
                rejected.add(eid)
                continue
        accepted.add(eid)
    return accepted, rejected


# --------------------------------------------------------------------------- content builders


def user_epoch_content(
    links: List[p.Link], signer_links: Optional[List[p.Link]] = None
) -> dict:
    tip = links[-1]
    c = {
        "status": "active",
        "links": [p.b64u(lnk.raw) for lnk in links],
        "height": tip.height,
        "tip": p.b64u(tip.digest),
        "custodian": "~" + p.b64u(req(tip.custodian, "custodian")),
        "display_user_id": tip.mxid,
    }
    if tip.msk is not None:
        c["master_key"] = p.b64u(tip.msk)
    if signer_links:
        c["signer_links"] = [p.b64u(lnk.raw) for lnk in signer_links]
    return c


def server_epoch_content(
    links: List[p.Link], signer_links: Optional[List[p.Link]] = None
) -> dict:
    tip = links[-1]
    c = {
        "status": "active",
        "links": [p.b64u(lnk.raw) for lnk in links],
        "height": tip.height,
        "tip": p.b64u(tip.digest),
        "online_key": p.b64u(req(tip.online_key, "online_key")),
        "server_name": tip.server_name,
    }
    if signer_links:
        c["signer_links"] = [p.b64u(lnk.raw) for lnk in signer_links]
    return c


def member(custodian: str, membership="join") -> dict:
    return {"membership": membership, "custodian": custodian}


# --------------------------------------------------------------------------- scenarios


def run():
    C = p.Checks()
    A0, A1, B0, U0, U1 = p.build_fixtures()
    SA, SB, alice = srv_id(A0), srv_id(B0), usr_id(U0)
    DEVICE_CREDENTIALS.clear()

    def register_device(principal, master_sk, seed_byte):
        DEVICE_CREDENTIALS[principal] = {
            "master": master_sk,
            "self_signing": p.sk_from_seed(p.seed(seed_byte)),
            "device": p.sk_from_seed(p.seed(seed_byte + 1)),
            "device_id": f"TEST{seed_byte:02x}",
        }

    register_device(alice, p.USR_MSK, 0x51)
    on0, on1, onB = p.SRV_A_ONLINE0, p.SRV_A_ONLINE1, p.SRV_B_ONLINE0

    def attempt(room, name, ev, expect_ok=True):
        try:
            eid = room.submit(ev)
            C.expect(
                name,
                expect_ok,
                "accepted" if expect_ok else "accepted, expected rejection",
            )
            return eid
        except Invalid as ex:
            C.expect(name, not expect_ok, f"rejected: {ex}")
            return None

    def founding(label, join_rule, acl):
        """Alice on server A (height 1) creates a room, sets join rules and an ACL, says hello."""
        R = Room(label)
        cr = R.build(
            "m.room.create",
            alice,
            {
                "room_version": ROOM_VERSION,
                "creator_links": {
                    "server": [p.b64u(A0.raw), p.b64u(A1.raw)],
                    "user": [p.b64u(U0.raw)],
                },
            },
            SA,
            1,
            on1,
            state_key="",
        )
        steps = [
            ("create", cr),
        ]
        R.submit(cr)
        steps.append(
            (
                "alice user epoch (genesis, signer_links)",
                R.build(
                    USER_EPOCH,
                    alice,
                    user_epoch_content([U0], [A0, A1]),
                    SA,
                    1,
                    on1,
                    state_key=alice,
                ),
            )
        )
        R.submit(steps[-1][1])
        steps.append(
            (
                "server A epoch (genesis, signer_links)",
                R.build(
                    SERVER_EPOCH,
                    alice,
                    server_epoch_content([A0], [A0, A1]),
                    SA,
                    1,
                    on1,
                    state_key=SA,
                ),
            )
        )
        R.submit(steps[-1][1])
        steps.append(
            (
                "server A epoch (advance to h=1)",
                R.build(
                    SERVER_EPOCH,
                    alice,
                    server_epoch_content([A1]),
                    SA,
                    1,
                    on1,
                    state_key=SA,
                ),
            )
        )
        R.submit(steps[-1][1])
        steps.append(
            (
                "alice joins",
                R.build(
                    "m.room.member", alice, member(SA), SA, 1, on1, state_key=alice
                ),
            )
        )
        R.submit(steps[-1][1])
        steps.append(
            (
                "join rules",
                R.build(
                    "m.room.join_rules",
                    alice,
                    {"join_rule": join_rule},
                    SA,
                    1,
                    on1,
                    state_key="",
                ),
            )
        )
        R.submit(steps[-1][1])
        steps.append(
            (
                "server ACL",
                R.build("m.room.server_acl", alice, acl, SA, 1, on1, state_key=""),
            )
        )
        R.submit(steps[-1][1])
        steps.append(
            (
                "message via A",
                R.build(
                    "m.room.message",
                    alice,
                    {"msgtype": "m.text", "body": "hello"},
                    SA,
                    1,
                    on1,
                ),
            )
        )
        R.submit(steps[-1][1])
        return R, steps

    # --- P1: founding flow -------------------------------------------------
    open_acl = {"allow": ["*"], "deny": [], "allow_ip_literals": False}
    try:
        R, vector_steps = founding("P1", "invite", open_acl)
        C.expect(
            "P1 founding flow (create, genesis-only epochs, join, message) accepted",
            True,
            f"room {R.room_id}",
        )
    except Invalid as ex:
        C.expect("P1 founding flow accepted", False, f"rejected: {ex}")
        return C, None

    R0 = Room("P1-bad")
    bad = R0.build(
        "m.room.create",
        alice,
        {
            "room_version": ROOM_VERSION,
            "creator_links": {
                "server": [p.b64u(A0.raw), p.b64u(A1.raw)],
                "user": [p.b64u(U0.raw)],
            },
        },
        SA,
        0,
        on0,
        state_key="",
    )
    attempt(
        R0, "P1 create signed with the server's retired key is rejected", bad, False
    )
    attempt(
        R,
        "P1 a second genesis introduction for server A is rejected (already introduced)",
        R.build(
            SERVER_EPOCH,
            alice,
            server_epoch_content([A0], [A0, A1]),
            SA,
            1,
            on1,
            state_key=SA,
        ),
        False,
    )
    malformed_cert = R.build(
        "m.room.message",
        alice,
        {"msgtype": "m.text", "body": "bad certificate"},
        SA,
        1,
        on1,
    )
    malformed_cert["device_certificate"]["device_key"] = "!"
    malformed_cert = sign(malformed_cert, SA, 1, on1)
    attempt(
        R,
        "P1 malformed device certificate is rejected",
        malformed_cert,
        False,
    )

    # --- P2: migration to server B -----------------------------------------
    changed_msk_link = p.make_rotation(
        U0,
        p.USR_ROT1,
        p.commitment(p.pub(p.USR_ROT2)),
        custodian=B0.digest,
        msk=p.pub(p.USR_ROT2),
        mxid="@alice:second.example.net",
    )
    attempt(
        R,
        "P2 custodian cannot replace Alice's master key in a migration link",
        R.build(
            USER_EPOCH,
            alice,
            user_epoch_content([changed_msk_link], [B0]),
            SB,
            0,
            onB,
            state_key=alice,
        ),
        False,
    )
    mig = R.build(
        USER_EPOCH, alice, user_epoch_content([U1], [B0]), SB, 0, onB, state_key=alice
    )
    attempt(R, "P2 alice's migration link, signed by new custodian B", mig)
    vector_steps.append(("alice moves to B (user epoch advance, signer_links)", mig))
    attempt(
        R,
        "P2 old custodian A can no longer send as alice",
        R.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "A speaking"},
            SA,
            1,
            on1,
        ),
        False,
    )
    attempt(
        R,
        "P2 B cannot send for alice before B is introduced",
        R.build(
            "m.room.message", alice, {"msgtype": "m.text", "body": "early"}, SB, 0, onB
        ),
        False,
    )
    bintro = R.build(
        SERVER_EPOCH, alice, server_epoch_content([B0], [B0]), SB, 0, onB, state_key=SB
    )
    attempt(R, "P2 server B introduced (sender alice, now custodied by B)", bintro)
    vector_steps.append(("server B epoch (genesis, signer_links)", bintro))
    attempt(
        R,
        "P2 once B is present, A's signature is refused for alice",
        R.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "A speaking"},
            SA,
            1,
            on1,
        ),
        False,
    )
    attempt(
        R,
        "P2 B cannot send for alice before she rebinds",
        R.build(
            "m.room.message", alice, {"msgtype": "m.text", "body": "early"}, SB, 0, onB
        ),
        False,
    )
    rebind = R.build("m.room.member", alice, member(SB), SB, 0, onB, state_key=alice)
    attempt(R, "P2 rebinding join via B (invite-only room, ACL open)", rebind)
    vector_steps.append(("alice rebinds to B", rebind))
    msgB = R.build(
        "m.room.message",
        alice,
        {"msgtype": "m.text", "body": "hello from B"},
        SB,
        0,
        onB,
    )
    attempt(R, "P2 alice sends via B", msgB)
    vector_steps.append(("message via B", msgB))

    # --- P3: ACL gate on rebinding -----------------------------------------
    deny_a = {"allow": ["*"], "deny": ["chat.example.org"], "allow_ip_literals": False}
    for jr, ok in (("invite", False), ("public", True)):
        Rx, _ = founding(f"P3-{jr}", jr, deny_a)
        Rx.submit(
            Rx.build(
                USER_EPOCH,
                alice,
                user_epoch_content([U1], [B0]),
                SB,
                0,
                onB,
                state_key=alice,
            )
        )
        Rx.submit(
            Rx.build(
                SERVER_EPOCH,
                alice,
                server_epoch_content([B0], [B0]),
                SB,
                0,
                onB,
                state_key=SB,
            )
        )
        attempt(
            Rx,
            f"P3 rebinding when the ACL denies the old server, join rule {jr}",
            Rx.build("m.room.member", alice, member(SB), SB, 0, onB, state_key=alice),
            ok,
        )

    # --- P4: prefix replay by an ex-custodian, then relay ------------------
    bob_rot = p.sk_from_seed(p.seed(0x31))
    bob_master = p.sk_from_seed(p.seed(0x53))
    bob0 = p.make_user_genesis(
        B0.digest,
        p.commitment(p.pub(bob_rot)),
        "@bob:second.example.net",
        p.pub(bob_master),
    )
    bob = usr_id(bob0)
    register_device(bob, bob_master, 0x55)

    def bobs_room(label):
        Q = Room(label)
        Q.submit(
            Q.build(
                "m.room.create",
                bob,
                {
                    "room_version": ROOM_VERSION,
                    "creator_links": {
                        "server": [p.b64u(B0.raw)],
                        "user": [p.b64u(bob0.raw)],
                    },
                },
                SB,
                0,
                onB,
                state_key="",
            )
        )
        Q.submit(
            Q.build(
                USER_EPOCH,
                bob,
                user_epoch_content([bob0], [B0]),
                SB,
                0,
                onB,
                state_key=bob,
            )
        )
        Q.submit(
            Q.build(
                SERVER_EPOCH,
                bob,
                server_epoch_content([B0], [B0]),
                SB,
                0,
                onB,
                state_key=SB,
            )
        )
        Q.submit(Q.build("m.room.member", bob, member(SB), SB, 0, onB, state_key=bob))
        Q.submit(
            Q.build(
                "m.room.join_rules",
                bob,
                {"join_rule": "public"},
                SB,
                0,
                onB,
                state_key="",
            )
        )
        return Q

    Q = bobs_room("P4")
    # Alice has already moved to B, but A still holds her old state and replays it here.
    attempt(
        Q,
        "P4 ex-custodian A introduces alice's h=0 prefix (no key needed)",
        Q.build(
            USER_EPOCH,
            alice,
            user_epoch_content([U0], [A0, A1]),
            SA,
            1,
            on1,
            state_key=alice,
        ),
    )
    Q.submit(
        Q.build(
            SERVER_EPOCH,
            alice,
            server_epoch_content([A0], [A0, A1]),
            SA,
            1,
            on1,
            state_key=SA,
        )
    )
    Q.submit(
        Q.build(
            SERVER_EPOCH, alice, server_epoch_content([A1]), SA, 1, on1, state_key=SA
        )
    )
    attempt(
        Q,
        "P4 ex-custodian cannot forge Alice's join without her device signature",
        Q.build(
            "m.room.member",
            alice,
            member(SA),
            SA,
            1,
            on1,
            state_key=alice,
            device_sign=False,
        ),
        False,
    )
    attempt(
        Q,
        "P4 ex-custodian cannot post as Alice without her device signature",
        Q.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "impostor"},
            SA,
            1,
            on1,
            device_sign=False,
        ),
        False,
    )
    outsider = "@" + p.b64u(p.sha256(b"nobody"))
    attempt(
        Q,
        "P4 a non-member cannot relay (relay requires join)",
        Q.build(
            USER_EPOCH, outsider, user_epoch_content([U1]), SB, 0, onB, state_key=alice
        ),
        False,
    )
    stale_auth = Q.select_auth("m.room.message", alice, None, {})
    attempt(
        Q,
        "P4 bob's server relays alice's newer link (signed by B as bob's custodian)",
        Q.build(USER_EPOCH, bob, user_epoch_content([U1]), SB, 0, onB, state_key=alice),
    )
    attempt(
        Q,
        "P4 after the relay, A can no longer send as alice",
        Q.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "impostor"},
            SA,
            1,
            on1,
        ),
        False,
    )
    attempt(
        Q,
        "P4 citing the pre-relay state is rejected as stale",
        Q.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "impostor"},
            SA,
            1,
            on1,
            auth=stale_auth,
        ),
        False,
    )

    # --- P5: retired online key replay, then relay -------------------------
    mal_rot = p.sk_from_seed(p.seed(0x35))
    mal_master = p.sk_from_seed(p.seed(0x57))
    mal0 = p.make_user_genesis(
        A0.digest,
        p.commitment(p.pub(mal_rot)),
        "@mallory:chat.example.org",
        p.pub(mal_master),
    )
    mallory = usr_id(mal0)
    register_device(mallory, mal_master, 0x59)
    attempt(
        Q,
        "P5 retired key 0 of server A is useless where the room knows A's current tip",
        Q.build(
            USER_EPOCH,
            mallory,
            user_epoch_content([mal0], [A0]),
            SA,
            0,
            on0,
            state_key=mallory,
        ),
        False,
    )
    Z = bobs_room("P5")
    attempt(
        Z,
        "P5 thief with A's retired key 0 introduces a user under A's h=0 prefix",
        Z.build(
            USER_EPOCH,
            mallory,
            user_epoch_content([mal0], [A0]),
            SA,
            0,
            on0,
            state_key=mallory,
        ),
    )
    Z.submit(
        Z.build(
            SERVER_EPOCH,
            mallory,
            server_epoch_content([A0], [A0]),
            SA,
            0,
            on0,
            state_key=SA,
        )
    )
    attempt(
        Z,
        "P5 thief cannot join Mallory without her device signature",
        Z.build(
            "m.room.member",
            mallory,
            member(SA),
            SA,
            0,
            on0,
            state_key=mallory,
            device_sign=False,
        ),
        False,
    )
    attempt(
        Z,
        "P5 thief cannot post for Mallory without her device signature",
        Z.build(
            "m.room.message",
            mallory,
            {"msgtype": "m.text", "body": "spoof"},
            SA,
            0,
            on0,
            device_sign=False,
        ),
        False,
    )
    attempt(
        Z,
        "P5 bob's server relays A's newer link",
        Z.build(
            SERVER_EPOCH, bob, server_epoch_content([A1]), SB, 0, onB, state_key=SA
        ),
    )
    attempt(
        Z,
        "P5 after the relay, the retired key no longer verifies",
        Z.build(
            "m.room.message",
            mallory,
            {"msgtype": "m.text", "body": "spoof"},
            SA,
            0,
            on0,
        ),
        False,
    )

    # --- G: known gaps (expected current failures) -------------------------
    # These vectors reproduce behaviour MSC-00FC does not prevent. C.gap marks
    # a reproduction as KNOWN, so it does not fail the run. If a vector stops
    # reproducing the run fails: that is the signal to promote it to a
    # conformance check and update the MSC and pid_known_gaps.json.

    def exploit(room, ev):
        """Submit an event that the current rules arguably should refuse."""
        try:
            room.submit(ev)
            return True, "accepted: nothing ties the branch to the room's current tip"
        except Invalid as ex:
            return False, f"rejected: {ex}"

    def retired_key_room(label):
        """A room that saw server A at h=0, joined alice, then advanced to h=1.

        Returns the room and a snapshot of the state before the advancement, so
        a vector can attach an event where the retired online key on0 was
        current.
        """
        G = Room(label)
        G.submit(
            G.build(
                "m.room.create",
                alice,
                {
                    "room_version": ROOM_VERSION,
                    "creator_links": {
                        "server": [p.b64u(A0.raw)],
                        "user": [p.b64u(U0.raw)],
                    },
                },
                SA,
                0,
                on0,
                state_key="",
            )
        )
        G.submit(
            G.build(
                USER_EPOCH,
                alice,
                user_epoch_content([U0], [A0]),
                SA,
                0,
                on0,
                state_key=alice,
            )
        )
        G.submit(
            G.build(
                SERVER_EPOCH,
                alice,
                server_epoch_content([A0], [A0]),
                SA,
                0,
                on0,
                state_key=SA,
            )
        )
        G.submit(
            G.build("m.room.member", alice, member(SA), SA, 0, on0, state_key=alice)
        )
        G.submit(
            G.build(
                "m.room.power_levels",
                alice,
                {"users": {alice: 100}, "users_default": 0},
                SA,
                0,
                on0,
                state_key="",
            )
        )
        before = G.snapshot()
        G.submit(
            G.build(
                SERVER_EPOCH,
                alice,
                server_epoch_content([A1]),
                SA,
                1,
                on1,
                state_key=SA,
            )
        )
        return G, before

    # G1: a hostile custodian supplies the old branch before device signing.
    # The event is fully co-signed, so this is a placement gap, not a forgery.
    G, before = retired_key_room("G1")
    branch = G.branch_at(before)
    ok, detail = exploit(
        branch,
        branch.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "signed after the rotation"},
            SA,
            0,
            on0,
        ),
    )
    C.gap(
        "G1 device co-signs a message on a custodian-selected pre-rotation branch",
        ok,
        detail,
        problem="open problem 2",
    )

    branch = G.branch_at(before)
    ok, detail = exploit(
        branch,
        branch.build(
            "m.room.power_levels",
            alice,
            {"users": {alice: 100}, "users_default": 100},
            SA,
            0,
            on0,
            state_key="",
        ),
    )
    C.gap(
        "G1 device co-signs a state event on a custodian-selected pre-rotation branch",
        ok,
        f"{detail}; §6 defines no rule that drops it from state resolution",
        problem="open problem 2",
    )

    attempt(
        G,
        "G1 control: the same retired key is refused at the room's current tip",
        G.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "signed after the rotation"},
            SA,
            0,
            on0,
        ),
        False,
    )

    # G2: two disjoint views of the same identity, one lagging at h=0 and one
    # advanced at h=1, each accepting its own tip, with no local check that can
    # compare them. Open problem 1.
    behind = G.branch_at(before)
    ok_lag, detail_lag = exploit(
        behind,
        behind.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "h=0 view"},
            SA,
            0,
            on0,
        ),
    )
    ok_tip, detail_tip = exploit(
        G,
        G.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "h=1 view"},
            SA,
            1,
            on1,
        ),
    )
    C.gap(
        "G2 lagging and advanced tips accepted in two disjoint views of one chain, no local cross-check",
        ok_lag and ok_tip,
        f"h=0 view {detail_lag}; h=1 view {detail_tip}",
        problem="open problem 1",
    )

    # G7 candidate merge path. Each branch first accepts its own events under
    # the ordinary PDU/device rules. The merge then applies the proposed seal
    # ancestry rule against the union DAG and resolved seal.
    seal_base, seal_before = retired_key_room("G7")
    seal_main = seal_base.branch_at(seal_before)
    honest_old_id = seal_main.submit(
        seal_main.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "honest pre-rotation event"},
            SA,
            0,
            on0,
        )
    )
    seal_main.submit(
        seal_main.build(
            SERVER_EPOCH,
            alice,
            server_epoch_content([A1]),
            SA,
            1,
            on1,
            state_key=SA,
        )
    )
    seal_content = {"sealed_height": 1, "previous_seal": None}
    seal_auth = seal_main.select_auth(SERVER_SEAL, alice, SA, seal_content)
    seal_pdu = {
        "type": SERVER_SEAL,
        "sender": alice,
        "state_key": SA,
        "room_id": seal_main.room_id,
        "content": seal_content,
        "origin_server_ts": seal_main.ts + 1,
        "depth": len(seal_main.order) + 1,
        "prev_events": seal_main.order[-1:],
        "auth_events": seal_auth,
    }
    seal_pdu = sign(seal_pdu, SA, 1, on1)

    seal_late = seal_base.branch_at(seal_before)
    late_message_id = seal_late.submit(
        seal_late.build(
            "m.room.message",
            alice,
            {"msgtype": "m.text", "body": "valid on historical branch"},
            SA,
            0,
            on0,
        )
    )
    late_power_id = seal_late.submit(
        seal_late.build(
            "m.room.power_levels",
            alice,
            {"users": {alice: 100}, "users_default": 100},
            SA,
            0,
            on0,
            state_key="",
        )
    )
    power_before_seal = seal_main.state[("m.room.power_levels", "")]
    seal_accepted, seal_rejected = candidate_g7_merge(
        [seal_main, seal_late], seal_pdu, SA, seal_main
    )
    C.expect(
        "G7 merge: create and signer_links use the actual server signing height",
        server_signing_height(vector_steps[0][1], SA, R.events) == 1
        and server_signing_height(vector_steps[2][1], SA, R.events) == 1
        and server_signing_height(
            seal_late.events[late_message_id], SA, seal_late.events
        )
        == 0,
        "creator links and signer_links may be ahead of an introduced subject chain",
    )
    foreign_create = copy.deepcopy(vector_steps[0][1])
    foreign_create["signatures"][SB] = copy.deepcopy(foreign_create["signatures"][SA])
    C.expect(
        "G7 merge: creator and signer chains are bound to the subject server",
        server_signing_height(foreign_create, SB, R.events) is None,
        "a chain beginning at another server cannot supply this server's height",
    )
    C.expect(
        "G7 merge: seal signature verifies under the active epoch",
        event_id(seal_pdu) not in seal_rejected,
        "candidate seal signed by server A at height 1",
    )
    unrelated_sender_seal = copy.deepcopy(seal_pdu)
    unrelated_sender_seal["sender"] = outsider
    C.rejects(
        "G7 merge: seal sender must be custodied by the subject server",
        candidate_g7_merge,
        [seal_main, seal_late],
        unrelated_sender_seal,
        SA,
        seal_main,
    )

    class _Branch:
        def __init__(self, events):
            self.events = events

    bob_epoch_id = "$bobuser"
    bob_member_id = "$bobmember"
    bob_graph = dict(seal_main.events)
    bob_graph[bob_epoch_id] = {
        "type": USER_EPOCH,
        "state_key": bob,
        "sender": bob,
        "content": {"status": "active", "custodian": SB},
        "auth_events": [],
        "prev_events": [],
        "signatures": {},
    }
    bob_graph[bob_member_id] = {
        "type": "m.room.member",
        "state_key": bob,
        "sender": bob,
        "content": {"membership": "join", "custodian": SB},
        "auth_events": [],
        "prev_events": [],
        "signatures": {},
    }
    bob_sender_seal = copy.deepcopy(seal_pdu)
    bob_sender_seal["sender"] = bob
    bob_sender_seal["auth_events"] = list(bob_sender_seal["auth_events"]) + [
        bob_epoch_id,
        bob_member_id,
    ]
    C.rejects(
        "G7 merge: a sender custodied by another server is rejected",
        candidate_g7_merge,
        [_Branch(bob_graph)],
        bob_sender_seal,
        SA,
        seal_main,
    )

    left_graph = dict(bob_graph)
    left_graph[bob_epoch_id] = {
        **left_graph[bob_epoch_id],
        "content": {"status": "active", "custodian": SA},
    }
    left_graph[bob_member_id] = {
        **left_graph[bob_member_id],
        "content": {"membership": "leave", "custodian": SA},
    }
    left_sender_seal = copy.deepcopy(bob_sender_seal)
    C.rejects(
        "G7 merge: a non-joined seal sender is rejected",
        candidate_g7_merge,
        [_Branch(left_graph)],
        left_sender_seal,
        SA,
        seal_main,
    )
    C.expect(
        "G7 merge: honest old-height ancestor survives",
        honest_old_id in seal_accepted,
        "the event is in the seal's prev_events ancestry",
    )
    C.expect(
        "G7 merge: historical-branch message is excluded by the resolved seal",
        late_message_id in seal_rejected,
        "old-height server signature is outside the resolved seal's causal past",
    )
    C.expect(
        "G7 merge: historical-branch state event is excluded before state resolution",
        late_power_id in seal_rejected and power_before_seal in seal_accepted,
        "the event was valid on its branch but is outside the merged seal's ancestry",
    )

    # G3 and G4 depend on creator-majority finality; G5 depends on a
    # device-revocation rule; G6 depends on a per-signer event chain; G7
    # depends on a self-sealing rotation rule. They stay in pid_known_gaps.json
    # and are reported as SPEC so they cannot silently drop out of the record.
    gaps_doc = json.loads(Path(__file__).with_name("pid_known_gaps.json").read_text())
    declared = {v["id"] for v in gaps_doc["vectors"]}
    spec_gaps = [
        (
            "G3-finality-checkpoint-signed-by-retired-online-key",
            "a checkpoint signed by a retired online key is irreversible, so "
            "00FA-style finality inherits open problem 2 unless checkpoint "
            "signers are rotation keys",
        ),
        (
            "G4-finality-tradeoff-for-late-branches",
            "sealed history rejects late branches and their state, trading "
            "availability for no-backdating",
        ),
        (
            "G5-custodian-notice-cannot-revoke-a-device",
            "an honest current custodian can refuse to sign for a compromised "
            "device, but the refusal is local and a former or colluding "
            "custodian can still make its certificate count",
        ),
        (
            "G6-per-device-event-chain-fork",
            "a per-signer event chain would turn a cloned-device fork into "
            "in-DAG evidence, but room version N does not define the chain",
        ),
        (
            "G7-self-sealing-rotation",
            "a self-signed epoch advancement could seal the height it leaves, "
            "but room version N has no ancestry rule tying old-height events "
            "to it",
        ),
    ]
    for vid, why in spec_gaps:
        C.gap(vid, None, why)
    missing = [vid for vid, _ in spec_gaps if vid not in declared]
    if missing:
        raise RuntimeError(f"pid_known_gaps.json is missing SPEC vectors: {missing}")

    # Executable vector names must match the records this run made, so a rename
    # cannot drift between pid_known_gaps.json and the check text. G1's control
    # row is a PASS, not a gap, so it is excluded.
    exec_names = [
        name
        for v in gaps_doc["vectors"]
        if v["executable"]
        for name in v["vectors"]
        if not name.startswith("G1 control")
    ]
    recorded = {g["name"] for g in C.gaps}
    drift = [name for name in exec_names if name not in recorded]
    if drift:
        raise RuntimeError(f"executable gap names not recorded: {drift}")

    # --- P6: redaction keeps what auth needs -------------------------------
    for label, (_, ev) in (
        ("server ACL", vector_steps[6]),
        ("rebinding member", vector_steps[-2]),
    ):
        r = redact(ev)
        need = {
            "server ACL": ("allow", "deny"),
            "rebinding member": ("membership", "custodian"),
        }[label]
        C.expect(
            f"P6 redacted {label} keeps {', '.join(need)}",
            all(k in r["content"] for k in need),
        )
    epoch = vector_steps[1][1]
    C.expect(
        "P6 redacted user epoch keeps all content",
        redact(epoch)["content"] == epoch["content"],
    )

    # --- P7: device certificate schema version -----------------------------
    def resign_after_mutation(ev, principal, server, height, sk_):
        """Re-sign a hand-edited event as its device, then as its custodian."""
        creds = DEVICE_CREDENTIALS[principal]
        ev["hashes"] = {"sha256": content_hash(ev)}
        ev["signatures"][principal] = {
            f"{p.pid_sig.KEY_ALGORITHM}:{creds['device_id']}": p.b64u(
                creds["device"].sign(DEVICE_EVENT_TAG + signing_input(ev))
            )
        }
        return sign(ev, server, height, sk_)

    future = G.build(
        "m.room.message", alice, {"msgtype": "m.text", "body": "future"}, SA, 1, on1
    )
    future["device_certificate"]["future_field"] = "ignored"
    attempt(
        G,
        "P7 unknown device-certificate fields are ignored at version 1",
        resign_after_mutation(future, alice, SA, 1, on1),
    )

    v2 = G.build(
        "m.room.message", alice, {"msgtype": "m.text", "body": "v2"}, SA, 1, on1
    )
    v2["device_certificate"]["version"] = 2
    attempt(
        G,
        "P7 unsupported device-certificate version is rejected",
        resign_after_mutation(v2, alice, SA, 1, on1),
        False,
    )

    boolver = G.build(
        "m.room.message", alice, {"msgtype": "m.text", "body": "bool"}, SA, 1, on1
    )
    boolver["device_certificate"]["version"] = True
    attempt(
        G,
        "P7 non-integer device-certificate version is rejected",
        resign_after_mutation(boolver, alice, SA, 1, on1),
        False,
    )
    attempt(
        R,
        "P1 malformed principal entry in server ACL is rejected",
        R.build(
            "m.room.server_acl",
            alice,
            {"allow": ["~*"], "deny": [], "allow_ip_literals": False},
            SA,
            1,
            on1,
            state_key="",
        ),
        False,
    )
    acl_entry = "~" + p.b64u(bytes([0xFB, 0xFF]) * 16)
    C.accepts(
        "P8 canonical principal encoding is accepted in server ACL",
        validate_server_acl,
        {"allow": [acl_entry], "deny": []},
    )
    malformed_acl_entries = [
        ("padded principal encoding", acl_entry + "="),
        ("42-character principal payload", acl_entry[:-1]),
        ("44-character principal payload", acl_entry + "A"),
        ("standard-base64 plus", acl_entry.replace("-", "+")),
        ("standard-base64 slash", acl_entry.replace("_", "/")),
    ]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    final_index = alphabet.index(acl_entry[-1])
    noncanonical_tail = acl_entry[:-1] + alphabet[final_index + 1]
    malformed_acl_entries.append(("nonzero base64url trailing bits", noncanonical_tail))
    for label, bad_entry in malformed_acl_entries:
        C.rejects(
            f"P8 rejects {label} in server ACL",
            validate_server_acl,
            {"allow": [bad_entry], "deny": []},
        )
    C.rejects(
        "P8 principal_digest rejects padded input",
        principal_digest,
        acl_entry + "=",
    )
    return C, (R, vector_steps)


def main():
    C, vec = run()
    if vec:
        R, steps = vec
        out = {
            "room_version": ROOM_VERSION,
            "room_id": R.room_id,
            "events": [
                {
                    "step": s,
                    "event_id": event_id(e),
                    "reference_hash_hex": reference_hash(e).hex(),
                    "content_hash": e["hashes"]["sha256"],
                    "pdu": e,
                }
                for s, e in steps
            ],
            "checks": [{"name": n, "pass": ok, "detail": d} for n, ok, d in C.results],
            "known_gaps": C.gaps,
        }
        p.write_json("pid_pdu_vectors.json", out)
    sys.exit(p.report(C))


if __name__ == "__main__":
    main()
