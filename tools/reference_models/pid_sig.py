"""Hash-based signatures for the reference model: WOTS+ in a Merkle tree.

Mirrors `src/wots.rs` and `src/sig.rs` byte for byte (8-bit chains, 160-bit
salted digest, depth 6). A public key is the 32-byte tree root; a signature is
`leaf_index(4, BE) | pub_seed | salt | 22 chain values | 4 path nodes`.
"""

import hashlib
import struct

DEPTH = 6
CHAINS = 22  # 20 message bytes + 2 checksum bytes
W_MAX = 255
# Signature key-id prefix; mirrors `sig::TREE_DEPTH` in src/envelope.rs.
KEY_ALGORITHM = f"wots-sha256-160-8-mt{DEPTH}"
SIGNATURE_LEN = 4 + 32 + 16 + CHAINS * 32 + DEPTH * 32


def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def _tweak(domain: int, chain: int, step: int, seed: bytes, data: bytes) -> bytes:
    return _h(bytes([domain, chain]), struct.pack("<H", step), seed, data)


def _advance(value: bytes, chain: int, start: int, steps: int, pub_seed: bytes) -> bytes:
    for step in range(start, start + steps):
        value = _tweak(0x01, chain, step, pub_seed, value)
    return value


def _steps(pub_seed: bytes, salt: bytes, msg: bytes) -> list:
    digest = _tweak(0x02, 0, 0, pub_seed, salt + msg)
    steps = list(digest[:20])
    checksum = sum(W_MAX - w for w in steps)
    return steps + [(checksum >> 8) & 0xFF, checksum & 0xFF]


def _expand(seed: bytes):
    pub_seed = _tweak(0x00, 0xFF, 0, seed, b"pub-seed")
    return pub_seed, [_tweak(0x00, i, 0, seed, b"sk") for i in range(CHAINS)]


def _compress(pub_seed: bytes, tips: list) -> bytes:
    return _h(b"\x03", pub_seed, *tips)


def _leaf_seed(seed: bytes, index: int) -> bytes:
    return _tweak(0x06, 0, 0, seed, struct.pack("<Q", index))


def _leaf_public(seed: bytes) -> bytes:
    pub_seed, secrets = _expand(seed)
    return _compress(
        pub_seed, [_advance(sk, i, 0, W_MAX, pub_seed) for i, sk in enumerate(secrets)]
    )


def _node(index: int, left: bytes, right: bytes) -> bytes:
    return _tweak(0x05, 0, index, left, right)


_TREES: dict = {}


class SigningKey:
    """A tree of 2**DEPTH one-time keys; each signature burns the next leaf."""

    def __init__(self, seed: bytes):
        assert len(seed) == 32
        self.seed = seed
        self.next = 0
        if seed not in _TREES:
            leaves = 1 << DEPTH
            nodes = [b"\0" * 32] * (2 * leaves)
            for i in range(leaves):
                nodes[leaves + i] = _leaf_public(_leaf_seed(seed, i))
            for i in range(leaves - 1, 0, -1):
                nodes[i] = _node(i, nodes[2 * i], nodes[2 * i + 1])
            _TREES[seed] = nodes
        self.nodes = _TREES[seed]

    def public_bytes(self) -> bytes:
        return self.nodes[1]

    def sign(self, msg: bytes) -> bytes:
        index = self.next
        if index >= 1 << DEPTH:
            raise RuntimeError("signing key exhausted")
        self.next += 1
        leaf_seed = _leaf_seed(self.seed, index)
        pub_seed, secrets = _expand(leaf_seed)
        salt = _tweak(0x04, 0, 0, leaf_seed, msg)[:16]
        steps = _steps(pub_seed, salt, msg)
        chains = [
            _advance(sk, i, 0, steps[i], pub_seed) for i, sk in enumerate(secrets)
        ]
        path = []
        at = (1 << DEPTH) + index
        for _ in range(DEPTH):
            path.append(self.nodes[at ^ 1])
            at >>= 1
        return struct.pack(">I", index) + pub_seed + salt + b"".join(chains) + b"".join(path)


def verify(root: bytes, msg: bytes, sig: bytes) -> bool:
    if len(root) != 32 or len(sig) != SIGNATURE_LEN:
        return False
    index = struct.unpack(">I", sig[:4])[0]
    if index >= 1 << DEPTH:
        return False
    pub_seed, salt = sig[4:36], sig[36:52]
    chains = [sig[52 + 32 * i : 84 + 32 * i] for i in range(CHAINS)]
    path_at = 52 + 32 * CHAINS
    path = [sig[path_at + 32 * i : path_at + 32 * (i + 1)] for i in range(DEPTH)]
    steps = _steps(pub_seed, salt, msg)
    tips = [
        _advance(chains[i], i, steps[i], W_MAX - steps[i], pub_seed)
        for i in range(CHAINS)
    ]
    current = _compress(pub_seed, tips)
    at = (1 << DEPTH) + index
    for sibling in path:
        parent = at >> 1
        current = _node(parent, current, sibling) if at & 1 == 0 else _node(parent, sibling, current)
        at >>= 1
    return current == root
