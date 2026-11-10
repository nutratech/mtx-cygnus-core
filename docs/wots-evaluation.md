# WOTS+ evaluation

Cygnus briefly replaced Ed25519 with WOTS+ Merkle-tree signatures (0bb7d28,
981e729) and then went back (6d33d02). The WOTS+ code has since been removed;
its last version, `src/wots.rs` behind the `wots-experimental` feature, is in
commit 14b67c7. This note records why Cygnus does not use it.

## Sizes and timings

Measured on an Intel Coffee Lake desktop (AVX2, no SHA-NI), with a `cargo test`
build in which `sha2` is at `opt-level = 3` and `cygnus-core` is unoptimized.
Chain steps use one SHA-256 compression each (14b67c7). Reproduce from that
commit with:

```sh
cargo test --features wots-experimental --lib wots -- --ignored --nocapture
```

| Scheme                    | Signature          | Keygen         | Sign  | Verify |
| ------------------------- | ------------------ | -------------- | ----- | ------ |
| Ed25519 (`ed25519-zebra`) | 64 B               | not measured   | 17 µs | 31 µs  |
| WOTS+ 8-bit (`Bytes`)     | 752 B              | 17 ms          | 7 ms  | 10 ms  |
| WOTS+ 16-bit (`Words`)    | 432 B              | 2.4 s          | 1.0 s | 1.4 s  |
| Tree, depth _d_ (`Bytes`) | 752 + 4 + 32·_d_ B | 2^_d_ × keygen | 7 ms  | ~10 ms |

- Ed25519 timings are from a release build of `ed25519-zebra` 4 on the same
  machine (100-byte message); WOTS+ timings are from the test build above.
- The `Bytes` profile has 22 chains of 255 steps; `Words` has 12 chains of
  65,535 steps. Doubling the bits per chain digit squares the chain length and
  only halves the chain count, so `Words` costs about 140 times more hashing
  to save 320 bytes.
- A depth-6 tree (64 signatures) gives 948-byte signatures; a depth-10 tree
  (1,024 signatures) took 17.5 s to build.
- Each chain step depends on the previous one, so a single chain cannot be
  parallelized. Only chains within a key (22 lanes) and leaves within a tree
  are independent.

## The reuse attack

A WOTS+ signature reveals, for each chain, the value at the position given by
that chain's digit. Anyone can hash forward from a revealed value, so a
signature can be turned into one for any digit at or above the revealed one.
The checksum chains block this for a single signature: raising a message
digit lowers the checksum, and lowering a checksum digit would require
inverting SHA-256.

Two signatures from the same one-time key reveal, per chain, the lower of two
positions, including on the checksum chains. An attacker then picks a message
and grinds the salt until every digit, checksum included, is at or above
those minimums. The chains are not independent: digits high enough to pass
the message chains make the checksum low, which then has to clear the
checksum minimums. Computing the exact success probability for 5,000 random
signature pairs gives a median of about 1 in 8.5 million attempts per pair,
with 10% of pairs easier than 1 in 140,000 and 10% harder than 1 in 800
million. Each attempt is one SHA-256 digest, so a typical forgery of an
arbitrary message takes seconds to minutes of hashing on one machine.
No hash is ever inverted, and precomputed tables do not help because every
step is domain-separated by `pub_seed`, chain and step.

Reuse happens without any attacker involvement: a crash between signing and
persisting the leaf counter, a backup or VM snapshot restore, or one key on
two devices. A power loss during development zeroed files that had just been
written, which is exactly how a leaf counter would roll back.

## Why Cygnus keeps Ed25519

- **Reuse is safe.** Ed25519 signs any number of messages. Its nonces are
  derived from the key and the message, so a retry after a crash or restore
  reproduces the same signature for the same message and a fresh nonce for a
  different one; neither leaks the key. A rotation key that signs
  two different next links produces a fork, not a forgery, and the two
  signatures are the fraud proof that burns the epoch (`src/bundle.rs`). With
  WOTS+, the same mistake also lets third parties forge further histories.
- **No signer state.** Tree WOTS+ needs a durable, never-rolled-back leaf
  counter on every device. A depth-6 tree runs out after 64 signatures; real
  servers and devices sign thousands of PDUs per epoch.
- **Size.** 64-byte signatures versus 752 to 948 bytes, in every link,
  certificate and PDU.
- **Interoperability.** ZIP-215 verification (`tests/zip215.rs`) is the
  agreed validity rule; the vendored vectors and the upstream proposal use it.

## Where hash-based signatures would fit

If post-quantum signatures become a requirement, one-time WOTS+ keys suit the
pre-rotated link chain, since each rotation key signs exactly one next link
and the chain itself is the state. PDUs need a stateless scheme such as
SLH-DSA (SPHINCS+), possibly alongside Ed25519, rather than stateful trees on
user devices.
