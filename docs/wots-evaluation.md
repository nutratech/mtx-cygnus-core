# WOTS+ evaluation

Cygnus briefly replaced Ed25519 with WOTS+ Merkle-tree signatures (0bb7d28,
981e729) and then went back (6d33d02). The WOTS+ code remains in
`src/wots.rs` behind the `wots-experimental` feature. This note records why.

## Sizes and timings

Measured on an Intel Coffee Lake desktop (AVX2, no SHA-NI), with a `cargo test`
build in which `sha2` is at `opt-level = 3` and `cygnus-core` is unoptimized.
Chain steps use one SHA-256 compression each (14b67c7). Reproduce with:

```sh
cargo test --features wots-experimental --lib wots -- --ignored --nocapture
```

| Scheme                    | Signature          | Keygen         | Sign  | Verify |
| ------------------------- | ------------------ | -------------- | ----- | ------ |
| Ed25519                   | 64 B               | µs             | µs    | µs     |
| WOTS+ 8-bit (`Bytes`)     | 752 B              | 17 ms          | 7 ms  | 10 ms  |
| WOTS+ 16-bit (`Words`)    | 432 B              | 2.4 s          | 1.0 s | 1.4 s  |
| Tree, depth _d_ (`Bytes`) | 752 + 4 + 32·_d_ B | 2^_d_ × keygen | 7 ms  | ~10 ms |

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
those minimums. Treating the minimums as random, each chain passes about 2/3
of the time, so one attempt succeeds with probability about (2/3)^22, roughly
1 in 7,500. A forgery of an arbitrary message costs a few thousand hashes.
No hash is ever inverted, and precomputed tables do not help because every
step is domain-separated by `pub_seed`, chain and step.

Reuse happens without any attacker involvement: a crash between signing and
persisting the leaf counter, a backup or VM snapshot restore, or one key on
two devices. A power loss during development zeroed files that had just been
written, which is exactly how a leaf counter would roll back.

## Why Cygnus keeps Ed25519

- **Reuse is safe.** Ed25519 signs any number of messages; deterministic nonces
  rule out nonce reuse across crashes and restores. A rotation key that signs
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
