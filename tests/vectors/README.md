# Vendored MSC00FC test vectors

These files are copied verbatim from the proposal repository so the
conformance tests do not depend on a sibling checkout or on the network.

| File                   | Source path                      | SHA-256                                                            |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------ |
| `pid_vectors.json`     | `proposals/pid_vectors.json`     | `2b143f3413eacbbbd7439200616bed94100ef425f26590969462ca906461840e` |
| `pid_pdu_vectors.json` | `proposals/pid_pdu_vectors.json` | `ef09553563b737a5ac2158ebbd7b757558d1340a968adab79521ac199677a4ec` |
| `pid_known_gaps.json`  | `proposals/pid_known_gaps.json`  | `61159a3aac4536fc85d62c86a5acbda0d438c05920b5d60ee2a678d42c9cc9cb` |

- Source: `https://gitlab.com/wombat-foundation/proposals` (or the
  `../proposals` checkout), commit `c26d7c7779ea97cc1ac174d33aa8dcf05dc3e234`.
- License: Apache License 2.0. See `LICENSE-APACHE`, copied from the source
  repository's `LICENSE`.
- **Modified:** the reference model here no longer uses Ed25519. `pid_sig.py`
  (WOTS+ Merkle trees, mirroring `src/sig.rs`) replaces it and the two
  vector files are regenerated, so they differ from the upstream proposal.
- Regenerating: the vectors are produced by `proposals/pid_ref.py` and
  `proposals/pid_pdu.py`. Those scripts are the reference model; do not edit
  the JSON by hand.

`pid_known_gaps.json` is the expected-failure list (G1–G7). It is vendored so
the harness can assert that known gaps stay gaps instead of silently passing.

When updating the source commit, refresh all three files and the SHA-256
column above in the same change.
