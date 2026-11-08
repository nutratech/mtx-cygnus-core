# Vendored MSC00FC test vectors

These files are copied verbatim from the proposal repository so the
conformance tests do not depend on a sibling checkout or on the network.

| File                   | Source path                      | SHA-256                                                            |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------ |
| `pid_vectors.json`     | `proposals/pid_vectors.json`     | `d8a66c5fbd28607a58e997ee8203a4bb402f75d71d5d2dbbe1db1b2f63451dbf` |
| `pid_pdu_vectors.json` | `proposals/pid_pdu_vectors.json` | `a17c3ababc1716f6cba61f3e7a3648aa927082f75228c6587fd86a843360a93a` |
| `pid_known_gaps.json`  | `proposals/pid_known_gaps.json`  | `61159a3aac4536fc85d62c86a5acbda0d438c05920b5d60ee2a678d42c9cc9cb` |

- Source: `https://gitlab.com/wombat-foundation/proposals` (or the
  `../proposals` checkout), commit `d85eafda527a89c021103f44814d7e57513a0192`.
- License: Apache License 2.0. See `LICENSE-APACHE`, copied from the source
  repository's `LICENSE`.
- Regenerating: the vectors are produced by `proposals/pid_ref.py` and
  `proposals/pid_pdu.py`. Those scripts are the reference model; do not edit
  the JSON by hand.

`pid_known_gaps.json` is the expected-failure list (G1–G7). It is vendored so
the harness can assert that known gaps stay gaps instead of silently passing.

When updating the source commit, refresh all three files and the SHA-256
column above in the same change.
