# Vendored MSC00FC test vectors

These files are copied verbatim from the proposal repository so the
conformance tests do not depend on a sibling checkout or on the network.
The table below lists the three proposal-sourced PID vector files. The broader
`provenance.json` manifest also hashes repository-maintained DMLS fixtures and
reference-model files; those are not additional files from the MSC00FC proposal
checkout.

| File                   | Source path                      | SHA-256                                                            |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------ |
| `pid_vectors.json`     | `proposals/pid_vectors.json`     | `d8a66c5fbd28607a58e997ee8203a4bb402f75d71d5d2dbbe1db1b2f63451dbf` |
| `pid_pdu_vectors.json` | `proposals/pid_pdu_vectors.json` | `7f71294f687605d3147d742f07f1bd525b12ca8213668a1f92e70e0354955297` |
| `pid_known_gaps.json`  | `proposals/pid_known_gaps.json`  | `61159a3aac4536fc85d62c86a5acbda0d438c05920b5d60ee2a678d42c9cc9cb` |

- Source: `https://gitlab.com/wombat-foundation/proposals` (or the
  `../proposals` checkout), commit `b76dffcec5478abbe3e73b9fc7f91042f62f4662`.
- License: Apache License 2.0. See `LICENSE-APACHE`, copied from the source
  repository's `LICENSE`.
- Regenerating: the vectors are produced by `proposals/pid_ref.py` and
  `proposals/pid_pdu.py`. Those scripts are the reference model; do not edit
  the JSON by hand.

`pid_known_gaps.json` is the expected-failure list (G1–G7). It is vendored so
the harness can assert that known gaps stay gaps instead of silently passing.

When updating the source commit, refresh all three files and the SHA-256
column above in the same change.
