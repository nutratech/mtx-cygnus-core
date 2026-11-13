# Vendored MSC00FC test vectors

These files are copied verbatim from the proposal repository so the
conformance tests do not depend on a sibling checkout or on the network.
The table below lists the three PID vector files. The broader
`provenance.json` manifest additionally hashes the DMLS fixtures
(`tests/vectors/dmls/`) and the reference models (`tools/reference_models/`),
which are copied verbatim from the same `proposals/` directory at the same
commit. Only `tools/reference_models/check.py` and `requirements.txt` are
maintained here.

| File                   | Source path                      | SHA-256                                                            |
| ---------------------- | -------------------------------- | ------------------------------------------------------------------ |
| `pid_vectors.json`     | `proposals/pid_vectors.json`     | `2f51dc3f6efe73858cb4af13e6c3feff270f620d029b5faeb39fcdec786ce432` |
| `pid_pdu_vectors.json` | `proposals/pid_pdu_vectors.json` | `54923a7100e9e0566cb46c0d2557a35f017a78bfdbe69ba7702368789034376d` |
| `pid_known_gaps.json`  | `proposals/pid_known_gaps.json`  | `61159a3aac4536fc85d62c86a5acbda0d438c05920b5d60ee2a678d42c9cc9cb` |

- Source: `https://gitlab.com/wombat-foundation/proposals` (or the
  `../proposals` checkout), commit `4e14a372dbfd5fb5f2aad0aa2a6c1275b6739b19`.
- License: Apache License 2.0. See `LICENSE-APACHE`, copied from the source
  repository's `LICENSE`.
- Regenerating: the vectors are produced by `proposals/pid_ref.py` and
  `proposals/pid_pdu.py`. Those scripts are the reference model; do not edit
  the JSON by hand.

`pid_known_gaps.json` is the expected-failure list (G1–G7). It is vendored so
the harness can assert that known gaps stay gaps instead of silently passing.

When updating the source commit, refresh all three files and the SHA-256
column above in the same change.
