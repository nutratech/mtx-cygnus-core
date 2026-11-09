# cygnus-core

I/O-free core for [MSC00FC](../proposals/proposals/00FC-self-certifying-identities.md)
(room version "Cygnus"): self-certifying server and user principals built from
pre-rotated Ed25519 link chains.

Planned layering (see the spec sections in parentheses):

| Module      | Status | Contents                                                                                                  |
| ----------- | ------ | --------------------------------------------------------------------------------------------------------- |
| `principal` | done   | `~`/`@` identifiers (§2.6)                                                                                |
| `link`      | done   | link codec, digests, commitments, `verify_link` (§2)                                                      |
| `cert`      | done   | master → self-signing → device certificate verification (§5.2.1)                                          |
| `envelope`  | done   | redaction, canonical signing bytes, hashes, event IDs, and device/custodian signatures (§4.3, §5.2.1, §9) |
| `bundle`    | active | create verification; active/burned epoch parsing; Pass 0 resolution (§4, §6)                              |

Conformance: Appendix A link vectors and Appendix C hashes/event IDs are
exercised by the Rust tests. Appendix B/C and DMLS reference models and
fixtures are vendored under `tests/vectors/` and `tools/reference_models/`;
`tools/reference_models/check.py` runs the upstream oracles. The bundle module
is in progress: P1 create/epoch structure and signatures are covered, while
tip-bundle verification, burn conformance, Pass 0 conformance, epoch
authorization, and full PDU-auth coverage remain to do. See
[`docs/client-integration.md`](docs/client-integration.md) for the SDK and
client API gaps. Bindings (wasm, uniffi) and a prototype CLI will live in
sibling workspace crates.

Setup: `pre-commit install` and `git config --local include.path ../.gitconfig`.
