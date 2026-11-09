# cygnus-core

I/O-free core for [MSC00FC](../proposals/proposals/00FC-self-certifying-identities.md)
(room version "Cygnus"): self-certifying server and user principals built from
pre-rotated Ed25519 link chains.

Layering (see the spec sections in parentheses):

| Module      | Status | Contents                                                                                                  |
| ----------- | ------ | --------------------------------------------------------------------------------------------------------- |
| `principal` | done   | `~`/`@` identifiers (§2.6)                                                                                |
| `link`      | done   | link codec, digests, commitments, `verify_link` (§2)                                                      |
| `bootstrap` | done   | fresh rotation keys, genesis commitment C₀, user/server genesis and successor builders (§4)               |
| `cert`      | done   | master → self-signing → device certificate verification (§5.2.1)                                          |
| `envelope`  | done   | redaction, canonical signing bytes, hashes, event IDs, and device/custodian signatures (§4.3, §5.2.1, §9) |
| `bundle`    | done   | create/epoch/burn verification, Pass 0 resolution, tip bundles (§4, §6)                                   |
| `auth`      | active | epoch, custodian, device and relay authorization overlay (§5); state-before check 21 is external          |
| `seal`      | active | server-seal cutover predicates (§7); seal-specific authorization (G7 checks 32–34) remains                |

Conformance: Appendix A link vectors and Appendix C hashes/event IDs are
exercised by the Rust tests. Appendix B/C and DMLS reference models and
fixtures are vendored under `tests/vectors/` and `tools/reference_models/`;
`tools/reference_models/check.py` runs the upstream oracles. P1–P5 auth,
including the relay and retired-key scenarios, is covered. Remaining gaps are
the stale-`auth_events` check 21 (owned by base auth/state selection) and G7
seal authorization 32–34. See
[`docs/client-integration.md`](docs/client-integration.md) for the SDK and
client API gaps. Bindings (wasm, uniffi) and a prototype CLI will live in
sibling workspace crates; key generation stays in this core and out of the
verify-only wasm crate.

Setup: `pre-commit install` and `git config --local include.path ../.gitconfig`.
