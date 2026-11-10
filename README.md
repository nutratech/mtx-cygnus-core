# cygnus-core

I/O-free core for [MSC00FC](../proposals/proposals/00FC-self-certifying-identities.md)
(room version "Cygnus"): self-certifying server and user principals built from
pre-rotated WOTS+ hash-signature link chains.

The current signature format is the experimental SHA-256 WOTS+ Merkle profile.
Signing keys are stateful: each tree leaf must be used at most once, and the
client must persist its next-leaf position safely across restarts and backups.
This custom profile has not had an independent cryptographic review and should
not be treated as a standardized post-quantum signature scheme.

Layering (see the spec sections in parentheses):

| Module      | Status | Contents                                                                                                  |
| ----------- | ------ | --------------------------------------------------------------------------------------------------------- |
| `principal` | done   | `~`/`@` identifiers (§2.6)                                                                                |
| `link`      | done   | link codec, digests, commitments, `verify_link` (§2)                                                      |
| `bootstrap` | done   | rotation key generation, commitment C₀, user/server genesis and successor builders (§4)                   |
| `cert`      | done   | master → self-signing → device certificate verification (§5.2.1)                                          |
| `envelope`  | done   | redaction, canonical signing bytes, hashes, event IDs, and device/custodian signatures (§4.3, §5.2.1, §9) |
| `bundle`    | done   | create/epoch/burn verification, Pass 0 resolution, tip bundles (§4, §6)                                   |
| `auth`      | active | epoch, custodian, device and relay authorization overlay (§5); state-before check 21 is external          |
| `seal`      | done   | server-seal cutover predicates and `authorize_seal` (§7)                                                  |

Conformance: Appendix A link vectors and Appendix C hashes/event IDs are
exercised by the Rust tests. Appendix B/C and DMLS reference models and
fixtures are vendored under `tests/vectors/` and `tools/reference_models/`;
`tools/reference_models/check.py` runs the upstream oracles. P1–P5 auth,
including the relay and retired-key scenarios, is covered. Remaining gaps are
the stale-`auth_events` check 21 (owned by base auth/state selection) and the
two G7 merge scenarios (29–30). See
[`docs/client-integration.md`](docs/client-integration.md) for the SDK and
client API gaps. Bindings (wasm, uniffi) and a prototype CLI will live in
sibling workspace crates; key generation stays in this core and out of the
verify-only wasm crate.

Setup: `pre-commit install` and `git config --local include.path ../.gitconfig`.
