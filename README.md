# cygnus-core

I/O-free core for [MSC00FC](../proposals/proposals/00FC-self-certifying-identities.md)
(room version "Cygnus"): self-certifying server and user principals built from
pre-rotated Ed25519 link chains.

Planned layering (see the spec sections in parentheses):

| Module      | Status | Contents                                                         |
| ----------- | ------ | ---------------------------------------------------------------- |
| `principal` | done   | `~`/`@` identifiers (§2.6)                                       |
| `link`      | done   | link codec, digests, commitments, `verify_link` (§2)             |
| `cert`      | done   | master → self-signing → device certificate verification (§5.2.1) |
| `envelope`  | todo   | client-built event envelope + device signature (§5.2.1, §9)      |
| `bundle`    | todo   | tip-bundle verification, epoch events, burns (§4, §9)            |

Conformance: Appendix A/C vectors from the MSC are in `tests/`. Bindings
(wasm, uniffi) and a prototype CLI will live in sibling workspace crates.

Setup: `pre-commit install` and `git config --local include.path ../.gitconfig`.
