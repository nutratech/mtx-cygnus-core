# Conformance coverage

Maps the vendored `tests/vectors/` checks to Rust tests. Status:
**done** = ported and passing; **partial** = resolution logic covered, event-level
path not; **needs module** = depends on code that does not exist yet.

## `pid_vectors.json` (43)

| Group | Checks | Status | Tests |
|---|---|---|---|
| Link layer | 7 | done | `appendix_a*.rs`, `link_negative.rs` |
| Name binding | 5 | done | `binding.rs` |
| Ingress | 8 | done | `binding.rs` |
| T1–T7 burns, Pass 0, freezes | 23 | partial | `bundle_pass0.rs`, `bundle_burn.rs` |

## `pid_pdu_vectors.json` (53)

| Group | Checks | Status | Tests |
|---|---|---|---|
| P1 founding, create, genesis, cert | 5 | done (cert negatives via `cert.rs`) | `bundle_p1.rs`, `tip_bundle.rs` |
| P2 custodian change / rebinding | 9 | needs module (auth-state layer) | — |
| P3 ACL denies old server | 2 | needs module (auth state) | — |
| P4 ex-custodian, relay, stale tip | 7 | needs module (auth state) | — |
| P5 retired key, relay | 5 | needs module (auth state) | — |
| G1 retired key at current tip | 1 | KNOWN gap (expected failure) | — |
| G7 merge / seal | 9 | seal predicates done; normative auth needs module | `seal.rs` |
| P6 redaction keeps fields | 3 | done | `envelope.rs` |
| P7 device-cert version | 3 | see `cert.rs` | `cert.rs` |
| P8 principal encoding | 8 | principal parse done; ACL entry parsing needs module | `principal_p8.rs` |

G3–G7 in `known_gaps` are SPEC and intentionally not implemented.
Per-check names are in `pid_pdu_vectors.json`; the counts above were taken
from the group prefixes, so treat them as approximate until each check is
mapped one to one.
