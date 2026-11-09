# Conformance coverage

Maps the vendored `tests/vectors/` checks to Rust tests.

Status:

- **done** — ported and passing.
- **partial** — the rule exists, but the check's scenario or event path is not
  exercised (usually because there is no room auth/state engine).
- **needs module** — no Rust code path exists.
- **SPEC** — intentionally not implemented; the proposals mark it as an open
  problem or prototype.

## `pid_vectors.json` (43)

| Group                        | Checks | Status                                                                                         | Tests                                |
| ---------------------------- | ------ | ---------------------------------------------------------------------------------------------- | ------------------------------------ |
| Link layer                   | 7      | done                                                                                           | `appendix_a*.rs`, `link_negative.rs` |
| Name binding                 | 5      | done                                                                                           | `binding.rs`                         |
| Ingress                      | 8      | done                                                                                           | `binding.rs`                         |
| T1–T7 burns, Pass 0, freezes | 23     | partial — resolution and event-level burn parsing covered; not one-to-one with every sub-check | `bundle_pass0.rs`, `bundle_burn.rs`  |

## `pid_pdu_vectors.json` (53)

### P1 — founding flow (4)

| #   | Check                                       | Status  | Rust evidence / gap                                                                                                                                                                                               |
| --- | ------------------------------------------- | ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | Founding flow accepted                      | partial | `bundle_p1` verifies the create, both epoch introductions, and the server rotation. Join and message acceptance need room auth.                                                                                   |
| 1   | Create signed with the retired key rejected | partial | `VerifiedCreate::verify` uses the current server-chain tip key; no fixture drives a retired-key create.                                                                                                           |
| 2   | Second genesis introduction rejected        | partial | `VerifiedEpoch::active(None)` requires exactly one genesis link; `bundle_p1::first_epoch_introduction_cannot_include_a_rotation_slice` covers the slice rule. Re-introduction is state logic and is not modelled. |
| 3   | Malformed device certificate rejected       | partial | `cert` rejects bad versions, non-canonical base64, and modified fields. No test uses a malformed-certificate fixture.                                                                                             |

### P2 — custodian migration (9)

| #   | Check                                           | Status       | Rust evidence / gap                                                     |
| --- | ----------------------------------------------- | ------------ | ----------------------------------------------------------------------- |
| 4   | Custodian cannot replace the master key         | done         | `link_negative::user_rotation_cannot_replace_its_committed_master_key`. |
| 5   | Migration link signed by new custodian accepted | partial      | `Link::verify_successor` accepts custodian changes; no scenario test.   |
| 6   | Old custodian can no longer send                | needs module | Membership/custodian auth state.                                        |
| 7   | New custodian cannot send before introduction   | needs module | Server epoch state.                                                     |
| 8   | Server B introduced                             | needs module | Room auth/state.                                                        |
| 9   | A's signature refused after B is present        | needs module | Sender-custodian auth.                                                  |
| 10  | B cannot send before rebinding                  | needs module | Membership binding auth.                                                |
| 11  | Rebinding join via B                            | needs module | Join-rule/ACL auth.                                                     |
| 12  | Alice sends via B                               | needs module | Sender-custodian auth.                                                  |

### P3 — rebinding and ACLs (2)

| #   | Check                                                     | Status       | Rust evidence / gap                                                 |
| --- | --------------------------------------------------------- | ------------ | ------------------------------------------------------------------- |
| 13  | Rebinding denied by ACL, invite room                      | needs module | `binding::admit` handles ingress ACLs, not rebinding authorization. |
| 14  | Rebinding allowed when ACL denies old server, public room | needs module | Same.                                                               |

### P4 — relays (7)

| #   | Check                                                          | Status       | Rust evidence / gap                                                                                             |
| --- | -------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------- |
| 15  | Ex-custodian introduces the h=0 prefix                         | partial      | `VerifiedEpoch::active` verifies a genesis-only introduction without a key, but not the ex-custodian auth path. |
| 16  | Ex-custodian cannot forge a join without the device signature  | partial      | `verify_device_signature` exists; the custodian auth path does not.                                             |
| 17  | Ex-custodian cannot post as Alice without the device signature | partial      | Same.                                                                                                           |
| 18  | Non-member cannot relay                                        | needs module | Relay auth is not modelled.                                                                                     |
| 19  | Bob's server relays Alice's newer link                         | needs module | Relay auth is not modelled.                                                                                     |
| 20  | After the relay, A cannot send as Alice                        | needs module | State-before/auth sequencing.                                                                                   |
| 21  | Citing pre-relay state is stale                                | needs module | State-before check.                                                                                             |

### P5 — retired keys (6)

| #   | Check                                                      | Status       | Rust evidence / gap                                                                                                 |
| --- | ---------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------- |
| 22  | Retired key useless at the room's current tip              | partial      | Link succession and `verify_epoch_custodian_signature` reject wrong heights; the room-tip scenario is not modelled. |
| 23  | Thief introduces a user under the h=0 prefix               | partial      | Genesis introduction needs no signature; auth/state is absent.                                                      |
| 24  | Thief cannot join Mallory without her device signature     | partial      | Device signature verification exists; auth path absent.                                                             |
| 25  | Thief cannot post for Mallory without her device signature | partial      | Same.                                                                                                               |
| 26  | Bob's server relays A's newer link                         | needs module | Relay auth is not modelled.                                                                                         |
| 27  | After the relay, the retired key no longer verifies        | needs module | State-before/auth sequencing.                                                                                       |

### G1 and G7 (10)

| #   | Check                                                          | Status       | Rust evidence / gap                                                                                          |
| --- | -------------------------------------------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------ |
| 28  | G1 control: retired key refused at the current tip             | partial      | Same components as #22; scenario not modelled.                                                               |
| 29  | Create and `signer_links` use the actual server signing height | partial      | `bundle::signer_chain` and `verify_epoch_custodian_signature` resolve the signing height; no merge scenario. |
| 30  | Creator and signer chains bound to the subject server          | partial      | `VerifiedCreate::verify` binds custodian, display domain, and sender; no merge scenario.                     |
| 31  | Seal signature verifies under the active epoch                 | partial      | `seal::seal_auth_ok` enforces the height rule; signature/auth-state verification is absent.                  |
| 32  | Seal sender must be custodied by the subject server            | needs module | Auth-state layer.                                                                                            |
| 33  | Sender custodied by another server rejected                    | needs module | Same.                                                                                                        |
| 34  | Non-joined seal sender rejected                                | needs module | Same.                                                                                                        |
| 35  | Honest old-height ancestor survives                            | done         | `seal::cutover_filter_keeps_only_the_seal_causal_past`.                                                      |
| 36  | Historical-branch message excluded by the resolved seal        | done         | `seal::a_higher_seals_ancestry_decides_which_old_events_survive`.                                            |
| 37  | Historical-branch state event excluded before state resolution | done         | Same predicate; the filter is event-type agnostic.                                                           |

### P6 — redaction (3)

| #   | Check                                                 | Status  | Rust evidence / gap                                                                            |
| --- | ----------------------------------------------------- | ------- | ---------------------------------------------------------------------------------------------- |
| 38  | Redacted server ACL keeps allow, deny                 | partial | `envelope::kept_content_fields` keeps `allow`, `deny`, `allow_ip_literals`; no dedicated test. |
| 39  | Redacted rebinding member keeps membership, custodian | done    | `envelope::redaction_keeps_cygnus_fields_and_room_v12_content_rules`.                          |
| 40  | Redacted user epoch keeps all content                 | done    | `envelope::epoch_events_keep_full_content_and_ordinary_events_are_redacted`.                   |

### P7 — device certificates (3)

| #   | Check                                           | Status  | Rust evidence / gap                                                                  |
| --- | ----------------------------------------------- | ------- | ------------------------------------------------------------------------------------ |
| 41  | Unknown certificate fields ignored at version 1 | done    | `cert::tests::verifies_certificate_chain_and_ignores_unknown_v1_fields`.             |
| 42  | Unsupported version rejected                    | partial | `DeviceCertificate::parse_and_verify` rejects any `version != 1`; no integer-2 test. |
| 43  | Non-integer version rejected                    | done    | `cert::tests::rejects_boolean_version` (plus float and `1e0` spellings).             |

### P8 — principal encodings (9)

`Principal::parse` enforces the sigil, exactly 43 base64url characters, the
no-padding alphabet, canonical trailing bits, and a 32-byte payload. There is no
server-ACL parser that consumes principal entries, so #44 and #52 remain partial.

| #   | Check                                      | Status  | Rust evidence / gap                                                         |
| --- | ------------------------------------------ | ------- | --------------------------------------------------------------------------- |
| 44  | Malformed principal in server ACL rejected | partial | `Principal::parse` rejects malformed entries; no ACL surface.               |
| 45  | Canonical principal accepted               | done    | `principal_p8::canonical_principal_encoding_is_accepted`.                   |
| 46  | Padded encoding rejected                   | done    | `principal_p8::rejects_padded_encoding`.                                    |
| 47  | 42-character payload rejected              | done    | `principal_p8::rejects_42_and_44_character_payloads`.                       |
| 48  | 44-character payload rejected              | done    | Same.                                                                       |
| 49  | Standard-base64 `+` rejected               | done    | `principal_p8::rejects_standard_base64_alphabet`.                           |
| 50  | Standard-base64 `/` rejected               | done    | Same.                                                                       |
| 51  | Nonzero trailing bits rejected             | done    | `principal_p8::rejects_nonzero_trailing_bits`.                              |
| 52  | `principal_digest` rejects padded input    | partial | No `principal_digest` helper; the equivalent rule is in `Principal::parse`. |

## PDU summary

| Group           | Checks |   done | partial | needs module |
| --------------- | -----: | -----: | ------: | -----------: |
| P1 founding     |      4 |      0 |       4 |            0 |
| P2 migration    |      9 |      1 |       1 |            7 |
| P3 rebinding    |      2 |      0 |       0 |            2 |
| P4 relays       |      7 |      0 |       3 |            4 |
| P5 retired keys |      6 |      0 |       4 |            2 |
| G1/G7           |     10 |      3 |       4 |            3 |
| P6 redaction    |      3 |      2 |       1 |            0 |
| P7 certificates |      3 |      2 |       1 |            0 |
| P8 encodings    |      9 |      7 |       2 |            0 |
| **Total**       | **53** | **15** |  **20** |       **18** |

The largest gap is deliberate: P2–P5 are room authorization and state
sequencing, and the crate currently has no auth engine. That same engine is what
would turn G7 checks 31–34 from _needs module_ into _done_. The P6, P7 and P8
partials are small, self-contained test additions rather than module work.

G3–G7 in `known_gaps` are SPEC and intentionally not implemented.
