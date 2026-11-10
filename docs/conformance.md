# Conformance coverage

Maps the vendored `tests/vectors/` checks to Rust tests.

Status:

- **done** — ported and passing.
- **partial** — the rule exists, but its proposal scenario or complete
  end-to-end path is not exercised.
- **needs module** — no Rust code path exists for the rule.
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

| #   | Check                                       | Status | Rust evidence / gap                                                                                                                                               |
| --- | ------------------------------------------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0   | Founding flow accepted                      | done   | `rezzy_integration::p1_founding_flow_passes_the_combined_entry_point` replays every P1–P3 PDU through `authorize_pdu` (citations, v12 base auth, Cygnus overlay). |
| 1   | Create signed with the retired key rejected | done   | `p1_g7_fixtures` re-signs the P1 create with the retired h=0 key (as h=0 and as h=1): `Error::Signature`; the current key is accepted.                            |
| 2   | Second genesis introduction rejected        | done   | `p1_g7_fixtures` re-introduces A from genesis after A reached h=1: `Error::Successor("height")`.                                                                  |
| 3   | Malformed device certificate rejected       | done   | `p1_g7_fixtures` sets the P1 message certificate's `device_key` to `!`: `Error::Certificate("invalid base64url key")`.                                            |

### P2 — custodian migration (9)

| #   | Check                                           | Status | Rust evidence / gap                                                         |
| --- | ----------------------------------------------- | ------ | --------------------------------------------------------------------------- |
| 4   | Custodian cannot replace the master key         | done   | `link_negative::user_rotation_cannot_replace_its_committed_master_key`.     |
| 5   | Migration link signed by new custodian accepted | done   | `auth_p2::authorizes_user_move_new_server_introduction_rebind_and_message`. |
| 6   | Old custodian can no longer send                | done   | `auth_p2` rejects the pre-move A-signed message after Alice moves.          |
| 7   | New custodian cannot send before introduction   | done   | `auth_p2` rejects B's message before B's server epoch is introduced.        |
| 8   | Server B introduced                             | done   | `auth_p2` verifies B's epoch introduction.                                  |
| 9   | A's signature refused after B is present        | done   | `auth_p2` rejects the A-signed message after B is introduced.               |
| 10  | B cannot send before rebinding                  | done   | `auth_p2` rejects B's message while membership still names A.               |
| 11  | Rebinding join via B                            | done   | `auth_p2` accepts Alice's rebind under B.                                   |
| 12  | Alice sends via B                               | done   | `auth_p2` accepts the post-rebind message.                                  |

### P3 — rebinding and ACLs (2)

| #   | Check                                                     | Status | Rust evidence / gap                                                                   |
| --- | --------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------- |
| 13  | Rebinding denied by ACL, invite room                      | done   | `auth_p2` rejects rebind when the previous custodian is ACL-denied in an invite room. |
| 14  | Rebinding allowed when ACL denies old server, public room | done   | `auth_p2` accepts the rebind when the room is public.                                 |

### P4 — relays (7)

| #   | Check                                                          | Status | Rust evidence / gap                                                                                                                                                    |
| --- | -------------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 15  | Ex-custodian introduces the h=0 prefix                         | done   | `auth_p4_p5` introduces Alice's genesis in a room that has never seen her, carrying A's signer chain.                                                                  |
| 16  | Ex-custodian cannot forge a join without the device signature  | done   | `auth_p4_p5` rejects the ex-custodian's join with no device certificate.                                                                                               |
| 17  | Ex-custodian cannot post as Alice without the device signature | done   | `auth_p4_p5` rejects the ex-custodian's message with no device certificate.                                                                                            |
| 18  | Non-member cannot relay                                        | done   | `auth_p4_p5` rejects an outsider relaying Alice's newer link because the relay sender is not joined.                                                                   |
| 19  | Bob's server relays Alice's newer link                         | done   | `auth_p4_p5` accepts the relay signed by Bob's custodian and advances Alice's epoch.                                                                                   |
| 20  | After the relay, A cannot send as Alice                        | done   | `auth_p4_p5` rejects the ex-custodian's device-signed message after the relay.                                                                                         |
| 21  | Citing pre-relay state is stale                                | done   | `rezzy_integration::citing_a_superseded_user_epoch_is_stale`: after Alice's user epoch is superseded, `authorize_pdu` rejects a message citing the old epoch as stale. |

### P5 — retired keys (6)

| #   | Check                                                      | Status | Rust evidence / gap                                                                                              |
| --- | ---------------------------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------- |
| 22  | Retired key useless at the room's current tip              | done   | `auth_p4_p5` rejects the retired h=0 key once the room knows A's current tip.                                    |
| 23  | Thief introduces a user under the h=0 prefix               | done   | `auth_p4_p5` accepts Mallory's genesis introduction signed only by the retired key in a room unaware of A's tip. |
| 24  | Thief cannot join Mallory without her device signature     | done   | `auth_p4_p5` rejects the retired key's join with no device certificate.                                          |
| 25  | Thief cannot post for Mallory without her device signature | done   | `auth_p4_p5` rejects the retired key's message with no device certificate.                                       |
| 26  | Bob's server relays A's newer link                         | done   | `auth_p4_p5` accepts Bob's relay of A's successor link.                                                          |
| 27  | After the relay, the retired key no longer verifies        | done   | `auth_p4_p5` rejects a fully device-signed message under the retired key after the relay (`Error::Signature`).   |

### G1 and G7 (10)

| #   | Check                                                          | Status | Rust evidence / gap                                                                                                                                                                        |
| --- | -------------------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 28  | G1 control: retired key refused at the current tip             | done   | `auth_p4_p5` rejects the retired h=0 key at A's current tip (same scenario as #22).                                                                                                        |
| 29  | Create and `signer_links` use the actual server signing height | done   | `p1_g7_fixtures`: the create is signed at A's creator-chain tip (h=1); A's genesis epoch (`links` [A0]) and Alice's epoch verify through `signer_links` at h=1, not at the subject height. |
| 30  | Creator and signer chains bound to the subject server          | done   | `p1_g7_fixtures`: A's create signature moved under B fails; A's and B's epochs reject each other's signer chains.                                                                          |
| 31  | Seal signature verifies under the active epoch                 | done   | `auth::authorize_seal` verifies the subject server's current tip key and the epoch height.                                                                                                 |
| 32  | Seal sender must be custodied by the subject server            | done   | `auth_seal` accepts a joined sender whose active user epoch names the subject server.                                                                                                      |
| 33  | Sender custodied by another server rejected                    | done   | `auth_seal` rejects a sender whose user epoch names a different custodian.                                                                                                                 |
| 34  | Non-joined seal sender rejected                                | done   | `auth_seal` rejects a sender whose membership is not `join`.                                                                                                                               |
| 35  | Honest old-height ancestor survives                            | done   | `seal::cutover_filter_keeps_only_the_seal_causal_past`.                                                                                                                                    |
| 36  | Historical-branch message excluded by the resolved seal        | done   | `seal::a_higher_seals_ancestry_decides_which_old_events_survive`.                                                                                                                          |
| 37  | Historical-branch state event excluded before state resolution | done   | Same predicate; the filter is event-type agnostic.                                                                                                                                         |

### P6 — redaction (3)

| #   | Check                                                 | Status | Rust evidence / gap                                                          |
| --- | ----------------------------------------------------- | ------ | ---------------------------------------------------------------------------- |
| 38  | Redacted server ACL keeps allow, deny                 | done   | `envelope::redacted_server_acl_keeps_allow_deny_and_ip_literal_policy`.      |
| 39  | Redacted rebinding member keeps membership, custodian | done   | `envelope::redaction_keeps_cygnus_fields_and_room_v12_content_rules`.        |
| 40  | Redacted user epoch keeps all content                 | done   | `envelope::epoch_events_keep_full_content_and_ordinary_events_are_redacted`. |

### P7 — device certificates (3)

| #   | Check                                           | Status | Rust evidence / gap                                                      |
| --- | ----------------------------------------------- | ------ | ------------------------------------------------------------------------ |
| 41  | Unknown certificate fields ignored at version 1 | done   | `cert::tests::verifies_certificate_chain_and_ignores_unknown_v1_fields`. |
| 42  | Unsupported version rejected                    | done   | `cert::tests::rejects_unsupported_integer_version`.                      |
| 43  | Non-integer version rejected                    | done   | `cert::tests::rejects_boolean_version` (plus float and `1e0` spellings). |

### P8 — principal encodings (9)

`Principal::parse` enforces the sigil, exactly 43 base64url characters, the
no-padding alphabet, canonical trailing bits, and a 32-byte payload.
`validate_server_acl_content` applies that parser to `~` entries in ACLs.
Check 44 is labelled `P1` in the vendored vectors but belongs with these
encoding rules, so it is listed here.

| #   | Check                                      | Status | Rust evidence / gap                                                                                                               |
| --- | ------------------------------------------ | ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| 44  | Malformed principal in server ACL rejected | done   | `acl_pdu::rejects_malformed_or_noncanonical_principal_acl_entries`.                                                               |
| 45  | Canonical principal accepted               | done   | `principal_p8::canonical_principal_encoding_is_accepted`.                                                                         |
| 46  | Padded encoding rejected                   | done   | `principal_p8::rejects_padded_encoding`.                                                                                          |
| 47  | 42-character payload rejected              | done   | `principal_p8::rejects_42_and_44_character_payloads`.                                                                             |
| 48  | 44-character payload rejected              | done   | Same.                                                                                                                             |
| 49  | Standard-base64 `+` rejected               | done   | `principal_p8::rejects_standard_base64_alphabet`.                                                                                 |
| 50  | Standard-base64 `/` rejected               | done   | Same.                                                                                                                             |
| 51  | Nonzero trailing bits rejected             | done   | `principal_p8::rejects_nonzero_trailing_bits`.                                                                                    |
| 52  | `principal_digest` rejects padded input    | done   | `principal_p8::principal_digest_rejects_the_vector_padded_input` (the model's `principal_digest` is `Principal::parse(..).root`). |

## PDU summary

| Group           | Checks |   done | partial | needs module |
| --------------- | -----: | -----: | ------: | -----------: |
| P1 founding     |      4 |      4 |       0 |            0 |
| P2 migration    |      9 |      9 |       0 |            0 |
| P3 rebinding    |      2 |      2 |       0 |            0 |
| P4 relays       |      7 |      7 |       0 |            0 |
| P5 retired keys |      6 |      6 |       0 |            0 |
| G1/G7           |     10 |     10 |       0 |            0 |
| P6 redaction    |      3 |      3 |       0 |            0 |
| P7 certificates |      3 |      3 |       0 |            0 |
| P8 encodings    |      9 |      9 |       0 |            0 |
| **Total**       | **53** | **53** |   **0** |        **0** |

All 53 PDU checks are covered. P1 check 0 and P4 check 21 run through
`rezzy_integration::authorize_pdu`, which validates `auth_events` citations
against the state-before, applies v12 base auth where it applies, and then the
Cygnus overlay. G7 seal authorization (31–34) runs through
`auth::authorize_seal`, and the merge checks (29–30) are driven from the P1
PDUs in `p1_g7_fixtures`. The causal filtering predicates remain covered
separately.

The regenerated PDU fixtures now omit `m.room.create` from `auth_events`, as
required by room v12. The proposal model and vector source should stay in sync
with the vendored files; otherwise event IDs, hashes and the derived room ID
drift.

## Rezzy integration

`rezzy_integration` maps Cygnus PDUs to Rezzy's generic event model and runs
base v12 authorization under the optional `state-res` feature. Rezzy registers
`tk.nutra.cygnus.12` as a v12-derived version (`V2_1`), accepts principal
senders, and permits `m.room.user_epoch`, `m.room.server_epoch`,
`m.room.server_seal`, and `m.room.server_acl` in `auth_events`. Epoch and seal
events are skipped by base auth because §5.3/§5.6 fully define their sender,
admission, signature, and chain rules; `src/auth.rs` owns those checks. All
other events run base auth and then the Cygnus overlay. Cygnus event hashing
and signatures stay in `envelope.rs`; Rezzy's redaction table is not used for
Cygnus event IDs.

Limits of the overlay, which callers must account for:

- Prefer `authorize_pdu`: it validates citations, routes with
  `base_auth_applies`, runs base auth where it applies, and then the matching
  Cygnus check (create, active or burned epoch, seal, or user event). It does
  not update state; the caller applies an accepted event to both the
  `RoomAuthState` and the `AuthContext`.
- Callers that route by hand must pair them correctly. Seal events skip base
  auth only because `auth::authorize_seal` replaces it; epoch events are
  checked by `authorize_active_epoch`/`authorize_burn`, and the
  `*_with_citations` wrappers validate the event's cited auth state first. A
  caller that skips base auth without running the corresponding Cygnus check
  has no authorization at all.
- The raw overlay functions do not validate `auth_events` citations. Callers
  must use `authorize_pdu` or the `*_with_citations` wrappers (or perform the same state-before
  validation themselves). `validate_auth_event_citations` rejects stale,
  missing, duplicate, and non-state citations. The caller still selects the
  complete required auth-event set under room v12 and §5.1.
- `AuthContext` trusts the `VerifiedEpoch` values placed in it. Its epoch maps
  are private: `insert_epoch` files each epoch under its own principal, and a
  `VerifiedEpoch` can only come from the verification functions (or
  `from_parts_unchecked` behind `test-support`). Membership, creators, join
  rule and ACL are still caller-selected state.

G3–G7 in `known_gaps` are SPEC and intentionally not implemented.
