# DMLS wasm API — draft for review

Status: **draft, nothing implemented.** Names and shapes below are what Hydrogen
may wire the capability gate and event routing against. All exports are new and
additive; no existing `cygnus-wasm` signature changes. Spec: MSC00FD.

Conventions (same as the existing exports): strings in, strings out; bytes are
unpadded base64url; JSON is canonical text from `content.rs`; Hydrogen sends
`content` verbatim and never re-serializes. Failures that are _errors_ throw a
JS `Error` whose message starts with a stable code (`code: detail`). Normal
protocol outcomes are returned as a `status`, not thrown.

## 0. Design correction: state is per extremity, not per group

MSC00FD §9.1 requires one MLS state **per extremity** (a fork has several tips).
So the registry key is `group_id`, but each entry holds
`branches: { commit_id -> MlsGroup state }` plus the `Branch`/extremity set.
Consequences:

- `dmlsApplyCommit` never mutates the base state. It loads the base branch,
  applies into a **copy**, and only on success inserts the new branch and
  updates the extremity set (`(extremities - resolves) ∪ {new}`, idempotent).
  `deferred`/`orphaned`/`rejected` therefore leave all state untouched by
  construction. An error mid-apply drops the copy.
- Encrypt/decrypt name a branch (`atCommitId`), defaulting to the sole tip. With
  several tips, `dmlsEncrypt` without `atCommitId` throws `fork_unresolved`.
- `dmlsDecrypt` selects the branch by the ciphertext's `mls_epoch` among held
  branches; none held ⇒ status `missing_state` (buffer per §13.4).

## 1. Lifecycle and ownership

- The registry lives in wasm memory, keyed by `group_id` (base64url, 32 bytes).
  The signing seed is **not** held by the registry; see §3.
- **Startup: lazy.** Hydrogen calls `dmlsImportGroup` the first time a room's
  DMLS event or send is touched, not for every room. Rooms without the
  capability are never imported. `dmlsHasGroup(groupId)` tells it what is loaded.
- `dmlsForget(groupId)` drops the entry from wasm memory only. It does not touch
  the persisted blob; it is for room close/memory pressure. Leaving a room and
  deleting its blob is Hydrogen's job (and it should wipe the blob).
- **Two tabs.** MLS state is single-writer: a second writer forks the ratchet.
  Hydrogen must hold `navigator.locks` (`cygnus-dmls:<group_id>`) around
  import→mutate→export, and the blob carries a monotonic `seq`. Persist with
  compare-and-set on `seq` in IndexedDB; on conflict, discard the in-memory
  entry (`dmlsForget`), re-import, and retry the event. Wasm itself is per-tab
  and cannot enforce this.

## 2. Function table

H = handshake (returns `{eventType, content}` ready to send), A = application,
S = state/utility. "Mutates" means the registry entry changes; Hydrogen must
re-export after any mutating call.

| JS name              | Args                                                                       | Returns                                                            | Mutates                | Kind |
| -------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------ | ---------------------- | ---- |
| `dmlsKeyPackage`     | `identityJson, deviceSeedB64, roomId`                                      | `{eventType, content, keyPackageId, secretsB64}`                   | no (see §4)            | H    |
| `dmlsCreateGroup`    | `identityJson, deviceSeedB64, roomId, nonceB64`                            | `{groupId, eventType, content, stateB64}`                          | new entry              | H    |
| `dmlsCommit`         | `groupId, deviceSeedB64, opsJson, atCommitId?`                             | `{eventType, content, welcomes: [{toDevice, eventType, content}]}` | adds branch            | H    |
| `dmlsPlanMerge`      | `groupId, requestedJson`                                                   | `{status, plan?}` (see §5)                                         | no                     | S    |
| `dmlsMerge`          | `groupId, deviceSeedB64, requestedJson`                                    | `{eventType, content, welcomes}`                                   | adds branch            | H    |
| `dmlsExternalCommit` | `identityJson, deviceSeedB64, groupInfoContentJson`                        | `{groupId, eventType, content}`                                    | new entry/branch       | H    |
| `dmlsApplyCommit`    | `groupId, eventType, contentJson, ctxJson`                                 | `{status, reason?, commitId?, epoch?, members?}`                   | on `applied` only      | S    |
| `dmlsJoinWelcome`    | `identityJson, deviceSeedB64, roomId, welcomeContentJson, secretsB64?`     | `{status, groupId?, epoch?, members?}`                             | new entry on `applied` | S    |
| `dmlsReboot`         | `groupId, deviceSeedB64, reason, membersJson, baseEventId`                 | `{newGroupId, eventType, content, welcomes}`                       | new entry              | H    |
| `dmlsEncrypt`        | `groupId, deviceSeedB64, roomId, innerType, innerContentJson, atCommitId?` | `{eventType, content}`                                             | ratchet                | A    |
| `dmlsDecrypt`        | `groupId, contentJson, roomId`                                             | `{status, innerType?, innerContentJson?, senderMember?, epoch?}`   | ratchet on `ok`        | A    |
| `dmlsExportGroup`    | `groupId`                                                                  | `stateB64`                                                         | no                     | S    |
| `dmlsImportGroup`    | `stateB64`                                                                 | `{groupId, seq, extremities}`                                      | new/replace entry      | S    |
| `dmlsHasGroup`       | `groupId`                                                                  | `bool`                                                             | no                     | S    |
| `dmlsForget`         | `groupId`                                                                  | `void`                                                             | drops entry            | S    |

Notes:

- `ctxJson` for `dmlsApplyCommit` is caller-supplied room context Hydrogen has
  and wasm cannot: `{"roomId", "senderMember", "ancestors": [event_id...]}` —
  the DAG ancestry check (§9.2 step 4) and the sender's auth are Hydrogen's.
  Wasm checks that every `base`/`resolves` event_id is in `ancestors`.
- `dmlsApplyCommit.status`:
    - `applied` — new branch stored, extremities updated.
    - `deferred` — a `base`/`resolves` state is not held, or a referenced event is
      not in `ancestors` (normal, §9.2 step 3). `reason`: `missing_base_state`,
      `missing_branch`, `unheld_ancestor`. Retry after more events arrive.
    - `orphaned` — external-commit whose joiner is excluded by every held tip
      (§9.4 ORPHANED); caller re-issues via `dmlsExternalCommit`.
    - `rejected` — permanently invalid (bad `commit_id`, wrong `mls_epoch`, MLS
      verification failure, plan mismatch). `reason` carries the error code below.
      Never retried.
- `dmlsDecrypt.status`: `ok`, `missing_state` (epoch not held; buffer),
  `rejected` (bad MLS message, inactive leaf, `room_id` mismatch).
- `dmlsJoinWelcome.status`: `applied`, `wrong_key_package` (no retained secret
  decrypts it — the §6 rule 5 race loser; re-add needed), `rejected`.
- `deviceSeedB64` is an argument, not retained (see §3).
- `dmlsEncrypt` `innerType`/`innerContentJson` are wrapped with `room_id` into
  the §13 plaintext inside wasm; Hydrogen does not build it.

### Error codes (thrown, `code: detail`)

`bad_argument`, `bad_state` (blob unparsable), `unsupported_version`,
`unknown_group`, `fork_unresolved`, `content_too_large` (>60 000 B),
`mismatch` (+`:field`), `malformed` (+`:field`), `missing` (+`:field`),
`stale_epoch`, `not_a_member`, `crypto` (MLS/OpenMLS failure), `internal`.
`dmlsApplyCommit`/`dmlsDecrypt`/`dmlsJoinWelcome` map these into
`status: rejected` + `reason` instead of throwing; they throw only for
`bad_argument`, `bad_state`, `unknown_group`, `internal`.

## 3. Persisted state blob

`dmlsExportGroup` returns base64url of a versioned binary container:

```text
magic "CYDM" | version u16 | seq u64 | group_id 32 | body | blake3(all preceding) 32
```

`body` holds:

- `branches`: for each held extremity, `commit_id` and the serialized
  `MlsGroup` plus its OpenMLS storage entries (epoch secrets, ratchet tree,
  own leaf private keys, encryption key pairs).
- `extremities` and the `Branch` values (`members`, retained removals,
  external joiners, `resolves`) from `merge.rs`.
- `own_member` (`principal:device`).
- **Unredeemed KeyPackage secrets** are _not_ here; they are per-device, not
  per-group (§4).

**The device signing key is not in the group blob.** Group blobs contain the
MLS _public_ signature key only; Hydrogen already stores the device seed and
passes it on each call (`deviceSeedB64`). Wasm never persists it. The blob still
contains **MLS epoch secrets and leaf HPKE private keys, so it is secret
material**: Hydrogen must encrypt it with its existing secret storage before
IndexedDB, and must not log it.

Integrity/atomicity: the trailing BLAKE3 detects truncation/partial writes;
`dmlsImportGroup` throws `bad_state` on mismatch and never installs a partial
entry. `dmlsImportGroup` replaces atomically (build new entry, then swap).
`dmlsExportGroup` is a snapshot of one consistent entry. Persist
export-after-every-mutation in one IndexedDB transaction with the `seq`
compare-and-set from §1. Old `version`s are migrated on import or rejected with
`unsupported_version`; exporting always writes the current version.

## 4. Key packages

- Per device, not per group; one **device key-package store**, blob-persisted
  separately: `dmlsKeyPackage` returns `secretsB64` (the init private key and
  KeyPackage private material, keyed by `key_package_id`). Hydrogen stores
  `{keyPackageId -> secretsB64}`, encrypted, and keeps the pool (target 3
  unexpired per §6 rule 6; replace after an Add is accepted). The `m.dmls.key_package`
  event is the returned `{eventType, content}`.
- `dmlsJoinWelcome` takes the `secretsB64` for the Welcome's `key_package_id`
  (parsed from the Welcome content by `WelcomeContent`, which names it).
  Hydrogen looks it up by that id; if absent ⇒ `wrong_key_package`. On
  `applied`, Hydrogen deletes that secret (single-use, §6 rule 5).
- **Open point:** OpenMLS can look up the init key itself if its storage is
  imported wholesale. Passing explicit `secretsB64` keeps the contract
  stateless; it costs Hydrogen a small store. Flag if you prefer a wasm-held
  device store.

## 5. Merge planning

`dmlsPlanMerge` runs `merge.rs` in wasm (not reimplemented in Hydrogen).
Input `requestedJson`: `{"requested": [commit_id_b64...]}` — branch extremity
ids; Hydrogen supplies no membership. Wasm derives `Branch` values from the held
branches. Leaf signature checks use the held `LeafNode`s via the verify callback.
Device-root identity needs the `DeviceRootRegistry`, which Hydrogen holds from
00FC chains; passed as `registryJson` (`{principal: {device_id: root_key}}`).
That adds one arg: `dmlsPlanMerge(groupId, requestedJson, registryJson)`.

Output: `{status: "planned" | "deferred", plan?: PlanSummary, reason?}`.
`deferred` + `missing_base_state` when a requested extremity is not held
(`MergeError::MissingBaseState`); a bad plan is `rejected`. `dmlsMerge` plans,
then builds the MLS Commit and returns the `m.dmls.merge` content
(`resolves = requested`, `base = plan.base`, `plan` embedded). `required_self_updates`
are reported in the plan; each named member later calls `dmlsCommit` with a
self-update op. It never fabricates an `UpdateOther`.

## 6. Implementation prerequisites (native, in `cygnus-dmls`, before any export)

1. Verify OpenMLS 0.8.3 storage can be snapshotted/restored (the default
   `openmls_memory_storage` is an in-memory map; may need a snapshot wrapper).
2. `DmlsClient` becomes multi-group and multi-branch; `receive`/`add_member`
   keep working.
3. New methods behind each export above, each native-tested, including: failed
   apply leaves state byte-identical (export-before == export-after).
4. A conformance vector for the blob format.

Landing order: 1→2→3, then wasm exports + `make install`, announced to Hydrogen
with the final `.d.ts` diff.

## Open questions for review

1. Per-extremity branch storage (§0) vs. "one state per group": agree?
2. Lazy import + `navigator.locks` (§1): acceptable for Hydrogen?
3. Explicit `secretsB64` key-package store in Hydrogen (§4) vs. wasm-held store.
4. `registryJson` passed per `dmlsPlanMerge` call (§5), or hold the registry in wasm?
5. Should `deviceSeedB64` be passed per call (current draft) or set once with a
   `dmlsUnlock(seed)` registry-scoped call?
