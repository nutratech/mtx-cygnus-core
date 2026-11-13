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
- `dmlsDecrypt` selects branches by the ciphertext's `mls_epoch`. Sibling tips can
  share an epoch, so it tries each held branch at that epoch (only the right
  epoch secrets succeed) and persists the one that decrypts; none held ⇒ status `missing_state` (buffer per §13.4).

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
- **Lock scope.** The lock covers the whole read → import → mutate → export →
  CAS-write transaction, not just the wasm call. Publish to Matrix only **after**
  the CAS write succeeds, so a crash never sends a Commit whose state was not
  persisted. `dmlsDecrypt` mutates too (it advances the secret tree), so it runs
  under the lock and is persisted. If `navigator.locks` is unavailable, claim a
  single-writer tab via `BroadcastChannel`/`localStorage`, or refuse DMLS sends in
  secondary tabs.
- **Extremity cap.** Wasm holds at most `MAX_HELD_EXTREMITIES = 8` branches per
  group. The cap is checked on the **post-update** set
  `next = (held − resolves) ∪ {new}`; only `next.len() > 8` is refused, so a
  merge that resolves six tips and adds one is accepted at eight. Past the cap,
  `dmlsApplyCommit` returns `deferred` with reason `extremity_cap` and **no
  state change**. Hydrogen's first response is `dmlsPlanMerge` on the held tips
  (that usually lowers the count); only if no held subset can make progress does
  it enter the §11 reboot path. No tip is ever silently evicted. Apply and
  import results carry the current `extremityCount` so Hydrogen sees pressure
  coming.
- **Tips vs held states.** A commit's `resolves` includes its `base`, so applying
  it retires the base as a _tip_ but the base _state_ stays held; otherwise a
  concurrent sibling commit on the same base could never apply. Held states
  are bounded by `MAX_RETAINED_STATES = 16` (oldest epoch evicted first, commit id
  breaking ties; tips never). This is a bounded cache, not a guarantee for
  arbitrarily late backfill. A sibling whose base was evicted returns `deferred`
  `missing_base_state`. The cap of 8 counts tips only.
- **`seq`.** Every mutating call increments the entry's `seq` (create, join,
  apply, commit, merge, encrypt, **decrypt**). `dmlsExportGroup` serializes the
  current value without changing it; Hydrogen's CAS expects the stored `seq` to
  be exactly the pre-call value, writing the post-call one.
- **Import over a loaded entry.** If the group is loaded and the blob's `seq` is
  lower than the loaded one, `dmlsImportGroup` throws `stale_state` instead of
  replacing it, so a lock bug is a visible error and not a ratchet fork. An equal
  `seq` is idempotent only if the blob is byte-identical to the loaded export;
  a different blob at the same `seq` is two writers diverging and also throws
  `stale_state`.

## 2. Function table

H = handshake (returns `{eventType, content}` ready to send), A = application,
S = state/utility. "Mutates" means the registry entry changes; Hydrogen must
re-export after any mutating call.

| JS name              | Args                                                                       | Returns                                                                        | Mutates                | Kind |
| -------------------- | -------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ---------------------- | ---- |
| `dmlsKeyPackage`     | `identityJson, deviceSeedB64`                                              | `{eventType, content, keyPackageId, secretsB64}`                               | no (see §4)            | H    |
| `dmlsCreateGroup`    | `identityJson, deviceSeedB64, roomId`                                      | `{groupId, commitId, epoch, members, stateB64}` (nothing to publish, see §2.1) | new entry              | H    |
| `dmlsCommit`         | `groupId, deviceSeedB64, opsJson, atCommitId?`                             | `{eventType, content, welcomes: [{toDevice, eventType, content}]}`             | adds branch            | H    |
| `dmlsPlanMerge`      | `groupId, requestedJson, registryJson`                                     | `{status, plan?}` (see §5)                                                     | no                     | S    |
| `dmlsMerge`          | `groupId, deviceSeedB64, requestedJson, registryJson`                      | `{eventType, content, welcomes}`                                               | adds branch            | H    |
| `dmlsExternalCommit` | `identityJson, deviceSeedB64, roomId, groupInfoContentJson`                | `{groupId, eventType, content}` (checked against `wire::group_id(roomId)`)     | new entry/branch       | H    |
| `dmlsApplyCommit`    | `groupId, eventType, contentJson, ctxJson`                                 | `{status, reason?, commitId?, epoch?, members?}`                               | on `applied` only      | S    |
| `dmlsJoinWelcome`    | `identityJson, deviceSeedB64, roomId, welcomeContentJson, secretsB64?`     | `{status, groupId?, epoch?, members?}`                                         | new entry on `applied` | S    |
| `dmlsReboot`         | `groupId, deviceSeedB64, reason, membersJson, baseEventId`                 | `{newGroupId, eventType, content, welcomes}`                                   | new entry              | H    |
| `dmlsEncrypt`        | `groupId, deviceSeedB64, roomId, innerType, innerContentJson, atCommitId?` | `{eventType, content}`                                                         | ratchet                | A    |
| `dmlsDecrypt`        | `groupId, contentJson, roomId`                                             | `{status, innerType?, innerContentJson?, senderMember?, epoch?}`               | ratchet on `ok`        | A    |
| `dmlsExportGroup`    | `groupId`                                                                  | `stateB64`                                                                     | no                     | S    |
| `dmlsImportGroup`    | `stateB64`                                                                 | `{groupId, seq, extremities, extremityCount}`                                  | new/replace entry      | S    |
| `dmlsHasGroup`       | `groupId`                                                                  | `bool`                                                                         | no                     | S    |
| `dmlsForget`         | `groupId`                                                                  | `void`                                                                         | drops entry            | S    |

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

### 2.1 Creation and the genesis base

`dmlsCreateGroup` **publishes nothing**. It builds the epoch-0 `MlsGroup` for
`wire::group_id(roomId)` and installs it locally as the group's genesis
extremity:

```text
commit_id = BLAKE3("cygnus-dmls-genesis-v1\0" ‖ group_id)
extremity = (mls_epoch 0, commit_id)
```

This synthetic id is derivable from the room, so the first published event is
the epoch-1 Commit (`dmlsCommit`) whose `base`, and sole `resolves` entry, is
that genesis reference **with no `event_id`**. `CommitContent` is unchanged in
shape; the only rule is that a reference may omit its DAG hint when it names
the group's genesis, and `dmlsApplyCommit` accepts that base only from the
state this client created. Every other reference still requires an `event_id`
and an `ancestors` match.

Consequences:

- A creator that loses its local state before adding anyone simply creates the
  group again; the genesis id is deterministic and no peer holds epoch 0.
- The genesis state is retained as a non-tip state after the first Commit, so
  two epoch-1 Commits from the same creator (Add Bob, Add Carol) both apply and
  can be merged.
- No `m.dmls.commit` with `mls_epoch: 0` exists, so there is no ingest path
  that initialises a group from an unauthenticated epoch-0 event.

### Error codes (thrown, `code: detail`)

`bad_argument`, `bad_state` (blob unparsable), `stale_state` (import older than
loaded), `unsupported_version`,
`unknown_group`, `fork_unresolved`, `content_too_large` (>60 000 B),
`mismatch` (+`:field`), `malformed` (+`:field`), `missing` (+`:field`),
`stale_epoch`, `not_a_member`, `crypto` (MLS/OpenMLS failure), `internal`.
`dmlsApplyCommit`/`dmlsDecrypt`/`dmlsJoinWelcome` map these into
`status: rejected` + `reason` instead of throwing; they throw only for
`bad_argument`, `bad_state`, `unknown_group`, `internal`.

## 3. Persisted state blob

**Storage mechanism (verified by `cygnus-dmls/tests/storage_snapshot.rs`).**
`openmls_memory_storage::MemoryStorage::values` is a public
`RwLock<HashMap<Vec<u8>, Vec<u8>>>`; its `serialize`/`deserialize` are
`test-utils` KAT helpers and are **not** used. Each held extremity owns one
`OpenMlsRustCrypto`; a snapshot is our own versioned, length-prefixed encoding
of its `values`, restored by extending a fresh provider's map. The spike
restores a group this way and encrypts from it.
**`SignatureKeyPair::store` is never called**: operations take `&SignatureKeyPair`
built from the per-call seed, so the seed never enters `values`. A test asserts
the seed bytes do not appear in any exported blob. (`DmlsClient::new` no longer calls `store`; the engine `Signer` is built per call.)

`dmlsExportGroup` returns base64url of a versioned binary container:

```text
magic "CYDM" | version u16 | seq u64 | group_id 32 | body | blake3(all preceding) 32
```

`body` holds:

- `branches`: for each held extremity, `commit_id` and the serialized
  `MlsGroup` plus its OpenMLS storage entries (epoch secrets, ratchet tree,
  own leaf private keys, encryption key pairs).
- per branch: a tip flag, its `resolves` list (`mls_epoch`, `commit_id`), and
  `meta`, the parts of a merge `Branch` that an `MlsGroup` cannot give back:
  `parent_transcript_hash`, retained `removed` leaves, and `external_joiners`.
  `members` is **derived from the held group at plan time** and checked against
  `meta`, so it cannot drift. Blob **version 2** (nothing shipped as v1).
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

Key-package secrets live **in Hydrogen**, not wasm; wasm stays group-scoped.

- `dmlsKeyPackage` returns `secretsB64` (init/leaf private material) and
  `keyPackageId`. Hydrogen persists `{keyPackageId -> secretsB64}`, encrypted with
  the same mechanism as the group blob, never logged. **Write-ahead:** persist
  before publishing the `m.dmls.key_package` event, so a Welcome can never arrive
  for a secret that was not stored. Pool target: 3 unexpired (§6 rule 6).
- `dmlsJoinWelcome` takes the `secretsB64` for the `key_package_id` parsed from
  the Welcome content. Hydrogen looks it up by that id and does **not**
  trial-decrypt the pool. Absent or non-matching id → `wrong_key_package`.
- Delete the secret only after a successful join, or on expiry.

## 5. Merge planning

`dmlsPlanMerge` runs `merge.rs` in wasm (not reimplemented in Hydrogen).
Input `requestedJson`: `{"requested": [commit_id_b64...]}` — branch extremity
ids; Hydrogen supplies no membership. Wasm derives `Branch` values from the held
branches. Leaf signature checks use the held `LeafNode`s via the verify callback.
Device-root identity needs the `DeviceRootRegistry`, which Hydrogen holds from
00FC chains; passed as `registryJson` (`{principal: {device_id: root_key}}`).
That adds one arg to both `dmlsPlanMerge` and `dmlsMerge` (which plans
internally). It is passed **per call**, never cached: a stale registry is a
security bug. It is scoped to the room's members, derived from the **auth
events of the requested branches** (not current room state), and rejected over
a size cap (`bad_argument`).

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

## Resolved in review (6c576c9)

Per-extremity state; lazy import under Web Locks (scope above); key-package
secrets in Hydrogen; `registryJson` per call; seed per call (no `dmlsUnlock`).
`dmlsCreateGroup` has no nonce, and `dmlsKeyPackage` takes no `roomId`.
