# DMLS wasm API — draft for review

Status: **native and wasm implementations complete; Hydrogen integration
pending.** The native `cygnus-dmls` crate implements the group lifecycle, branch
persistence, commit operations, merge planning, merge Commit construction,
external joins, and reboot. `cygnus-wasm` exports the table below. All exports
are new and additive; no existing `cygnus-wasm` signature changes. Spec:
MSC00FD.

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
- `dmlsDecrypt` selects branches by the ciphertext's `mls_epoch`. Sibling tips
  can share an epoch, so it tries each held branch at that epoch (only the right
  epoch secrets succeed) and persists the one that decrypts; none held ⇒ status
  `missing_state` (buffer per §13.4).

## 1. Lifecycle and ownership

- The registry lives in wasm memory, keyed by `group_id` (base64url, 32 bytes).
  The signing seed is **not** held by the registry; see §3.
- **Startup: lazy.** Hydrogen calls `dmlsImportGroup` the first time a room's
  DMLS event or send is touched, not for every room. Rooms without the
  capability are never imported. `dmlsHasGroup(groupId)` tells it what is
  loaded.
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
  CAS-write transaction, not just the wasm call. Publish to Matrix only
  **after** the CAS write succeeds, so a crash never sends a Commit whose state
  was not persisted. `dmlsDecrypt` mutates too (it advances the secret tree), so
  it runs under the lock and is persisted. If `navigator.locks` is unavailable,
  claim a single-writer tab via `BroadcastChannel`/`localStorage`, or refuse
  DMLS sends in secondary tabs.
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
- **Tips vs held states.** A commit's `resolves` includes its `base`, so
  applying it retires the base as a _tip_ but the base _state_ stays held;
  otherwise a concurrent sibling commit on the same base could never apply. Held
  states are bounded by `MAX_RETAINED_STATES = 16` (oldest epoch evicted first,
  commit id breaking ties; tips never). This is a bounded cache, not a guarantee
  for arbitrarily late backfill. A sibling whose base was evicted returns
  `deferred` `missing_base_state`. The cap of 8 counts tips only.
- **`seq`.** Every mutating call increments the entry's `seq` (create, join,
  apply, commit, merge, encrypt, **decrypt**). `dmlsExportGroup` serializes the
  current value without changing it; Hydrogen's CAS expects the stored `seq` to
  be exactly the pre-call value, writing the post-call one.
- **Import over a loaded entry.** If the group is loaded and the blob's `seq` is
  lower than the loaded one, `dmlsImportGroup` throws `stale_state` instead of
  replacing it, so a lock bug is a visible error and not a ratchet fork. An
  equal `seq` is idempotent only if the blob is byte-identical to the loaded
  export; a different blob at the same `seq` is two writers diverging and also
  throws `stale_state`.

## 2. Function table

H = handshake (returns `{eventType, content}` ready to send), A = application, S
= state/utility. "Mutates" means the registry entry changes; Hydrogen must
re-export after any mutating call.

| JS name              | Args                                                                       | Returns                                                                                  | Mutates                | Kind |
| -------------------- | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- | ---------------------- | ---- |
| `dmlsKeyPackage`     | `identityJson, deviceSeedB64`                                              | `{eventType, content, keyPackageId, secretsB64}`                                         | no (see §4)            | H    |
| `dmlsCreateGroup`    | `identityJson, deviceSeedB64, roomId`                                      | `{groupId, commitId, epoch, members, stateB64}` (nothing to publish, see §2.1)           | new entry              | H    |
| `dmlsCommit`         | `groupId, deviceSeedB64, opsJson, baseJson?`                               | `{eventType, content, groupId, commitId, epoch, members, welcome, recipients}` | adds branch            | H    |
| `dmlsWelcomeContent` | `groupId, commitEventId, commitId, keyPackageId, welcomeB64`               | `{eventType, content}`                                                                   | no                     | H    |
| `dmlsPlanMerge`      | `groupId, requestedJson, registryJson`                                     | `{status, plan?}` (see §5)                                                               | no                     | S    |
| `dmlsMerge`          | `groupId, deviceSeedB64, requestedJson, registryJson`                      | `{status, eventType?, content?, commitId?, epoch?, members?, reason?}`                   | adds branch            | H    |
| `dmlsExternalCommit` | `identityJson, deviceSeedB64, roomId, targetJson, sourceContentJson`       | `{eventType, content, groupId, commitId, epoch, members}`                                | new entry/branch       | H    |
| `dmlsApplyCommit`    | `groupId, eventType, contentJson, ctxJson, registryJson?`                  | `{status, reason?, groupId?, commitId?, epoch?, members?, extremityCount}`               | on `applied` only      | S    |
| `dmlsCheckReboot`    | `groupId, contentJson, ctxJson`                                            | `{status, newGroupId?, members?, reason?}`                                               | no                     | S    |
| `dmlsJoinWelcome`    | `identityJson, deviceSeedB64, welcomeContentJson, secretsB64?`             | `{status, reason?, groupId?, commitId?, epoch?, members?}`                               | new entry on `applied` | S    |
| `dmlsReboot`         | `groupId, deviceSeedB64, reason, keyPackagesJson, baseJson`                | `{newGroupId, rebootContent, commitContent, commitId, welcome, recipients}`              | new entry              | H    |
| `dmlsEncrypt`        | `groupId, deviceSeedB64, roomId, innerType, innerContentJson, atCommitId?` | `{eventType, content}`                                                                   | ratchet                | A    |
| `dmlsDecrypt`        | `groupId, contentJson, roomId`                                             | `{status, innerType?, innerContentJson?, senderMember?, epoch?, commitId?}`              | ratchet on `ok`        | A    |
| `dmlsExportGroup`    | `groupId`                                                                  | `stateB64`                                                                               | no                     | S    |
| `dmlsImportGroup`    | `stateB64`                                                                 | `{groupId, seq, extremities, extremityCount}`                                            | new/replace entry      | S    |
| `dmlsHasGroup`       | `groupId`                                                                  | `bool`                                                                                   | no                     | S    |
| `dmlsForget`         | `groupId`                                                                  | `void`                                                                                   | drops entry            | S    |

Notes:

- `identityJson` is `{"principal": "@...", "deviceId": "D1"}`. It is needed
  only when the device is not yet represented by a held state (key package,
  create, external join, welcome). Calls on a loaded group read the caller's
  identity back from the group's own leaf, so they take only `deviceSeedB64`.
- `opsJson` for `dmlsCommit` is exactly one operation:
  `{"op":"add","keyPackage":"<b64url>"}`,
  `{"op":"remove","member":"<principal:device>"}`, or `{"op":"self_update"}`.
  One Commit carries one operation; `dmlsMerge` is the only multi-extremity
  path.
- `baseJson` for `dmlsCommit` is the held base extremity
  (`{mls_epoch, commit_id, event_id}`). Omit it to commit on the genesis state,
  whose reference has no `event_id` (§2.1). A later base without an event id is
  `bad_argument`.
- `ctxJson` for `dmlsApplyCommit` is caller-supplied context Hydrogen has and
  wasm cannot:
  `{"senderMember": "<principal:device>", "ancestors": [event_id...]}`. The DAG
  ancestry check (§9.2 step 4) and the sender's auth are Hydrogen's; wasm checks
  that every `base`/`resolves` event id is in `ancestors`. `roomId` may be
  present and is ignored: a reboot group's id is not room-derived.
- `registryJson` is **required** when `eventType` is `m.dmls.merge` and ignored
  otherwise. This is the same per-call registry used by `dmlsPlanMerge`; the
  merge apply path is exactly the plan-verifying one (`apply_merge` natively).
  Omitting it for a merge is `bad_argument` (`registry_required`), never an
  unchecked apply. Plain commits and external commits do not need it.
- `dmlsApplyCommit` routes by `eventType`: `m.dmls.commit` uses the plain apply
  path, `m.dmls.merge` uses the plan-verifying path with `registryJson`, and
  `m.dmls.external_commit` uses the external-commit apply path (no
  `registryJson`). The external-commit path checks the target is an ancestor,
  the sender is the joiner, the resulting epoch is `target + 1`, the Commit
  carries no Add/Update/Remove proposal, the joiner holds no leaf in the target
  state, exactly one leaf for the joiner is added, and `group_info` is the
  joiner's signed GroupInfo for the resulting state.
- `targetJson` for `dmlsExternalCommit` is the target extremity
  (`{mls_epoch, commit_id, event_id}`). `sourceContentJson` is the content of
  the event that produced it. Wasm checks that the source's derived
  `mls_epoch`/`commit_id` match the target and takes `group_info` from it; the
  group is `wire::group_id(roomId)`.
- `dmlsWelcomeContent` builds `m.dmls.welcome` once the Commit's room event id
  is known. `dmlsCommit` and `dmlsReboot` return raw `welcome` because they run
  before the Commit is published. Their `recipients` are
  `[{toDevice:{principal,deviceId}, keyPackageId}]`: one to-device event per
  recipient, all carrying the same Welcome bytes.
- `requestedJson` for `dmlsPlanMerge`/`dmlsMerge` is an array of
  `{"commit_id":"<b64url32>","event_id":"$..."}`. The epoch is read from the
  held state, not supplied. Any unheld `commit_id` defers with
  `missing_base_state`.
- `dmlsReboot` lists members to carry over as `keyPackagesJson`, an array of
  base64url serialized KeyPackages. `baseJson` is the held old-group extremity
  (`{mls_epoch, commit_id, event_id}`). Native `reboot` derives each member from
  its KeyPackage and refuses anyone outside `base`, a repeat, or the caller. The
  replacement group id is derived from the old group and the base commit, so it
  is **not** `wire::group_id(roomId)`.
- `dmlsApplyCommit.status`:
    - `applied` — new branch stored, extremities updated.
    - `deferred` — a `base`/`resolves` state is not held, or a referenced event
      is not in `ancestors` (normal, §9.2 step 3). `reason`:
      `missing_base_state`, `missing_branch`, `unheld_ancestor`,
      `extremity_cap`. Retry after more events arrive.
    - `rejected` — permanently invalid (bad `commit_id`, wrong `mls_epoch`, MLS
      verification failure, plan mismatch, external-commit rule violation).
      `reason` carries the error code below. Never retried. For `m.dmls.merge`,
      `mismatch:plan` means the recomputed base, plan summary or merged member
      set disagrees with the event; `uncertified_device` means the registry
      cannot certify a leaf.
- `dmlsPlanMerge` plan fields are `base` (`{mls_epoch, commit_id}`), `adds`,
  `removes`, `requiredSelfUpdates`, and `orphanedExternalJoiners`; member lists
  are `<principal:device>` strings.
- `dmlsCheckReboot` authorizes a received `m.dmls.reboot` without mutating
  state. `accepted` returns the derived `newGroupId` and the listed `members`;
  it defers with `missing_base_state` when the named base is not held (the
  rebooting member is exactly the one who may lack it). The caller then treats
  the replacement group's first Commit as a new group.
- `dmlsDecrypt.status`: `ok`, `missing_state` (epoch not held; buffer),
  `rejected` (bad MLS message, inactive leaf, `room_id` mismatch). A wrong room
  still advances that branch's ratchet because the MLS message was valid, so
  persist the export even on this rejection.
- `dmlsJoinWelcome.status`: `applied`, `wrong_key_package` (the supplied secret
  does not redeem the Welcome — the §6 rule 5 race loser; re-add needed), or
  `rejected` for a malformed or foreign Welcome. The group id comes from the
  Welcome content, so a reboot replacement group joins the same way as a
  room-derived one.
- `deviceSeedB64` is an argument, not retained (see §3).
- `dmlsEncrypt` `innerType`/`innerContentJson` are wrapped with `room_id` into
  the §13 plaintext inside wasm; Hydrogen does not build it. `room_id` is the
  room id, which is not required to hash to `groupId` for a reboot group.

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
shape; the only rule is that a reference may omit its DAG hint when it names the
group's genesis, and `dmlsApplyCommit` accepts that base only from the state
this client created. Every other reference still requires an `event_id` and an
`ancestors` match.

Consequences:

- A creator that loses its local state before adding anyone simply creates the
  group again; the genesis id is deterministic and no peer holds epoch 0.
- The genesis state is retained as a non-tip state after the first Commit, so
  two epoch-1 Commits from the same creator (Add Bob, Add Carol) both apply and
  can be merged.
- No `m.dmls.commit` with `mls_epoch: 0` exists, so there is no ingest path that
  initialises a group from an unauthenticated epoch-0 event.

### Error codes (thrown, `code: detail`)

`bad_argument`, `bad_state` (blob unparsable), `stale_state` (import older than
loaded), `unsupported_version`, `unknown_group`, `fork_unresolved`,
`content_too_large` (>60 000 B), `mismatch` (+`:field`), `malformed`
(+`:field`), `missing` (+`:field`), `stale_epoch`, `not_a_member`, `crypto`
(MLS/OpenMLS failure), `internal`.
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
restores a group this way and encrypts from it. **`SignatureKeyPair::store` is
never called**: operations take `&SignatureKeyPair` built from the per-call
seed, so the seed never enters `values`. A test asserts the seed bytes do not
appear in any exported blob. (`DmlsClient::new` no longer calls `store`; the
engine `Signer` is built per call.)

`dmlsExportGroup` returns base64url of a versioned binary container:

```text
magic "CYDM" | version u16 | seq u64 | group_id 32 | body | blake3(all preceding) 32
```

`body` holds:

- `branches`: for each held extremity, `commit_id` and the serialized `MlsGroup`
  plus its OpenMLS storage entries (epoch secrets, ratchet tree, own leaf
  private keys, encryption key pairs).
- per branch: a tip flag, its `resolves` list (`mls_epoch`, `commit_id`), and
  `meta`, the parts of a merge `Branch` that an `MlsGroup` cannot give back:
  `parent_transcript_hash`, retained `removed` leaves, and `external_joiners`.
  `members` is **derived from the held group at plan time** and checked against
  `meta`, so it cannot drift. Blob **version 1**: nothing has been released, so
  the format mutates in place and there is no older-version compatibility path.
- `own_member` (`principal:device`).
- **Unredeemed KeyPackage secrets** are _not_ here; they are per-device, not
  per-group (§4).

**The device signing key is not in the group blob.** Group blobs contain the MLS
_public_ signature key only; Hydrogen already stores the device seed and passes
it on each call (`deviceSeedB64`). Wasm never persists it. The blob still
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
`cygnus-dmls/tests/fixtures/group-blob-v1.b64` is a real two-state export;
`blob_vector.rs` imports and re-exports it byte-for-byte and checks truncation,
corruption, and version rejection. Regenerate it with
`CYGNUS_REGEN_BLOB_VECTOR=1` when the v1 layout changes.

## 4. Key packages

Key-package secrets live **in Hydrogen**, not wasm; wasm stays group-scoped.

- `dmlsKeyPackage` returns `secretsB64` (init/leaf private material) and
  `keyPackageId`. Hydrogen persists `{keyPackageId -> secretsB64}`, encrypted
  with the same mechanism as the group blob, never logged. **Write-ahead:**
  persist before publishing the `m.dmls.key_package` event, so a Welcome can
  never arrive for a secret that was not stored. Pool target: 3 unexpired (§6
  rule 6).
- `dmlsJoinWelcome` takes the `secretsB64` for the `key_package_id` parsed from
  the Welcome content. Hydrogen looks it up by that id and does **not**
  trial-decrypt the pool. Absent or non-matching id → `wrong_key_package`.
- Delete the secret only after a successful join, or on expiry.

## 5. Merge planning

`dmlsPlanMerge` runs `merge.rs` in wasm (not reimplemented in Hydrogen). Input
`requestedJson` names branch extremities; Hydrogen supplies no membership. Each
reference includes its `commit_id` and the corresponding room `event_id`,
because every non-genesis reference in the resulting `CommitContent` needs a DAG
hint. The locally derived genesis reference has no event ID. Wasm derives
`Branch` values from the held branches. Leaf signature checks use the held
`LeafNode`s via the verify callback. Device-root identity needs the
`DeviceRootRegistry`, which Hydrogen holds from 00FC chains; passed as
`registryJson` (§5.1). That adds one arg to both `dmlsPlanMerge` and `dmlsMerge`
(which plans internally). It is passed **per call**, never cached: a stale
registry is a security bug. It is scoped to the room's members, derived from the
**auth events of the requested branches** (not current room state), and rejected
over a size cap (`bad_argument`).

Output: `{status: "planned" | "deferred", plan?: PlanSummary, reason?}`. `plan`
is
`{base: {mls_epoch, commit_id}, adds, removes, requiredSelfUpdates, orphanedExternalJoiners}`,
with member lists as `<principal:device>` strings. `deferred` +
`missing_base_state` when a requested extremity is not held
(`MergeError::MissingBaseState`); a bad plan is `rejected`. `dmlsMerge` plans,
then builds the MLS Commit and returns
`{status: "merged", eventType, content, commitId, epoch, members}` (or
`{status, reason}`). The `m.dmls.merge` content has `resolves = requested` and
`base = plan.base`, with the plan embedded. Merge never adds a member, so it
returns no welcomes. `required_self_updates` are reported in the plan; each
named member later calls `dmlsCommit` with a self-update op. It never fabricates
an `UpdateOther`. Until merge inputs retain the original KeyPackages, a plan
that needs an Add returns `unsupported_add`; the affected member must rejoin.

On receive, `m.dmls.merge` must go through `dmlsApplyCommit` with a fresh
`registryJson`. It recomputes the plan and rejects a mismatch in the base, plan
summary or resulting member set. The plain `m.dmls.commit` apply path does not
accept merge events.

### 5.1 `registryJson` schema

`registryJson` is a JSON **text** argument, parsed with the same strict
canonical parser as event content, at most 262,144 bytes. It must be enough to
rebuild the `DeviceRootRegistry`, because merge planning resolves leaf identity
against certificates and roots, not against a bare device-id map.

```json
{
    "masterKeys": [{ "principal": "@...", "key": "<b64url32>" }],
    "roots": [
        {
            "principal": "@...",
            "userEpochHeight": 7,
            "generation": 1,
            "selfSigningKey": "<b64url32>"
        }
    ],
    "certificates": [
        {
            "principal": "@...",
            "certificate": {
                "version": 1,
                "device_id": "D1",
                "device_key": "<b64url32>",
                "self_signing_key": "<b64url32>",
                "self_signing_signature": "<b64url>",
                "device_key_signature": "<b64url>"
            }
        }
    ],
    "revoked": ["<b64url32>"]
}
```

Rules:

1. **Bounds.** The 262,144-byte cap binds first; additionally each of
   `masterKeys`, `roots`, `certificates` and `revoked` is at most 4,096 entries.
   Duplicate principals, duplicated `(principal, generation)` roots, and
   duplicated device keys are `bad_argument` rather than last-one-wins.
2. **`masterKeys`.** One 32-byte key per user principal, sorted by principal.
   `DeviceCertificate::parse_and_verify` uses it to check the certificate chain,
   so an absent entry means the principal cannot be pinned.
3. **`roots`.** The complete, ordered per-principal `m.room.device_root` chain,
   ascending by `(userEpochHeight, generation)`, starting at generation 1 for
   each height and advancing by exactly one within a height. Wasm replays
   `DeviceRootRegistry::install_root`, so a gap, a conflict at the same height
   and generation, or a backwards height is `bad_argument`. Only the last root
   per principal is retained; the earlier entries exist to re-validate the
   chain.
4. **`certificates`.** Every certificate verified against a master key,
   **including stale ones** for rotated or revoked devices: merge planning needs
   them to recognise a member and plan a Remove. `principal` is the auth-event
   sender the certificate was validated for (it is bound by the signature and is
   not a certificate field). Wasm re-runs `parse_and_verify` with
   `masterKeys[principal]`, then `certify`; a certificate that fails is
   `bad_argument`, as is the same device key certified for a different
   `(principal, device_id)`.
5. **`revoked`.** Device keys, 32 bytes each, whether or not they appear in
   `certificates`. Wasm calls `DeviceRootRegistry::revoke` for each.
6. **Trust and scope.** The roots and certificates are **re-verified in wasm**;
   Hydrogen's resolution is not trusted. Revocations cannot be re-derived from a
   device key, so they are Hydrogen's assertion, accepted only within the branch
   auth-event scope below. A leaf whose key has no master key, root or
   certificate resolves to `MergeError::UncertifiedDevice`, i.e. `rejected` —
   never a Megolm fallback and never "unknown device allowed".
7. **Scope.** Entries MUST come only from the auth events of the `requested`
   branches, not from current room state and not from the whole room history. A
   member that is not in that ancestry must not appear; a needed member that is
   absent surfaces as an uncertified leaf.
8. **Never cached.** Every `dmlsPlanMerge` and `dmlsMerge` call takes a fresh
   `registryJson`, scoped to that call's `requestedJson`. Caching a previous
   value is a security bug, because revocation and rotation are exactly what it
   is meant to reflect.

## 6. Implementation status and remaining work

The native crate has snapshot/restore storage, per-extremity group state,
version-1 blob persistence, create/join/encrypt/decrypt, Add/Remove/self-update
commits, apply, merge planning, merge Commit construction, plan-verifying
received merges, external commits, and reboot. Native tests cover the commit,
merge, external-join, and reboot paths, including failed operations leaving
exported state unchanged.

`cygnus-wasm` now exports every function in §2 (built with `make wasm`), and
`cygnus-wasm/tests/dmls.rs` round-trips create/add/join/encrypt/decrypt,
external joins, apply, reboot, and received-reboot checks natively. The
string-level implementation is `cygnus-dmls/src/api.rs`, which carries its own
native tests. The blob conformance vector is
`cygnus-dmls/tests/fixtures/group-blob-v1.b64`.

Remaining work: Hydrogen integrates the exports and announces the final
bindings. The blob is unreleased and remains version 1 while its format is still
changing.

## Resolved in review (6c576c9)

Per-extremity state; lazy import under Web Locks (scope above); key-package
secrets in Hydrogen; `registryJson` per call; seed per call (no `dmlsUnlock`).
`dmlsCreateGroup` has no nonce, and `dmlsKeyPackage` takes no `roomId`.
