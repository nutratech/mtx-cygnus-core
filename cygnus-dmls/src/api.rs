//! String-level API behind the `cygnus-wasm` `dmls*` exports.
//!
//! Every function takes a [`Registry`] plus plain strings and returns canonical
//! JSON text (or a base64url string), so the whole export surface is testable
//! natively and the wasm layer is a one-line wrapper per function. Keys of the
//! returned objects are `camelCase`; extremity references and event content keep
//! the `snake_case` of the wire format.
//!
//! Failures that are *errors* are an [`ApiError`] whose message starts with a
//! stable `code:`. Protocol outcomes (`applied`, `deferred`, `rejected`, ...) are
//! returned as a `status`.

use std::collections::BTreeSet;
use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rezzy_json::{to_canonical_string, Object, Value};

use crate::{
    content::{
        application_plaintext, parse_application_plaintext, ContentError, ExtremityRef,
        PlanSummary, WelcomeContent,
    },
    engine::{
        self, ApplyCtx, ApplyOutcome, CommitOp, CommitOut, DecryptOutcome, EngineError,
        GroupSummary, MergeOutcome, PlanOutcome, RebootCheck, RebootRecipient, Signer,
    },
    merge::ExtremityId,
    registry::{GroupEntry, Registry},
    registry_json::parse_registry_json,
    wire::{self, MemberKey},
    MemberIdentity,
};

/// A failure surfaced to JavaScript as a thrown `Error`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    /// Stable machine-readable code.
    pub code: &'static str,
    /// Human-readable detail.
    pub detail: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            f.write_str(self.code)
        } else {
            write!(f, "{}: {}", self.code, self.detail)
        }
    }
}

impl std::error::Error for ApiError {}

/// Result alias for this module.
pub type ApiResult<T = String> = Result<T, ApiError>;

fn bad(detail: &'static str) -> ApiError {
    ApiError {
        code: "bad_argument",
        detail: detail.to_owned(),
    }
}

fn from_engine(error: &EngineError) -> ApiError {
    let code = error.code();
    let text = error.to_string();
    let detail = text
        .strip_prefix(code)
        .and_then(|rest| rest.strip_prefix(':'))
        .map_or(text.as_str(), str::trim)
        .to_owned();
    ApiError { code, detail }
}

impl From<EngineError> for ApiError {
    fn from(error: EngineError) -> Self {
        from_engine(&error)
    }
}

impl From<ContentError> for ApiError {
    fn from(error: ContentError) -> Self {
        ApiError {
            code: error.code(),
            detail: error.to_string(),
        }
    }
}

/// Codes an apply-style call throws; every other engine failure is a
/// `rejected` status with the code as its reason.
fn is_thrown(code: &str) -> bool {
    matches!(
        code,
        "bad_argument" | "bad_state" | "unknown_group" | "internal"
    )
}

// ---------- argument and output helpers ----------

fn obj(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut out = Object::new();
    for (key, value) in entries {
        out.insert(key.to_owned(), value);
    }
    Value::Object(out)
}

fn text(value: &Value) -> ApiResult {
    to_canonical_string(value).map_err(|_| ApiError {
        code: "internal",
        detail: "output is not canonical JSON".to_owned(),
    })
}

fn parse_json(input: &str, what: &'static str) -> ApiResult<Value> {
    Value::parse_strict(input).map_err(|_| bad(what))
}

fn b64(bytes: &[u8]) -> Value {
    Value::from(B64.encode(bytes))
}

fn decode32(value: &str, what: &'static str) -> ApiResult<[u8; 32]> {
    let bytes = B64.decode(value).map_err(|_| bad(what))?;
    if B64.encode(&bytes) != value {
        return Err(bad(what));
    }
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| bad(what))
}

fn decode_bytes(value: &str, what: &'static str) -> ApiResult<Vec<u8>> {
    let bytes = B64.decode(value).map_err(|_| bad(what))?;
    if bytes.is_empty() || B64.encode(&bytes) != value {
        return Err(bad(what));
    }
    Ok(bytes)
}

fn signer(identity: MemberIdentity, seed_b64: &str) -> ApiResult<Signer> {
    Ok(Signer::new(identity, decode32(seed_b64, "seed")?))
}

fn identity_from_json(identity_json: &str) -> ApiResult<MemberIdentity> {
    let value = parse_json(identity_json, "identity_json")?;
    let principal = value
        .get("principal")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("identity.principal"))?;
    let device = value
        .get("deviceId")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("identity.deviceId"))?;
    MemberIdentity::new(principal, device).map_err(|_| bad("identity"))
}

fn member_value(key: &MemberKey) -> Value {
    Value::from(key.to_wire())
}

fn members_value(members: &[MemberKey]) -> Value {
    Value::Array(members.iter().map(member_value).collect())
}

fn to_device(key: &MemberKey) -> Value {
    obj([
        ("principal", Value::from(key.principal.as_str())),
        ("deviceId", Value::from(key.device_id.as_str())),
    ])
}

fn summary_fields(summary: &GroupSummary) -> Vec<(&'static str, Value)> {
    vec![
        ("groupId", b64(&summary.group_id)),
        ("commitId", b64(&summary.commit_id)),
        ("epoch", Value::from(summary.mls_epoch)),
        ("members", members_value(&summary.members)),
    ]
}

fn recipients_value(recipients: &[RebootRecipient]) -> Value {
    Value::Array(
        recipients
            .iter()
            .map(|r| {
                obj([
                    ("toDevice", to_device(&r.member)),
                    ("keyPackageId", b64(&r.key_package_id)),
                ])
            })
            .collect(),
    )
}

fn entry_mut<'a>(registry: &'a mut Registry, group_id: &str) -> ApiResult<&'a mut GroupEntry> {
    let id = decode32(group_id, "group_id")?;
    registry.get_mut(&id).ok_or(ApiError {
        code: "unknown_group",
        detail: String::new(),
    })
}

/// Install a received or joined root into the room's entry, creating it first.
fn install_root(
    registry: &mut Registry,
    group_id: [u8; 32],
    commit_id: [u8; 32],
    branch: crate::registry::HeldBranch,
) -> ApiResult<()> {
    if let Some(entry) = registry.get_mut(&group_id) {
        return entry
            .insert_root(commit_id, branch)
            .map_err(|e| from_engine(&e.into()));
    }
    let mut entry = GroupEntry::new(group_id);
    entry
        .insert_root(commit_id, branch)
        .map_err(|e| from_engine(&e.into()))?;
    registry.insert(entry);
    Ok(())
}

fn extremity_ref(value: &Value, require_event_id: bool) -> ApiResult<ExtremityRef> {
    Ok(ExtremityRef::parse(value, require_event_id)?)
}

/// `baseJson` for a commit: an extremity reference, or the group's genesis.
fn base_ref(entry: &GroupEntry, base_json: Option<&str>) -> ApiResult<ExtremityRef> {
    match base_json {
        None => Ok(ExtremityRef::genesis(&entry.group_id())),
        Some(json) => extremity_ref(&parse_json(json, "base_json")?, false),
    }
}

/// Parse `[{commit_id, event_id}]`, taking each epoch from the held state.
///
/// `None` means at least one named state is not held, which is a normal
/// deferral rather than an error.
fn requested_refs(
    entry: &GroupEntry,
    requested_json: &str,
) -> ApiResult<Option<Vec<ExtremityRef>>> {
    let Value::Array(items) = parse_json(requested_json, "requested_json")? else {
        return Err(bad("requested_json"));
    };
    if items.is_empty() {
        return Err(bad("requested_json"));
    }
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let commit_id = decode32(
            item.get("commit_id")
                .or_else(|| item.get("commitId"))
                .and_then(Value::as_str)
                .ok_or_else(|| bad("commit_id"))?,
            "commit_id",
        )?;
        let event_id = item
            .get("event_id")
            .or_else(|| item.get("eventId"))
            .and_then(Value::as_str)
            .ok_or_else(|| bad("event_id"))?;
        let Some(branch) = entry.branch(&commit_id) else {
            return Ok(None);
        };
        refs.push(ExtremityRef::new(
            ExtremityId::new(branch.epoch(), commit_id),
            event_id,
        ));
    }
    Ok(Some(refs))
}

fn registry_from(registry_json: &str) -> ApiResult<crate::device_root::DeviceRootRegistry> {
    parse_registry_json(registry_json).map_err(bad)
}

fn status(name: &'static str, extra: Vec<(&'static str, Value)>) -> ApiResult {
    let mut entries = vec![("status", Value::from(name))];
    entries.extend(extra);
    text(&obj(entries))
}

fn reason(name: &'static str, why: &str) -> ApiResult {
    status(name, vec![("reason", Value::from(why))])
}

// ---------- key packages and group creation ----------

/// `dmlsKeyPackage`.
///
/// # Errors
///
/// [`ApiError`] for a bad identity or seed, or an `OpenMLS` failure.
pub fn key_package(identity_json: &str, seed_b64: &str) -> ApiResult {
    let signer = signer(identity_from_json(identity_json)?, seed_b64)?;
    let out = engine::key_package(&signer, None)?;
    text(&obj([
        ("eventType", Value::from(wire::KEY_PACKAGE_EVENT)),
        ("content", out.content),
        ("keyPackageId", b64(&out.key_package_id)),
        ("secretsB64", b64(&out.secrets)),
    ]))
}

/// `dmlsCreateGroup`: nothing is published; see the genesis rule in the docs.
///
/// # Errors
///
/// [`ApiError`] (`already_held`) if the room's group is already loaded.
pub fn create_group(
    registry: &mut Registry,
    identity_json: &str,
    seed_b64: &str,
    room_id: &str,
) -> ApiResult {
    let signer = signer(identity_from_json(identity_json)?, seed_b64)?;
    let group_id = wire::group_id(room_id);
    if registry.has(&group_id) {
        return Err(ApiError {
            code: "already_held",
            detail: String::new(),
        });
    }
    let (branch, summary) = engine::create_group(&signer, group_id)?;
    let mut entry = GroupEntry::new(group_id);
    entry
        .insert_root(summary.commit_id, branch)
        .map_err(|e| from_engine(&e.into()))?;
    let state = entry.export();
    registry.insert(entry);
    let mut fields = summary_fields(&summary);
    fields.push(("stateB64", b64(&state)));
    text(&obj(fields))
}

// ---------- commits ----------

fn op_from_json(value: &Value) -> ApiResult<CommitOp> {
    let kind = value
        .get("op")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("op"))?;
    let package = |v: &Value| -> ApiResult<Vec<u8>> {
        decode_bytes(v.as_str().ok_or_else(|| bad("keyPackage"))?, "keyPackage")
    };
    match kind {
        "add" => Ok(CommitOp::Add(package(
            value.get("keyPackage").ok_or_else(|| bad("keyPackage"))?,
        )?)),
        "add_all" => {
            let Some(Value::Array(items)) = value.get("keyPackages") else {
                return Err(bad("keyPackages"));
            };
            Ok(CommitOp::AddAll(
                items.iter().map(package).collect::<ApiResult<_>>()?,
            ))
        }
        "remove" => {
            let member = value
                .get("member")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("member"))?;
            Ok(CommitOp::Remove(
                MemberKey::parse(member).map_err(|_| bad("member"))?,
            ))
        }
        "self_update" => Ok(CommitOp::SelfUpdate),
        _ => Err(bad("op")),
    }
}

/// A JSON array of base64url `KeyPackage`s.
fn key_package_list(json: &str) -> ApiResult<Vec<Vec<u8>>> {
    let Value::Array(items) = parse_json(json, "key_packages_json")? else {
        return Err(bad("key_packages_json"));
    };
    items
        .iter()
        .map(|v| decode_bytes(v.as_str().ok_or_else(|| bad("keyPackage"))?, "keyPackage"))
        .collect()
}

fn welcome_recipients(op: &CommitOp) -> ApiResult<Vec<RebootRecipient>> {
    let packages: &[Vec<u8>] = match op {
        CommitOp::Add(package) => std::slice::from_ref(package),
        CommitOp::AddAll(packages) => packages,
        _ => return Ok(Vec::new()),
    };
    packages
        .iter()
        .map(|package| {
            Ok(RebootRecipient {
                member: engine::key_package_owner(package)?,
                key_package_id: wire::key_package_id(package),
            })
        })
        .collect()
}

fn commit_result(
    event_type: &'static str,
    out: &CommitOut,
    recipients: &[RebootRecipient],
) -> ApiResult {
    let mut fields = vec![
        ("eventType", Value::from(event_type)),
        ("content", out.content.clone()),
    ];
    fields.extend(summary_fields(&out.summary));
    fields.push(("welcome", out.welcome.as_deref().map_or(Value::Null, b64)));
    fields.push(("recipients", recipients_value(recipients)));
    text(&obj(fields))
}

/// `dmlsCommit`: one membership change on `base_json` (default: genesis).
///
/// The Welcome (if any) and its `recipients` are returned unfinished: the
/// to-device `m.dmls.welcome` needs the Commit's event id, which exists only
/// after the Commit is sent; build it with [`welcome_content`].
///
/// # Errors
///
/// [`ApiError`] for bad arguments or an engine failure; state is unchanged.
pub fn commit(
    registry: &mut Registry,
    group_id: &str,
    seed_b64: &str,
    ops_json: &str,
    base_json: Option<&str>,
) -> ApiResult {
    let entry = entry_mut(registry, group_id)?;
    let signer = signer(engine::own_identity(entry)?, seed_b64)?;
    let op = op_from_json(&parse_json(ops_json, "ops_json")?)?;
    let recipients = welcome_recipients(&op)?;
    let base = base_ref(entry, base_json)?;
    let out = engine::commit(entry, &signer, &base, &op)?;
    commit_result(wire::COMMIT_EVENT, &out, &recipients)
}

/// `dmlsWelcomeContent`: finish the to-device `m.dmls.welcome` content once the
/// Commit's event id is known.
///
/// # Errors
///
/// [`ApiError`] for malformed arguments.
pub fn welcome_content(
    group_id: &str,
    commit_event_id: &str,
    commit_id: &str,
    key_package_id: &str,
    welcome_b64: &str,
) -> ApiResult {
    let content = WelcomeContent {
        group_id: decode32(group_id, "group_id")?,
        commit_event_id: commit_event_id.to_owned(),
        commit_id: decode32(commit_id, "commit_id")?,
        key_package_id: decode32(key_package_id, "key_package_id")?,
        welcome: decode_bytes(welcome_b64, "welcome")?,
    };
    text(&content.to_value()?)
}

// ---------- merge ----------

fn plan_value(summary: &PlanSummary, base: &ExtremityId) -> Value {
    obj([
        (
            "base",
            obj([
                ("mls_epoch", Value::from(base.mls_epoch)),
                ("commit_id", b64(&base.commit_id)),
            ]),
        ),
        ("adds", members_value(&summary.adds)),
        ("removes", members_value(&summary.removes)),
        (
            "requiredSelfUpdates",
            members_value(&summary.required_self_updates),
        ),
        (
            "orphanedExternalJoiners",
            members_value(&summary.orphaned_external_joiners),
        ),
    ])
}

/// `dmlsPlanMerge`.
///
/// # Errors
///
/// [`ApiError`] for bad arguments or corrupt stored metadata.
pub fn plan_merge(
    registry: &mut Registry,
    group_id: &str,
    requested_json: &str,
    registry_json: &str,
) -> ApiResult {
    let entry = entry_mut(registry, group_id)?;
    let Some(requested) = requested_refs(entry, requested_json)? else {
        return reason("deferred", "missing_base_state");
    };
    let roots = registry_from(registry_json)?;
    let ids: Vec<[u8; 32]> = requested.iter().map(|r| r.id.commit_id).collect();
    match engine::plan_merge(entry, &ids, &roots)? {
        PlanOutcome::Planned(plan) => {
            let summary = PlanSummary::from_plan(&plan)?;
            status("planned", vec![("plan", plan_value(&summary, &plan.base))])
        }
        PlanOutcome::Deferred(why) => reason("deferred", why),
        PlanOutcome::Rejected(why) => reason("rejected", why),
    }
}

/// `dmlsMerge`: plan, then build the merge Commit (a plain `m.dmls.commit` when
/// only one distinct tip is requested).
///
/// # Errors
///
/// [`ApiError`] for bad arguments or an engine failure.
pub fn merge(
    registry: &mut Registry,
    group_id: &str,
    seed_b64: &str,
    requested_json: &str,
    registry_json: &str,
    key_packages_json: Option<&str>,
) -> ApiResult {
    let entry = entry_mut(registry, group_id)?;
    let signer = signer(engine::own_identity(entry)?, seed_b64)?;
    let packages = key_packages_json.map_or(Ok(Vec::new()), key_package_list)?;
    let recipients = welcome_recipients(&CommitOp::AddAll(packages.clone()))?;
    let Some(requested) = requested_refs(entry, requested_json)? else {
        return reason("deferred", "missing_base_state");
    };
    let roots = registry_from(registry_json)?;
    let distinct = requested
        .iter()
        .map(|r| r.id)
        .collect::<BTreeSet<_>>()
        .len();
    match engine::merge(entry, &signer, &requested, &roots, &packages)? {
        MergeOutcome::Merged(out) => {
            let event_type = if distinct > 1 {
                wire::MERGE_EVENT
            } else {
                wire::COMMIT_EVENT
            };
            let mut fields = vec![
                ("status", Value::from("merged")),
                ("eventType", Value::from(event_type)),
                ("content", out.content.clone()),
            ];
            fields.extend(summary_fields(&out.summary));
            fields.push(("welcome", out.welcome.as_deref().map_or(Value::Null, b64)));
            fields.push(("recipients", recipients_value(&recipients)));
            text(&obj(fields))
        }
        MergeOutcome::Deferred(why) => reason("deferred", why),
        MergeOutcome::Rejected(why) => reason("rejected", why),
    }
}

// ---------- external commit, apply, welcome ----------

/// `dmlsExternalCommit`: join by external Commit against `target_json`'s
/// `GroupInfo`, taken from `source_content_json` (the content of the event that
/// produced that extremity, whose `commit_id` and `mls_epoch` must match).
///
/// # Errors
///
/// [`ApiError`] for bad arguments, a `GroupInfo` that does not belong to the
/// target, or an engine failure; nothing is installed on error.
pub fn external_commit(
    registry: &mut Registry,
    identity_json: &str,
    seed_b64: &str,
    room_id: &str,
    target_json: &str,
    source_content_json: &str,
) -> ApiResult {
    let signer = signer(identity_from_json(identity_json)?, seed_b64)?;
    let group_id = wire::group_id(room_id);
    let target = extremity_ref(&parse_json(target_json, "target_json")?, true)?;
    let source = parse_json(source_content_json, "group_info_content")?;
    let field = |name: &'static str| source.get(name).and_then(Value::as_str);
    let group_info = decode_bytes(
        field("group_info").ok_or_else(|| bad("group_info"))?,
        "group_info",
    )?;
    let source_epoch = source.get("mls_epoch").and_then(Value::as_u64);
    let source_commit = decode32(
        field("commit_id").ok_or_else(|| bad("commit_id"))?,
        "commit_id",
    )?;
    if source_commit != target.id.commit_id || source_epoch != Some(target.id.mls_epoch) {
        return Err(ApiError {
            code: "mismatch",
            detail: "group_info content is not the target extremity".to_owned(),
        });
    }
    let (branch, out) = engine::external_commit(&signer, &group_id, &target, &group_info)?;
    install_root(registry, group_id, out.commit_id, branch)?;
    let mut fields = vec![
        ("eventType", Value::from(wire::EXTERNAL_COMMIT_EVENT)),
        ("content", out.content),
    ];
    fields.extend(summary_fields(&out.summary));
    text(&obj(fields))
}

fn apply_ctx(ctx_json: &str) -> ApiResult<ApplyCtx> {
    let ctx = parse_json(ctx_json, "ctx_json")?;
    let sender = ctx
        .get("senderMember")
        .and_then(Value::as_str)
        .ok_or_else(|| bad("ctx.senderMember"))?;
    let Some(Value::Array(items)) = ctx.get("ancestors") else {
        return Err(bad("ctx.ancestors"));
    };
    let ancestors = items
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or_else(|| bad("ctx.ancestors"))
        })
        .collect::<ApiResult<BTreeSet<_>>>()?;
    Ok(ApplyCtx {
        sender: MemberKey::parse(sender).map_err(|_| bad("ctx.senderMember"))?,
        ancestors,
    })
}

/// `dmlsApplyCommit`: routes by `event_type`; `registry_json` is required for
/// `m.dmls.merge` only.
///
/// # Errors
///
/// [`ApiError`] only for `bad_argument`, `bad_state`, `unknown_group` and
/// `internal`; every other failure is a `rejected` status.
pub fn apply_commit(
    registry: &mut Registry,
    group_id: &str,
    event_type: &str,
    content_json: &str,
    ctx_json: &str,
    registry_json: Option<&str>,
) -> ApiResult {
    let entry = entry_mut(registry, group_id)?;
    let Ok(content) = Value::parse_strict(content_json) else {
        return reason("rejected", "malformed");
    };
    let ctx = apply_ctx(ctx_json)?;
    let result = match event_type {
        wire::COMMIT_EVENT => engine::apply_commit(entry, event_type, &content, &ctx),
        wire::MERGE_EVENT => {
            let json = registry_json.ok_or_else(|| bad("registry_required"))?;
            let roots = registry_from(json)?;
            engine::apply_merge(entry, event_type, &content, &ctx, &roots)
        }
        wire::EXTERNAL_COMMIT_EVENT => engine::apply_external_commit(entry, &content, &ctx),
        _ => return Err(bad("event_type")),
    };
    let count = Value::from(entry.extremity_count() as u64);
    match result {
        Ok(ApplyOutcome::Applied(summary)) => {
            let mut fields = vec![("status", Value::from("applied"))];
            fields.extend(
                summary_fields(&summary)
                    .into_iter()
                    .filter(|(name, _)| *name != "groupId"),
            );
            fields.push(("extremityCount", count));
            text(&obj(fields))
        }
        Ok(ApplyOutcome::Deferred(why)) => status(
            "deferred",
            vec![("reason", Value::from(why)), ("extremityCount", count)],
        ),
        Ok(ApplyOutcome::Rejected(why)) => reason("rejected", why),
        Err(error) if is_thrown(error.code()) => Err(from_engine(&error)),
        Err(error) => reason("rejected", error.code()),
    }
}

/// `dmlsJoinWelcome`: redeem a Welcome with the `KeyPackage` secrets Hydrogen
/// looked up by `key_package_id`.
///
/// # Errors
///
/// [`ApiError`] for bad arguments only; protocol failures are statuses.
pub fn join_welcome(
    registry: &mut Registry,
    identity_json: &str,
    seed_b64: &str,
    welcome_content_json: &str,
    secrets_b64: Option<&str>,
) -> ApiResult {
    let signer = signer(identity_from_json(identity_json)?, seed_b64)?;
    let Ok(value) = Value::parse_strict(welcome_content_json) else {
        return reason("rejected", "malformed");
    };
    let group_id = match value.get("group_id").and_then(Value::as_str) {
        Some(group_id) => decode32(group_id, "group_id")?,
        None => return reason("rejected", "missing"),
    };
    let content = match WelcomeContent::parse(&value, &group_id) {
        Ok(content) => content,
        Err(error) => return reason("rejected", error.code()),
    };
    let Some(secrets) = secrets_b64 else {
        return status("wrong_key_package", vec![]);
    };
    let secrets = decode_bytes(secrets, "secrets")?;
    match engine::join_welcome(
        &signer,
        &secrets,
        &content.welcome,
        &group_id,
        content.commit_id,
    ) {
        Ok((branch, summary)) => {
            install_root(registry, group_id, summary.commit_id, branch)?;
            let mut fields = vec![("status", Value::from("applied"))];
            fields.extend(summary_fields(&summary));
            text(&obj(fields))
        }
        Err(EngineError::Mls(detail)) if detail.contains("NoMatchingKeyPackage") => {
            status("wrong_key_package", vec![])
        }
        Err(error) if is_thrown(error.code()) => Err(from_engine(&error)),
        Err(error) => reason("rejected", error.code()),
    }
}

// ---------- reboot ----------

/// `dmlsReboot`: start the replacement group from `base_json`, carrying over the
/// members whose `KeyPackage`s are listed (a JSON array of base64url bytes).
///
/// Returns the `m.dmls.reboot` content, the new group's epoch-1
/// `m.dmls.commit` content, the one `welcome` for every recipient, and the
/// `recipients`. The old group is untouched.
///
/// # Errors
///
/// [`ApiError`] for bad arguments or an engine failure.
pub fn reboot(
    registry: &mut Registry,
    group_id: &str,
    seed_b64: &str,
    reason_text: &str,
    key_packages_json: &str,
    base_json: &str,
) -> ApiResult {
    let old_id = decode32(group_id, "group_id")?;
    let base = extremity_ref(&parse_json(base_json, "base_json")?, true)?;
    let packages = key_package_list(key_packages_json)?;
    let old = registry.get(&old_id).ok_or(ApiError {
        code: "unknown_group",
        detail: String::new(),
    })?;
    let signer = signer(engine::own_identity(old)?, seed_b64)?;
    let out = engine::reboot(old, &signer, reason_text, &base, &packages)?;
    if registry.has(&out.new_group_id) {
        return Err(ApiError {
            code: "already_held",
            detail: String::new(),
        });
    }
    let result = text(&obj([
        ("newGroupId", b64(&out.new_group_id)),
        ("rebootContent", out.reboot.clone()),
        ("commitContent", out.commit.content.clone()),
        ("commitId", b64(&out.commit.commit_id)),
        (
            "welcome",
            out.commit.welcome.as_deref().map_or(Value::Null, b64),
        ),
        ("recipients", recipients_value(&out.recipients)),
    ]))?;
    registry.insert(out.entry);
    Ok(result)
}

/// `dmlsCheckReboot`: authorize a received `m.dmls.reboot` against the old
/// group without changing local state.
///
/// Returns `{status:"accepted", newGroupId, members}` or
/// `{status, reason}`. A member that lost the base state defers with
/// `missing_base_state`.
///
/// # Errors
///
/// [`ApiError`] for bad arguments or an unknown group.
pub fn check_reboot(
    registry: &Registry,
    group_id: &str,
    content_json: &str,
    ctx_json: &str,
) -> ApiResult {
    let id = decode32(group_id, "group_id")?;
    let entry = registry.get(&id).ok_or(ApiError {
        code: "unknown_group",
        detail: String::new(),
    })?;
    let Ok(content) = Value::parse_strict(content_json) else {
        return reason("rejected", "malformed");
    };
    let ctx = apply_ctx(ctx_json)?;
    match engine::check_reboot(entry, &content, &ctx) {
        RebootCheck::Accepted(content) => status(
            "accepted",
            vec![
                ("newGroupId", b64(&content.new_group_id())),
                ("members", members_value(&content.members)),
            ],
        ),
        RebootCheck::Deferred(why) => reason("deferred", why),
        RebootCheck::Rejected(why) => reason("rejected", why),
    }
}

// ---------- application messages ----------

/// `dmlsEncrypt`: wrap `{room_id, type, content}` (§13) and encrypt it.
///
/// # Errors
///
/// [`ApiError`] (`fork_unresolved` when several tips are held and none named).
pub fn encrypt(
    registry: &mut Registry,
    group_id: &str,
    seed_b64: &str,
    room_id: &str,
    inner_type: &str,
    inner_content_json: &str,
    at_commit_id: Option<&str>,
) -> ApiResult {
    let entry = entry_mut(registry, group_id)?;
    let signer = signer(engine::own_identity(entry)?, seed_b64)?;
    let inner = parse_json(inner_content_json, "inner_content_json")?;
    let plaintext = application_plaintext(room_id, inner_type, &inner)?;
    let at = at_commit_id
        .map(|id| decode32(id, "at_commit_id"))
        .transpose()?;
    let content = engine::encrypt_at(entry, &signer, at.as_ref(), &plaintext)?;
    text(&obj([
        ("eventType", Value::from(wire::ENCRYPTED_EVENT)),
        ("content", content),
    ]))
}

/// `dmlsDecrypt`: try every held state at the ciphertext's epoch.
///
/// # Errors
///
/// [`ApiError`] for bad arguments or an unknown group; undecryptable input is a
/// `rejected` status and an unheld epoch is `missing_state`.
pub fn decrypt(
    registry: &mut Registry,
    group_id: &str,
    content_json: &str,
    room_id: &str,
) -> ApiResult {
    let entry = entry_mut(registry, group_id)?;
    let Ok(content) = Value::parse_strict(content_json) else {
        return reason("rejected", "malformed");
    };
    match engine::decrypt_in(entry, &content) {
        DecryptOutcome::Ok { message, commit_id } => {
            match parse_application_plaintext(&message.plaintext, room_id) {
                Ok((inner_type, inner)) => status(
                    "ok",
                    vec![
                        ("innerType", Value::from(inner_type)),
                        ("innerContentJson", Value::from(text(&inner)?)),
                        ("senderMember", member_value(&message.sender)),
                        ("epoch", Value::from(message.mls_epoch)),
                        ("commitId", b64(&commit_id)),
                    ],
                ),
                // The ratchet already advanced for this message; the caller
                // must still persist (seq changed) even though it is refused.
                Err(error) => reason(
                    "rejected",
                    &format!("{}:{}", error.code(), plaintext_field(&error)),
                ),
            }
        }
        DecryptOutcome::MissingState(epoch) => {
            status("missing_state", vec![("epoch", Value::from(epoch))])
        }
        DecryptOutcome::Rejected(why) => reason("rejected", why),
    }
}

fn plaintext_field(error: &ContentError) -> &'static str {
    match error {
        ContentError::Mismatch(field)
        | ContentError::Missing(field)
        | ContentError::Malformed(field) => field,
        _ => "plaintext",
    }
}

// ---------- state ----------

/// `dmlsExportGroup`.
///
/// # Errors
///
/// [`ApiError`] (`unknown_group`).
pub fn export_group(registry: &Registry, group_id: &str) -> ApiResult {
    let id = decode32(group_id, "group_id")?;
    let blob = registry.export(&id).map_err(|e| from_engine(&e.into()))?;
    Ok(B64.encode(blob))
}

/// `dmlsImportGroup`.
///
/// # Errors
///
/// [`ApiError`] (`bad_state`, `stale_state`, `unsupported_version`).
pub fn import_group(registry: &mut Registry, state_b64: &str) -> ApiResult {
    let blob = B64.decode(state_b64).map_err(|_| ApiError {
        code: "bad_state",
        detail: "not base64url".to_owned(),
    })?;
    let info = registry.import(&blob).map_err(|e| from_engine(&e.into()))?;
    text(&obj([
        ("groupId", b64(&info.group_id)),
        ("seq", Value::from(info.seq)),
        (
            "extremities",
            Value::Array(info.extremities.iter().map(|id| b64(id)).collect()),
        ),
        ("extremityCount", Value::from(info.extremities.len() as u64)),
    ]))
}

/// `dmlsHasGroup`.
///
/// # Errors
///
/// [`ApiError`] for a malformed id.
pub fn has_group(registry: &Registry, group_id: &str) -> ApiResult<bool> {
    Ok(registry.has(&decode32(group_id, "group_id")?))
}

/// `dmlsForget`.
///
/// # Errors
///
/// [`ApiError`] for a malformed id.
pub fn forget(registry: &mut Registry, group_id: &str) -> ApiResult<()> {
    registry.forget(&decode32(group_id, "group_id")?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "!room:example.org";

    fn principal(byte: u8) -> String {
        format!("@{}", B64.encode([byte; 32]))
    }

    fn identity(byte: u8, device: &str) -> String {
        format!(
            r#"{{"deviceId":"{device}","principal":"{}"}}"#,
            principal(byte)
        )
    }

    fn seed(byte: u8) -> String {
        B64.encode([byte; 32])
    }

    fn json(text: &str) -> Value {
        Value::parse_strict(text).unwrap()
    }

    fn s(value: &Value, key: &str) -> String {
        value.get(key).and_then(Value::as_str).unwrap().to_owned()
    }

    fn compact(value: &Value) -> String {
        to_canonical_string(value).unwrap()
    }

    fn reference(epoch: u64, commit_id: &str, event: &str) -> String {
        format!(r#"{{"commit_id":"{commit_id}","event_id":"{event}","mls_epoch":{epoch}}}"#)
    }

    fn ctx(sender: &str, ancestors: &[&str]) -> String {
        let list = ancestors
            .iter()
            .map(|a| format!("\"{a}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"ancestors":[{list}],"roomId":"{ROOM}","senderMember":"{sender}"}}"#)
    }

    /// Alice creates the room and adds Bob (event `$c1`); returns both
    /// registries and the epoch-1 commit id.
    fn alice_and_bob() -> (Registry, Registry, String, String) {
        let mut alice = Registry::new();
        let mut bob = Registry::new();
        let created = json(&create_group(&mut alice, &identity(1, "A1"), &seed(1), ROOM).unwrap());
        let group = s(&created, "groupId");
        let kp = json(&key_package(&identity(2, "B1"), &seed(2)).unwrap());
        let package = s(kp.get("content").unwrap(), "key_package");
        let ops = format!(r#"{{"keyPackage":"{package}","op":"add"}}"#);
        let out = json(&commit(&mut alice, &group, &seed(1), &ops, None).unwrap());
        assert_eq!(s(&out, "eventType"), wire::COMMIT_EVENT);
        let Some(Value::Array(recipients)) = out.get("recipients") else {
            panic!("recipients");
        };
        let recipient = &recipients[0];
        assert_eq!(s(recipient.get("toDevice").unwrap(), "deviceId"), "B1");
        assert_eq!(s(recipient, "keyPackageId"), s(&kp, "keyPackageId"));
        let welcome = welcome_content(
            &group,
            "$c1",
            &s(&out, "commitId"),
            &s(recipient, "keyPackageId"),
            &s(&out, "welcome"),
        )
        .unwrap();
        let joined = json(
            &join_welcome(
                &mut bob,
                &identity(2, "B1"),
                &seed(2),
                &welcome,
                Some(&s(&kp, "secretsB64")),
            )
            .unwrap(),
        );
        assert_eq!(s(&joined, "status"), "applied");
        (alice, bob, group, s(&out, "commitId"))
    }

    #[test]
    fn create_add_join_and_talk_both_ways() {
        let (mut alice, mut bob, group, _) = alice_and_bob();
        let sent = json(
            &encrypt(
                &mut alice,
                &group,
                &seed(1),
                ROOM,
                "m.room.message",
                r#"{"body":"hi"}"#,
                None,
            )
            .unwrap(),
        );
        assert_eq!(s(&sent, "eventType"), wire::ENCRYPTED_EVENT);
        let received = json(
            &decrypt(
                &mut bob,
                &group,
                &compact(sent.get("content").unwrap()),
                ROOM,
            )
            .unwrap(),
        );
        assert_eq!(s(&received, "status"), "ok");
        assert_eq!(s(&received, "innerType"), "m.room.message");
        assert_eq!(s(&received, "innerContentJson"), r#"{"body":"hi"}"#);
        assert_eq!(s(&received, "senderMember"), format!("{}:A1", principal(1)));

        let reply = json(
            &encrypt(
                &mut bob,
                &group,
                &seed(2),
                ROOM,
                "m.room.message",
                r#"{"body":"yo"}"#,
                None,
            )
            .unwrap(),
        );
        let back = json(
            &decrypt(
                &mut alice,
                &group,
                &compact(reply.get("content").unwrap()),
                ROOM,
            )
            .unwrap(),
        );
        assert_eq!(s(&back, "innerContentJson"), r#"{"body":"yo"}"#);
    }

    #[test]
    fn decrypt_binds_the_room_and_reports_unheld_epochs() {
        let (mut alice, mut bob, group, _) = alice_and_bob();
        let sent =
            json(&encrypt(&mut alice, &group, &seed(1), ROOM, "t", r#"{"a":1}"#, None).unwrap());
        let content = compact(sent.get("content").unwrap());
        // Garbage and replays are statuses.
        let garbage = json(&decrypt(&mut bob, &group, "{}", ROOM).unwrap());
        assert_eq!(s(&garbage, "status"), "rejected");
        let first = json(&decrypt(&mut bob, &group, &content, ROOM).unwrap());
        assert_eq!(s(&first, "status"), "ok");
        let replay = json(&decrypt(&mut bob, &group, &content, ROOM).unwrap());
        assert_eq!(s(&replay, "status"), "rejected");
        // A different room id is a protocol rejection. It consumes the message
        // ratchet (the ciphertext was valid MLS), so use a fresh message.
        let sent =
            json(&encrypt(&mut alice, &group, &seed(1), ROOM, "t", r#"{"a":2}"#, None).unwrap());
        let wrong = json(
            &decrypt(
                &mut bob,
                &group,
                &compact(sent.get("content").unwrap()),
                "!other:example.org",
            )
            .unwrap(),
        );
        assert_eq!(s(&wrong, "reason"), "mismatch:room_id");
        // An epoch nobody holds is missing_state.
        let mut future = json(&content);
        if let Value::Object(map) = &mut future {
            map.insert("mls_epoch".to_owned(), Value::from(9_u64));
        }
        let missing = json(&decrypt(&mut bob, &group, &compact(&future), ROOM).unwrap());
        assert_eq!(s(&missing, "status"), "missing_state");
    }

    #[test]
    fn welcome_failures_are_statuses() {
        let mut alice = Registry::new();
        let mut bob = Registry::new();
        let group = s(
            &json(&create_group(&mut alice, &identity(1, "A1"), &seed(1), ROOM).unwrap()),
            "groupId",
        );
        let kp = json(&key_package(&identity(2, "B1"), &seed(2)).unwrap());
        let other = json(&key_package(&identity(2, "B1"), &seed(2)).unwrap());
        let package = s(kp.get("content").unwrap(), "key_package");
        let ops = format!(r#"{{"keyPackage":"{package}","op":"add"}}"#);
        let out = json(&commit(&mut alice, &group, &seed(1), &ops, None).unwrap());
        let welcome = welcome_content(
            &group,
            "$c1",
            &s(&out, "commitId"),
            &s(&kp, "keyPackageId"),
            &s(&out, "welcome"),
        )
        .unwrap();
        let join = |bob: &mut Registry, secrets: Option<&str>| {
            json(&join_welcome(bob, &identity(2, "B1"), &seed(2), &welcome, secrets).unwrap())
        };
        assert_eq!(s(&join(&mut bob, None), "status"), "wrong_key_package");
        assert_eq!(
            s(&join(&mut bob, Some(&s(&other, "secretsB64"))), "status"),
            "wrong_key_package"
        );
        assert!(!has_group(&bob, &group).unwrap());
        assert_eq!(
            s(&join(&mut bob, Some(&s(&kp, "secretsB64"))), "status"),
            "applied"
        );
        assert!(has_group(&bob, &group).unwrap());
        // A malformed Welcome content is rejected, not thrown.
        let bad = join_welcome(&mut bob, &identity(2, "B1"), &seed(2), "{}", None).unwrap();
        assert_eq!(s(&json(&bad), "status"), "rejected");
    }

    #[test]
    fn apply_routes_by_event_type() {
        let (mut alice, mut bob, group, c1) = alice_and_bob();
        let base = reference(1, &c1, "$c1");
        let out = json(
            &commit(
                &mut alice,
                &group,
                &seed(1),
                r#"{"op":"self_update"}"#,
                Some(&base),
            )
            .unwrap(),
        );
        let content = compact(out.get("content").unwrap());
        let sender = format!("{}:A1", principal(1));
        // Missing ancestry defers; the real context applies.
        let deferred = json(
            &apply_commit(
                &mut bob,
                &group,
                wire::COMMIT_EVENT,
                &content,
                &ctx(&sender, &[]),
                None,
            )
            .unwrap(),
        );
        assert_eq!(s(&deferred, "status"), "deferred");
        let applied = json(
            &apply_commit(
                &mut bob,
                &group,
                wire::COMMIT_EVENT,
                &content,
                &ctx(&sender, &["$c1"]),
                None,
            )
            .unwrap(),
        );
        assert_eq!(s(&applied, "status"), "applied");
        assert_eq!(applied.get("epoch").and_then(Value::as_u64), Some(2));
        // A merge needs the registry; an unknown type is a caller error.
        let merge_error = apply_commit(
            &mut bob,
            &group,
            wire::MERGE_EVENT,
            &content,
            &ctx(&sender, &["$c1"]),
            None,
        )
        .unwrap_err();
        assert_eq!(
            (merge_error.code, merge_error.detail.as_str()),
            ("bad_argument", "registry_required")
        );
        assert_eq!(
            apply_commit(
                &mut bob,
                &group,
                "m.dmls.nope",
                &content,
                &ctx(&sender, &[]),
                None
            )
            .unwrap_err()
            .code,
            "bad_argument"
        );
        // `roomId` in the context is ignored: a reboot group is not derived
        // from the room, so the context cannot bind it.
        let ignored_room = ctx(&sender, &["$c1"]).replace(ROOM, "!x:example.org");
        let idempotent = json(
            &apply_commit(
                &mut bob,
                &group,
                wire::COMMIT_EVENT,
                &content,
                &ignored_room,
                None,
            )
            .unwrap(),
        );
        assert_eq!(s(&idempotent, "status"), "applied");
    }

    #[test]
    fn external_commit_is_applied_by_event_type_without_a_registry() {
        let (mut alice, mut bob, group, c1) = alice_and_bob();
        // Source: alice's commit content at epoch 1. Rebuild it by committing a
        // self-update whose GroupInfo carol uses as the target.
        let base = reference(1, &c1, "$c1");
        let out = json(
            &commit(
                &mut alice,
                &group,
                &seed(1),
                r#"{"op":"self_update"}"#,
                Some(&base),
            )
            .unwrap(),
        );
        let source = out.get("content").unwrap();
        let sender = format!("{}:A1", principal(1));
        apply_commit(
            &mut bob,
            &group,
            wire::COMMIT_EVENT,
            &compact(source),
            &ctx(&sender, &["$c1"]),
            None,
        )
        .unwrap();
        let target = reference(2, &s(&out, "commitId"), "$c2");
        let mut carol = Registry::new();
        let joined = json(
            &external_commit(
                &mut carol,
                &identity(3, "C1"),
                &seed(3),
                ROOM,
                &target,
                &compact(source),
            )
            .unwrap(),
        );
        assert_eq!(s(&joined, "eventType"), wire::EXTERNAL_COMMIT_EVENT);
        assert!(has_group(&carol, &group).unwrap());
        // A source that is not the target extremity is refused.
        let wrong = reference(2, &B64.encode([9u8; 32]), "$c2");
        assert_eq!(
            external_commit(
                &mut Registry::new(),
                &identity(3, "C1"),
                &seed(3),
                ROOM,
                &wrong,
                &compact(source)
            )
            .unwrap_err()
            .code,
            "mismatch"
        );
        let carol_sender = format!("{}:C1", principal(3));
        let applied = json(
            &apply_commit(
                &mut bob,
                &group,
                wire::EXTERNAL_COMMIT_EVENT,
                &compact(joined.get("content").unwrap()),
                &ctx(&carol_sender, &["$c2"]),
                None,
            )
            .unwrap(),
        );
        assert_eq!(s(&applied, "status"), "applied");
        assert_eq!(applied.get("epoch").and_then(Value::as_u64), Some(3));
    }

    #[test]
    fn reboot_returns_the_new_group_and_leaves_the_old_one() {
        let (mut alice, _bob, group, c1) = alice_and_bob();
        let kp = json(&key_package(&identity(2, "B1"), &seed(2)).unwrap());
        let package = s(kp.get("content").unwrap(), "key_package");
        let base = reference(1, &c1, "$c1");
        let out = json(
            &reboot(
                &mut alice,
                &group,
                &seed(1),
                "state-loss",
                &format!(r#"["{package}"]"#),
                &base,
            )
            .unwrap(),
        );
        let new_group = s(&out, "newGroupId");
        assert!(has_group(&alice, &new_group).unwrap());
        assert!(has_group(&alice, &group).unwrap());
        assert_ne!(new_group, group);
        assert!(out.get("welcome").and_then(Value::as_str).is_some());
        // A repeat of the same reboot is refused rather than overwriting.
        let again = reboot(
            &mut alice,
            &group,
            &seed(1),
            "state-loss",
            &format!(r#"["{package}"]"#),
            &base,
        );
        assert_eq!(again.unwrap_err().code, "already_held");
    }

    #[test]
    fn state_round_trips_and_stale_imports_throw() {
        let (alice, _bob, group, _) = alice_and_bob();
        let blob = export_group(&alice, &group).unwrap();
        let mut fresh = Registry::new();
        let info = json(&import_group(&mut fresh, &blob).unwrap());
        assert_eq!(s(&info, "groupId"), group);
        assert_eq!(info.get("extremityCount").and_then(Value::as_u64), Some(1));
        assert_eq!(export_group(&fresh, &group).unwrap(), blob);
        // Idempotent re-import of an identical blob; a corrupt one is bad_state.
        assert!(import_group(&mut fresh, &blob).is_ok());
        let mut raw = B64.decode(&blob).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert_eq!(
            import_group(&mut fresh, &B64.encode(raw)).unwrap_err().code,
            "bad_state"
        );
        forget(&mut fresh, &group).unwrap();
        assert!(!has_group(&fresh, &group).unwrap());
        assert_eq!(
            export_group(&fresh, &group).unwrap_err().code,
            "unknown_group"
        );
    }

    #[test]
    fn errors_are_coded_and_state_is_unchanged() {
        let (mut alice, _bob, group, _) = alice_and_bob();
        let before = export_group(&alice, &group).unwrap();
        // Wrong seed: the own-leaf key check refuses to sign.
        let error = commit(
            &mut alice,
            &group,
            &seed(9),
            r#"{"op":"self_update"}"#,
            Some(&reference(1, &B64.encode([0u8; 32]), "$c")),
        )
        .unwrap_err();
        assert!(
            ["bad_argument", "missing_base_state"].contains(&error.code),
            "{error}"
        );
        assert_eq!(
            encrypt(&mut alice, &group, &seed(9), ROOM, "t", "{}", None)
                .unwrap_err()
                .code,
            "bad_argument"
        );
        assert_eq!(
            commit(&mut alice, &group, &seed(1), r#"{"op":"nope"}"#, None)
                .unwrap_err()
                .to_string(),
            "bad_argument: op"
        );
        assert_eq!(export_group(&alice, &group).unwrap(), before);
        assert_eq!(
            commit(&mut alice, &B64.encode([5u8; 32]), &seed(1), "{}", None)
                .unwrap_err()
                .code,
            "unknown_group"
        );
    }
}
