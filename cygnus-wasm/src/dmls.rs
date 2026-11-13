//! `wasm-bindgen` wrappers over `cygnus_dmls::api`.
//!
//! The string-level API is implemented and tested natively; these exports only
//! own the process-wide [`Registry`] and translate [`ApiError`] into a thrown
//! JavaScript `Error`.

use std::sync::{Mutex, MutexGuard, OnceLock};

use cygnus_dmls::{api, registry::Registry};
use wasm_bindgen::prelude::*;

/// The one in-memory registry for this wasm instance.
fn registry() -> MutexGuard<'static, Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY
        .get_or_init(|| Mutex::new(Registry::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn js(error: api::ApiError) -> JsError {
    JsError::new(&error.to_string())
}

/// Build a single-use key package and the secrets that redeem its Welcome.
///
/// Returns `{eventType, content, keyPackageId, secretsB64}`. Persist
/// `secretsB64` keyed by `keyPackageId` before publishing `content`.
///
/// # Errors
/// Throws for a malformed identity or seed, or an MLS failure.
#[wasm_bindgen(js_name = dmlsKeyPackage)]
pub fn dmls_key_package(identity_json: &str, device_seed_b64: &str) -> Result<String, JsError> {
    api::key_package(identity_json, device_seed_b64).map_err(js)
}

/// Create the epoch-0 group for `roomId` and install it locally.
///
/// Returns `{groupId, commitId, epoch, members, stateB64}`. Nothing is
/// published; the first event is the epoch-1 Commit from `dmlsCommit`.
///
/// # Errors
/// Throws for a malformed identity or seed, an already loaded group, or an MLS
/// failure.
#[wasm_bindgen(js_name = dmlsCreateGroup)]
pub fn dmls_create_group(
    identity_json: &str,
    device_seed_b64: &str,
    room_id: &str,
) -> Result<String, JsError> {
    api::create_group(&mut registry(), identity_json, device_seed_b64, room_id).map_err(js)
}

/// Produce one Commit from a single membership operation.
///
/// `opsJson` is one object: `{"op":"add","keyPackage":"<b64>"}`,
/// `{"op":"remove","member":"<principal:device>"}`, or
/// `{"op":"self_update"}`. `baseJson` is the held base extremity
/// (`{mls_epoch, commit_id, event_id}`); omit it only when the base is the
/// genesis state.
///
/// Returns `{eventType, content, groupId, commitId, epoch, members, welcome,
/// recipients}`. A Welcome is `welcome` (base64url) plus `recipients`
/// (`[{toDevice:{principal,deviceId}, keyPackageId}]`); finish the to-device
/// content with `dmlsWelcomeContent` after the Commit event is published.
///
/// # Errors
/// Throws for a malformed argument, a bad base, or an MLS failure.
#[wasm_bindgen(js_name = dmlsCommit)]
pub fn dmls_commit(
    group_id_json: &str,
    device_seed_b64: &str,
    ops_json: &str,
    base_json: Option<String>,
) -> Result<String, JsError> {
    api::commit(
        &mut registry(),
        group_id_json,
        device_seed_b64,
        ops_json,
        base_json.as_deref(),
    )
    .map_err(js)
}

/// Build the to-device `m.dmls.welcome` content once the Commit's event id is
/// known.
///
/// Returns `{eventType, content}` for each added recipient, using the shared
/// Welcome bytes and that recipient's `keyPackageId`.
///
/// # Errors
/// Throws for a malformed id or an empty Welcome.
#[wasm_bindgen(js_name = dmlsWelcomeContent)]
pub fn dmls_welcome_content(
    group_id_json: &str,
    commit_event_id: &str,
    commit_id: &str,
    key_package_id: &str,
    welcome_b64: &str,
) -> Result<String, JsError> {
    let content = api::welcome_content(
        group_id_json,
        commit_event_id,
        commit_id,
        key_package_id,
        welcome_b64,
    )
    .map_err(js)?;
    let mut object = rezzy_json::Object::new();
    object.insert(
        "eventType".into(),
        rezzy_json::Value::from("m.dmls.welcome"),
    );
    object.insert(
        "content".into(),
        rezzy_json::Value::parse_strict(&content).map_err(|_| JsError::new("internal: content"))?,
    );
    rezzy_json::to_canonical_string(&rezzy_json::Value::Object(object))
        .map_err(|_| JsError::new("internal: content"))
}

/// Plan a merge over the held branches named by `requestedJson`.
///
/// Each entry is `{"commit_id":"<b64url32>","event_id":"$..."}`; the epoch is
/// read from the held state. `registryJson` is the per-call device-root
/// registry (§5.1) and is never cached.
///
/// Returns `{status:"planned", plan}` or `{status, reason}`.
///
/// # Errors
/// Throws for a malformed argument or corrupt stored metadata.
#[wasm_bindgen(js_name = dmlsPlanMerge)]
pub fn dmls_plan_merge(
    group_id_json: &str,
    requested_json: &str,
    registry_json: &str,
) -> Result<String, JsError> {
    api::plan_merge(
        &mut registry(),
        group_id_json,
        requested_json,
        registry_json,
    )
    .map_err(js)
}

/// Plan and build an `m.dmls.merge` Commit.
///
/// Inputs are as `dmlsPlanMerge`. The Commit resolves every requested state and
/// uses the plan's base. Plans that need an Add are `rejected` with
/// `unsupported_add`.
///
/// Returns `{status:"merged", eventType, content, groupId, commitId, epoch,
/// members}` or `{status, reason}`.
///
/// # Errors
/// Throws for a malformed argument or an MLS failure.
#[wasm_bindgen(js_name = dmlsMerge)]
pub fn dmls_merge(
    group_id_json: &str,
    device_seed_b64: &str,
    requested_json: &str,
    registry_json: &str,
) -> Result<String, JsError> {
    api::merge(
        &mut registry(),
        group_id_json,
        device_seed_b64,
        requested_json,
        registry_json,
    )
    .map_err(js)
}

/// Join a group by external Commit against a target extremity.
///
/// `targetJson` is the target extremity (`{mls_epoch, commit_id, event_id}`)
/// and `sourceContentJson` is the content of the event that produced it. Wasm
/// checks that the source content's `mls_epoch`/`commit_id` are the target's
/// and takes `group_info` from it.
///
/// Returns `{eventType, content, groupId, commitId, epoch, members}`.
///
/// # Errors
/// Throws for a malformed argument, a mismatched source, or an MLS failure.
#[wasm_bindgen(js_name = dmlsExternalCommit)]
pub fn dmls_external_commit(
    identity_json: &str,
    device_seed_b64: &str,
    room_id: &str,
    target_json: &str,
    source_content_json: &str,
) -> Result<String, JsError> {
    api::external_commit(
        &mut registry(),
        identity_json,
        device_seed_b64,
        room_id,
        target_json,
        source_content_json,
    )
    .map_err(js)
}

/// Apply a received Commit, merge, or external Commit.
///
/// `ctxJson` is `{"senderMember":"<principal:device>","ancestors":[event_id...]}`
/// (`roomId` may be present and is ignored). `registryJson` is required for
/// `m.dmls.merge` and ignored otherwise.
///
/// Returns `{status:"applied", groupId, commitId, epoch, members,
/// extremityCount}`, `{status:"deferred", reason, extremityCount}`, or
/// `{status:"rejected", reason}`.
///
/// # Errors
/// Throws for a malformed argument, an unknown group, or a missing registry.
#[wasm_bindgen(js_name = dmlsApplyCommit)]
pub fn dmls_apply_commit(
    group_id_json: &str,
    event_type: &str,
    content_json: &str,
    ctx_json: &str,
    registry_json: Option<String>,
) -> Result<String, JsError> {
    api::apply_commit(
        &mut registry(),
        group_id_json,
        event_type,
        content_json,
        ctx_json,
        registry_json.as_deref(),
    )
    .map_err(js)
}

/// Authorize a received `m.dmls.reboot` without changing local state.
///
/// The sender must be an active member of the named base and every listed
/// member must be in it. A member that lost the base defers with
/// `missing_base_state`.
///
/// Returns `{status:"accepted", newGroupId, members}` or `{status, reason}`.
///
/// # Errors
/// Throws for a malformed argument or an unknown group.
#[wasm_bindgen(js_name = dmlsCheckReboot)]
pub fn dmls_check_reboot(
    group_id_json: &str,
    content_json: &str,
    ctx_json: &str,
) -> Result<String, JsError> {
    api::check_reboot(&registry(), group_id_json, content_json, ctx_json).map_err(js)
}

/// Join a group from a received `m.dmls.welcome`.
///
/// `welcomeContentJson` is the verified event content and `secretsB64` is the
/// stored secret for its `key_package_id`. A missing secret is
/// `{status:"wrong_key_package"}`. The group id comes from the content, so a
/// reboot replacement group joins the same way as a room-derived one.
///
/// Returns `{status:"applied", groupId, commitId, epoch, members}` or
/// `{status, reason}`.
///
/// # Errors
/// Throws for a malformed identity or an already loaded group.
#[wasm_bindgen(js_name = dmlsJoinWelcome)]
pub fn dmls_join_welcome(
    identity_json: &str,
    device_seed_b64: &str,
    welcome_content_json: &str,
    secrets_b64: Option<String>,
) -> Result<String, JsError> {
    api::join_welcome(
        &mut registry(),
        identity_json,
        device_seed_b64,
        welcome_content_json,
        secrets_b64.as_deref(),
    )
    .map_err(js)
}

/// Start a replacement group after unrecoverable state loss (00FD §11).
///
/// `keyPackagesJson` is a JSON array of base64url serialized KeyPackages, one
/// per member carried over. `baseJson` is the held old-group extremity
/// (`{mls_epoch, commit_id, event_id}`).
///
/// Returns `{newGroupId, rebootContent, commitContent, commitId, welcome,
/// recipients}`. The one Welcome is shared; build each recipient's to-device
/// content with `dmlsWelcomeContent` once the new Commit's event id is known.
///
/// # Errors
/// Throws for a malformed argument, a non-member KeyPackage, or an MLS failure.
#[wasm_bindgen(js_name = dmlsReboot)]
pub fn dmls_reboot(
    group_id_json: &str,
    device_seed_b64: &str,
    reason: &str,
    key_packages_json: &str,
    base_json: &str,
) -> Result<String, JsError> {
    api::reboot(
        &mut registry(),
        group_id_json,
        device_seed_b64,
        reason,
        key_packages_json,
        base_json,
    )
    .map_err(js)
}

/// Encrypt one application message at the named branch or the sole tip.
///
/// The §13 plaintext `{room_id, type, content}` is built inside wasm. `roomId`
/// is the room id; for a reboot group it does not hash to `groupId`.
///
/// Returns `{eventType:"m.room.encrypted", content}`.
///
/// # Errors
/// Throws for a malformed argument, an unknown group, an unheld branch, a
/// `fork_unresolved` ambiguous tip, or a seed that does not match the group.
#[wasm_bindgen(js_name = dmlsEncrypt)]
pub fn dmls_encrypt(
    group_id_json: &str,
    device_seed_b64: &str,
    room_id: &str,
    inner_type: &str,
    inner_content_json: &str,
    at_commit_id: Option<String>,
) -> Result<String, JsError> {
    api::encrypt(
        &mut registry(),
        group_id_json,
        device_seed_b64,
        room_id,
        inner_type,
        inner_content_json,
        at_commit_id.as_deref(),
    )
    .map_err(js)
}

/// Decrypt one application message, trying every held state at its epoch.
///
/// Returns `{status:"ok", innerType, innerContentJson, senderMember, epoch,
/// commitId}`, `{status:"missing_state", epoch}`, or
/// `{status:"rejected", reason}`.
///
/// # Errors
/// Throws for a malformed argument or an unknown group.
#[wasm_bindgen(js_name = dmlsDecrypt)]
pub fn dmls_decrypt(
    group_id_json: &str,
    content_json: &str,
    room_id: &str,
) -> Result<String, JsError> {
    api::decrypt(&mut registry(), group_id_json, content_json, room_id).map_err(js)
}

/// Serialize a loaded group to its versioned blob, base64url encoded.
///
/// # Errors
/// Throws for an unknown group.
#[wasm_bindgen(js_name = dmlsExportGroup)]
pub fn dmls_export_group(group_id_json: &str) -> Result<String, JsError> {
    api::export_group(&registry(), group_id_json).map_err(js)
}

/// Import a group blob, replacing a loaded entry atomically.
///
/// Returns `{groupId, seq, extremities, extremityCount}`.
///
/// # Errors
/// Throws for a malformed blob, an unsupported version, or a stale `seq`.
#[wasm_bindgen(js_name = dmlsImportGroup)]
pub fn dmls_import_group(state_b64: &str) -> Result<String, JsError> {
    api::import_group(&mut registry(), state_b64).map_err(js)
}

/// Whether a group is loaded in this wasm instance.
///
/// # Errors
/// Throws for a malformed group id.
#[wasm_bindgen(js_name = dmlsHasGroup)]
pub fn dmls_has_group(group_id_json: &str) -> Result<bool, JsError> {
    api::has_group(&registry(), group_id_json).map_err(js)
}

/// Drop a group from wasm memory. The persisted blob is untouched.
///
/// # Errors
/// Throws for a malformed group id.
#[wasm_bindgen(js_name = dmlsForget)]
pub fn dmls_forget(group_id_json: &str) -> Result<(), JsError> {
    api::forget(&mut registry(), group_id_json).map_err(js)
}
