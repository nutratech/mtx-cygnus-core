//! Typed event content for the DMLS Matrix transport.
//!
//! The schemas are specified in MSC00FD
//! (`proposals/00FD-dmls-matrix-transport.md`). Each
//! `*Content` type here is the decoded form of one event's `content`:
//!
//! - `parse` is strict: known fields that are missing or malformed are
//!   rejected, unknown fields are ignored, and every derived identifier is
//!   recomputed from the decoded bytes rather than trusted;
//! - `to_value` builds canonical-JSON-ready [`Value`]s and refuses content that
//!   would not parse back, or that would not fit in one room event.
//!
//! Nothing in this module calls `OpenMLS`. It returns and accepts raw MLS bytes
//! and identifiers, so it can run before any group state is loaded. The checks
//! that need group state (the leaf is a member of `base`, the Welcome decrypts)
//! belong to the caller.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{Kind, Principal};
use rezzy_json::{to_canonical_string, Object, Value};

use crate::merge::{ExtremityId, MemberId, MergePlan};
use crate::wire::{self, MemberKey, WireError};

/// Largest canonical-JSON `content` this module will build.
///
/// Federation caps a whole PDU at 64 KiB. The rest is the envelope: signatures,
/// the device certificate, auth and prev events. Because `group_info` carries
/// the ratchet tree, this cap is what bounds the group size.
pub const MAX_CONTENT_BYTES: usize = 60_000;

/// Largest integer a canonical-JSON number may hold (2^53 − 1).
const MAX_SAFE: u64 = (1 << 53) - 1;

/// A transport value that failed validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContentError {
    /// A required field is absent.
    #[error("missing field `{0}`")]
    Missing(&'static str),
    /// A field has the wrong type, encoding, length or value.
    #[error("malformed field `{0}`")]
    Malformed(&'static str),
    /// A declared value disagrees with the value derived from the content.
    #[error("field `{0}` does not match its derived value")]
    Mismatch(&'static str),
    /// The content would not fit in one room event.
    #[error("content exceeds {MAX_CONTENT_BYTES} bytes")]
    TooLarge,
    /// The value is not strict canonical JSON (a float or out-of-range integer).
    #[error("content is not canonical JSON")]
    Canonical,
}

impl From<WireError> for ContentError {
    fn from(_: WireError) -> Self {
        Self::Malformed("member")
    }
}

impl ContentError {
    /// The stable error code surfaced to JavaScript; the `Display` text is the
    /// detail after the colon.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Missing(_) => "missing_field",
            Self::Malformed(_) => "malformed",
            Self::Mismatch(_) => "mismatch",
            Self::TooLarge => "too_large",
            Self::Canonical => "bad_content",
        }
    }
}

type Result<T> = core::result::Result<T, ContentError>;

/// Encode bytes as unpadded base64url.
#[must_use]
pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Decode unpadded base64url, rejecting padding and non-canonical trailing bits.
///
/// # Errors
///
/// Returns [`ContentError::Malformed`] naming `field` for any other input.
pub fn b64_decode(value: &str, field: &'static str) -> Result<Vec<u8>> {
    let bytes = B64
        .decode(value)
        .map_err(|_| ContentError::Malformed(field))?;
    // `decode` tolerates non-zero trailing bits; two spellings of one value
    // would give one Commit two byte strings.
    if B64.encode(&bytes) != value {
        return Err(ContentError::Malformed(field));
    }
    Ok(bytes)
}

fn digest(value: &str, field: &'static str) -> Result<[u8; 32]> {
    b64_decode(value, field)?
        .try_into()
        .map_err(|_| ContentError::Malformed(field))
}

fn field<'a>(object: &'a Value, name: &'static str) -> Result<&'a Value> {
    object.get(name).ok_or(ContentError::Missing(name))
}

fn string<'a>(object: &'a Value, name: &'static str) -> Result<&'a str> {
    field(object, name)?
        .as_str()
        .ok_or(ContentError::Malformed(name))
}

fn bytes(object: &Value, name: &'static str) -> Result<Vec<u8>> {
    let decoded = b64_decode(string(object, name)?, name)?;
    if decoded.is_empty() {
        return Err(ContentError::Malformed(name));
    }
    Ok(decoded)
}

fn id32(object: &Value, name: &'static str) -> Result<[u8; 32]> {
    digest(string(object, name)?, name)
}

fn epoch(object: &Value, name: &'static str) -> Result<u64> {
    let value = field(object, name)?
        .as_u64()
        .ok_or(ContentError::Malformed(name))?;
    check_epoch(value, name)
}

fn check_epoch(value: u64, name: &'static str) -> Result<u64> {
    if value > MAX_SAFE {
        return Err(ContentError::Malformed(name));
    }
    Ok(value)
}

fn array<'a>(object: &'a Value, name: &'static str) -> Result<&'a [Value]> {
    match field(object, name)? {
        Value::Array(items) => Ok(items),
        _ => Err(ContentError::Malformed(name)),
    }
}

fn event_id(value: &str, name: &'static str) -> Result<()> {
    if value.len() < 2 || !value.starts_with('$') {
        return Err(ContentError::Malformed(name));
    }
    Ok(())
}

fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    let mut out = Object::new();
    for (key, value) in entries {
        out.insert(key.to_owned(), value);
    }
    Value::Object(out)
}

fn epoch_value(value: u64, name: &'static str) -> Result<Value> {
    Ok(Value::from(check_epoch(value, name)?))
}

/// Serialize and size-check a built value.
fn finish(value: Value) -> Result<Value> {
    let text = to_canonical_string(&value).map_err(|_| ContentError::Canonical)?;
    if text.len() > MAX_CONTENT_BYTES {
        return Err(ContentError::TooLarge);
    }
    Ok(value)
}

fn require_user(key: &MemberKey) -> Result<()> {
    match Principal::parse(&key.principal) {
        Ok(principal) if principal.kind == Kind::User && !key.device_id.is_empty() => Ok(()),
        _ => Err(ContentError::Malformed("member")),
    }
}

/// A reference to one commit extremity: `(mls_epoch, commit_id)` plus a DAG hint.
///
/// The epoch is the epoch of the state **after** the Commit applies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtremityRef {
    /// The identity: epoch and commit digest.
    pub id: ExtremityId,
    /// The room event that carries the Commit. Required in room events.
    pub event_id: Option<String>,
}

impl ExtremityRef {
    /// Create a reference with a DAG hint.
    #[must_use]
    pub fn new(id: ExtremityId, event_id: impl Into<String>) -> Self {
        Self {
            id,
            event_id: Some(event_id.into()),
        }
    }

    /// The genesis extremity of `group_id`: epoch 0, the synthetic
    /// [`wire::genesis_commit_id`], and no DAG hint.
    #[must_use]
    pub fn genesis(group_id: &[u8; 32]) -> Self {
        Self {
            id: ExtremityId::new(0, wire::genesis_commit_id(group_id)),
            event_id: None,
        }
    }

    /// Whether this is `group_id`'s genesis reference.
    #[must_use]
    pub fn is_genesis(&self, group_id: &[u8; 32]) -> bool {
        self.event_id.is_none() && self.id == ExtremityId::new(0, wire::genesis_commit_id(group_id))
    }

    /// Parse `{mls_epoch, commit_id, event_id?}`.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] if a field is missing or malformed, or if
    /// `require_event_id` is set and the hint is absent.
    pub fn parse(value: &Value, require_event_id: bool) -> Result<Self> {
        let event = match value.get("event_id") {
            None => None,
            Some(Value::String(text)) => {
                event_id(text, "event_id")?;
                Some(text.clone())
            }
            Some(_) => return Err(ContentError::Malformed("event_id")),
        };
        if require_event_id && event.is_none() {
            return Err(ContentError::Missing("event_id"));
        }
        Ok(Self {
            id: ExtremityId::new(epoch(value, "mls_epoch")?, id32(value, "commit_id")?),
            event_id: event,
        })
    }

    /// Build the JSON object.
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::Malformed`] if the epoch is out of range.
    pub fn to_value(&self) -> Result<Value> {
        let mut entries = vec![
            ("mls_epoch", epoch_value(self.id.mls_epoch, "mls_epoch")?),
            ("commit_id", Value::from(b64_encode(&self.id.commit_id))),
        ];
        if let Some(event) = &self.event_id {
            entries.push(("event_id", Value::from(event.as_str())));
        }
        Ok(object(entries))
    }
}

fn parse_refs(
    value: &Value,
    name: &'static str,
    min: usize,
    require_event_id: bool,
) -> Result<Vec<ExtremityRef>> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for item in array(value, name)? {
        let reference = ExtremityRef::parse(item, require_event_id)?;
        // Duplicate references to one `(epoch, commit_id)` collapse to one.
        if seen.insert(reference.id) {
            out.push(reference);
        }
    }
    if out.len() < min {
        return Err(ContentError::Malformed(name));
    }
    Ok(out)
}

/// The audit record a Commit carries from its `MergePlan`.
///
/// Observers that hold every referenced branch recompute the plan and compare.
/// Each list is sorted and deduplicated, so two equal plans are equal values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PlanSummary {
    /// Members the Commit adds.
    pub adds: Vec<MemberKey>,
    /// Members the Commit removes.
    pub removes: Vec<MemberKey>,
    /// Members that must send their own Update in a later epoch.
    pub required_self_updates: Vec<MemberKey>,
    /// External joiners the merge discarded; they must rejoin.
    pub orphaned_external_joiners: Vec<MemberKey>,
}

fn normalize(keys: impl IntoIterator<Item = MemberKey>) -> Vec<MemberKey> {
    keys.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn member_key(id: &MemberId) -> Result<MemberKey> {
    let principal =
        std::str::from_utf8(&id.principal).map_err(|_| ContentError::Malformed("member"))?;
    Ok(MemberKey::parse(&format!("{principal}:{}", id.device_id))?)
}

impl PlanSummary {
    /// Build the summary from a [`MergePlan`].
    ///
    /// # Errors
    ///
    /// Returns [`ContentError::Malformed`] if a member is not a canonical user
    /// principal with a device ID.
    pub fn from_plan(plan: &MergePlan) -> Result<Self> {
        fn keys<'a>(ids: impl Iterator<Item = &'a MemberId>) -> Result<Vec<MemberKey>> {
            Ok(normalize(ids.map(member_key).collect::<Result<Vec<_>>>()?))
        }
        Ok(Self {
            adds: keys(plan.adds.iter().map(|(id, _)| id))?,
            removes: keys(plan.removes.iter())?,
            required_self_updates: keys(plan.required_self_updates.iter())?,
            orphaned_external_joiners: keys(plan.orphaned_external_joiners.iter())?,
        })
    }

    fn parse(value: &Value) -> Result<Self> {
        let list = |name: &'static str| -> Result<Vec<MemberKey>> {
            let keys = array(value, name)?
                .iter()
                .map(|item| {
                    let text = item.as_str().ok_or(ContentError::Malformed(name))?;
                    MemberKey::parse(text).map_err(|_| ContentError::Malformed(name))
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(normalize(keys))
        };
        Ok(Self {
            adds: list("adds")?,
            removes: list("removes")?,
            required_self_updates: list("required_self_updates")?,
            orphaned_external_joiners: list("orphaned_external_joiners")?,
        })
    }

    fn to_value(&self) -> Result<Value> {
        let list = |keys: &[MemberKey]| -> Result<Value> {
            let mut out = Vec::with_capacity(keys.len());
            for key in normalize(keys.iter().cloned()) {
                require_user(&key)?;
                out.push(Value::from(key.to_wire()));
            }
            Ok(Value::Array(out))
        };
        Ok(object([
            ("adds", list(&self.adds)?),
            ("removes", list(&self.removes)?),
            ("required_self_updates", list(&self.required_self_updates)?),
            (
                "orphaned_external_joiners",
                list(&self.orphaned_external_joiners)?,
            ),
        ]))
    }
}

/// Content of `m.dmls.commit` and `m.dmls.merge`.
///
/// `mls_epoch` and `commit_id` are derived, not stored: they are always
/// `base.mls_epoch + 1` and the digest of [`Self::commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitContent {
    /// The room-derived group ID.
    pub group_id: [u8; 32],
    /// The extremity the committer applied the Commit to.
    pub base: ExtremityRef,
    /// Every extremity the Commit supersedes, `base` included.
    pub resolves: Vec<ExtremityRef>,
    /// The TLS-serialized Commit `MLSMessage`.
    pub commit: Vec<u8>,
    /// The TLS-serialized `GroupInfo` `MLSMessage`, with the ratchet tree.
    pub group_info: Vec<u8>,
    /// Standalone MLS Proposals the Commit commits to; usually empty.
    pub proposals: Vec<Vec<u8>>,
    /// The merge-plan audit record.
    pub plan: PlanSummary,
}

impl CommitContent {
    /// The epoch of the state this Commit produces.
    #[must_use]
    pub fn mls_epoch(&self) -> u64 {
        self.base.id.mls_epoch.saturating_add(1)
    }

    /// `BLAKE3("cygnus-dmls-commit-v1\0" ‖ commit)`.
    #[must_use]
    pub fn commit_id(&self) -> [u8; 32] {
        wire::commit_id(&self.commit)
    }

    /// The extremity this Commit creates, with no DAG hint.
    #[must_use]
    pub fn extremity(&self) -> ExtremityId {
        ExtremityId::new(self.mls_epoch(), self.commit_id())
    }

    /// The event type: [`wire::MERGE_EVENT`] if it resolves more than one
    /// extremity, otherwise [`wire::COMMIT_EVENT`].
    #[must_use]
    pub fn event_type(&self) -> &'static str {
        if self.resolves.len() > 1 {
            wire::MERGE_EVENT
        } else {
            wire::COMMIT_EVENT
        }
    }

    fn validate(&self) -> Result<()> {
        check_epoch(self.base.id.mls_epoch, "base")?;
        check_epoch(self.base.id.mls_epoch.saturating_add(1), "mls_epoch")?;
        if self.commit.is_empty() {
            return Err(ContentError::Malformed("commit"));
        }
        if self.group_info.is_empty() {
            return Err(ContentError::Malformed("group_info"));
        }
        if self.proposals.iter().any(Vec::is_empty) {
            return Err(ContentError::Malformed("proposals"));
        }
        if !self.resolves.iter().any(|item| item.id == self.base.id) {
            return Err(ContentError::Mismatch("resolves"));
        }
        let distinct = self
            .resolves
            .iter()
            .map(|item| item.id)
            .collect::<BTreeSet<_>>();
        if distinct.len() != self.resolves.len() {
            return Err(ContentError::Malformed("resolves"));
        }
        for reference in self.resolves.iter().chain([&self.base]) {
            match &reference.event_id {
                Some(event) => event_id(event, "event_id")?,
                // The genesis base is derivable from the room, so it is the one
                // reference that may omit a DAG hint.
                None if reference.is_genesis(&self.group_id) => {}
                None => return Err(ContentError::Missing("event_id")),
            }
        }
        Ok(())
    }

    /// Parse an `m.dmls.commit` or `m.dmls.merge` content.
    ///
    /// `event_type` selects the `resolves` rule: exactly one entry for a
    /// commit, at least two for a merge. `expected_group_id` is the ID derived
    /// from the room.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a missing or malformed field, a
    /// `group_id`, `commit_id` or `mls_epoch` that disagrees with what the
    /// content implies, or a `resolves` list that breaks the rules in §5.
    pub fn parse(event_type: &str, content: &Value, expected_group_id: &[u8; 32]) -> Result<Self> {
        let group_id = id32(content, "group_id")?;
        if &group_id != expected_group_id {
            return Err(ContentError::Mismatch("group_id"));
        }
        let base = ExtremityRef::parse(field(content, "base")?, false)?;
        let resolves = parse_refs(content, "resolves", 1, false)?;
        let proposals = array(content, "proposals")?
            .iter()
            .map(|item| {
                let text = item.as_str().ok_or(ContentError::Malformed("proposals"))?;
                let decoded = b64_decode(text, "proposals")?;
                if decoded.is_empty() {
                    return Err(ContentError::Malformed("proposals"));
                }
                Ok(decoded)
            })
            .collect::<Result<Vec<_>>>()?;
        let parsed = Self {
            group_id,
            base,
            resolves,
            commit: bytes(content, "commit")?,
            group_info: bytes(content, "group_info")?,
            proposals,
            plan: PlanSummary::parse(field(content, "plan")?)?,
        };
        if epoch(content, "mls_epoch")? != check_epoch(parsed.mls_epoch(), "mls_epoch")? {
            return Err(ContentError::Mismatch("mls_epoch"));
        }
        if id32(content, "commit_id")? != parsed.commit_id() {
            return Err(ContentError::Mismatch("commit_id"));
        }
        parsed.validate()?;
        match (event_type, parsed.resolves.len()) {
            (wire::COMMIT_EVENT, 1) | (wire::MERGE_EVENT, 2..) => {}
            _ => return Err(ContentError::Mismatch("resolves")),
        }
        Ok(parsed)
    }

    /// Build the event content.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] if the content would not parse back, or if it
    /// is larger than [`MAX_CONTENT_BYTES`].
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        let refs = |items: &[ExtremityRef]| -> Result<Value> {
            Ok(Value::Array(
                items
                    .iter()
                    .map(ExtremityRef::to_value)
                    .collect::<Result<_>>()?,
            ))
        };
        finish(object([
            ("group_id", Value::from(b64_encode(&self.group_id))),
            ("mls_epoch", epoch_value(self.mls_epoch(), "mls_epoch")?),
            ("commit_id", Value::from(b64_encode(&self.commit_id()))),
            ("base", self.base.to_value()?),
            ("resolves", refs(&self.resolves)?),
            ("commit", Value::from(b64_encode(&self.commit))),
            ("group_info", Value::from(b64_encode(&self.group_info))),
            (
                "proposals",
                Value::Array(
                    self.proposals
                        .iter()
                        .map(|item| Value::from(b64_encode(item)))
                        .collect(),
                ),
            ),
            ("plan", self.plan.to_value()?),
        ]))
    }
}

/// Content of `m.dmls.key_package`.
///
/// `key_package_id` is derived from [`Self::key_package`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageContent {
    /// The principal and device that own the package.
    pub owner: MemberKey,
    /// The TLS-serialized `KeyPackage`.
    pub key_package: Vec<u8>,
    /// Advisory expiry in milliseconds; the MLS lifetime is authoritative.
    pub expires_ts: Option<u64>,
}

impl KeyPackageContent {
    /// `BLAKE3("cygnus-dmls-key-package-v1\0" ‖ key_package)`.
    #[must_use]
    pub fn key_package_id(&self) -> [u8; 32] {
        wire::key_package_id(&self.key_package)
    }

    /// Parse the content of an `m.dmls.key_package` event.
    ///
    /// `sender` is the principal and certified device of the event envelope;
    /// the content must name the same member.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a missing or malformed field, a recomputed
    /// ID that differs from the declared one, or an owner that is not `sender`.
    pub fn parse(content: &Value, sender: &MemberKey) -> Result<Self> {
        let owner = MemberKey {
            principal: string(content, "principal")?.to_owned(),
            device_id: string(content, "device_id")?.to_owned(),
        };
        require_user(&owner)?;
        if &owner != sender {
            return Err(ContentError::Mismatch("principal"));
        }
        let parsed = Self {
            owner,
            key_package: bytes(content, "key_package")?,
            expires_ts: match content.get("expires_ts") {
                None => None,
                Some(value) => Some(
                    value
                        .as_u64()
                        .filter(|ts| *ts <= MAX_SAFE)
                        .ok_or(ContentError::Malformed("expires_ts"))?,
                ),
            },
        };
        if id32(content, "key_package_id")? != parsed.key_package_id() {
            return Err(ContentError::Mismatch("key_package_id"));
        }
        Ok(parsed)
    }

    /// Build the event content.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for an invalid owner or an oversized package.
    pub fn to_value(&self) -> Result<Value> {
        require_user(&self.owner)?;
        if self.key_package.is_empty() {
            return Err(ContentError::Malformed("key_package"));
        }
        let mut entries = vec![
            ("principal", Value::from(self.owner.principal.as_str())),
            ("device_id", Value::from(self.owner.device_id.as_str())),
            (
                "key_package_id",
                Value::from(b64_encode(&self.key_package_id())),
            ),
            ("key_package", Value::from(b64_encode(&self.key_package))),
        ];
        if let Some(ts) = self.expires_ts {
            entries.push(("expires_ts", epoch_value(ts, "expires_ts")?));
        }
        finish(object(entries))
    }
}

/// Content of the to-device `m.dmls.welcome`.
///
/// `welcome_id` is derived from [`Self::welcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WelcomeContent {
    /// The group the Welcome joins.
    pub group_id: [u8; 32],
    /// The room event carrying the Commit that added the recipient.
    pub commit_event_id: String,
    /// The `commit_id` of that Commit.
    pub commit_id: [u8; 32],
    /// The consumed `KeyPackage`'s ID.
    pub key_package_id: [u8; 32],
    /// The TLS-serialized Welcome `MLSMessage`.
    pub welcome: Vec<u8>,
}

impl WelcomeContent {
    /// `BLAKE3("cygnus-dmls-welcome-v1\0" ‖ welcome)`.
    #[must_use]
    pub fn welcome_id(&self) -> [u8; 32] {
        wire::welcome_id(&self.welcome)
    }

    /// Parse the content of an `m.dmls.welcome` event.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a missing or malformed field, a
    /// `group_id` other than `expected_group_id`, or a `welcome_id` that
    /// differs from the recomputed digest.
    pub fn parse(content: &Value, expected_group_id: &[u8; 32]) -> Result<Self> {
        if &id32(content, "group_id")? != expected_group_id {
            return Err(ContentError::Mismatch("group_id"));
        }
        let commit_event_id = string(content, "commit_event_id")?;
        event_id(commit_event_id, "commit_event_id")?;
        let parsed = Self {
            group_id: id32(content, "group_id")?,
            commit_event_id: commit_event_id.to_owned(),
            commit_id: id32(content, "commit_id")?,
            key_package_id: id32(content, "key_package_id")?,
            welcome: bytes(content, "welcome")?,
        };
        if id32(content, "welcome_id")? != parsed.welcome_id() {
            return Err(ContentError::Mismatch("welcome_id"));
        }
        Ok(parsed)
    }

    /// Build the event content.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a malformed event ID or empty Welcome.
    pub fn to_value(&self) -> Result<Value> {
        event_id(&self.commit_event_id, "commit_event_id")?;
        if self.welcome.is_empty() {
            return Err(ContentError::Malformed("welcome"));
        }
        finish(object([
            ("group_id", Value::from(b64_encode(&self.group_id))),
            (
                "commit_event_id",
                Value::from(self.commit_event_id.as_str()),
            ),
            ("commit_id", Value::from(b64_encode(&self.commit_id))),
            (
                "key_package_id",
                Value::from(b64_encode(&self.key_package_id)),
            ),
            ("welcome_id", Value::from(b64_encode(&self.welcome_id()))),
            ("welcome", Value::from(b64_encode(&self.welcome))),
        ]))
    }
}

/// Content of `m.dmls.external_commit`.
///
/// `mls_epoch` and `commit_id` are derived: `target.mls_epoch + 1` and the
/// digest of [`Self::commit`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalCommitContent {
    /// The room-derived group ID.
    pub group_id: [u8; 32],
    /// The extremity whose `GroupInfo` the joiner used.
    pub target: ExtremityRef,
    /// The TLS-serialized external Commit `MLSMessage`.
    pub commit: Vec<u8>,
    /// The resulting epoch's `GroupInfo` `MLSMessage`, with the ratchet tree.
    pub group_info: Vec<u8>,
    /// The joining principal and device.
    pub joiner: MemberKey,
}

impl ExternalCommitContent {
    /// The epoch of the state this Commit produces.
    #[must_use]
    pub fn mls_epoch(&self) -> u64 {
        self.target.id.mls_epoch.saturating_add(1)
    }

    /// `BLAKE3("cygnus-dmls-commit-v1\0" ‖ commit)`.
    #[must_use]
    pub fn commit_id(&self) -> [u8; 32] {
        wire::commit_id(&self.commit)
    }

    /// The extremity this Commit creates, with no DAG hint.
    #[must_use]
    pub fn extremity(&self) -> ExtremityId {
        ExtremityId::new(self.mls_epoch(), self.commit_id())
    }

    fn validate(&self) -> Result<()> {
        check_epoch(self.target.id.mls_epoch, "target")?;
        check_epoch(self.target.id.mls_epoch.saturating_add(1), "mls_epoch")?;
        match &self.target.event_id {
            Some(event) => event_id(event, "event_id")?,
            None => return Err(ContentError::Missing("event_id")),
        }
        require_user(&self.joiner)?;
        if self.commit.is_empty() {
            return Err(ContentError::Malformed("commit"));
        }
        if self.group_info.is_empty() {
            return Err(ContentError::Malformed("group_info"));
        }
        Ok(())
    }

    /// Parse the content of an `m.dmls.external_commit` event.
    ///
    /// `sender` is the principal and certified device of the event envelope;
    /// the `joiner` must be that member.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a missing or malformed field, a
    /// `group_id`, `commit_id` or `mls_epoch` that disagrees with what the
    /// content implies, or a joiner that is not `sender`.
    pub fn parse(
        content: &Value,
        sender: &MemberKey,
        expected_group_id: &[u8; 32],
    ) -> Result<Self> {
        let group_id = id32(content, "group_id")?;
        if &group_id != expected_group_id {
            return Err(ContentError::Mismatch("group_id"));
        }
        let joiner = field(content, "joiner")?;
        let parsed = Self {
            group_id,
            target: ExtremityRef::parse(field(content, "target")?, true)?,
            commit: bytes(content, "commit")?,
            group_info: bytes(content, "group_info")?,
            joiner: MemberKey {
                principal: string(joiner, "principal")?.to_owned(),
                device_id: string(joiner, "device_id")?.to_owned(),
            },
        };
        parsed.validate()?;
        if &parsed.joiner != sender {
            return Err(ContentError::Mismatch("joiner"));
        }
        if epoch(content, "mls_epoch")? != parsed.mls_epoch() {
            return Err(ContentError::Mismatch("mls_epoch"));
        }
        if id32(content, "commit_id")? != parsed.commit_id() {
            return Err(ContentError::Mismatch("commit_id"));
        }
        Ok(parsed)
    }

    /// Build the event content.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] if the content would not parse back, or if it
    /// is larger than [`MAX_CONTENT_BYTES`].
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        finish(object([
            ("group_id", Value::from(b64_encode(&self.group_id))),
            ("mls_epoch", epoch_value(self.mls_epoch(), "mls_epoch")?),
            ("commit_id", Value::from(b64_encode(&self.commit_id()))),
            ("commit", Value::from(b64_encode(&self.commit))),
            ("group_info", Value::from(b64_encode(&self.group_info))),
            ("target", self.target.to_value()?),
            (
                "joiner",
                object([
                    ("principal", Value::from(self.joiner.principal.as_str())),
                    ("device_id", Value::from(self.joiner.device_id.as_str())),
                ]),
            ),
        ]))
    }
}

/// Content of `m.dmls.reboot`.
///
/// `new_group_id` is derived:
/// `BLAKE3("cygnus-dmls-reboot-v1\0" ‖ old_group_id ‖ base.commit_id)`.
/// Whether the sender and `members` belong to `base` is a caller-side check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebootContent {
    /// The room-derived group being abandoned.
    pub old_group_id: [u8; 32],
    /// Why the rebooter could not continue, e.g. `state-loss`.
    pub reason: String,
    /// The members the rebooter will send a Welcome to.
    pub members: Vec<MemberKey>,
    /// The old-group extremity the reboot starts from; the event ID is required.
    pub base: ExtremityRef,
}

impl RebootContent {
    /// The `group_id` of the replacement group.
    #[must_use]
    pub fn new_group_id(&self) -> [u8; 32] {
        wire::reboot_group_id(&self.old_group_id, &self.base.id.commit_id)
    }

    fn validate(&self) -> Result<()> {
        if self.reason.is_empty() {
            return Err(ContentError::Malformed("reason"));
        }
        if self.base.event_id.is_none() {
            return Err(ContentError::Missing("event_id"));
        }
        self.members.iter().try_for_each(require_user)
    }

    /// Parse the content of an `m.dmls.reboot` event.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a missing or malformed field, an
    /// `old_group_id` other than `expected_group_id`, a `base` without an event
    /// ID, or a `new_group_id` that differs from the recomputed value.
    pub fn parse(content: &Value, expected_group_id: &[u8; 32]) -> Result<Self> {
        let old_group_id = id32(content, "old_group_id")?;
        if &old_group_id != expected_group_id {
            return Err(ContentError::Mismatch("old_group_id"));
        }
        let members = array(content, "members")?
            .iter()
            .map(|item| {
                let text = item.as_str().ok_or(ContentError::Malformed("members"))?;
                MemberKey::parse(text).map_err(|_| ContentError::Malformed("members"))
            })
            .collect::<Result<Vec<_>>>()?;
        let parsed = Self {
            old_group_id,
            reason: string(content, "reason")?.to_owned(),
            members: normalize(members),
            base: ExtremityRef::parse(field(content, "base")?, true)?,
        };
        parsed.validate()?;
        if id32(content, "new_group_id")? != parsed.new_group_id() {
            return Err(ContentError::Mismatch("new_group_id"));
        }
        Ok(parsed)
    }

    /// Build the event content.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] if the content would not parse back, or if it
    /// is larger than [`MAX_CONTENT_BYTES`].
    pub fn to_value(&self) -> Result<Value> {
        self.validate()?;
        let members = normalize(self.members.iter().cloned())
            .iter()
            .map(|key| Value::from(key.to_wire()))
            .collect();
        finish(object([
            ("old_group_id", Value::from(b64_encode(&self.old_group_id))),
            (
                "new_group_id",
                Value::from(b64_encode(&self.new_group_id())),
            ),
            ("reason", Value::from(self.reason.as_str())),
            ("members", Value::Array(members)),
            ("base", self.base.to_value()?),
        ]))
    }
}

/// Content of a DMLS `m.room.encrypted` application message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedContent {
    /// The room-derived group ID.
    pub group_id: [u8; 32],
    /// The epoch the message was encrypted in.
    pub mls_epoch: u64,
    /// A display hint; the authoritative sender is the MLS leaf.
    pub sender_device: String,
    /// The TLS-serialized `PrivateMessage` `MLSMessage`.
    pub ciphertext: Vec<u8>,
}

impl EncryptedContent {
    /// Parse the content of a DMLS `m.room.encrypted` event.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for a missing or malformed field, an
    /// algorithm other than [`wire::ALGORITHM`], or a `group_id` that is not
    /// `expected_group_id`.
    pub fn parse(content: &Value, expected_group_id: &[u8; 32]) -> Result<Self> {
        if string(content, "algorithm")? != wire::ALGORITHM {
            return Err(ContentError::Mismatch("algorithm"));
        }
        let group_id = id32(content, "group_id")?;
        if &group_id != expected_group_id {
            return Err(ContentError::Mismatch("group_id"));
        }
        let sender_device = string(content, "sender_device")?;
        if sender_device.is_empty() {
            return Err(ContentError::Malformed("sender_device"));
        }
        Ok(Self {
            group_id,
            mls_epoch: epoch(content, "mls_epoch")?,
            sender_device: sender_device.to_owned(),
            ciphertext: bytes(content, "ciphertext")?,
        })
    }

    /// Build the event content.
    ///
    /// # Errors
    ///
    /// Returns a [`ContentError`] for an out-of-range epoch, an empty field, or
    /// a ciphertext that does not fit in one event.
    pub fn to_value(&self) -> Result<Value> {
        if self.sender_device.is_empty() {
            return Err(ContentError::Malformed("sender_device"));
        }
        if self.ciphertext.is_empty() {
            return Err(ContentError::Malformed("ciphertext"));
        }
        finish(object([
            ("algorithm", Value::from(wire::ALGORITHM)),
            ("group_id", Value::from(b64_encode(&self.group_id))),
            ("mls_epoch", epoch_value(self.mls_epoch, "mls_epoch")?),
            ("sender_device", Value::from(self.sender_device.as_str())),
            ("ciphertext", Value::from(b64_encode(&self.ciphertext))),
        ]))
    }
}

/// Build the §13 application plaintext: canonical JSON
/// `{"room_id", "type", "content"}`.
///
/// # Errors
///
/// [`ContentError::Malformed`] if `content` is not a JSON object or `inner_type`
/// is empty, [`ContentError::Canonical`] if it cannot be serialized.
pub fn application_plaintext(room_id: &str, inner_type: &str, content: &Value) -> Result<Vec<u8>> {
    if inner_type.is_empty() {
        return Err(ContentError::Malformed("type"));
    }
    if !matches!(content, Value::Object(_)) {
        return Err(ContentError::Malformed("content"));
    }
    let value = object([
        ("room_id", Value::from(room_id)),
        ("type", Value::from(inner_type)),
        ("content", content.clone()),
    ]);
    to_canonical_string(&value)
        .map(String::into_bytes)
        .map_err(|_| ContentError::Canonical)
}

/// Parse a decrypted §13 plaintext and bind it to `expected_room`.
///
/// Returns the inner event type and content.
///
/// # Errors
///
/// [`ContentError`] for non-canonical or non-JSON bytes, a missing or extra
/// field, or a `room_id` other than `expected_room` (`mismatch:room_id`), which
/// is what stops a ciphertext replayed into another room.
pub fn parse_application_plaintext(
    plaintext: &[u8],
    expected_room: &str,
) -> Result<(String, Value)> {
    let text = std::str::from_utf8(plaintext).map_err(|_| ContentError::Malformed("plaintext"))?;
    let value = Value::parse_strict(text).map_err(|_| ContentError::Malformed("plaintext"))?;
    let Value::Object(entries) = &value else {
        return Err(ContentError::Malformed("plaintext"));
    };
    if entries.len() != 3 {
        return Err(ContentError::Malformed("plaintext"));
    }
    if string(&value, "room_id")? != expected_room {
        return Err(ContentError::Mismatch("room_id"));
    }
    let inner_type = string(&value, "type")?;
    if inner_type.is_empty() {
        return Err(ContentError::Malformed("type"));
    }
    let content = field(&value, "content")?;
    if !matches!(content, Value::Object(_)) {
        return Err(ContentError::Malformed("content"));
    }
    Ok((inner_type.to_owned(), content.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "!room:example.org";
    const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";
    const BOB: &str = "@xEw0nI6Ms4QXQpTGgOPxVJwqXUZ-SYfbVXkjB0GbJZs";

    fn member(principal: &str, device: &str) -> MemberKey {
        MemberKey::parse(&format!("{principal}:{device}")).unwrap()
    }

    fn reference(epoch: u64, byte: u8, event: &str) -> ExtremityRef {
        ExtremityRef::new(ExtremityId::new(epoch, [byte; 32]), event)
    }

    fn commit() -> CommitContent {
        CommitContent {
            group_id: wire::group_id(ROOM),
            base: reference(6, 0xd4, "$abc"),
            resolves: vec![reference(6, 0xd4, "$abc")],
            commit: b"commit message".to_vec(),
            group_info: b"group info".to_vec(),
            proposals: vec![],
            plan: PlanSummary {
                adds: vec![member(BOB, "BOB1")],
                ..PlanSummary::default()
            },
        }
    }

    fn merge() -> CommitContent {
        let mut content = commit();
        content.resolves.push(reference(6, 0x9b, "$def"));
        content.plan = PlanSummary {
            removes: vec![member(ALICE, "D1")],
            required_self_updates: vec![member(BOB, "D2")],
            ..PlanSummary::default()
        };
        content
    }

    /// Apply `edit` to the JSON built from `content` and return it.
    fn tampered(content: &Value, edit: impl FnOnce(&mut Object)) -> Value {
        let mut value = content.clone();
        edit(value.as_object_mut().unwrap());
        value
    }

    fn set(key: &str, value: Value) -> impl FnOnce(&mut Object) + '_ {
        move |object| {
            object.insert(key.to_owned(), value);
        }
    }

    fn unset(key: &str) -> impl FnOnce(&mut Object) + '_ {
        move |object| {
            object.remove(key);
        }
    }

    #[test]
    fn reboot_round_trips_and_recomputes_the_new_group() {
        let group = wire::group_id(ROOM);
        let content = RebootContent {
            old_group_id: group,
            reason: "state-loss".into(),
            members: vec![member(BOB, "BOB1"), member(ALICE, "D1")],
            base: reference(9, 0x44, "$base"),
        };
        assert_eq!(
            content.new_group_id(),
            wire::reboot_group_id(&group, &[0x44; 32])
        );
        assert_ne!(content.new_group_id(), group);
        let value = content.to_value().unwrap();
        let parsed = RebootContent::parse(&value, &group).unwrap();
        assert_eq!(parsed.members.len(), 2);
        assert_eq!(parsed.new_group_id(), content.new_group_id());

        let wrong = set("new_group_id", Value::from(b64_encode(&[1; 32])));
        assert_eq!(
            RebootContent::parse(&tampered(&value, wrong), &group),
            Err(ContentError::Mismatch("new_group_id"))
        );
        let other = set("old_group_id", Value::from(b64_encode(&[1; 32])));
        assert_eq!(
            RebootContent::parse(&tampered(&value, other), &group),
            Err(ContentError::Mismatch("old_group_id"))
        );
        let mut base = value["base"].clone();
        base.as_object_mut().unwrap().remove("event_id");
        assert_eq!(
            RebootContent::parse(&tampered(&value, set("base", base)), &group),
            Err(ContentError::Missing("event_id"))
        );
        let bad_members = set("members", Value::Array(vec![Value::from("@bob:x")]));
        assert_eq!(
            RebootContent::parse(&tampered(&value, bad_members), &group),
            Err(ContentError::Malformed("members"))
        );
        assert_eq!(
            RebootContent::parse(&tampered(&value, unset("reason")), &group),
            Err(ContentError::Missing("reason"))
        );
        let mut bad = content;
        bad.reason.clear();
        assert_eq!(bad.to_value(), Err(ContentError::Malformed("reason")));
    }

    #[test]
    fn epoch_accessors_do_not_overflow() {
        let mut content = commit();
        content.base = reference(u64::MAX, 1, "$x");
        content.resolves = vec![content.base.clone()];
        assert_eq!(content.mls_epoch(), u64::MAX);
        assert!(content.to_value().is_err());
    }

    #[test]
    fn base64_is_strict() {
        assert_eq!(b64_decode("AAEC", "f").unwrap(), [0, 1, 2]);
        assert_eq!(b64_encode(&[0, 1, 2]), "AAEC");
        // Padding, the standard alphabet and non-zero trailing bits all fail.
        for bad in ["AAE=", "AA+/", "AAF", "AB"] {
            assert_eq!(
                b64_decode(bad, "f"),
                Err(ContentError::Malformed("f")),
                "{bad}"
            );
        }
        assert_eq!(b64_decode("", "f").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn commit_round_trips_and_derives_its_fields() {
        let content = commit();
        let value = content.to_value().unwrap();
        assert_eq!(value["mls_epoch"].as_u64(), Some(7));
        assert_eq!(
            value["commit_id"].as_str().unwrap(),
            b64_encode(&wire::commit_id(b"commit message"))
        );
        assert_eq!(content.event_type(), wire::COMMIT_EVENT);
        assert_eq!(
            CommitContent::parse(wire::COMMIT_EVENT, &value, &wire::group_id(ROOM)).unwrap(),
            content
        );
        // Re-serializing the parse is byte-identical.
        let text = to_canonical_string(&value).unwrap();
        let reparsed = Value::parse_strict(&text).unwrap();
        assert_eq!(to_canonical_string(&reparsed).unwrap(), text);
    }

    #[test]
    fn first_commit_may_name_the_genesis_base_without_an_event_id() {
        let group = wire::group_id(ROOM);
        let genesis = ExtremityRef::genesis(&group);
        assert!(genesis.is_genesis(&group));
        let content = CommitContent {
            group_id: group,
            base: genesis.clone(),
            resolves: vec![genesis],
            commit: b"first commit".to_vec(),
            group_info: b"group info".to_vec(),
            proposals: vec![],
            plan: PlanSummary::default(),
        };
        let value = content.to_value().unwrap();
        assert_eq!(value["mls_epoch"].as_u64(), Some(1));
        assert!(value["base"].get("event_id").is_none());
        assert_eq!(
            CommitContent::parse(wire::COMMIT_EVENT, &value, &group).unwrap(),
            content
        );

        // Only the group's genesis may omit the hint: another epoch-0 id, or
        // the genesis id in a non-genesis slot, is rejected.
        let forged = ExtremityRef {
            id: ExtremityId::new(0, [0x11; 32]),
            event_id: None,
        };
        let mut bad = content.clone();
        bad.base = forged.clone();
        bad.resolves = vec![forged];
        assert_eq!(bad.to_value(), Err(ContentError::Missing("event_id")));

        // A genesis reference is still group-scoped.
        let mut foreign = content.clone();
        foreign.base = ExtremityRef::genesis(&wire::group_id("!other:x"));
        foreign.resolves = vec![foreign.base.clone()];
        assert_eq!(foreign.to_value(), Err(ContentError::Missing("event_id")));
    }

    #[test]
    fn merge_round_trips_and_requires_two_resolves() {
        let content = merge();
        assert_eq!(content.event_type(), wire::MERGE_EVENT);
        let value = content.to_value().unwrap();
        let group = wire::group_id(ROOM);
        assert_eq!(
            CommitContent::parse(wire::MERGE_EVENT, &value, &group).unwrap(),
            content
        );
        // The same content under the other event type breaks the arity rule.
        assert_eq!(
            CommitContent::parse(wire::COMMIT_EVENT, &value, &group),
            Err(ContentError::Mismatch("resolves"))
        );
        assert_eq!(
            CommitContent::parse(wire::MERGE_EVENT, &commit().to_value().unwrap(), &group),
            Err(ContentError::Mismatch("resolves"))
        );
        assert_eq!(
            CommitContent::parse(wire::REBOOT_EVENT, &value, &group),
            Err(ContentError::Mismatch("resolves"))
        );
    }

    #[test]
    fn commit_rejects_tampering() {
        let group = wire::group_id(ROOM);
        let good = merge().to_value().unwrap();
        let parse = |value: &Value| CommitContent::parse(wire::MERGE_EVENT, value, &group);
        assert!(parse(&good).is_ok());

        // Wrong digest: the declared commit_id is never trusted.
        let wrong_digest = set("commit_id", Value::from(b64_encode(&[7; 32])));
        assert_eq!(
            parse(&tampered(&good, wrong_digest)),
            Err(ContentError::Mismatch("commit_id"))
        );
        // Swapped commit bytes with the old commit_id.
        let swapped = set("commit", Value::from(b64_encode(b"other commit")));
        assert_eq!(
            parse(&tampered(&good, swapped)),
            Err(ContentError::Mismatch("commit_id"))
        );
        // Wrong epoch: neither a skip nor a step back.
        for epoch in [6_u64, 8, 0] {
            assert_eq!(
                parse(&tampered(&good, set("mls_epoch", Value::from(epoch)))),
                Err(ContentError::Mismatch("mls_epoch"))
            );
        }
        // Wrong room.
        assert_eq!(
            CommitContent::parse(wire::MERGE_EVENT, &good, &wire::group_id("!other:x")),
            Err(ContentError::Mismatch("group_id"))
        );
        let short_group = set("group_id", Value::from(b64_encode(&[1; 16])));
        assert_eq!(
            parse(&tampered(&good, short_group)),
            Err(ContentError::Malformed("group_id"))
        );
        // Missing required fields.
        for name in [
            "base",
            "resolves",
            "commit",
            "group_info",
            "plan",
            "proposals",
        ] {
            assert_eq!(
                parse(&tampered(&good, unset(name))),
                Err(ContentError::Missing(name))
            );
        }
    }

    #[test]
    fn commit_rejects_bad_references() {
        let group = wire::group_id(ROOM);
        let good = merge().to_value().unwrap();
        let parse = |value: &Value| CommitContent::parse(wire::MERGE_EVENT, value, &group);

        // `resolves` that omits `base`.
        let other = ExtremityRef::new(ExtremityId::new(6, [0x01; 32]), "$x")
            .to_value()
            .unwrap();
        let omits_base = Value::Array(vec![other.clone(), other.clone()]);
        assert_eq!(
            parse(&tampered(&good, set("resolves", omits_base))),
            Err(ContentError::Mismatch("resolves"))
        );
        // A merge whose duplicates collapse below two entries.
        let base = ExtremityRef::new(ExtremityId::new(6, [0xd4; 32]), "$abc")
            .to_value()
            .unwrap();
        let duplicated = Value::Array(vec![base.clone(), base.clone()]);
        assert_eq!(
            parse(&tampered(&good, set("resolves", duplicated))),
            Err(ContentError::Mismatch("resolves"))
        );
        // An empty `resolves`.
        assert_eq!(
            parse(&tampered(&good, set("resolves", Value::Array(vec![])))),
            Err(ContentError::Malformed("resolves"))
        );
        // The DAG hint is required in room events and must look like an event ID.
        let mut no_hint = base.clone();
        no_hint.as_object_mut().unwrap().remove("event_id");
        assert_eq!(
            parse(&tampered(&good, set("base", no_hint))),
            Err(ContentError::Missing("event_id"))
        );
        let mut bad_hint = base;
        bad_hint
            .as_object_mut()
            .unwrap()
            .insert("event_id".into(), Value::from("abc"));
        assert_eq!(
            parse(&tampered(&good, set("base", bad_hint))),
            Err(ContentError::Malformed("event_id"))
        );
    }

    #[test]
    fn plan_member_keys_are_validated_and_normalized() {
        let group = wire::group_id(ROOM);
        let good = commit().to_value().unwrap();
        let parse = |value: &Value| CommitContent::parse(wire::COMMIT_EVENT, value, &group);
        let with_adds = |adds: Vec<Value>| {
            let mut plan = good["plan"].clone();
            plan.as_object_mut()
                .unwrap()
                .insert("adds".into(), Value::Array(adds));
            tampered(&good, set("plan", plan))
        };

        for bad in [
            "no-colon",
            "~server:DEV",
            &format!("{ALICE}:"),
            "@short:DEV",
        ] {
            assert_eq!(
                parse(&with_adds(vec![Value::from(bad)])),
                Err(ContentError::Malformed("adds")),
                "{bad}"
            );
        }
        assert_eq!(
            parse(&with_adds(vec![Value::from(7_u64)])),
            Err(ContentError::Malformed("adds"))
        );

        // Order and duplicates do not change the parsed plan.
        let a = Value::from(format!("{ALICE}:A1"));
        let b = Value::from(format!("{BOB}:B1"));
        let one = parse(&with_adds(vec![b.clone(), a.clone(), b.clone()])).unwrap();
        let two = parse(&with_adds(vec![a, b])).unwrap();
        assert_eq!(one.plan, two.plan);
        assert_eq!(one.plan.adds.len(), 2);

        // A plan missing a list is rejected.
        let mut plan = good["plan"].clone();
        plan.as_object_mut().unwrap().remove("removes");
        assert_eq!(
            parse(&tampered(&good, set("plan", plan))),
            Err(ContentError::Missing("removes"))
        );
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let group = wire::group_id(ROOM);
        let good = commit().to_value().unwrap();
        let extra = tampered(&good, set("future_field", Value::from(1_u64)));
        assert_eq!(
            CommitContent::parse(wire::COMMIT_EVENT, &extra, &group).unwrap(),
            commit()
        );
    }

    #[test]
    fn commit_builder_refuses_what_the_parser_would() {
        let mut content = commit();
        content.resolves = vec![reference(6, 0x01, "$x")];
        assert_eq!(content.to_value(), Err(ContentError::Mismatch("resolves")));

        let mut content = commit();
        content.base.id.mls_epoch = MAX_SAFE;
        content.resolves[0].id.mls_epoch = MAX_SAFE;
        assert_eq!(
            content.to_value(),
            Err(ContentError::Malformed("mls_epoch"))
        );

        let mut content = commit();
        content.commit.clear();
        assert_eq!(content.to_value(), Err(ContentError::Malformed("commit")));

        let mut content = commit();
        content.base.event_id = None;
        assert_eq!(content.to_value(), Err(ContentError::Missing("event_id")));

        let mut content = commit();
        content.plan.adds = vec![MemberKey {
            principal: "~server".into(),
            device_id: "D".into(),
        }];
        assert_eq!(content.to_value(), Err(ContentError::Malformed("member")));
    }

    #[test]
    fn the_size_cap_bounds_the_group_info() {
        let mut content = commit();
        content.group_info = vec![0xab; MAX_CONTENT_BYTES];
        assert_eq!(content.to_value(), Err(ContentError::TooLarge));
        // The cap is on the encoded content, which is 4/3 of the raw bytes.
        content.group_info = vec![0xab; MAX_CONTENT_BYTES * 3 / 4 - 1_000];
        assert!(content.to_value().is_ok());
    }

    #[test]
    fn plan_summary_comes_from_a_merge_plan() {
        let id = |principal: &str, device: &str| MemberId::new(principal.as_bytes(), device);
        let plan = MergePlan {
            base: ExtremityId::new(6, [1; 32]),
            members: std::collections::BTreeMap::new(),
            required_self_updates: vec![id(BOB, "B2")],
            adds: vec![],
            removes: vec![id(BOB, "B1"), id(ALICE, "A1"), id(BOB, "B1")],
            orphaned_external_joiners: vec![],
        };
        let summary = PlanSummary::from_plan(&plan).unwrap();
        assert_eq!(summary.removes, [member(ALICE, "A1"), member(BOB, "B1")]);
        assert_eq!(summary.required_self_updates, [member(BOB, "B2")]);
        assert!(summary.adds.is_empty());

        let bad = MergePlan {
            removes: vec![MemberId::new(b"not a principal".as_slice(), "D")],
            ..plan.clone()
        };
        assert_eq!(
            PlanSummary::from_plan(&bad),
            Err(ContentError::Malformed("member"))
        );
        let non_utf8 = MergePlan {
            removes: vec![MemberId::new(vec![0xff, 0xfe], "D")],
            ..plan
        };
        assert_eq!(
            PlanSummary::from_plan(&non_utf8),
            Err(ContentError::Malformed("member"))
        );
    }

    #[test]
    fn key_package_round_trips_and_binds_the_sender() {
        let alice = member(ALICE, "ALICE1");
        let content = KeyPackageContent {
            owner: alice.clone(),
            key_package: b"key package".to_vec(),
            expires_ts: Some(1_794_000_000_000),
        };
        let value = content.to_value().unwrap();
        assert_eq!(KeyPackageContent::parse(&value, &alice).unwrap(), content);

        // Optional expiry.
        let no_expiry = KeyPackageContent {
            expires_ts: None,
            ..content.clone()
        };
        let bare = no_expiry.to_value().unwrap();
        assert_eq!(KeyPackageContent::parse(&bare, &alice).unwrap(), no_expiry);

        // The package must belong to the event's sender and certified device.
        for other in [member(BOB, "ALICE1"), member(ALICE, "ALICE2")] {
            assert_eq!(
                KeyPackageContent::parse(&value, &other),
                Err(ContentError::Mismatch("principal"))
            );
        }
        // key_package_id is recomputed.
        let wrong = set("key_package_id", Value::from(b64_encode(&[9; 32])));
        assert_eq!(
            KeyPackageContent::parse(&tampered(&value, wrong), &alice),
            Err(ContentError::Mismatch("key_package_id"))
        );
        let swapped = set("key_package", Value::from(b64_encode(b"another")));
        assert_eq!(
            KeyPackageContent::parse(&tampered(&value, swapped), &alice),
            Err(ContentError::Mismatch("key_package_id"))
        );
        // Malformed or missing fields.
        assert_eq!(
            KeyPackageContent::parse(&tampered(&value, unset("device_id")), &alice),
            Err(ContentError::Missing("device_id"))
        );
        assert_eq!(
            KeyPackageContent::parse(
                &tampered(&value, set("expires_ts", Value::from("x"))),
                &alice
            ),
            Err(ContentError::Malformed("expires_ts"))
        );
        let placeholder = set("principal", Value::from("@alice:chat.example.org"));
        assert_eq!(
            KeyPackageContent::parse(&tampered(&value, placeholder), &alice),
            Err(ContentError::Malformed("member"))
        );
        // The builder refuses an empty package and an out-of-range expiry.
        let mut bad = content.clone();
        bad.key_package.clear();
        assert_eq!(bad.to_value(), Err(ContentError::Malformed("key_package")));
        let mut bad = content;
        bad.expires_ts = Some(MAX_SAFE + 1);
        assert_eq!(bad.to_value(), Err(ContentError::Malformed("expires_ts")));
    }

    #[test]
    fn welcome_round_trips_and_recomputes_its_id() {
        let content = WelcomeContent {
            group_id: wire::group_id(ROOM),
            commit_event_id: "$commit".into(),
            commit_id: [3; 32],
            key_package_id: [4; 32],
            welcome: b"welcome".to_vec(),
        };
        let value = content.to_value().unwrap();
        assert_eq!(
            WelcomeContent::parse(&value, &wire::group_id(ROOM)).unwrap(),
            content
        );

        let wrong = set("welcome_id", Value::from(b64_encode(&[5; 32])));
        assert_eq!(
            WelcomeContent::parse(&tampered(&value, wrong), &wire::group_id(ROOM)),
            Err(ContentError::Mismatch("welcome_id"))
        );
        let swapped = set("welcome", Value::from(b64_encode(b"different")));
        assert_eq!(
            WelcomeContent::parse(&tampered(&value, swapped), &wire::group_id(ROOM)),
            Err(ContentError::Mismatch("welcome_id"))
        );
        assert_eq!(
            WelcomeContent::parse(
                &tampered(&value, unset("commit_event_id")),
                &wire::group_id(ROOM)
            ),
            Err(ContentError::Missing("commit_event_id"))
        );
        assert_eq!(
            WelcomeContent::parse(
                &tampered(&value, set("commit_event_id", Value::from("c"))),
                &wire::group_id(ROOM)
            ),
            Err(ContentError::Malformed("commit_event_id"))
        );
        let other = set("group_id", Value::from(b64_encode(&[9; 32])));
        assert_eq!(
            WelcomeContent::parse(&tampered(&value, other), &wire::group_id(ROOM)),
            Err(ContentError::Mismatch("group_id"))
        );
        let mut bad = content;
        bad.welcome.clear();
        assert_eq!(bad.to_value(), Err(ContentError::Malformed("welcome")));
    }

    fn external() -> ExternalCommitContent {
        ExternalCommitContent {
            group_id: wire::group_id(ROOM),
            target: reference(7, 0x77, "$target"),
            commit: b"external commit".to_vec(),
            group_info: b"group info".to_vec(),
            joiner: member(BOB, "BOB1"),
        }
    }

    #[test]
    fn external_commit_round_trips_and_checks_epoch_and_joiner() {
        let group = wire::group_id(ROOM);
        let joiner = member(BOB, "BOB1");
        let content = external();
        let value = content.to_value().unwrap();
        assert_eq!(value["mls_epoch"].as_u64(), Some(8));
        assert_eq!(
            ExternalCommitContent::parse(&value, &joiner, &group).unwrap(),
            content
        );
        assert_eq!(content.extremity().mls_epoch, 8);

        // The joiner must be the event's sender and device.
        for other in [member(ALICE, "BOB1"), member(BOB, "BOB2")] {
            assert_eq!(
                ExternalCommitContent::parse(&value, &other, &group),
                Err(ContentError::Mismatch("joiner"))
            );
        }
        for epoch in [7_u64, 9] {
            assert_eq!(
                ExternalCommitContent::parse(
                    &tampered(&value, set("mls_epoch", Value::from(epoch))),
                    &joiner,
                    &group
                ),
                Err(ContentError::Mismatch("mls_epoch"))
            );
        }
        let wrong = set("commit_id", Value::from(b64_encode(&[1; 32])));
        assert_eq!(
            ExternalCommitContent::parse(&tampered(&value, wrong), &joiner, &group),
            Err(ContentError::Mismatch("commit_id"))
        );
        assert_eq!(
            ExternalCommitContent::parse(&value, &joiner, &wire::group_id("!other:x")),
            Err(ContentError::Mismatch("group_id"))
        );
        for name in ["target", "joiner", "commit", "group_info"] {
            assert!(
                matches!(
                    ExternalCommitContent::parse(&tampered(&value, unset(name)), &joiner, &group),
                    Err(ContentError::Missing(_))
                ),
                "{name}"
            );
        }
        // A target without a DAG hint cannot be checked, so it is rejected.
        let mut bare = content.clone();
        bare.target.event_id = None;
        assert_eq!(bare.to_value(), Err(ContentError::Missing("event_id")));
        let mut service = content;
        service.joiner = MemberKey {
            principal: "~server".into(),
            device_id: "D".into(),
        };
        assert_eq!(service.to_value(), Err(ContentError::Malformed("member")));
    }

    #[test]
    fn encrypted_content_round_trips_and_checks_algorithm() {
        let group = wire::group_id(ROOM);
        let content = EncryptedContent {
            group_id: group,
            mls_epoch: 7,
            sender_device: "ALICE1".into(),
            ciphertext: b"ciphertext".to_vec(),
        };
        let value = content.to_value().unwrap();
        assert_eq!(value["algorithm"], wire::ALGORITHM);
        assert_eq!(EncryptedContent::parse(&value, &group).unwrap(), content);

        let megolm = set("algorithm", Value::from("m.megolm.v1.aes-sha2"));
        assert_eq!(
            EncryptedContent::parse(&tampered(&value, megolm), &group),
            Err(ContentError::Mismatch("algorithm"))
        );
        assert_eq!(
            EncryptedContent::parse(&value, &wire::group_id("!other:x")),
            Err(ContentError::Mismatch("group_id"))
        );
        assert_eq!(
            EncryptedContent::parse(&tampered(&value, unset("ciphertext")), &group),
            Err(ContentError::Missing("ciphertext"))
        );
        let empty_device = set("sender_device", Value::from(""));
        assert_eq!(
            EncryptedContent::parse(&tampered(&value, empty_device), &group),
            Err(ContentError::Malformed("sender_device"))
        );
        let float = set("mls_epoch", Value::parse("7.5").unwrap());
        assert_eq!(
            EncryptedContent::parse(&tampered(&value, float), &group),
            Err(ContentError::Malformed("mls_epoch"))
        );
        let mut bad = content.clone();
        bad.sender_device.clear();
        assert_eq!(
            bad.to_value(),
            Err(ContentError::Malformed("sender_device"))
        );
        let mut bad = content.clone();
        bad.ciphertext.clear();
        assert_eq!(bad.to_value(), Err(ContentError::Malformed("ciphertext")));
        let mut bad = content;
        bad.mls_epoch = MAX_SAFE + 1;
        assert_eq!(bad.to_value(), Err(ContentError::Malformed("mls_epoch")));
    }

    #[test]
    fn extremity_ref_round_trips() {
        let with_hint = reference(3, 0x33, "$e");
        assert_eq!(
            ExtremityRef::parse(&with_hint.to_value().unwrap(), true).unwrap(),
            with_hint
        );
        let bare = ExtremityRef {
            event_id: None,
            ..with_hint
        };
        let value = bare.to_value().unwrap();
        assert_eq!(ExtremityRef::parse(&value, false).unwrap(), bare);
        assert_eq!(
            ExtremityRef::parse(&value, true),
            Err(ContentError::Missing("event_id"))
        );
        let numeric = tampered(&value, set("event_id", Value::from(5_u64)));
        assert_eq!(
            ExtremityRef::parse(&numeric, false),
            Err(ContentError::Malformed("event_id"))
        );
        let huge = tampered(&value, set("mls_epoch", Value::from(MAX_SAFE + 1)));
        assert_eq!(
            ExtremityRef::parse(&huge, false),
            Err(ContentError::Malformed("mls_epoch"))
        );
    }

    #[test]
    fn application_plaintext_round_trips_and_binds_the_room() {
        let content = Value::parse_strict(r#"{"body":"hi","msgtype":"m.text"}"#).unwrap();
        let bytes = application_plaintext(ROOM, "m.room.message", &content).unwrap();
        let (kind, parsed) = parse_application_plaintext(&bytes, ROOM).unwrap();
        assert_eq!((kind.as_str(), &parsed), ("m.room.message", &content));
        assert_eq!(
            parse_application_plaintext(&bytes, "!other:example.org").unwrap_err(),
            ContentError::Mismatch("room_id")
        );
        // Extra fields, non-objects and non-canonical input are refused.
        assert!(parse_application_plaintext(
            br#"{"a":1,"content":{},"room_id":"!room:example.org","type":"t"}"#,
            ROOM
        )
        .is_err());
        assert!(parse_application_plaintext(b"[]", ROOM).is_err());
        assert!(parse_application_plaintext(b"\xff", ROOM).is_err());
        assert!(application_plaintext(ROOM, "", &content).is_err());
        assert!(application_plaintext(ROOM, "t", &Value::from("x")).is_err());
    }
}
