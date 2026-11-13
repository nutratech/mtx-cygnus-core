//! Matrix transport constants and identifier derivations for DMLS.
//!
//! The event schemas and rules are specified in MSC00FD
//! (`proposals/00FD-dmls-matrix-transport.md`). This module owns the parts that
//! every implementation must compute identically: the event type names, the
//! capability flag in `m.room.create`, and the domain-separated BLAKE3
//! identifiers.
//!
//! Matrix PDU content and reference hashes stay SHA-256. Only the DMLS object
//! identifiers below use BLAKE3.

use cygnus_core::{Kind, Principal};
use rezzy_json::Value;

/// Application-message algorithm in `m.room.encrypted`.
pub const ALGORITHM: &str = "tk.nutra.cygnus.dmls.v1";

/// Message event carrying one single-use `KeyPackage`.
pub const KEY_PACKAGE_EVENT: &str = "m.dmls.key_package";
/// Message event carrying a one-parent MLS Commit.
pub const COMMIT_EVENT: &str = "m.dmls.commit";
/// Message event carrying a Commit that resolves more than one extremity.
pub const MERGE_EVENT: &str = "m.dmls.merge";
/// Message event carrying an external-commit join.
pub const EXTERNAL_COMMIT_EVENT: &str = "m.dmls.external_commit";
/// Message event starting a replacement group after state loss.
pub const REBOOT_EVENT: &str = "m.dmls.reboot";
/// To-device event carrying a Welcome for one `KeyPackage`.
pub const WELCOME_EVENT: &str = "m.dmls.welcome";
/// State event carrying an MSC00FC device root.
pub const DEVICE_ROOT_EVENT: &str = "m.room.device_root";
/// Message event carrying DMLS application ciphertext.
pub const ENCRYPTED_EVENT: &str = "m.room.encrypted";

/// `m.room.create` content key that opts a Cygnus room into DMLS.
pub const CREATE_CAPABILITY: &str = "tk.nutra.cygnus.dmls";

const GROUP_TAG: &[u8] = b"cygnus-dmls-group-v1\0";
const COMMIT_TAG: &[u8] = b"cygnus-dmls-commit-v1\0";
const KEY_PACKAGE_TAG: &[u8] = b"cygnus-dmls-key-package-v1\0";
const WELCOME_TAG: &[u8] = b"cygnus-dmls-welcome-v1\0";
const GROUP_INFO_TAG: &[u8] = b"cygnus-dmls-group-info-v1\0";
const REBOOT_TAG: &[u8] = b"cygnus-dmls-reboot-v1\0";

/// A malformed DMLS transport value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireError {
    /// A `"<principal>:<device_id>"` member key is malformed.
    #[error("malformed DMLS member key")]
    MemberKey,
}

fn tagged(tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(tag);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

/// `BLAKE3("cygnus-dmls-group-v1\0" ‖ room_id)`.
///
/// All members derive the same `group_id` from the Matrix room ID, so no extra
/// event is needed to establish it.
#[must_use]
pub fn group_id(room_id: &str) -> [u8; 32] {
    tagged(GROUP_TAG, room_id.as_bytes())
}

/// `BLAKE3("cygnus-dmls-commit-v1\0" ‖ mls_message_bytes)`.
#[must_use]
pub fn commit_id(mls_message_bytes: &[u8]) -> [u8; 32] {
    tagged(COMMIT_TAG, mls_message_bytes)
}

/// `BLAKE3("cygnus-dmls-key-package-v1\0" ‖ key_package_bytes)`.
#[must_use]
pub fn key_package_id(key_package_bytes: &[u8]) -> [u8; 32] {
    tagged(KEY_PACKAGE_TAG, key_package_bytes)
}

/// `BLAKE3("cygnus-dmls-welcome-v1\0" ‖ welcome_bytes)`.
#[must_use]
pub fn welcome_id(welcome_bytes: &[u8]) -> [u8; 32] {
    tagged(WELCOME_TAG, welcome_bytes)
}

/// `BLAKE3("cygnus-dmls-group-info-v1\0" ‖ group_info_bytes)`.
#[must_use]
pub fn group_info_id(group_info_bytes: &[u8]) -> [u8; 32] {
    tagged(GROUP_INFO_TAG, group_info_bytes)
}

/// `BLAKE3("cygnus-dmls-reboot-v1\0" ‖ old_group_id ‖ base_commit_id)`.
///
/// The `group_id` of the replacement group an `m.dmls.reboot` starts.
#[must_use]
pub fn reboot_group_id(old_group_id: &[u8; 32], base_commit_id: &[u8; 32]) -> [u8; 32] {
    let mut input = [0_u8; 64];
    input[..32].copy_from_slice(old_group_id);
    input[32..].copy_from_slice(base_commit_id);
    tagged(REBOOT_TAG, &input)
}

/// The DMLS capability version advertised by an `m.room.create` content, if any.
#[must_use]
pub fn dmls_version(create_content: &Value) -> Option<i64> {
    create_content
        .get(CREATE_CAPABILITY)
        .and_then(Value::as_object)
        .and_then(|capability| capability.get("version"))
        .and_then(Value::as_i64)
}

/// Whether this `m.room.create` content opts the room into DMLS version 1.
///
/// A Cygnus room without this object keeps the legacy Matrix E2EE path.
#[must_use]
pub fn room_uses_dmls(create_content: &Value) -> bool {
    dmls_version(create_content) == Some(1)
}

/// A `"<principal>:<device_id>"` member key used in `plan` metadata.
///
/// The principal never contains `:`, so the split is at the last colon. This is
/// the same pair as [`crate::MemberIdentity`], but in the compact transport form.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberKey {
    /// Canonical user principal.
    pub principal: String,
    /// Matrix device ID.
    pub device_id: String,
}

impl MemberKey {
    /// Parse `"<principal>:<device_id>"`.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::MemberKey`] if the value has no colon, the
    /// principal is not a canonical user principal, or the device ID is empty.
    pub fn parse(value: &str) -> Result<Self, WireError> {
        let (principal, device_id) = value.rsplit_once(':').ok_or(WireError::MemberKey)?;
        let parsed = Principal::parse(principal).map_err(|_| WireError::MemberKey)?;
        if parsed.kind != Kind::User || device_id.is_empty() {
            return Err(WireError::MemberKey);
        }
        Ok(Self {
            principal: principal.to_owned(),
            device_id: device_id.to_owned(),
        })
    }

    /// Render the compact transport form.
    #[must_use]
    pub fn to_wire(&self) -> String {
        format!("{}:{}", self.principal, self.device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOM: &str = "!room:example.org";
    const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";

    #[test]
    fn group_id_is_room_scoped_and_deterministic() {
        let first = group_id(ROOM);
        assert_eq!(first, group_id(ROOM));
        assert_ne!(first, group_id("!other:example.org"));
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn object_ids_are_domain_separated() {
        let bytes = b"same bytes";
        let ids = [
            commit_id(bytes),
            key_package_id(bytes),
            welcome_id(bytes),
            group_info_id(bytes),
        ];
        for (index, left) in ids.iter().enumerate() {
            assert_ne!(*left, *blake3::hash(bytes).as_bytes());
            for right in &ids[index + 1..] {
                assert_ne!(left, right);
            }
        }
    }

    #[test]
    fn reboot_group_id_binds_both_inputs() {
        let (a, b) = ([1_u8; 32], [2_u8; 32]);
        assert_ne!(reboot_group_id(&a, &b), reboot_group_id(&b, &a));
        assert_ne!(reboot_group_id(&a, &b), reboot_group_id(&a, &a));
        assert_ne!(reboot_group_id(&a, &b), group_id("x"));
    }

    #[test]
    fn capability_requires_version_one() {
        let enabled = Value::parse(r#"{"tk.nutra.cygnus.dmls":{"version":1}}"#).unwrap();
        assert!(room_uses_dmls(&enabled));
        assert_eq!(dmls_version(&enabled), Some(1));

        let legacy = Value::parse(r#"{"room_version":"tk.nutra.cygnus.12"}"#).unwrap();
        assert!(!room_uses_dmls(&legacy));

        let future = Value::parse(r#"{"tk.nutra.cygnus.dmls":{"version":2}}"#).unwrap();
        assert!(!room_uses_dmls(&future));
        assert_eq!(dmls_version(&future), Some(2));
    }

    #[test]
    fn member_keys_split_at_the_last_colon() {
        let key = MemberKey::parse(&format!("{ALICE}:ALICE1")).unwrap();
        assert_eq!(key.principal, ALICE);
        assert_eq!(key.device_id, "ALICE1");
        assert_eq!(key.to_wire(), format!("{ALICE}:ALICE1"));

        assert_eq!(MemberKey::parse("no-colon"), Err(WireError::MemberKey));
        assert_eq!(MemberKey::parse("~server:DEV"), Err(WireError::MemberKey));
        assert_eq!(
            MemberKey::parse(&format!("{ALICE}:")),
            Err(WireError::MemberKey)
        );
    }
}
