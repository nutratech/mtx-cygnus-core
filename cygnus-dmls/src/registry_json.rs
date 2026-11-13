//! Strict, bounded parser for the per-merge device-root registry argument.

use std::collections::BTreeSet;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{Kind, Principal};
use rezzy_json::{to_canonical_string, Value};

use crate::device_root::{DeviceRoot, DeviceRootRegistry};

const MAX_BYTES: usize = 262_144;
const MAX_ENTRIES: usize = 4_096;

/// Parse the bounded registry payload and re-verify its roots and certificates.
///
/// # Errors
///
/// Returns `bad_argument` for malformed, oversized, duplicate, or invalid data.
pub fn parse_registry_json(input: &str) -> Result<DeviceRootRegistry, &'static str> {
    if input.len() > MAX_BYTES {
        return Err("registry_too_large");
    }
    let value = Value::parse_strict(input).map_err(|_| "registry_json")?;
    if to_canonical_string(&value).map_err(|_| "registry_json")? != input {
        return Err("registry_json_not_canonical");
    }
    let masters = array(&value, "masterKeys")?;
    let roots = array(&value, "roots")?;
    let certificates = array(&value, "certificates")?;
    let revoked = array(&value, "revoked")?;
    if [
        masters.len(),
        roots.len(),
        certificates.len(),
        revoked.len(),
    ]
    .into_iter()
    .any(|count| count > MAX_ENTRIES)
    {
        return Err("registry_entries");
    }

    let mut master_keys = Vec::with_capacity(masters.len());
    let mut principals = BTreeSet::new();
    let mut previous: Option<String> = None;
    for item in masters {
        let principal = string(item, "principal")?;
        require_principal(principal)?;
        if previous.as_deref().is_some_and(|prev| prev >= principal)
            || !principals.insert(principal.to_owned())
        {
            return Err("registry_master_order");
        }
        previous = Some(principal.to_owned());
        master_keys.push((principal.to_owned(), bytes32(item, "key")?));
    }
    let mut registry = DeviceRootRegistry::new(master_keys);

    let mut last_root: Option<(String, u64, u64)> = None;
    let mut root_keys = BTreeSet::new();
    for item in roots {
        let principal = string(item, "principal")?;
        require_principal(principal)?;
        let height = uint(item, "userEpochHeight")?;
        let generation = uint(item, "generation")?;
        let order = (principal.to_owned(), height, generation);
        if last_root.as_ref().is_some_and(|prev| prev >= &order)
            || !root_keys.insert((principal.to_owned(), generation))
        {
            return Err("registry_root_order");
        }
        last_root = Some(order);
        registry
            .install_root(DeviceRoot {
                principal: principal.to_owned(),
                user_epoch_height: height,
                generation,
                self_signing_key: bytes32(item, "selfSigningKey")?,
            })
            .map_err(|_| "registry_root")?;
    }

    let mut device_keys = BTreeSet::new();
    for item in certificates {
        let principal = string(item, "principal")?;
        require_principal(principal)?;
        let certificate = item.get("certificate").ok_or("registry_certificate")?;
        // Verify before recording; the signature binds principal and keys.
        let device = registry
            .certify(principal, certificate)
            .map_err(|_| "registry_certificate")?;
        if !device_keys.insert(device.device_key) {
            return Err("registry_duplicate_device_key");
        }
    }
    let mut revoked_keys = BTreeSet::new();
    for item in revoked {
        let key = decode32(item.as_str().ok_or("registry_revoked")?)?;
        if !revoked_keys.insert(key) {
            return Err("registry_duplicate_revocation");
        }
        registry.revoke(&key);
    }
    Ok(registry)
}

fn array<'a>(value: &'a Value, name: &'static str) -> Result<&'a [Value], &'static str> {
    value
        .get(name)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(name)
}

fn string<'a>(value: &'a Value, name: &'static str) -> Result<&'a str, &'static str> {
    value.get(name).and_then(Value::as_str).ok_or(name)
}

fn uint(value: &Value, name: &'static str) -> Result<u64, &'static str> {
    value.get(name).and_then(Value::as_u64).ok_or(name)
}

fn decode32(value: &str) -> Result<[u8; 32], &'static str> {
    let decoded = B64.decode(value).map_err(|_| "registry_key")?;
    if B64.encode(&decoded) != value {
        return Err("registry_key");
    }
    decoded.try_into().map_err(|_| "registry_key")
}

fn bytes32(value: &Value, name: &'static str) -> Result<[u8; 32], &'static str> {
    decode32(string(value, name)?)
}

fn require_principal(value: &str) -> Result<(), &'static str> {
    match Principal::parse(value) {
        Ok(principal) if principal.kind == Kind::User => Ok(()),
        _ => Err("registry_principal"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "@BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

    fn payload(roots: &str) -> String {
        let json = format!(
            r#"{{"masterKeys":[{{"principal":"{USER}","key":"{}"}}],"roots":{roots},"certificates":[],"revoked":[]}}"#,
            B64.encode([7_u8; 32])
        );
        to_canonical_string(&Value::parse_strict(&json).unwrap()).unwrap()
    }

    #[test]
    fn accepts_ordered_root_chain_and_empty_certificates() {
        let root = |height, generation, key: [u8; 32]| {
            format!(
                r#"{{"principal":"{USER}","userEpochHeight":{height},"generation":{generation},"selfSigningKey":"{}"}}"#,
                B64.encode(key)
            )
        };
        let json = payload(&format!(
            "[{},{}]",
            root(7, 1, [8; 32]),
            root(7, 2, [9; 32])
        ));
        assert!(parse_registry_json(&json).is_ok());
    }

    #[test]
    fn rejects_duplicate_or_out_of_order_roots() {
        let root = format!(
            r#"{{"principal":"{USER}","userEpochHeight":7,"generation":1,"selfSigningKey":"{}"}}"#,
            B64.encode([8_u8; 32])
        );
        assert_eq!(
            parse_registry_json(&payload(&format!("[{root},{root}]"))).unwrap_err(),
            "registry_root_order"
        );
    }

    #[test]
    fn rejects_noncanonical_json_and_oversize_input() {
        assert!(parse_registry_json(
            r#"{"masterKeys":[],"roots":[],"certificates":[],"revoked":[],"x":1.0}"#
        )
        .is_err());
        assert_eq!(
            parse_registry_json(&" ".repeat(MAX_BYTES + 1)).unwrap_err(),
            "registry_too_large"
        );
    }
}
