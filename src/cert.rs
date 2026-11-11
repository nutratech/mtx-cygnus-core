//! Self-contained master → self-signing → device certificates (§5.2.1).

use crate::{link::verify, Error, Principal, DEVICE_CERT_TAG};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_zebra::{SigningKey, VerificationKey};
use rezzy_json::Value;

/// A verified device certificate. Unknown JSON fields are ignored at version 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceCertificate {
    /// ASCII device identifier.
    pub device_id: String,
    /// Device Ed25519 public key.
    pub device_key: [u8; 32],
    /// Certified self-signing Ed25519 public key.
    pub self_signing_key: [u8; 32],
}

impl DeviceCertificate {
    /// Parse and verify a certificate against the master key committed by the
    /// sender's active user epoch (or create event).
    ///
    /// The input is the JSON value of `device_certificate`. Verification uses
    /// canonical JSON for the two signed certificate statements and ZIP-215
    /// Ed25519 rules, via `ed25519-zebra`.
    ///
    /// # Errors
    /// Returns [`Error::Certificate`] for malformed fields or invalid chain
    /// signatures, and [`Error::Principal`] for a non-user principal.
    pub fn parse_and_verify(
        value: &Value,
        sender: &str,
        master_key: &[u8; 32],
    ) -> Result<Self, Error> {
        let principal = Principal::parse(sender)?;
        if principal.kind != crate::link::Kind::User || principal.to_id() != sender {
            return Err(Error::Principal);
        }
        let obj = value
            .as_object()
            .ok_or(Error::Certificate("object required"))?;
        let version = obj
            .get("version")
            .and_then(Value::as_i64)
            .ok_or(Error::Certificate("version must be integer 1"))?;
        if version != 1 {
            return Err(Error::Certificate("unsupported version"));
        }

        let device_id = string(obj.get("device_id"))?.to_owned();
        check_device_id(&device_id)?;
        let device_key_text = string(obj.get("device_key"))?;
        let self_key_text = string(obj.get("self_signing_key"))?;
        let device_key = decode_key(device_key_text)?;
        let self_signing_key = decode_key(self_key_text)?;
        let self_sig = decode_signature(string(obj.get("self_signing_signature"))?)?;
        let device_sig = decode_signature(string(obj.get("device_key_signature"))?)?;

        let self_statement = canonical_self_statement(sender, self_key_text);
        verify(
            master_key,
            &[DEVICE_CERT_TAG, &self_statement].concat(),
            &self_sig,
        )?;
        let device_statement = canonical_device_statement(sender, &device_id, device_key_text);
        verify(
            &self_signing_key,
            &[DEVICE_CERT_TAG, &device_statement].concat(),
            &device_sig,
        )?;

        Ok(Self {
            device_id,
            device_key,
            self_signing_key,
        })
    }

    /// Issue a version-1 certificate for `device` under `sender`'s master key:
    /// the master key certifies `self_signing`, which certifies the device.
    ///
    /// Returns the `device_certificate` JSON value, which
    /// [`DeviceCertificate::parse_and_verify`] accepts for the master key.
    ///
    /// # Errors
    /// Returns [`Error::Principal`] if `sender` is not a canonical user
    /// principal and [`Error::Certificate`] for an invalid `device_id`.
    pub fn issue(
        sender: &str,
        master: &SigningKey,
        self_signing: &SigningKey,
        device_id: &str,
        device: &SigningKey,
    ) -> Result<Value, Error> {
        let principal = Principal::parse(sender)?;
        if principal.kind != crate::link::Kind::User || principal.to_id() != sender {
            return Err(Error::Principal);
        }
        check_device_id(device_id)?;
        let self_key = B64.encode(<[u8; 32]>::from(self_signing.verification_key()));
        let device_key = B64.encode(<[u8; 32]>::from(device.verification_key()));
        let self_signature = master.sign(
            &[
                DEVICE_CERT_TAG,
                &canonical_self_statement(sender, &self_key),
            ]
            .concat(),
        );
        let device_signature = self_signing.sign(
            &[
                DEVICE_CERT_TAG,
                &canonical_device_statement(sender, device_id, &device_key),
            ]
            .concat(),
        );
        let mut object = rezzy_json::Object::new();
        object.insert("version".into(), 1u64.into());
        object.insert("device_id".into(), device_id.into());
        object.insert("device_key".into(), device_key.into());
        object.insert("self_signing_key".into(), self_key.into());
        object.insert(
            "self_signing_signature".into(),
            B64.encode(self_signature.to_bytes()).into(),
        );
        object.insert(
            "device_key_signature".into(),
            B64.encode(device_signature.to_bytes()).into(),
        );
        Ok(Value::Object(object))
    }
}

/// Validate a device ID's length and permitted ASCII characters.
fn check_device_id(device_id: &str) -> Result<(), Error> {
    if device_id.is_empty()
        || device_id.len() > 255
        || !device_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(Error::Certificate("invalid device_id"));
    }
    Ok(())
}

/// Extract a required string field from certificate content.
fn string(value: Option<&Value>) -> Result<&str, Error> {
    value
        .and_then(Value::as_str)
        .ok_or(Error::Certificate("string field required"))
}

/// Decode a canonical, valid base64url Ed25519 public key.
fn decode_key(value: &str) -> Result<[u8; 32], Error> {
    let bytes = B64
        .decode(value)
        .map_err(|_| Error::Certificate("invalid base64url key"))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| Error::Certificate("key must be 32 bytes"))?;
    if B64.encode(key) != value {
        return Err(Error::Certificate("non-canonical base64url key"));
    }
    VerificationKey::try_from(key.as_slice()).map_err(|_| Error::PublicKey)?;
    Ok(key)
}

/// Decode a canonical base64url Ed25519 signature.
fn decode_signature(value: &str) -> Result<[u8; 64], Error> {
    let bytes = B64
        .decode(value)
        .map_err(|_| Error::Certificate("invalid base64url signature"))?;
    let signature: [u8; 64] = bytes
        .try_into()
        .map_err(|_| Error::Certificate("signature must be 64 bytes"))?;
    if B64.encode(signature) != value {
        return Err(Error::Certificate("non-canonical base64url signature"));
    }
    Ok(signature)
}

// Certificate statements are canonical JSON objects of ASCII-only string
// fields. Building them through `rezzy-json` keeps key ordering and escaping
// in one place, and the strict writer rejects any future numeric field.
/// Encode a certificate statement as canonical JSON bytes.
fn canonical_statement(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut object = rezzy_json::Object::new();
    for (key, value) in fields {
        object.insert((*key).into(), Value::String((*value).into()));
    }
    rezzy_json::to_canonical_string(&Value::Object(object))
        .expect("certificate statements contain only strings")
        .into_bytes()
}

/// Canonical bytes for a master-key self-signing statement.
fn canonical_self_statement(sender: &str, key: &str) -> Vec<u8> {
    canonical_statement(&[
        ("key", key),
        ("principal", sender),
        ("purpose", "self_signing"),
    ])
}

/// Canonical bytes for a device-certificate statement.
fn canonical_device_statement(sender: &str, device_id: &str, key: &str) -> Vec<u8> {
    canonical_statement(&[
        ("device_id", device_id),
        ("key", key),
        ("principal", sender),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use rezzy_json::json;

    fn signed_certificate() -> (String, [u8; 32], Value) {
        let master = SigningKey::from([0x31; 32]);
        let sender = Principal {
            kind: crate::link::Kind::User,
            root: [0x44; 32],
        }
        .to_id();
        let value = DeviceCertificate::issue(
            &sender,
            &master,
            &SigningKey::from([0x32; 32]),
            "DEVICE-1",
            &SigningKey::from([0x33; 32]),
        )
        .unwrap();
        (sender, <[u8; 32]>::from(master.verification_key()), value)
    }

    #[test]
    fn issued_certificate_names_the_certified_keys() {
        let (sender, master_key, value) = signed_certificate();
        let cert = DeviceCertificate::parse_and_verify(&value, &sender, &master_key).unwrap();
        let device = SigningKey::from([0x33; 32]);
        assert_eq!(cert.device_key, <[u8; 32]>::from(device.verification_key()));
        let self_signing = SigningKey::from([0x32; 32]);
        assert_eq!(
            cert.self_signing_key,
            <[u8; 32]>::from(self_signing.verification_key())
        );
    }

    /// Rejects empty, overlong, or non-ASCII device IDs and server senders.
    #[test]
    fn issue_rejects_bad_device_ids_and_server_senders() {
        let key = SigningKey::from([0x31; 32]);
        let user = Principal {
            kind: crate::link::Kind::User,
            root: [0x44; 32],
        }
        .to_id();
        for bad in ["", "has space", "dévice"] {
            assert_eq!(
                DeviceCertificate::issue(&user, &key, &key, bad, &key),
                Err(Error::Certificate("invalid device_id"))
            );
        }
        let server = Principal {
            kind: crate::link::Kind::Server,
            root: [0x44; 32],
        }
        .to_id();
        assert_eq!(
            DeviceCertificate::issue(&server, &key, &key, "D", &key),
            Err(Error::Principal)
        );
    }

    #[test]
    fn verifies_certificate_chain_and_ignores_unknown_v1_fields() {
        let (sender, master_key, mut value) = signed_certificate();
        value["future_field"] = json!("ignored");
        let cert = DeviceCertificate::parse_and_verify(&value, &sender, &master_key).unwrap();
        assert_eq!(cert.device_id, "DEVICE-1");
    }

    #[test]
    fn rejects_boolean_version() {
        let (sender, master_key, mut value) = signed_certificate();
        value["version"] = json!(true);
        assert!(DeviceCertificate::parse_and_verify(&value, &sender, &master_key).is_err());
    }

    #[test]
    fn rejects_unsupported_integer_version() {
        let (sender, master_key, mut value) = signed_certificate();
        value["version"] = json!(2);
        assert!(DeviceCertificate::parse_and_verify(&value, &sender, &master_key).is_err());
    }

    #[test]
    fn rejects_non_integer_version_spellings() {
        let (sender, master_key, mut value) = signed_certificate();

        value["version"] = json!(1.0);
        assert!(DeviceCertificate::parse_and_verify(&value, &sender, &master_key).is_err());

        value["version"] = Value::parse("1e0").unwrap();
        assert!(DeviceCertificate::parse_and_verify(&value, &sender, &master_key).is_err());
    }

    #[test]
    fn rejects_modified_device_id() {
        let (sender, master_key, mut value) = signed_certificate();
        value["device_id"] = json!("DEVICE-2");
        assert!(DeviceCertificate::parse_and_verify(&value, &sender, &master_key).is_err());
    }
}
