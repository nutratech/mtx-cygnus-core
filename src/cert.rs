//! Self-contained master → self-signing → device certificates (§5.2.1).

use crate::{link::verify, Error, Principal, DEVICE_CERT_TAG};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_consensus::VerificationKey;
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
    /// Ed25519 rules, via `ed25519-consensus`.
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
        if device_id.is_empty()
            || device_id.len() > 255
            || !device_id.is_ascii()
            || !device_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(Error::Certificate("invalid device_id"));
        }
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
}

fn string(value: Option<&Value>) -> Result<&str, Error> {
    value
        .and_then(Value::as_str)
        .ok_or(Error::Certificate("string field required"))
}

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
fn canonical_statement(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut object = rezzy_json::Object::new();
    for (key, value) in fields {
        object.insert((*key).into(), Value::String((*value).into()));
    }
    rezzy_json::to_canonical_string(&Value::Object(object))
        .expect("certificate statements contain only strings")
        .into_bytes()
}

fn canonical_self_statement(sender: &str, key: &str) -> Vec<u8> {
    canonical_statement(&[
        ("key", key),
        ("principal", sender),
        ("purpose", "self_signing"),
    ])
}

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
    use base64::Engine;
    use ed25519_consensus::SigningKey;
    use rezzy_json::json;

    fn signed_certificate() -> (String, [u8; 32], Value) {
        let master = SigningKey::from([0x31; 32]);
        let self_signing = SigningKey::from([0x32; 32]);
        let device = SigningKey::from([0x33; 32]);
        let sender = Principal {
            kind: crate::link::Kind::User,
            root: [0x44; 32],
        }
        .to_id();
        let self_key = B64.encode(self_signing.verification_key().to_bytes());
        let device_key = B64.encode(device.verification_key().to_bytes());
        let self_sig = master.sign(
            &[
                DEVICE_CERT_TAG,
                &canonical_self_statement(&sender, &self_key),
            ]
            .concat(),
        );
        let device_sig = self_signing.sign(
            &[
                DEVICE_CERT_TAG,
                &canonical_device_statement(&sender, "DEVICE-1", &device_key),
            ]
            .concat(),
        );
        let value = json!({
            "version": 1,
            "device_id": "DEVICE-1",
            "device_key": device_key,
            "self_signing_key": self_key,
            "self_signing_signature": B64.encode(self_sig.to_bytes()),
            "device_key_signature": B64.encode(device_sig.to_bytes()),
        });
        (sender, master.verification_key().to_bytes(), value)
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
