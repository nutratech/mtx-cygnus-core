//! Cygnus room-v12 event redaction, canonical signing bytes, and hashes.
//!
//! This is the client-side serialization boundary: SDKs should construct and
//! sign event objects here so Rust, wasm, `UniFFI`, and Dart use identical bytes.

use crate::sig::SigningKey;
use crate::Error;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use rezzy_json::{Object, Value};
use sha2::{Digest, Sha256};

/// Domain tag for a certified device's event signature, including trailing NUL.
pub const DEVICE_EVENT_TAG: &[u8] = b"matrix-cygnus-device-event-v1\0";

const KEPT_TOP_LEVEL: &[&str] = &[
    "event_id",
    "type",
    "room_id",
    "sender",
    "state_key",
    "content",
    "hashes",
    "signatures",
    "depth",
    "prev_events",
    "auth_events",
    "origin_server_ts",
    "device_certificate",
];

const FULL_CONTENT_TYPES: &[&str] = &[
    "m.room.create",
    "m.room.server_epoch",
    "m.room.user_epoch",
    "m.room.server_seal",
];

/// Redact an event using room-v12 rules plus MSC00FC's preserved fields.
///
/// The top-level `device_certificate` survives redaction. Epoch and create
/// contents survive intact. Other content follows the v12 event-type allowlist
/// extended by 00FC for membership custodian data and server ACLs.
///
/// # Errors
/// Returns [`Error::Envelope`] if the event or its content is not an object.
pub fn redact_event(event: &Value) -> Result<Value, Error> {
    let event_object = event
        .as_object()
        .ok_or(Error::Envelope("event must be an object"))?;
    let mut redacted = Object::new();
    for key in KEPT_TOP_LEVEL {
        if let Some(value) = event_object.get(*key) {
            redacted.insert((*key).to_owned(), value.clone());
        }
    }

    let event_type = event_object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(Error::Envelope("type must be a string"))?;
    if FULL_CONTENT_TYPES.contains(&event_type) {
        return Ok(Value::Object(redacted));
    }

    let content = event_object
        .get("content")
        .and_then(Value::as_object)
        .ok_or(Error::Envelope("content must be an object"))?;
    let allowed = kept_content_fields(event_type);
    let mut kept_content = Object::new();
    for (key, value) in content {
        if allowed.contains(&key.as_str()) {
            if event_type == "m.room.member" && key == "third_party_invite" {
                if let Some(signed) = value.get("signed") {
                    let mut invite = Object::new();
                    invite.insert("signed".to_owned(), signed.clone());
                    kept_content.insert(key.clone(), Value::Object(invite));
                }
            } else {
                kept_content.insert(key.clone(), value.clone());
            }
        }
    }
    redacted.insert("content".to_owned(), Value::Object(kept_content));
    Ok(Value::Object(redacted))
}

/// Canonical JSON bytes used for ordinary room-v12 event signing and reference
/// hashing: redacted event with `signatures`, `unsigned`, and any attached
/// `event_id` removed.
///
/// # Errors
/// Returns an error for an invalid event shape or non-canonical JSON value.
pub fn signing_bytes(event: &Value) -> Result<Vec<u8>, Error> {
    let mut object = redact_event(event)?;
    // `event_id` is not part of the signed room-v12 event.
    remove_fields(&mut object, &["event_id", "signatures", "unsigned"])?;
    rezzy_json::to_canonical_bytes(&object).map_err(|_| Error::CanonicalJson)
}

/// Bytes signed by the certified device for an event.
///
/// # Errors
/// See [`signing_bytes`].
pub fn device_signing_bytes(event: &Value) -> Result<Vec<u8>, Error> {
    let mut bytes = DEVICE_EVENT_TAG.to_vec();
    let mut object = redact_event(event)?;
    remove_fields(&mut object, &["event_id", "signatures", "unsigned"])?;
    bytes.extend_from_slice(
        &rezzy_json::to_canonical_bytes(&object).map_err(|_| Error::CanonicalJson)?,
    );
    Ok(bytes)
}

/// Matrix content hash: SHA-256 over canonical JSON after removing
/// `unsigned`, `signatures`, and `hashes`, and any attached `event_id` (a room
/// v12 PDU has none, but callers often add it).
///
/// # Errors
/// Returns [`Error::Envelope`] when the event is not an object, or
/// [`Error::CanonicalJson`] when canonical JSON validation fails.
pub fn content_hash(event: &Value) -> Result<[u8; 32], Error> {
    let mut object = event.clone();
    // `event_id` is not part of a room v12 PDU, but a caller may have attached it.
    remove_fields(
        &mut object,
        &["event_id", "unsigned", "signatures", "hashes"],
    )?;
    let bytes = rezzy_json::to_canonical_bytes(&object).map_err(|_| Error::CanonicalJson)?;
    Ok(Sha256::digest(bytes).into())
}

/// Base64url-no-padding form of [`content_hash`].
///
/// # Errors
/// See [`content_hash`].
pub fn content_hash_b64(event: &Value) -> Result<String, Error> {
    Ok(B64.encode(content_hash(event)?))
}

/// SHA-256 reference hash of the redacted signing object.
///
/// # Errors
/// See [`signing_bytes`].
pub fn reference_hash(event: &Value) -> Result<[u8; 32], Error> {
    Ok(Sha256::digest(signing_bytes(event)?).into())
}

/// Matrix v3 event ID (`$` plus unpadded base64url reference hash).
///
/// # Errors
/// See [`reference_hash`].
pub fn event_id(event: &Value) -> Result<String, Error> {
    Ok(format!("${}", B64.encode(reference_hash(event)?)))
}

/// Replace the event's `hashes` field with its Cygnus content hash.
///
/// Call this after assembling the event and before adding signatures.
///
/// # Errors
/// Returns [`Error::Envelope`] for a non-object event or
/// [`Error::CanonicalJson`] for invalid canonical JSON values.
pub fn set_content_hash(event: &mut Value) -> Result<(), Error> {
    let hash = content_hash_b64(event)?;
    let mut hashes = Object::new();
    hashes.insert("sha256".to_owned(), Value::String(hash));
    if !event.is_object() {
        return Err(Error::Envelope("event must be an object"));
    }
    event.insert("hashes".to_owned(), Value::Object(hashes));
    Ok(())
}

/// Add the certified device signature at
/// `signatures[sender]["ed25519:<device_id>"]`.
///
/// The caller must add the in-band `device_certificate` and content hash first.
///
/// # Errors
/// Returns an error for malformed event data or canonical JSON values.
pub fn sign_device(
    event: &mut Value,
    sender: &str,
    device_id: &str,
    key: &SigningKey,
) -> Result<(), Error> {
    let signature = key.sign(&device_signing_bytes(event)?);
    insert_signature(
        event,
        sender,
        &format!("ed25519:{device_id}"),
        &signature.to_bytes(),
    )
}

/// Add the custodian/server signature at
/// `signatures[custodian]["ed25519:<height>"]`.
///
/// Call this after setting the content hash. The device signature may already
/// be present; signature fields are excluded from the signing object, so both
/// parties sign identical event bytes.
///
/// # Errors
/// Returns an error for malformed event data or canonical JSON values.
pub fn sign_custodian(
    event: &mut Value,
    custodian: &str,
    height: u64,
    key: &SigningKey,
) -> Result<(), Error> {
    let signature = key.sign(&signing_bytes(event)?);
    insert_signature(
        event,
        custodian,
        &format!("ed25519:{height}"),
        &signature.to_bytes(),
    )
}

/// Verify the sender's certified-device event signature.
///
/// Certificate-chain verification is handled by [`crate::DeviceCertificate`];
/// this function checks the event signature against the already-verified key.
///
/// # Errors
/// Returns [`Error::Signature`] if the entry is missing, malformed, or invalid.
pub fn verify_device_signature(
    event: &Value,
    sender: &str,
    device_id: &str,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    let signature = signature_entry(event, sender, &format!("ed25519:{device_id}"))?;
    let bytes = device_signing_bytes(event)?;
    crate::link::verify(public_key, &bytes, &signature)
}

/// Verify a custodian/server event signature against an already-authorized key.
///
/// # Errors
/// Returns [`Error::Signature`] if the entry is missing, malformed, or invalid.
pub fn verify_custodian_signature(
    event: &Value,
    custodian: &str,
    height: u64,
    public_key: &[u8; 32],
) -> Result<(), Error> {
    let signature = signature_entry(event, custodian, &format!("ed25519:{height}"))?;
    crate::link::verify(public_key, &signing_bytes(event)?, &signature)
}

fn remove_fields(value: &mut Value, fields: &[&str]) -> Result<(), Error> {
    let object = value
        .as_object_mut()
        .ok_or(Error::Envelope("event must be an object"))?;
    for field in fields {
        object.remove(*field);
    }
    Ok(())
}

fn insert_signature(
    event: &mut Value,
    signer: &str,
    key_id: &str,
    signature: &[u8],
) -> Result<(), Error> {
    let signatures = ensure_object_field(event, "signatures")?;
    let signer_signatures = signatures
        .entry(signer.to_owned())
        .or_insert_with(|| Value::Object(Object::new()));
    let signer_signatures = signer_signatures
        .as_object_mut()
        .ok_or(Error::Envelope("signer signatures must be an object"))?;
    signer_signatures.insert(key_id.to_owned(), Value::String(B64.encode(signature)));
    Ok(())
}

fn ensure_object_field<'a>(event: &'a mut Value, field: &str) -> Result<&'a mut Object, Error> {
    let object = event
        .as_object_mut()
        .ok_or(Error::Envelope("event must be an object"))?;
    let value = object
        .entry(field.to_owned())
        .or_insert_with(|| Value::Object(Object::new()));
    value
        .as_object_mut()
        .ok_or(Error::Envelope("signatures must be an object"))
}

fn signature_entry(event: &Value, signer: &str, key_id: &str) -> Result<Vec<u8>, Error> {
    let signature = event
        .get("signatures")
        .and_then(|value| value.get(signer))
        .and_then(|value| value.get(key_id))
        .and_then(Value::as_str)
        .ok_or(Error::Signature)?;
    let bytes = B64.decode(signature).map_err(|_| Error::Signature)?;
    let signature = bytes;
    if B64.encode(&signature) != signature_entry_text(event, signer, key_id)? {
        return Err(Error::Signature);
    }
    Ok(signature)
}

fn signature_entry_text<'a>(
    event: &'a Value,
    signer: &str,
    key_id: &str,
) -> Result<&'a str, Error> {
    event
        .get("signatures")
        .and_then(|value| value.get(signer))
        .and_then(|value| value.get(key_id))
        .and_then(Value::as_str)
        .ok_or(Error::Signature)
}

fn kept_content_fields(event_type: &str) -> &'static [&'static str] {
    match event_type {
        "m.room.member" => &[
            "membership",
            "join_authorised_via_users_server",
            "third_party_invite",
            "custodian",
        ],
        "m.room.join_rules" => &["join_rule", "allow"],
        "m.room.power_levels" => &[
            "ban",
            "events",
            "events_default",
            "invite",
            "kick",
            "redact",
            "state_default",
            "users",
            "users_default",
        ],
        "m.room.history_visibility" => &["history_visibility"],
        "m.room.redaction" => &["redacts"],
        "m.room.server_acl" => &["allow", "deny", "allow_ip_literals"],
        _ => &[],
    }
}
