//! WebAssembly API over `cygnus-core` for browser clients: verification, plus
//! the client-side signing steps of MSC00FC §7/§9 (identity bootstrap, device
//! certificates, event signing and user-chain rotation).
//!
//! Every function takes and returns plain strings so it works from any JS
//! environment without extra glue. Events are passed as JSON text. Keys are
//! unpadded base64url. Errors are thrown as JS `Error`s carrying the
//! `cygnus-core` message. Seeds are 32 random bytes as unpadded base64url;
//! the caller generates them (for example with `crypto.getRandomValues`) and
//! is responsible for storing them.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{
    bootstrap::{self, RotationKey},
    envelope, link, DeviceCertificate, Kind, Link, Payload, Principal,
};
use ed25519_zebra::SigningKey;
use rezzy_json::Value;
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn event(json: &str) -> Result<Value, JsError> {
    Value::parse_strict(json).map_err(err)
}

fn require_device_certificate(event: &Value) -> Result<(), &'static str> {
    if matches!(event.get("device_certificate"), Some(Value::Object(_))) {
        Ok(())
    } else {
        Err("event must carry a device_certificate object")
    }
}

fn key(b64: &str) -> Result<[u8; 32], JsError> {
    let bytes = B64.decode(b64).map_err(err)?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| JsError::new("key must be 32 bytes"))
}

/// Parse a principal (`~server` or `@user`) and return its canonical form.
///
/// # Errors
/// Throws if the identifier is padded, the wrong length or not base64url.
#[wasm_bindgen(js_name = parsePrincipal)]
pub fn parse_principal(id: &str) -> Result<String, JsError> {
    Ok(Principal::parse(id).map_err(err)?.to_id())
}

/// Verify a link chain given as base64url links, genesis first, and return
/// the principal that the chain identifies.
///
/// # Errors
/// Throws on the first link that fails to parse or verify.
#[wasm_bindgen(js_name = verifyChain)]
pub fn verify_chain(links: Vec<String>) -> Result<String, JsError> {
    let parsed = links
        .iter()
        .map(|l| Link::from_b64(l))
        .collect::<Result<Vec<_>, _>>()
        .map_err(err)?;
    let (genesis, rest) = parsed
        .split_first()
        .ok_or_else(|| JsError::new("empty chain"))?;
    genesis.verify_genesis().map_err(err)?;
    link::verify_slice(genesis, rest).map_err(err)?;
    Ok(genesis.principal().to_id())
}

/// Matrix v3 event ID (`$` plus reference hash) of an event.
///
/// # Errors
/// Throws if the event is not valid canonical JSON.
#[wasm_bindgen(js_name = eventId)]
pub fn event_id(event_json: &str) -> Result<String, JsError> {
    envelope::event_id(&event(event_json)?).map_err(err)
}

/// Content hash of an event as unpadded base64url.
///
/// # Errors
/// Throws if the event is not valid canonical JSON.
#[wasm_bindgen(js_name = contentHash)]
pub fn content_hash(event_json: &str) -> Result<String, JsError> {
    envelope::content_hash_b64(&event(event_json)?).map_err(err)
}

/// Verify a device's signature over an event against its certified key.
///
/// # Errors
/// Throws if the signature entry is missing, malformed or invalid.
#[wasm_bindgen(js_name = verifyDeviceSignature)]
pub fn verify_device_signature(
    event_json: &str,
    sender: &str,
    device_id: &str,
    public_key: &str,
) -> Result<(), JsError> {
    envelope::verify_device_signature(&event(event_json)?, sender, device_id, &key(public_key)?)
        .map_err(err)
}

/// Verify a custodian (server) signature over an event at a chain height.
///
/// `height` is a decimal string, since protocol heights are `u64` and exceed
/// what a JS number represents exactly.
///
/// # Errors
/// Throws if the signature entry is missing, malformed or invalid.
#[wasm_bindgen(js_name = verifyCustodianSignature)]
pub fn verify_custodian_signature(
    event_json: &str,
    custodian: &str,
    height: &str,
    public_key: &str,
) -> Result<(), JsError> {
    envelope::verify_custodian_signature(
        &event(event_json)?,
        custodian,
        height
            .parse::<u64>()
            .map_err(|_| JsError::new("height must be a decimal u64"))?,
        &key(public_key)?,
    )
    .map_err(err)
}

fn signing_key(seed: &str) -> Result<SigningKey, JsError> {
    Ok(SigningKey::from(key(seed)?))
}

fn rotation_key(seed: &str) -> Result<RotationKey, JsError> {
    Ok(RotationKey::from_seed(key(seed)?))
}

/// Ed25519 public key for a 32-byte seed, as unpadded base64url.
///
/// # Errors
/// Throws if the seed is not 32 bytes of base64url.
#[wasm_bindgen(js_name = publicKey)]
pub fn public_key(seed: &str) -> Result<String, JsError> {
    Ok(B64.encode(<[u8; 32]>::from(signing_key(seed)?.verification_key())))
}

/// Rotation commitment `C = commitment(K_rot)` for a rotation seed, as sent to
/// the server in the §7 principal request.
///
/// # Errors
/// Throws if the seed is not 32 bytes of base64url.
#[wasm_bindgen(js_name = rotationCommitment)]
pub fn rotation_commitment(rotation_seed: &str) -> Result<String, JsError> {
    Ok(B64.encode(rotation_key(rotation_seed)?.commitment()))
}

/// Check the server's §7 `POST /principal` response against the rotation
/// seed and master key the client sent, and return the genesis link.
///
/// # Errors
/// Throws if the principal, link count, master key or commitment does not
/// match the request.
#[wasm_bindgen(js_name = verifyUserPrincipalResponse)]
pub fn verify_user_principal_response(
    rotation_seed: &str,
    master_pub: &str,
    principal: &str,
    links: Vec<String>,
) -> Result<String, JsError> {
    let link = bootstrap::verify_user_principal_response(
        &rotation_key(rotation_seed)?,
        &key(master_pub)?,
        principal,
        &links,
    )
    .map_err(err)?;
    Ok(link.to_b64())
}

/// Issue a version-1 `device_certificate` (JSON text): the master key
/// certifies the self-signing key, which certifies the device key.
///
/// # Errors
/// Throws for a non-user sender, an invalid device ID or a malformed seed.
#[wasm_bindgen(js_name = createDeviceCertificate)]
pub fn create_device_certificate(
    sender: &str,
    master_seed: &str,
    self_signing_seed: &str,
    device_id: &str,
    device_seed: &str,
) -> Result<String, JsError> {
    let certificate = DeviceCertificate::issue(
        sender,
        &signing_key(master_seed)?,
        &signing_key(self_signing_seed)?,
        device_id,
        &signing_key(device_seed)?,
    )
    .map_err(err)?;
    rezzy_json::to_canonical_string(&certificate).map_err(err)
}

/// Set the content hash and add the device signature to an event that
/// already carries its `device_certificate`; returns the signed event JSON.
/// The custodian signature is added by the server.
///
/// # Errors
/// Throws if the event is not valid JSON, lacks an object-valued
/// `device_certificate`, or a seed is malformed.
#[wasm_bindgen(js_name = signEvent)]
pub fn sign_event(
    event_json: &str,
    sender: &str,
    device_id: &str,
    device_seed: &str,
) -> Result<String, JsError> {
    let mut event = event(event_json)?;
    require_device_certificate(&event).map_err(JsError::new)?;
    envelope::set_content_hash(&mut event).map_err(err)?;
    envelope::sign_device(&mut event, sender, device_id, &signing_key(device_seed)?)
        .map_err(err)?;
    rezzy_json::to_canonical_string(&event).map_err(err)
}

/// Extend a user chain: sign the next link with the rotation key the parent
/// committed to, committing to `nextRotationSeed` for the following link.
///
/// `custodian` is the custodian server's 32-byte principal root (base64url).
///
/// # Errors
/// Throws if the parent is not a user link, the current rotation seed does
/// not match its commitment, or the master key differs from the parent's.
#[wasm_bindgen(js_name = userSuccessor)]
pub fn user_successor(
    parent_link: &str,
    current_rotation_seed: &str,
    next_rotation_seed: &str,
    custodian: &str,
    master_pub: &str,
    display_user_id: &str,
) -> Result<String, JsError> {
    let parent = Link::from_b64(parent_link).map_err(err)?;
    let link = bootstrap::user_successor(
        &parent,
        &rotation_key(current_rotation_seed)?,
        &rotation_key(next_rotation_seed)?,
        key(custodian)?,
        key(master_pub)?,
        display_user_id,
    )
    .map_err(err)?;
    Ok(link.to_b64())
}

/// Parse one link without verifying it, returning its fields as JSON text:
/// `kind` (`"user"`/`"server"`), `height` (decimal string), `principal`, and
/// for user links `custodian` (`~` ID), `master_key`, `display_user_id`, or for
/// server links `server_name` and `online_key`; the other kind's fields are
/// `null`. Pair it with [`verify_chain`] before trusting any field.
///
/// # Errors
/// Throws if the link is not well-formed base64url link bytes.
#[wasm_bindgen(js_name = parseLink)]
pub fn parse_link(link_b64: &str) -> Result<String, JsError> {
    let link = Link::from_b64(link_b64).map_err(err)?;
    let mut object = rezzy_json::Object::new();
    let string = |value: String| Value::String(value);
    object.insert("height".into(), string(link.body.height.to_string()));
    object.insert("principal".into(), string(link.principal().to_id()));
    let (kind, custodian, master_key, display_user_id, server_name, online_key) =
        match &link.body.payload {
            Payload::User {
                custodian,
                master_key,
                display_user_id,
            } => (
                "user",
                Some(
                    Principal {
                        kind: Kind::Server,
                        root: *custodian,
                    }
                    .to_id(),
                ),
                master_key.map(|key| B64.encode(key)),
                Some(display_user_id.clone()),
                None,
                None,
            ),
            Payload::Server {
                online_key,
                server_name,
            } => (
                "server",
                None,
                None,
                None,
                Some(server_name.clone()),
                Some(B64.encode(online_key)),
            ),
        };
    object.insert("kind".into(), kind.into());
    for (field, value) in [
        ("custodian", custodian),
        ("master_key", master_key),
        ("display_user_id", display_user_id),
        ("server_name", server_name),
        ("online_key", online_key),
    ] {
        object.insert(field.into(), value.map_or(Value::Null, string));
    }
    rezzy_json::to_canonical_string(&Value::Object(object)).map_err(err)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_certificate_must_be_present_and_be_an_object() {
        for json in [
            "{}",
            r#"{"device_certificate":null}"#,
            r#"{"device_certificate":"certificate"}"#,
            r#"{"device_certificate":[]}"#,
            r#"{"device_certificate":1}"#,
        ] {
            let event = Value::parse_strict(json).unwrap();
            assert!(require_device_certificate(&event).is_err(), "{json}");
        }
        let event = Value::parse_strict(r#"{"device_certificate":{}}"#).unwrap();
        assert!(require_device_certificate(&event).is_ok());
    }
}
