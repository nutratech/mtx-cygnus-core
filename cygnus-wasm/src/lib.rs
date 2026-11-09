//! Verify-only WebAssembly API over `cygnus-core` for browser clients.
//!
//! Every function takes and returns plain strings so it works from any JS
//! environment without extra glue. Events are passed as JSON text. Keys are
//! unpadded base64url. Errors are thrown as JS `Error`s carrying the
//! `cygnus-core` message.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_core::{envelope, link, Link, Principal};
use rezzy_json::Value;
use wasm_bindgen::prelude::*;

fn err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

fn event(json: &str) -> Result<Value, JsError> {
    Value::parse(json).map_err(err)
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
/// # Errors
/// Throws if the signature entry is missing, malformed or invalid.
#[wasm_bindgen(js_name = verifyCustodianSignature)]
pub fn verify_custodian_signature(
    event_json: &str,
    custodian: &str,
    height: u32,
    public_key: &str,
) -> Result<(), JsError> {
    envelope::verify_custodian_signature(
        &event(event_json)?,
        custodian,
        u64::from(height),
        &key(public_key)?,
    )
    .map_err(err)
}
