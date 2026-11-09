//! Optional Rezzy integration: base Matrix v12 authorization for Cygnus rooms.
//!
//! Cygnus extends room version 12 with principal-based senders, but stock
//! membership, power-level, join-rule, and `auth_events` checks are unchanged.
//! This module maps Cygnus PDUs into Rezzy's generic event model so a server
//! can run those base rules without reimplementing them. The Cygnus-specific
//! epoch, custodian, device, seal, and relay rules stay in [`crate::auth`].
//!
//! Enabled by the `state-res` feature so client and wasm builds do not compile
//! the state engine.
//!
//! `tk.nutra.cygnus.1` is registered in Rezzy as a v12-derived room version
//! (`StateResVersion::V2_1`), so events pass through unchanged. Rezzy only
//! knows the v12 redaction keys; Cygnus content hashing and signatures must go
//! through [`crate::envelope`] via a Cygnus `EventVerifier`.

use rezzy::auth::{check_auth_with_context, RoomState, StateProvider};
use rezzy::basespec::rezzy_types::{EventProvider, LeanEvent, StateResVersion};
use rezzy::JsonValue as Value;
use std::collections::BTreeMap;
use std::fmt;

/// Events keyed by event ID, for `auth_events` citation checks.
pub type EventMap = BTreeMap<String, LeanEvent<String, Value, String>>;

/// Failure parsing a PDU for the adapter or running base authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RezzyError {
    /// The PDU could not be represented as a Rezzy event.
    Parse(String),
    /// Rezzy's base authorization rejected the event.
    Auth(String),
}

impl fmt::Display for RezzyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(what) => write!(f, "rezzy adapter parse error: {what}"),
            Self::Auth(what) => write!(f, "rezzy base authorization failed: {what}"),
        }
    }
}

impl std::error::Error for RezzyError {}

/// The room state a server presents to base authorization.
///
/// Build it from the state events selected at the event's `prev_events`; this
/// adapter does not choose state or resolve conflicts.
#[derive(Debug, Default, Clone)]
pub struct RoomAuthState {
    state: RoomState<String, Value, String>,
}

impl RoomAuthState {
    /// Build state from `(event_id, event)` pairs. Non-state events are
    /// ignored. Duplicate `(type, state_key)` pairs with different event IDs
    /// are rejected rather than overwritten.
    ///
    /// # Errors
    /// [`RezzyError::Parse`] for malformed PDUs or conflicting state entries.
    pub fn from_state_events<I>(events: I) -> Result<Self, RezzyError>
    where
        I: IntoIterator<Item = (String, Value)>,
    {
        let mut state = RoomState::new();
        for (event_id, event) in events {
            let Some(state_key) = event.get("state_key").and_then(Value::as_str) else {
                continue;
            };
            let event_type = event
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| RezzyError::Parse("state event has no type".to_owned()))?
                .to_owned();
            let lean = adapter_event(&event)?;
            let key = (event_type, state_key.to_owned());
            if let Some(existing) = state.get(&key) {
                if existing.event_id != event_id {
                    return Err(RezzyError::Parse(format!("conflicting state for {key:?}")));
                }
            }
            state.insert(key, lean);
        }
        Ok(Self { state })
    }

    /// The selected state as a Rezzy `RoomState`.
    #[must_use]
    pub fn state(&self) -> &RoomState<String, Value, String> {
        &self.state
    }

    /// Look up one selected state event.
    #[must_use]
    pub fn get(
        &self,
        event_type: &str,
        state_key: &str,
    ) -> Option<&LeanEvent<String, Value, String>> {
        self.state.get_event(event_type, state_key)
    }
}

/// Parse a Cygnus PDU into a Rezzy event without deriving or verifying its ID.
///
/// The supplied `event_id` must already be present on the PDU.
///
/// # Errors
/// [`RezzyError::Parse`] when required Matrix fields are missing or malformed.
pub fn adapter_event(event: &Value) -> Result<LeanEvent<String, Value, String>, RezzyError> {
    LeanEvent::from_value(event, Some(crate::bundle::ROOM_VERSION)).map_err(RezzyError::Parse)
}

/// Whether Rezzy's base membership and power-level rules apply to an event.
///
/// Epoch and seal events are fully authorized by [`crate::auth`] (§5.3/§5.6):
/// their sender, admission, signature, and chain rules replace the v12 member
/// and power-level checks, and no power level is required. Ordinary events
/// still use base v12 authorization plus the Cygnus overlay.
#[must_use]
pub fn base_auth_applies(event: &Value) -> bool {
    !matches!(
        event.get("type").and_then(Value::as_str),
        Some("m.room.user_epoch" | "m.room.server_epoch" | "m.room.server_seal")
    )
}

/// Run Rezzy's base Matrix v12 authorization for one Cygnus PDU.
///
/// `events` supplies the cited `auth_events` for citation checks; pass `None`
/// only when the caller has already validated those citations. The
/// Cygnus-specific rules in [`crate::auth`] must run separately.
///
/// # Errors
/// [`RezzyError::Parse`] for an unrepresentable PDU, or [`RezzyError::Auth`]
/// when base authorization rejects it.
pub fn check_base_auth(
    event: &Value,
    state: &RoomAuthState,
    events: Option<&EventMap>,
) -> Result<(), RezzyError> {
    let lean = adapter_event(event)?;
    let auth_context: Option<&dyn EventProvider<String, Value, LeanEvent<String, Value, String>>> =
        events.map(|map| map as &dyn EventProvider<_, _, _>);
    check_auth_with_context(
        &lean,
        &state.state,
        StateResVersion::V2_1,
        None,
        auth_context,
    )
    .map_err(|error| RezzyError::Auth(error.to_string()))
}
