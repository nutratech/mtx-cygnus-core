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
//! `tk.nutra.cygnus.1` is a v12-derived room version. Rezzy does not know that
//! identifier, so the adapter presents the create event to Rezzy as v12 while
//! keeping the original event bytes untouched. Cygnus content hashing and
//! signatures never go through this mapping.

use rezzy::auth::{check_auth_with_context, RoomState, StateProvider};
use rezzy::basespec::rezzy_types::{EventProvider, LeanEvent, StateResVersion};
use rezzy_json::Value;
use std::collections::BTreeMap;
use std::fmt;

/// Base room version presented to Rezzy for `tk.nutra.cygnus.1`.
pub const BASE_ROOM_VERSION: &str = "12";

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
    let mut lean =
        LeanEvent::from_value(event, Some(BASE_ROOM_VERSION)).map_err(RezzyError::Parse)?;
    if lean.event_type == "m.room.create"
        && lean.content.get("room_version").and_then(Value::as_str)
            == Some(crate::bundle::ROOM_VERSION)
    {
        let object = lean
            .content
            .as_object_mut()
            .ok_or_else(|| RezzyError::Parse("create content is not an object".to_owned()))?;
        object.insert(
            "room_version".to_owned(),
            Value::String(BASE_ROOM_VERSION.to_owned()),
        );
    }
    Ok(lean)
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
