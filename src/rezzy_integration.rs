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

use crate::{auth, bundle::VerifiedEpoch, seal::ServerSeal, Error};
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
    /// A Cygnus-specific authorization check rejected the event.
    Cygnus(String),
}

impl fmt::Display for RezzyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(what) => write!(f, "rezzy adapter parse error: {what}"),
            Self::Auth(what) => write!(f, "rezzy base authorization failed: {what}"),
            Self::Cygnus(what) => write!(f, "Cygnus overlay rejected the event: {what}"),
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
        let mut originals: BTreeMap<(String, String), Value> = BTreeMap::new();
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
            if lean.event_id != event_id {
                return Err(RezzyError::Parse(format!(
                    "event ID {event_id} does not match the PDU's {}",
                    lean.event_id
                )));
            }
            let key = (event_type, state_key.to_owned());
            if let Some(existing) = originals.get(&key) {
                // The same event supplied twice is idempotent; anything else
                // would let input order pick the selected state.
                if existing != &event {
                    return Err(RezzyError::Parse(format!("conflicting state for {key:?}")));
                }
                continue;
            }
            originals.insert(key.clone(), event);
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
///
/// This is only a routing predicate. When it returns `false`, the caller must
/// run [`authorize_active_epoch_with_citations`], [`authorize_burn_with_citations`]
/// or [`authorize_seal_with_citations`] instead; skipping base auth without
/// them leaves the event unauthorized.
#[must_use]
pub fn base_auth_applies(event: &Value) -> bool {
    !matches!(
        event.get("type").and_then(Value::as_str),
        Some("m.room.user_epoch" | "m.room.server_epoch" | "m.room.server_seal")
    )
}

/// Validate that every cited auth event is a state event and is still the
/// selected value for its `(type, state_key)` in the supplied state-before.
///
/// Use this for Cygnus epoch and seal events, whose Cygnus authorization
/// replaces Rezzy's base membership and power-level checks. Ordinary events
/// get the same citation validation from [`check_base_auth`]. This validates
/// cited entries; callers must also select the complete required auth-event
/// set for the event according to room v12 and 00FC §5.1.
///
/// # Errors
/// [`RezzyError::Auth`] if a citation is missing, non-state, or stale;
/// [`RezzyError::Parse`] for malformed `auth_events` or a duplicated citation.
pub fn validate_auth_event_citations(
    event: &Value,
    state: &RoomAuthState,
    events: &EventMap,
) -> Result<(), RezzyError> {
    let citations = event
        .get("auth_events")
        .and_then(Value::as_array)
        .ok_or_else(|| RezzyError::Parse("auth_events must be an array".to_owned()))?;
    let mut seen = std::collections::BTreeSet::new();
    for citation in citations {
        let id = citation
            .as_str()
            .ok_or_else(|| RezzyError::Parse("auth event ID must be a string".to_owned()))?;
        if !seen.insert(id) {
            return Err(RezzyError::Parse(format!("duplicate auth event {id}")));
        }
        let cited = events
            .get(id)
            .ok_or_else(|| RezzyError::Auth(format!("auth event {id} is unavailable")))?;
        let state_key = cited
            .state_key
            .as_deref()
            .ok_or_else(|| RezzyError::Auth(format!("auth event {id} is not a state event")))?;
        let current = state
            .state
            .get_event(&cited.event_type, state_key)
            .ok_or_else(|| RezzyError::Auth(format!("auth event {id} is not current state")))?;
        if current.event_id != id {
            return Err(RezzyError::Auth(format!(
                "auth event {id} is stale; current state is {}",
                current.event_id
            )));
        }
    }
    Ok(())
}

/// Check state-before citations and authorize an active epoch event.
///
/// # Errors
/// [`RezzyError::Parse`] when `auth_events` is malformed or repeats a
/// citation, [`RezzyError::Auth`] when a citation is unavailable, is not a
/// state event, or is not the selected state-before event, and
/// [`RezzyError::Cygnus`] when the Cygnus authorization check fails.
pub fn authorize_active_epoch_with_citations(
    event: &Value,
    event_id: &str,
    context: &auth::AuthContext,
    state: &RoomAuthState,
    events: &EventMap,
) -> Result<VerifiedEpoch, RezzyError> {
    validate_auth_event_citations(event, state, events)?;
    auth::authorize_active_epoch(event, event_id, context)
        .map_err(|error: Error| RezzyError::Cygnus(error.to_string()))
}

/// Check state-before citations and authorize a burn event.
///
/// # Errors
/// [`RezzyError::Parse`] when `auth_events` is malformed or repeats a
/// citation, [`RezzyError::Auth`] when a citation is unavailable, is not a
/// state event, or is not the selected state-before event, and
/// [`RezzyError::Cygnus`] when the Cygnus authorization check fails.
pub fn authorize_burn_with_citations(
    event: &Value,
    event_id: &str,
    context: &auth::AuthContext,
    state: &RoomAuthState,
    events: &EventMap,
) -> Result<VerifiedEpoch, RezzyError> {
    validate_auth_event_citations(event, state, events)?;
    auth::authorize_burn(event, event_id, context)
        .map_err(|error: Error| RezzyError::Cygnus(error.to_string()))
}

/// Check state-before citations and authorize a server seal.
///
/// # Errors
/// [`RezzyError::Parse`] when `auth_events` is malformed or repeats a
/// citation, [`RezzyError::Auth`] when a citation is unavailable, is not a
/// state event, or is not the selected state-before event, and
/// [`RezzyError::Cygnus`] when the Cygnus authorization check fails.
pub fn authorize_seal_with_citations(
    event: &Value,
    context: &auth::AuthContext,
    state: &RoomAuthState,
    events: &EventMap,
) -> Result<ServerSeal, RezzyError> {
    validate_auth_event_citations(event, state, events)?;
    auth::authorize_seal(event, context)
        .map_err(|error: Error| RezzyError::Cygnus(error.to_string()))
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
