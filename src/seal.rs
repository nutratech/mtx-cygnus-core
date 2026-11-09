//! `m.room.server_seal` cutover predicates (SPEC).
//!
//! This models the causal graph rules the proposal sketches for self-sealing
//! rotation: seal authorization, top-down seal resolution with a common-ancestor
//! fallback, and the ancestry filter for events signed at a retired height.
//!
//! It is deliberately not room-version authorization. Event auth (membership,
//! custodian, and epoch state) is supplied by the caller, and the graph here is
//! only the `prev_events` DAG the rules need.
//!
//! The fixture scenarios live in `tools/reference_models/pid_cutover.py`.

use crate::{Error, Principal};
use std::collections::{BTreeMap, BTreeSet};

/// Degrees of freedom a seal resolution needs from one room event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEvent {
    /// Event ID, used for identity and tie-free resolution.
    pub event_id: String,
    /// `prev_events` edges.
    pub prev_events: Vec<String>,
    /// Server principal that signed the event.
    pub signer: String,
    /// Height of the signing key in that server's chain.
    pub signer_height: u64,
    /// Set when the event is an `m.room.server_seal`.
    pub seal: Option<SealClaim>,
}

/// Seal height claimed by an event, without the auth-state subject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealClaim {
    /// Height the seal claims to cover.
    pub sealed_height: u64,
    /// Advisory pointer ignored by resolution.
    pub previous_seal: Option<String>,
}

impl GraphEvent {
    /// Seal event at `sealed_height`, with no advisory predecessor.
    #[must_use]
    pub fn sealed(
        event_id: impl Into<String>,
        prev_events: &[&str],
        signer: impl Into<String>,
        signer_height: u64,
        sealed_height: u64,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            prev_events: prev_events.iter().map(|id| (*id).to_owned()).collect(),
            signer: signer.into(),
            signer_height,
            seal: Some(SealClaim {
                sealed_height,
                previous_seal: None,
            }),
        }
    }

    /// Non-seal event.
    #[must_use]
    pub fn plain(
        event_id: impl Into<String>,
        prev_events: &[&str],
        signer: impl Into<String>,
        signer_height: u64,
    ) -> Self {
        Self {
            event_id: event_id.into(),
            prev_events: prev_events.iter().map(|id| (*id).to_owned()).collect(),
            signer: signer.into(),
            signer_height,
            seal: None,
        }
    }
}

/// Parsed `m.room.server_seal` content, plus the subject server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSeal {
    /// Principal named by `state_key`.
    pub server: Principal,
    /// Height the seal claims to cover.
    pub sealed_height: u64,
    /// Advisory pointer to a lower seal; resolution uses ancestry instead.
    pub previous_seal: Option<String>,
}

impl ServerSeal {
    /// Parse the structural fields of a seal event.
    ///
    /// Signature, sender, membership, and epoch authorization are separate:
    /// they depend on the room's auth state, not on this content.
    ///
    /// # Errors
    /// Returns [`Error::Seal`] for the wrong event type, a non-server
    /// `state_key`, a missing or zero `sealed_height`, or a non-string
    /// `previous_seal`.
    pub fn parse(event: &rezzy_json::Value) -> Result<Self, Error> {
        if event
            .get("type")
            .and_then(rezzy_json::Value::as_str)
            .ok_or(Error::Seal("type must be a string"))?
            != "m.room.server_seal"
        {
            return Err(Error::Seal("event type is not m.room.server_seal"));
        }
        let server = Principal::parse(
            event
                .get("state_key")
                .and_then(rezzy_json::Value::as_str)
                .ok_or(Error::Seal("state_key must be a string"))?,
        )
        .map_err(|_| Error::Seal("state_key is not a principal"))?;
        if !matches!(server.kind, crate::Kind::Server) {
            return Err(Error::Seal("state_key is not a server principal"));
        }
        let content = event
            .get("content")
            .and_then(rezzy_json::Value::as_object)
            .ok_or(Error::Seal("content must be an object"))?;
        let sealed_height = content
            .get("sealed_height")
            .and_then(rezzy_json::Value::as_u64)
            .filter(|height| *height >= 1)
            .ok_or(Error::Seal("sealed_height must be a positive integer"))?;
        let previous_seal = match content.get("previous_seal") {
            None | Some(rezzy_json::Value::Null) => None,
            Some(rezzy_json::Value::String(id)) => Some(id.clone()),
            Some(_) => return Err(Error::Seal("previous_seal must be a string or null")),
        };
        Ok(Self {
            server,
            sealed_height,
            previous_seal,
        })
    }
}

/// A room `prev_events` graph indexed by event ID.
#[derive(Debug, Default, Clone)]
pub struct SealGraph {
    events: BTreeMap<String, GraphEvent>,
}

impl SealGraph {
    /// Empty graph.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an event. Reinserting the same event is idempotent; a different
    /// event with an existing ID is rejected.
    ///
    /// # Errors
    /// Returns [`Error::Seal`] when an ID is reused for different content.
    pub fn insert(&mut self, event: GraphEvent) -> Result<(), Error> {
        match self.events.get(&event.event_id) {
            Some(existing) if *existing != event => Err(Error::Seal("event ID reused")),
            _ => {
                self.events.insert(event.event_id.clone(), event);
                Ok(())
            }
        }
    }

    /// The event with `event_id`, if present.
    #[must_use]
    pub fn get(&self, event_id: &str) -> Option<&GraphEvent> {
        self.events.get(event_id)
    }

    /// `event_id` and every event reachable through `prev_events`.
    #[must_use]
    pub fn ancestors(&self, event_id: &str) -> BTreeSet<String> {
        let mut seen = BTreeSet::new();
        let mut stack = vec![event_id.to_owned()];
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if let Some(event) = self.events.get(&current) {
                stack.extend(event.prev_events.iter().cloned());
            }
        }
        seen
    }

    /// Whether `ancestor` is in `event_id`'s causal past (or is the event).
    #[must_use]
    pub fn is_ancestor(&self, ancestor: &str, event_id: &str) -> bool {
        self.ancestors(event_id).contains(ancestor)
    }

    /// Whether a seal may be considered: signed at or above its height and,
    /// above height 1, descending from a lower valid seal of the same server.
    #[must_use]
    pub fn seal_auth_ok(&self, event_id: &str) -> bool {
        let Some(event) = self.events.get(event_id) else {
            return false;
        };
        let Some(seal) = &event.seal else {
            return false;
        };
        if seal.sealed_height < 1 || event.signer_height < seal.sealed_height {
            return false;
        }
        if seal.sealed_height == 1 {
            return true;
        }
        self.ancestors(event_id).into_iter().any(|ancestor| {
            let Some(previous) = self.events.get(&ancestor) else {
                return false;
            };
            let Some(previous_seal) = &previous.seal else {
                return false;
            };
            previous.signer == event.signer
                && previous_seal.sealed_height >= 1
                && previous_seal.sealed_height < seal.sealed_height
                && previous.signer_height >= previous_seal.sealed_height
        })
    }

    /// Resolve the winning seal from the supplied candidates.
    ///
    /// Heights are examined highest first. Exactly one valid candidate at a
    /// height wins. Several at one height are equivocation: resolution falls
    /// back to the highest lower seal in every conflicting candidate's causal
    /// past. A retransmission (identical event ID) is a duplicate, never a
    /// conflict. `event_id` is never used as a tie-break.
    #[must_use]
    pub fn resolve_seal(&self, candidates: &[&str]) -> Option<&GraphEvent> {
        let mut by_height: BTreeMap<u64, BTreeSet<&str>> = BTreeMap::new();
        for id in candidates {
            if let Some(event) = self.events.get(*id) {
                if let Some(seal) = &event.seal {
                    by_height.entry(seal.sealed_height).or_default().insert(id);
                }
            }
        }

        let mut allowed: Option<BTreeSet<String>> = None;
        for candidates in by_height.values().rev() {
            let valid: Vec<&GraphEvent> = candidates
                .iter()
                .filter(|id| allowed.as_ref().is_none_or(|set| set.contains(**id)))
                .filter_map(|id| self.events.get(*id))
                .filter(|event| self.seal_auth_ok(&event.event_id))
                .collect();
            match valid.as_slice() {
                [winner] => return Some(winner),
                [] => {}
                conflicting => {
                    let mut common = self.ancestors(&conflicting[0].event_id);
                    for event in &conflicting[1..] {
                        let past = self.ancestors(&event.event_id);
                        common.retain(|id| past.contains(id));
                    }
                    allowed = Some(match allowed {
                        Some(previous) => previous.intersection(&common).cloned().collect(),
                        None => common,
                    });
                }
            }
        }
        None
    }

    /// Whether `event_id` may contribute once `seal_id` is accepted.
    ///
    /// Events signed by another server always pass. Events signed by the
    /// sealing server at or above `sealed_height` pass. Lower-height events
    /// pass only when they are in the seal's causal past.
    #[must_use]
    pub fn cutover_allows(&self, event_id: &str, seal_id: Option<&str>) -> bool {
        let (Some(event), Some(seal_id)) = (self.events.get(event_id), seal_id) else {
            return true;
        };
        let Some(seal_event) = self.events.get(seal_id) else {
            return true;
        };
        let Some(seal) = &seal_event.seal else {
            return true;
        };
        if event.signer != seal_event.signer || event.signer_height >= seal.sealed_height {
            return true;
        }
        self.is_ancestor(event_id, seal_id)
    }
}
