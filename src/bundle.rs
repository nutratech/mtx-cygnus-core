//! Client-verifiable create events, identity epochs, burns, and Pass 0 (§4/§6).

use crate::{
    cert::DeviceCertificate,
    envelope::{
        event_id as computed_event_id, verify_custodian_signature, verify_device_signature,
    },
    link::{Body, Kind, Link, Payload},
    Error, Principal,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Unstable room-version identifier used by the current MSC00FC vectors.
pub const ROOM_VERSION: &str = "tk.nutra.cygnus.1";

/// A verified create event and the two identity chains it establishes.
#[derive(Debug, Clone)]
pub struct VerifiedCreate {
    /// The derived room identifier (`!` + create reference hash).
    pub room_id: String,
    /// User principal of the creator.
    pub user_principal: Principal,
    /// Server principal of the founding server.
    pub server_principal: Principal,
    /// Verified user chain from genesis.
    pub user_links: Vec<Link>,
    /// Verified server chain from genesis.
    pub server_links: Vec<Link>,
}

impl VerifiedCreate {
    /// Validate the room-v12 Cygnus create event, its creator chains and both
    /// required signatures.
    ///
    /// `expected_event_id` is the event ID supplied by the surrounding PDU or
    /// event bundle. It is checked against the locally computed reference hash.
    ///
    /// # Errors
    /// Returns [`Error::Create`] for missing or inconsistent create data and
    /// the underlying link, certificate, canonicalization, or signature error
    /// for invalid cryptographic material.
    #[allow(clippy::too_many_lines)]
    pub fn verify(event: &rezzy_json::Value, expected_event_id: &str) -> Result<Self, Error> {
        let object = event
            .as_object()
            .ok_or(Error::Create("event must be an object"))?;
        if string(object.get("type"))? != "m.room.create" {
            return Err(Error::Create("wrong event type"));
        }
        if computed_event_id(event).map_err(|_| Error::CanonicalJson)? != expected_event_id {
            return Err(Error::Create("event ID does not match reference hash"));
        }
        let content = object
            .get("content")
            .and_then(rezzy_json::Value::as_object)
            .ok_or(Error::Create("content must be an object"))?;
        if string(content.get("room_version"))? != ROOM_VERSION {
            return Err(Error::Create("unsupported room version"));
        }
        let sender = string(object.get("sender"))?;
        let creators = content
            .get("creator_links")
            .and_then(rezzy_json::Value::as_object)
            .ok_or(Error::Create("creator_links must be an object"))?;
        let server_links = parse_chain(creators.get("server"), Kind::Server)?;
        let user_links = parse_chain(creators.get("user"), Kind::User)?;
        let server_genesis = server_links
            .first()
            .ok_or(Error::Create("empty server chain"))?;
        let user_genesis = user_links
            .first()
            .ok_or(Error::Create("empty user chain"))?;
        let server_principal = server_genesis.principal();
        let user_principal = user_genesis.principal();
        if sender != user_principal.to_id() {
            return Err(Error::Create("creator user chain does not match sender"));
        }

        let (user_custodian, master_key, display_user_id) = match &user_links
            .last()
            .expect("nonempty verified chain")
            .body
            .payload
        {
            Payload::User {
                custodian,
                master_key: Some(master_key),
                display_user_id,
            } => (*custodian, *master_key, display_user_id),
            Payload::User {
                master_key: None, ..
            } => {
                return Err(Error::Create("user chain must carry a master key"));
            }
            Payload::Server { .. } => return Err(Error::Create("user link has server payload")),
        };
        if user_custodian != server_principal.root {
            return Err(Error::Create("creator is not custodied by founding server"));
        }
        let server_name = match &server_links
            .last()
            .expect("nonempty verified chain")
            .body
            .payload
        {
            Payload::Server { server_name, .. } => server_name,
            Payload::User { .. } => return Err(Error::Create("server link has user payload")),
        };
        let display_domain = display_user_id
            .rsplit_once(':')
            .map(|(_, domain)| domain)
            .ok_or(Error::Create("display_user_id has no server name"))?;
        if display_domain != server_name {
            return Err(Error::Create("display_user_id does not match server name"));
        }

        let server_height = server_links.last().unwrap().body.height;
        let server_key = match &server_links.last().unwrap().body.payload {
            Payload::Server { online_key, .. } => online_key,
            Payload::User { .. } => unreachable!("chain kind checked"),
        };
        verify_custodian_signature(event, &server_principal.to_id(), server_height, server_key)?;

        let certificate = object
            .get("device_certificate")
            .ok_or(Error::Create("missing creator device certificate"))?;
        let verified_certificate =
            DeviceCertificate::parse_and_verify(certificate, sender, &master_key)?;
        verify_device_signature(
            event,
            sender,
            &verified_certificate.device_id,
            &verified_certificate.device_key,
        )?;

        let room_id = format!(
            "!{}",
            expected_event_id
                .strip_prefix('$')
                .unwrap_or(expected_event_id)
        );
        Ok(Self {
            room_id,
            user_principal,
            server_principal,
            user_links,
            server_links,
        })
    }
}

/// Whether a verified epoch establishes an active tip or a burn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochStatus {
    /// The epoch advances or introduces a chain.
    Active,
    /// The epoch proves a rotation-key fork.
    Burned,
}

/// A prior active epoch available to Pass 0 when a fork must freeze.
#[derive(Debug, Clone)]
pub struct ActiveAncestor {
    /// Event ID of the active epoch.
    pub event_id: String,
    /// Full chain established at that event.
    pub links: Vec<Link>,
}

/// A structurally and cryptographically verified identity epoch.
#[derive(Debug, Clone)]
pub struct VerifiedEpoch {
    /// Event ID used only for deterministic tie-breaking.
    pub event_id: String,
    /// Principal whose epoch is being advanced or burned.
    pub principal: Principal,
    /// Active or burned event form.
    pub status: EpochStatus,
    /// Full active chain, or the burn's anchored active chain.
    pub links: Vec<Link>,
    /// Burn fork height; absent for active epochs.
    pub fork_height: Option<u64>,
    /// The chain claim through height `fork_height - 1` for burns.
    pub claim: Vec<Link>,
    /// The two conflicting links for burns.
    pub branches: Option<(Link, Link)>,
    /// Prior active events on the auth chain, oldest first.
    pub ancestors: Vec<ActiveAncestor>,
}

/// Owned result of Pass 0. A freeze may select an auth-chain ancestor that is
/// not present in the candidate slice itself.
#[derive(Debug, Clone)]
pub struct Pass0Resolution {
    /// Selected epoch event ID.
    pub event_id: String,
    /// Resolved identity principal.
    pub principal: Principal,
    /// Whether the selected event is active or burned.
    pub status: EpochStatus,
    /// Active chain at the selected event, or the active anchor for a burn.
    pub links: Vec<Link>,
    /// Burn fork height, absent for an active result.
    pub fork_height: Option<u64>,
}

impl Pass0Resolution {
    fn from_epoch(epoch: &VerifiedEpoch) -> Self {
        Self {
            event_id: epoch.event_id.clone(),
            principal: epoch.principal,
            status: epoch.status,
            links: epoch.links.clone(),
            fork_height: epoch.fork_height,
        }
    }
}

impl VerifiedEpoch {
    /// Parse and verify an active `m.room.server_epoch` or
    /// `m.room.user_epoch` event. With `previous == None`, requires a genesis
    /// only introduction. Otherwise verifies a nonempty slice from the prior
    /// active tip and checks all restated tip fields.
    ///
    /// This verifies link and content integrity. Event authorization and the
    /// event signature's signer selection are supplied by the caller's auth
    /// context and are separate checks.
    ///
    /// # Errors
    /// Returns [`Error::Epoch`] for invalid structure or restated fields and
    /// underlying errors for malformed or invalid links.
    pub fn active(
        event: &rezzy_json::Value,
        event_id: impl Into<String>,
        previous: Option<&Self>,
    ) -> Result<Self, Error> {
        let event_id = event_id.into();
        if computed_event_id(event).map_err(|_| Error::CanonicalJson)? != event_id {
            return Err(Error::Epoch("event ID does not match reference hash"));
        }
        let object = event
            .as_object()
            .ok_or(Error::Epoch("event must be an object"))?;
        let event_type = string(object.get("type"))?;
        let expected_kind = match event_type {
            "m.room.server_epoch" => Kind::Server,
            "m.room.user_epoch" => Kind::User,
            _ => return Err(Error::Epoch("unsupported epoch event type")),
        };
        let principal = Principal::parse(string(object.get("state_key"))?)?;
        if principal.kind != expected_kind {
            return Err(Error::Epoch("state key kind does not match event type"));
        }
        let content = object
            .get("content")
            .and_then(rezzy_json::Value::as_object)
            .ok_or(Error::Epoch("content must be an object"))?;
        if string(content.get("status"))? != "active" {
            return Err(Error::Epoch("status must be active"));
        }
        if let Some(previous) = previous {
            if previous.principal != principal || previous.status != EpochStatus::Active {
                return Err(Error::Epoch(
                    "previous epoch is for another or burned chain",
                ));
            }
        }
        let slice = parse_link_slice(
            content.get("links"),
            expected_kind,
            previous.map(VerifiedEpoch::tip),
        )?;
        let links = if let Some(previous) = previous {
            if slice.is_empty() {
                return Err(Error::Epoch("active link slice must not be empty"));
            }
            [previous.links.as_slice(), slice.as_slice()].concat()
        } else {
            if slice.len() != 1 || slice[0].body.height != 0 || slice[0].digest() != principal.root
            {
                return Err(Error::Epoch(
                    "introduction must contain exactly its genesis link",
                ));
            }
            slice[0].verify_genesis()?;
            slice
        };
        check_restatements(content, expected_kind, links.last().unwrap())?;

        let mut ancestors = previous.map_or_else(Vec::new, |previous| previous.ancestors.clone());
        if let Some(previous) = previous {
            ancestors.push(ActiveAncestor {
                event_id: previous.event_id.clone(),
                links: previous.links.clone(),
            });
        }
        Ok(Self {
            event_id,
            principal,
            status: EpochStatus::Active,
            links,
            fork_height: None,
            claim: Vec::new(),
            branches: None,
            ancestors,
        })
    }

    /// Parse and verify a burn against an active epoch in its auth chain.
    ///
    /// # Errors
    /// Returns [`Error::Epoch`] when the fork proof is stale, incomplete, or
    /// inconsistent; malformed links return their underlying errors.
    pub fn burned(
        event: &rezzy_json::Value,
        event_id: impl Into<String>,
        anchor: &Self,
    ) -> Result<Self, Error> {
        let event_id = event_id.into();
        if computed_event_id(event).map_err(|_| Error::CanonicalJson)? != event_id {
            return Err(Error::Epoch("event ID does not match reference hash"));
        }
        let object = event
            .as_object()
            .ok_or(Error::Epoch("event must be an object"))?;
        let event_type = string(object.get("type"))?;
        let expected_kind = match event_type {
            "m.room.server_epoch" => Kind::Server,
            "m.room.user_epoch" => Kind::User,
            _ => return Err(Error::Epoch("unsupported epoch event type")),
        };
        let principal = Principal::parse(string(object.get("state_key"))?)?;
        if principal != anchor.principal
            || principal.kind != expected_kind
            || anchor.status != EpochStatus::Active
        {
            return Err(Error::Epoch("burn anchor does not match active principal"));
        }
        let content = object
            .get("content")
            .and_then(rezzy_json::Value::as_object)
            .ok_or(Error::Epoch("content must be an object"))?;
        if string(content.get("status"))? != "burned" {
            return Err(Error::Epoch("status must be burned"));
        }
        let fork_height = content
            .get("fork_height")
            .and_then(rezzy_json::Value::as_u64)
            .ok_or(Error::Epoch("fork_height must be an unsigned integer"))?;
        let tip = anchor.tip();
        let current_height = tip.body.height;
        if fork_height < 1 || fork_height < current_height {
            return Err(Error::Epoch("burn fork is below the current tip"));
        }
        let parent_bytes = decode_b64(string(content.get("parent"))?)?;
        let parent_body = Body::parse_exact(&parent_bytes)?;
        let parent_digest: [u8; 32] = Sha256::digest(&parent_bytes).into();
        let parent = Link {
            body: parent_body,
            body_bytes: parent_bytes,
            trailer: Vec::new(),
        };
        let bridge = parse_link_slice(content.get("bridge"), expected_kind, Some(tip))?;
        if fork_height == current_height {
            if !bridge.is_empty() {
                return Err(Error::Epoch("bridge must be empty at the current tip"));
            }
            if parent_digest != tip.body.prev || string(content.get("branch_a"))?.is_empty() {
                return Err(Error::Epoch(
                    "parent or branch_a does not anchor to the tip",
                ));
            }
        } else {
            let required = fork_height - 1 - current_height;
            if bridge.len() as u64 != required {
                return Err(Error::Epoch("bridge length does not reach the fork parent"));
            }
            crate::link::verify_slice(tip, &bridge)?;
            let expected_parent = bridge.last().unwrap_or(tip);
            if parent_digest != expected_parent.digest() {
                return Err(Error::Epoch("parent does not continue the anchored chain"));
            }
        }
        let branch_a = Link::from_b64(string(content.get("branch_a"))?)?;
        let branch_b = Link::from_b64(string(content.get("branch_b"))?)?;
        branch_a.verify_successor(&parent)?;
        branch_b.verify_successor(&parent)?;
        if branch_a.body.height != fork_height || branch_b.body.height != fork_height {
            return Err(Error::Epoch("branch height does not match fork_height"));
        }
        if branch_a.digest() == branch_b.digest() {
            return Err(Error::Epoch("burn branches are identical"));
        }
        if fork_height == current_height && branch_a.digest() != tip.digest() {
            return Err(Error::Epoch("branch_a must be the current tip"));
        }

        let fork_index = usize::try_from(fork_height)
            .map_err(|_| Error::Epoch("fork_height exceeds platform limits"))?;
        let claim = if fork_height == current_height {
            anchor.links[..fork_index].to_vec()
        } else {
            [anchor.links.clone(), bridge].concat()
        };
        let mut ancestors = anchor.ancestors.clone();
        ancestors.push(ActiveAncestor {
            event_id: anchor.event_id.clone(),
            links: anchor.links.clone(),
        });
        Ok(Self {
            event_id,
            principal,
            status: EpochStatus::Burned,
            links: anchor.links.clone(),
            fork_height: Some(fork_height),
            claim,
            branches: Some((branch_a, branch_b)),
            ancestors,
        })
    }

    /// Current active tip (burns retain their active anchor tip).
    #[must_use]
    pub fn tip(&self) -> &Link {
        self.links
            .last()
            .expect("verified epochs always have a genesis")
    }
}

/// Resolve one principal's verified epoch candidates using MSC00FC Pass 0.
///
/// The input must contain only same-principal events already validated
/// against their own auth events.
#[must_use]
pub fn resolve_pass0(candidates: &[VerifiedEpoch]) -> Option<Pass0Resolution> {
    let actives: Vec<&VerifiedEpoch> = candidates
        .iter()
        .filter(|candidate| candidate.status == EpochStatus::Active)
        .collect();
    let burns: Vec<&VerifiedEpoch> = candidates
        .iter()
        .filter(|candidate| candidate.status == EpochStatus::Burned)
        .collect();
    if actives.is_empty() {
        return burns
            .into_iter()
            .min_by_key(|burn| (burn.fork_height.unwrap_or(u64::MAX), burn.event_id.as_str()))
            .map(Pass0Resolution::from_epoch);
    }

    let chains: Vec<Vec<[u8; 32]>> = actives
        .iter()
        .map(|active| active.links.iter().map(Link::digest).collect())
        .collect();
    let longest = chains.iter().max_by_key(|chain| chain.len()).unwrap();
    let linear = chains.iter().all(|chain| is_prefix(chain, longest));
    let (common, threshold) = if linear {
        (longest.clone(), longest.len() as u64 - 1)
    } else {
        divergence(&chains)
    };

    let live_burn = burns
        .into_iter()
        .filter(|burn| burn_is_live(burn, &common, threshold, linear))
        .min_by_key(|burn| (burn.fork_height.unwrap_or(u64::MAX), burn.event_id.as_str()));
    if let Some(burn) = live_burn {
        return Some(Pass0Resolution::from_epoch(burn));
    }
    if linear {
        return actives
            .into_iter()
            .filter(|active| active.links.len() == longest.len())
            .min_by_key(|active| active.event_id.as_str())
            .map(Pass0Resolution::from_epoch);
    }

    let maximal: Vec<&Vec<[u8; 32]>> = chains
        .iter()
        .filter(|chain| {
            !chains
                .iter()
                .any(|other| *chain != other && is_prefix(chain, other))
        })
        .collect();
    let mut ancestors: BTreeMap<&str, &ActiveAncestor> = BTreeMap::new();
    for active in &actives {
        // The full-conflicted-set events themselves are candidates too, not
        // only events inherited through auth chains.
        // Keep the map value borrowed from a stable allocation below instead
        // of synthesizing temporary ancestors.
        for ancestor in &active.ancestors {
            ancestors.insert(&ancestor.event_id, ancestor);
        }
    }
    let common_events: Vec<&ActiveAncestor> = ancestors
        .into_values()
        .filter(|ancestor| {
            let chain: Vec<[u8; 32]> = ancestor.links.iter().map(Link::digest).collect();
            maximal.iter().all(|tip| is_prefix(&chain, tip))
        })
        .collect();
    let mut common: Vec<(String, Vec<Link>)> = common_events
        .into_iter()
        .map(|event| (event.event_id.clone(), event.links.clone()))
        .collect();
    for active in &actives {
        let chain: Vec<[u8; 32]> = active.links.iter().map(Link::digest).collect();
        if maximal.iter().all(|tip| is_prefix(&chain, tip)) {
            common.push((active.event_id.clone(), active.links.clone()));
        }
    }
    let (event_id, links) = common
        .into_iter()
        .max_by(|(id_a, links_a), (id_b, links_b)| {
            links_a
                .len()
                .cmp(&links_b.len())
                .then_with(|| id_b.cmp(id_a))
        })?;
    Some(Pass0Resolution {
        event_id,
        principal: candidates.first()?.principal,
        status: EpochStatus::Active,
        links,
        fork_height: None,
    })
}

/// Verify and extract the server-signing chain carried by an epoch's optional
/// `signer_links` field. The signer identity is the genesis principal.
///
/// # Errors
/// Returns an error if the event has no content object, the field is missing,
/// or any link in the chain is malformed or fails successor verification.
pub fn signer_chain(event: &rezzy_json::Value) -> Result<Vec<Link>, Error> {
    let content = event
        .get("content")
        .and_then(rezzy_json::Value::as_object)
        .ok_or(Error::Epoch("content must be an object"))?;
    parse_chain(content.get("signer_links"), Kind::Server)
}

/// Verify an epoch event's custodian signature using the server epoch selected
/// from that event's authorization state. This deliberately accepts the
/// selected epoch separately: callers must resolve `auth_events` first.
///
/// # Errors
/// Returns an error if the signer chain is not a valid server chain, the
/// event's custodian does not match it, or the signature is invalid.
pub fn verify_epoch_custodian_signature(
    event: &rezzy_json::Value,
    signer_links: &[Link],
) -> Result<(), Error> {
    let first = signer_links
        .first()
        .ok_or(Error::Epoch("custodian signer chain is empty"))?;
    if first.body.payload.kind() != Kind::Server {
        return Err(Error::Epoch(
            "custodian signer chain must be a server chain",
        ));
    }
    first.verify_genesis()?;
    for pair in signer_links.windows(2) {
        pair[1].verify_successor(&pair[0])?;
    }
    let principal = first.principal();
    let tip = signer_links.last().expect("nonempty signer chain");
    let online_key = match &tip.body.payload {
        Payload::Server { online_key, .. } => online_key,
        Payload::User { .. } => return Err(Error::Epoch("custodian epoch is not a server")),
    };
    let content = event
        .get("content")
        .and_then(rezzy_json::Value::as_object)
        .ok_or(Error::Epoch("content must be an object"))?;
    let expected_custodian = match string(event.get("type"))? {
        "m.room.user_epoch" => string(content.get("custodian"))?,
        "m.room.server_epoch" => string(event.get("state_key"))?,
        _ => return Err(Error::Epoch("unsupported epoch event type")),
    };
    if principal.to_id() != expected_custodian {
        return Err(Error::Epoch("custodian principal does not match event"));
    }
    verify_custodian_signature(event, &principal.to_id(), tip.body.height, online_key)
}

fn check_restatements(content: &rezzy_json::Object, kind: Kind, tip: &Link) -> Result<(), Error> {
    if content.get("height").and_then(rezzy_json::Value::as_u64) != Some(tip.body.height) {
        return Err(Error::Epoch("height does not match link tip"));
    }
    if decode_b64(string(content.get("tip"))?)? != tip.digest() {
        return Err(Error::Epoch("tip digest does not match link tip"));
    }
    match (&tip.body.payload, kind) {
        (
            Payload::Server {
                online_key,
                server_name,
            },
            Kind::Server,
        ) => {
            if decode_b64(string(content.get("online_key"))?)? != online_key[..] {
                return Err(Error::Epoch("online_key does not match link tip"));
            }
            if string(content.get("server_name"))? != server_name {
                return Err(Error::Epoch("server_name does not match link tip"));
            }
        }
        (
            Payload::User {
                custodian,
                master_key,
                display_user_id,
            },
            Kind::User,
        ) => {
            let custodian_id = Principal {
                kind: Kind::Server,
                root: *custodian,
            }
            .to_id();
            if string(content.get("custodian"))? != custodian_id {
                return Err(Error::Epoch("custodian does not match link tip"));
            }
            if string(content.get("display_user_id"))? != display_user_id {
                return Err(Error::Epoch("display_user_id does not match link tip"));
            }
            match (content.get("master_key"), master_key) {
                (Some(value), Some(expected))
                    if decode_b64(string(Some(value))?)? == expected[..] => {}
                _ => return Err(Error::Epoch("master_key does not match link tip")),
            }
        }
        _ => return Err(Error::Epoch("link kind does not match event type")),
    }
    Ok(())
}

fn parse_chain(value: Option<&rezzy_json::Value>, kind: Kind) -> Result<Vec<Link>, Error> {
    parse_link_slice(value, kind, None)
}

fn parse_link_slice(
    value: Option<&rezzy_json::Value>,
    kind: Kind,
    parent: Option<&Link>,
) -> Result<Vec<Link>, Error> {
    let values = value
        .and_then(rezzy_json::Value::as_array)
        .ok_or(Error::Epoch("link chain must be an array"))?;
    let mut links = Vec::with_capacity(values.len());
    for value in values {
        let encoded = value
            .as_str()
            .ok_or(Error::Epoch("link entry must be a base64url string"))?;
        let link = Link::from_b64(encoded)?;
        if link.body.payload.kind() != kind {
            return Err(Error::Epoch("link kind does not match event type"));
        }
        if B64.encode(link.to_bytes()) != encoded {
            return Err(Error::Epoch("non-canonical link encoding"));
        }
        if let Some(parent) = links.last().or(parent) {
            link.verify_successor(parent)?;
        } else {
            link.verify_genesis()?;
        }
        links.push(link);
    }
    Ok(links)
}

fn string(value: Option<&rezzy_json::Value>) -> Result<&str, Error> {
    value
        .and_then(rezzy_json::Value::as_str)
        .ok_or(Error::Epoch("required string field is missing"))
}

fn decode_b64(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = B64.decode(value).map_err(|_| Error::Base64)?;
    if B64.encode(&bytes) != value {
        return Err(Error::Epoch("non-canonical base64url encoding"));
    }
    Ok(bytes)
}

fn is_prefix<T: Eq>(prefix: &[T], value: &[T]) -> bool {
    prefix.len() <= value.len() && value[..prefix.len()] == *prefix
}

fn divergence(chains: &[Vec<[u8; 32]>]) -> (Vec<[u8; 32]>, u64) {
    let maximal: Vec<&Vec<[u8; 32]>> = chains
        .iter()
        .filter(|chain| {
            !chains
                .iter()
                .any(|other| *chain != other && is_prefix(chain, other))
        })
        .collect();
    let mut height = 0;
    while maximal.iter().all(|chain| chain.len() > height)
        && maximal
            .iter()
            .map(|chain| chain[height])
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 1
    {
        height += 1;
    }
    (maximal[0][..height].to_vec(), height as u64)
}

fn burn_is_live(burn: &VerifiedEpoch, common: &[[u8; 32]], threshold: u64, linear: bool) -> bool {
    let Some(fork_height) = burn.fork_height else {
        return false;
    };
    let Ok(fork_index) = usize::try_from(fork_height) else {
        return false;
    };
    if fork_height < threshold || burn.claim.len() < fork_index {
        return false;
    }
    let overlap = fork_index.min(common.len());
    if !burn.claim[..overlap]
        .iter()
        .map(Link::digest)
        .eq(common[..overlap].iter().copied())
    {
        return false;
    }
    if linear && fork_height == threshold {
        let Some((branch_a, branch_b)) = &burn.branches else {
            return false;
        };
        if common
            .get(fork_index)
            .is_none_or(|tip| branch_a.digest() != *tip && branch_b.digest() != *tip)
        {
            return false;
        }
    }
    true
}
