//! MSC00FC authorization additions over caller-selected room-v12 auth state.
//!
//! Matrix v12 state resolution and base authorization remain the caller's
//! responsibility. This module checks Cygnus epoch, custodian, device, and
//! relay rules against state selected from the event's auth events.

use crate::{
    binding::{validate_server_acl_content, Acl},
    bundle::{signer_chain, EpochStatus, VerifiedEpoch},
    cert::DeviceCertificate,
    envelope::{content_hash_b64, verify_custodian_signature, verify_device_signature},
    link::{Kind, Link, Payload},
    Error, Principal,
};
use std::collections::{BTreeMap, BTreeSet};

/// Current membership and custodian binding for a room member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberState {
    /// Matrix membership value.
    pub membership: String,
    /// Custodian principal in the membership event, if present.
    pub custodian: Option<String>,
}

/// State selected from auth events and validated by the room implementation.
#[derive(Debug, Default, Clone)]
pub struct AuthContext {
    /// Principals with creator privileges.
    pub creators: BTreeSet<String>,
    /// Current memberships, keyed by user principal ID.
    pub members: BTreeMap<String, MemberState>,
    /// Current user epochs, keyed by user principal ID.
    pub user_epochs: BTreeMap<String, VerifiedEpoch>,
    /// Current server epochs, keyed by server principal ID.
    pub server_epochs: BTreeMap<String, VerifiedEpoch>,
    /// Current join rule, if one exists.
    pub join_rule: Option<String>,
    /// Current validated server ACL, if one exists.
    pub server_acl: Option<Acl>,
}

/// Verify a Cygnus room create event, its content hash, event ID, creator
/// chains, device certificate, and required signatures.
///
/// # Errors
/// Returns an authorization or underlying create, canonicalization, or
/// signature error when the create PDU is invalid.
pub fn authorize_create(
    event: &rezzy_json::Value,
    event_id: &str,
) -> Result<crate::bundle::VerifiedCreate, Error> {
    verify_content_hash(event)?;
    crate::bundle::VerifiedCreate::verify(event, event_id)
}

/// Verify an active epoch event, its link chain, sender/admission rules, and
/// at least one permitted server signature.
///
/// # Errors
/// Returns an authorization or underlying parsing, link, ID, or signature
/// error when a Cygnus epoch rule fails.
pub fn authorize_active_epoch(
    event: &rezzy_json::Value,
    event_id: &str,
    context: &AuthContext,
) -> Result<VerifiedEpoch, Error> {
    verify_content_hash(event)?;
    let kind = match string(event.get("type"))? {
        "m.room.user_epoch" => Kind::User,
        "m.room.server_epoch" => Kind::Server,
        _ => return Err(Error::Authorization("not an epoch event")),
    };
    let state_key = string(event.get("state_key"))?;
    let previous = match kind {
        Kind::User => context.user_epochs.get(state_key),
        Kind::Server => context.server_epochs.get(state_key),
    };
    let epoch = VerifiedEpoch::active(event, event_id, previous)?;
    if kind == Kind::User
        && epoch.links.iter().any(|link| {
            !matches!(
                &link.body.payload,
                Payload::User {
                    master_key: Some(_),
                    ..
                }
            )
        })
    {
        return Err(Error::Authorization(
            "every active user link must retain its master key",
        ));
    }

    let sender = string(event.get("sender"))?;
    let event_content = event
        .get("content")
        .and_then(rezzy_json::Value::as_object)
        .ok_or(Error::Authorization("content must be an object"))?;
    let own_signer = match kind {
        Kind::Server => state_key.to_owned(),
        Kind::User => string(event_content.get("custodian"))?.to_owned(),
    };
    let principal_sends = match kind {
        Kind::User => sender == state_key,
        Kind::Server => {
            context
                .user_epochs
                .get(sender)
                .filter(|user| user.status == EpochStatus::Active)
                .and_then(user_custodian)
                .as_deref()
                == Some(state_key)
        }
    };
    let relay = previous.is_some()
        && context
            .members
            .get(sender)
            .is_some_and(|member| member.membership == "join");
    if !principal_sends && !relay {
        return Err(Error::Authorization("sender may not send this epoch event"));
    }
    if !admitted(context, sender) {
        return Err(Error::Authorization("sender is not admitted"));
    }

    let mut permitted = Vec::new();
    if principal_sends {
        permitted.push(own_signer);
    }
    if relay {
        if let Some(custodian) = context.user_epochs.get(sender).and_then(user_custodian) {
            permitted.push(custodian);
        }
    }
    let signed = permitted.iter().any(|signer| {
        signer_chain_for(event, signer, &epoch, previous, context)
            .and_then(|links| verify_server_signature(event, signer, &links))
            .is_ok()
    });
    if !signed {
        return Err(Error::Authorization("not signed by a permitted server"));
    }
    Ok(epoch)
}

/// Verify a burn proof and require a joined sender with a valid custodian
/// signature.
///
/// # Errors
/// Returns an authorization or underlying epoch-proof or signature error.
pub fn authorize_burn(
    event: &rezzy_json::Value,
    event_id: &str,
    context: &AuthContext,
) -> Result<VerifiedEpoch, Error> {
    verify_content_hash(event)?;
    let state_key = string(event.get("state_key"))?;
    let previous = match string(event.get("type"))? {
        "m.room.user_epoch" => context.user_epochs.get(state_key),
        "m.room.server_epoch" => context.server_epochs.get(state_key),
        _ => return Err(Error::Authorization("not an epoch event")),
    }
    .ok_or(Error::Authorization("burn has no active anchor"))?;
    if previous.status != EpochStatus::Active {
        return Err(Error::Authorization("burn anchor is not active"));
    }
    let epoch = VerifiedEpoch::burned(event, event_id, previous)?;
    let sender = string(event.get("sender"))?;
    if context
        .members
        .get(sender)
        .is_none_or(|member| member.membership != "join")
    {
        return Err(Error::Authorization("burn sender must be joined"));
    }
    let user = context
        .user_epochs
        .get(sender)
        .filter(|user| user.status == EpochStatus::Active)
        .ok_or(Error::Authorization("burn sender has no active user epoch"))?;
    let custodian =
        user_custodian(user).ok_or(Error::Authorization("burn sender has no custodian"))?;
    let server = context
        .server_epochs
        .get(&custodian)
        .filter(|server| server.status == EpochStatus::Active)
        .ok_or(Error::Authorization(
            "burn custodian has no active server epoch",
        ))?;
    verify_server_signature(event, &custodian, &server.links)?;
    Ok(epoch)
}

/// Verify the §5.5 active-epoch, membership-custodian, device-certificate,
/// device-signature, and custodian-signature requirements for an ordinary
/// user-sent event. Room-v12 base authorization remains external.
///
/// # Errors
/// Returns an authorization, certificate, or signature error when a required
/// state item or proof is missing or invalid.
pub fn authorize_user_event(event: &rezzy_json::Value, context: &AuthContext) -> Result<(), Error> {
    verify_content_hash(event)?;
    if string(event.get("type"))? == "m.room.server_acl" {
        let event_content = event
            .get("content")
            .ok_or(Error::Authorization("server ACL has no content"))?;
        validate_server_acl_content(event_content)?;
    }
    let sender = string(event.get("sender"))?;
    let principal = Principal::parse(sender)?;
    if principal.kind != Kind::User {
        return Err(Error::Authorization("sender is not a user principal"));
    }
    let user = context
        .user_epochs
        .get(sender)
        .filter(|user| user.status == EpochStatus::Active)
        .ok_or(Error::Authorization("sender has no active user epoch"))?;
    let custodian =
        user_custodian(user).ok_or(Error::Authorization("sender epoch has no custodian"))?;
    let server = context
        .server_epochs
        .get(&custodian)
        .filter(|server| server.status == EpochStatus::Active)
        .ok_or(Error::Authorization("custodian has no active server epoch"))?;
    let is_self_member = string(event.get("type"))? == "m.room.member"
        && event.get("state_key").and_then(rezzy_json::Value::as_str) == Some(sender);
    let member = context.members.get(sender);
    if is_self_member {
        let event_content = event
            .get("content")
            .and_then(rezzy_json::Value::as_object)
            .ok_or(Error::Authorization("content must be an object"))?;
        if string(event_content.get("custodian"))? != custodian {
            return Err(Error::Authorization("member event custodian mismatch"));
        }
        let rebind_join = string(event_content.get("membership"))? == "join"
            && member.is_some_and(|member| {
                member.membership == "join"
                    && member
                        .custodian
                        .as_deref()
                        .is_some_and(|old| old != custodian)
            });
        if rebind_join
            && context.join_rule.as_deref() != Some("public")
            && member.is_some_and(|member| acl_denies_old_custodian(member, context))
        {
            return Err(Error::Authorization(
                "rebinding denied by the previous custodian ACL",
            ));
        }
    } else if let Some(member) = member {
        if member.custodian.as_deref() != Some(&custodian) {
            return Err(Error::Authorization(
                "membership is bound to another custodian",
            ));
        }
    }

    let Payload::User {
        master_key: Some(master_key),
        ..
    } = &user.tip().body.payload
    else {
        return Err(Error::Authorization("user epoch has no master key"));
    };
    let certificate = event
        .get("device_certificate")
        .ok_or(Error::Authorization("missing device certificate"))?;
    let certificate = DeviceCertificate::parse_and_verify(certificate, sender, master_key)?;
    verify_device_signature(
        event,
        sender,
        &certificate.device_id,
        &certificate.device_key,
    )?;
    verify_server_signature(event, &custodian, &server.links)
}

fn signer_chain_for(
    event: &rezzy_json::Value,
    signer: &str,
    event_epoch: &VerifiedEpoch,
    previous: Option<&VerifiedEpoch>,
    context: &AuthContext,
) -> Result<Vec<Link>, Error> {
    let self_advance = event.get("type").and_then(rezzy_json::Value::as_str)
        == Some("m.room.server_epoch")
        && event.get("state_key").and_then(rezzy_json::Value::as_str) == Some(signer)
        && previous.is_some();
    if self_advance {
        return Ok(event_epoch.links.clone());
    }
    if let Some(epoch) = context.server_epochs.get(signer) {
        if epoch.status != EpochStatus::Active {
            return Err(Error::Authorization("signer server epoch is burned"));
        }
        return Ok(epoch.links.clone());
    }
    signer_chain(event)
}

fn verify_server_signature(
    event: &rezzy_json::Value,
    signer: &str,
    links: &[Link],
) -> Result<(), Error> {
    verify_content_hash(event)?;
    let first = links
        .first()
        .ok_or(Error::Authorization("signer chain is empty"))?;
    first.verify_genesis()?;
    for pair in links.windows(2) {
        pair[1].verify_successor(&pair[0])?;
    }
    let principal = first.principal();
    if principal.kind != Kind::Server || principal.to_id() != signer {
        return Err(Error::Authorization(
            "signer chain belongs to another server",
        ));
    }
    let tip = links.last().expect("nonempty signer chain");
    let key = match &tip.body.payload {
        Payload::Server { online_key, .. } => online_key,
        Payload::User { .. } => return Err(Error::Authorization("signer chain is not a server")),
    };
    verify_custodian_signature(event, signer, tip.body.height, key)
}

fn user_custodian(epoch: &VerifiedEpoch) -> Option<String> {
    match &epoch.tip().body.payload {
        Payload::User { custodian, .. } => Some(
            Principal {
                kind: Kind::Server,
                root: *custodian,
            }
            .to_id(),
        ),
        Payload::Server { .. } => None,
    }
}

fn admitted(context: &AuthContext, sender: &str) -> bool {
    context.creators.contains(sender)
        || context
            .members
            .get(sender)
            .is_some_and(|member| matches!(member.membership.as_str(), "join" | "invite" | "knock"))
        || context.join_rule.as_deref().is_some_and(|rule| {
            matches!(rule, "public" | "knock" | "restricted" | "knock_restricted")
        })
}

fn acl_denies_old_custodian(member: &MemberState, context: &AuthContext) -> bool {
    let Some(old) = member.custodian.as_deref() else {
        return false;
    };
    let mut names = vec![old.to_owned()];
    if let Some(epoch) = context.server_epochs.get(old) {
        if let Payload::Server { server_name, .. } = &epoch.tip().body.payload {
            names.push(server_name.clone());
        }
    }
    context.server_acl.as_ref().is_some_and(|acl| {
        acl.deny.iter().any(|pattern| {
            if pattern.starts_with('~') {
                pattern == old
            } else {
                names.iter().any(|name| wildcard(pattern, name))
            }
        })
    })
}

fn wildcard(pattern: &str, text: &str) -> bool {
    let (pattern, text): (Vec<char>, Vec<char>) =
        (pattern.chars().collect(), text.chars().collect());
    let (mut p, mut t) = (0, 0);
    let (mut star, mut mark) = (None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            mark = t;
        } else if let Some(star) = star {
            p = star + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

fn string(value: Option<&rezzy_json::Value>) -> Result<&str, Error> {
    value
        .and_then(rezzy_json::Value::as_str)
        .ok_or(Error::Authorization("required string field is missing"))
}

fn verify_content_hash(event: &rezzy_json::Value) -> Result<(), Error> {
    let expected = event
        .get("hashes")
        .and_then(|hashes| hashes.get("sha256"))
        .and_then(rezzy_json::Value::as_str)
        .ok_or(Error::Authorization("missing content hash"))?;
    if content_hash_b64(event)? != expected {
        return Err(Error::Authorization("content hash mismatch"));
    }
    Ok(())
}
