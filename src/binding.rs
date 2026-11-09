//! §8 name binding and ingress policy.
//!
//! These are pure state machines: DNS and lookup transport are external, and
//! the caller supplies complete, cryptographically verified server branches.

use crate::link::{Kind, Link, Payload};
use crate::{Error, Principal};
use std::collections::{BTreeMap, BTreeSet};

/// Observed state of one `(name, principal)` binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingState {
    /// Never observed.
    Unverified,
    /// The latest observation of `name` resolved to this principal.
    Verified,
    /// The latest observation of `name` resolved to a different principal.
    Contested,
    /// Observed verified, then a lookup outage; still admits until disproven.
    FormerlyVerified,
}

impl BindingState {
    /// Stable label matching the reference model's strings.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Verified => "verified",
            Self::Contested => "contested",
            Self::FormerlyVerified => "formerly verified",
        }
    }
}

/// Observations of server names and the principals each has resolved to.
#[derive(Debug, Default, Clone)]
pub struct NameBinding {
    states: BTreeMap<(String, String), BindingState>,
    seen: BTreeMap<String, BTreeSet<String>>,
}

impl NameBinding {
    /// Records a lookup result. `None` is an outage: it preserves verified
    /// pairs as [`BindingState::FormerlyVerified`] instead of clearing them.
    pub fn observe(&mut self, name: &str, principal: Option<&str>) {
        if let Some(principal) = principal {
            self.seen
                .entry(name.to_owned())
                .or_default()
                .insert(principal.to_owned());
        }
        let pairs = self.seen.get(name).cloned().unwrap_or_default();
        match principal {
            Some(principal) => {
                for pair in pairs {
                    let state = if pair == principal {
                        BindingState::Verified
                    } else {
                        BindingState::Contested
                    };
                    self.states.insert((name.to_owned(), pair), state);
                }
            }
            None => {
                for pair in pairs {
                    let key = (name.to_owned(), pair);
                    if self.states.get(&key) == Some(&BindingState::Verified) {
                        self.states.insert(key, BindingState::FormerlyVerified);
                    }
                }
            }
        }
    }

    /// Current state of `(name, principal)`, defaulting to unverified.
    #[must_use]
    pub fn state(&self, name: &str, principal: &str) -> BindingState {
        self.states
            .get(&(name.to_owned(), principal.to_owned()))
            .copied()
            .unwrap_or(BindingState::Unverified)
    }

    /// Whether any observation for `name` needs a fresh lookup.
    #[must_use]
    pub fn needs_reverification(&self, name: &str) -> bool {
        self.seen.get(name).is_some_and(|pairs| {
            pairs.iter().any(|pair| {
                matches!(
                    self.state(name, pair),
                    BindingState::Contested | BindingState::FormerlyVerified
                )
            })
        })
    }

    /// Whether `name` may satisfy an ACL `allow` rule for `principal`.
    #[must_use]
    pub fn admits_name_allow(&self, name: &str, principal: &str) -> bool {
        matches!(
            self.state(name, principal),
            BindingState::Verified | BindingState::FormerlyVerified
        )
    }
}

/// Ingress decision for a possibly new origin name (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingress {
    /// The origin may be admitted under the ACL.
    Admit,
    /// The origin is denied or its name is not on an accepted branch.
    Reject,
    /// First contact without a complete branch: supply links and retry.
    Defer,
}

/// A minimal name/principal ACL. Entries are glob patterns over server names,
/// or `~<principal>` to match a principal directly.
#[derive(Debug, Clone, Default)]
pub struct Acl {
    /// Allowed entries.
    pub allow: Vec<String>,
    /// Denied entries; checked before `allow`.
    pub deny: Vec<String>,
}

/// Parse and validate server ACL content, including canonical principal
/// syntax required for entries beginning with the server sigil.
///
/// # Errors
/// Returns an authorization error for non-array ACL fields, non-string
/// entries, or malformed/non-canonical server principal entries.
pub fn validate_server_acl_content(content: &rezzy_json::Value) -> Result<Acl, Error> {
    let object = content
        .as_object()
        .ok_or(Error::Authorization("server ACL content must be an object"))?;
    let mut acl = Acl::default();
    for (field, target) in [("allow", &mut acl.allow), ("deny", &mut acl.deny)] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let entries = value
            .as_array()
            .ok_or(Error::Authorization("server ACL entries must be arrays"))?;
        for value in entries {
            let entry = value
                .as_str()
                .ok_or(Error::Authorization("server ACL entries must be strings"))?;
            if entry.starts_with('~') {
                let principal = Principal::parse(entry)
                    .map_err(|_| Error::Authorization("invalid principal in server ACL"))?;
                if principal.kind != Kind::Server || principal.to_id() != entry {
                    return Err(Error::Authorization("invalid principal in server ACL"));
                }
            }
            target.push(entry.to_owned());
        }
    }
    Ok(acl)
}

/// Applies §8 ingress policy over complete, shard-verified server branches.
///
/// `known_branches` is `None` for true first contact; the caller cannot supply
/// complete history in that case and the result is [`Ingress::Defer`] unless a
/// direct deny already rejects the origin.
#[must_use]
pub fn admit(
    acl: &Acl,
    principal: &Principal,
    origin_name: &str,
    room_tip: Option<&Link>,
    known_branches: Option<&[Vec<Link>]>,
    bindings: &NameBinding,
) -> Ingress {
    let principal_id = principal.to_id();

    // Direct denies do not need chain history.
    if acl
        .deny
        .iter()
        .any(|entry| matches_entry(entry, &principal_id, &[origin_name]))
    {
        return Ingress::Reject;
    }

    let branches: Vec<&Vec<Link>> = known_branches
        .unwrap_or_default()
        .iter()
        .filter(|branch| complete_server_branch(branch, principal))
        .collect();
    if branches.is_empty() {
        return Ingress::Defer;
    }

    let origin_is_on_accepted_branch = branches.iter().any(|branch| match room_tip {
        // With no room epoch, only the tip of the validated origin branch counts.
        None => server_name(branch.last().expect("nonempty branch")) == Some(origin_name),
        Some(tip) => {
            if tip.principal() != *principal {
                return false;
            }
            let Some(index) = branch.iter().position(|link| {
                link.body.height == tip.body.height && link.digest() == tip.digest()
            }) else {
                return false;
            };
            branch[index..].iter().any(|link| {
                link.body.height >= tip.body.height && server_name(link) == Some(origin_name)
            })
        }
    });
    if !origin_is_on_accepted_branch {
        return Ingress::Reject;
    }

    // Historical denies cover every name on every validated branch, not just
    // the origin: an alias from before the current tip is still that origin.
    let historical_names: Vec<&str> = branches
        .iter()
        .flat_map(|branch| branch.iter())
        .filter_map(|link| server_name(link))
        .collect();
    let mut names = vec![origin_name];
    names.extend(historical_names);
    if acl
        .deny
        .iter()
        .any(|entry| matches_entry(entry, &principal_id, &names))
    {
        return Ingress::Reject;
    }

    for entry in &acl.allow {
        if entry.starts_with('~') {
            if *entry == principal_id {
                return Ingress::Admit;
            }
        } else if glob_match(entry, origin_name)
            && bindings.admits_name_allow(origin_name, &principal_id)
        {
            return Ingress::Admit;
        }
    }
    Ingress::Reject
}

fn matches_entry(entry: &str, principal_id: &str, names: &[&str]) -> bool {
    if entry.starts_with('~') {
        return entry == principal_id;
    }
    names.iter().any(|name| glob_match(entry, name))
}

/// Whether an ACL excludes `principal_id` at any of `names`.
///
/// Matches the reference model: an explicit deny wins, and otherwise the
/// principal is excluded unless at least one `allow` entry matches. An empty
/// `allow` list therefore denies everyone.
pub(crate) fn acl_denies(acl: &Acl, principal_id: &str, names: &[&str]) -> bool {
    if acl
        .deny
        .iter()
        .any(|entry| matches_entry(entry, principal_id, names))
    {
        return true;
    }
    !acl.allow
        .iter()
        .any(|entry| matches_entry(entry, principal_id, names))
}

/// Whole-string wildcard match supporting `*` (any run) and `?` (one char).
fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let text: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0, 0);
    let mut star: Option<usize> = None;
    let mut mark = 0;
    while ti < text.len() {
        if pi < pattern.len() && (pattern[pi] == '?' || pattern[pi] == text[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < pattern.len() && pattern[pi] == '*' {
            star = Some(pi);
            pi += 1;
            mark = ti;
        } else if let Some(star) = star {
            pi = star + 1;
            mark += 1;
            ti = mark;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == '*' {
        pi += 1;
    }
    pi == pattern.len()
}

fn server_name(link: &Link) -> Option<&str> {
    match &link.body.payload {
        Payload::Server { server_name, .. } => Some(server_name),
        Payload::User { .. } => None,
    }
}

fn complete_server_branch(branch: &[Link], principal: &Principal) -> bool {
    let Some(first) = branch.first() else {
        return false;
    };
    if first.body.payload.kind() != Kind::Server
        || first.body.height != 0
        || first.body.root != [0; 32]
        || first.body.prev != [0; 32]
        || first.principal() != *principal
    {
        return false;
    }
    branch.windows(2).all(|pair| {
        let (parent, link) = (&pair[0], &pair[1]);
        link.body.payload.kind() == Kind::Server
            && link.body.height == parent.body.height + 1
            && link.body.prev == parent.digest()
            && link.principal() == *principal
    })
}
