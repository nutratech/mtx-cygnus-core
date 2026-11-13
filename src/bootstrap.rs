//! Client bootstrap: fresh rotation keys, commitments, and genesis links.
//!
//! The core is I/O-free, so callers provide a platform CSPRNG. The client
//! keeps the resulting private key; only [`RotationKey::commitment`] is sent
//! to the custodian (§4, "Client-supplied genesis commitment").
//!
//! Cygnus identity keys are always generated fresh. They are never derived
//! from Olm or Megolm session keys: those are shared with room participants,
//! rotate per session, and are not private identity secrets.
//!
//! Storage, backup, export and destruction of the private key remain the
//! caller's responsibility. A client keeps exactly one rotation private key at
//! a time: the next one.

use crate::{
    commitment,
    link::{Body, Link, Payload},
    Error, Kind, Principal,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ed25519_zebra::SigningKey;
use rand_core::CryptoRng;
use rezzy_json::{Object, Value};

/// A private rotation key the client keeps until it signs the next link.
///
/// The custodian receives only `BLAKE3(ROT_TAG ‖ public_key)`.
pub struct RotationKey {
    key: SigningKey,
}

/// JSON request body for `POST /_matrix/client/unstable/tk.nutra.cygnus/principal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPrincipalRequest {
    /// Base64url Ed25519 master public key.
    pub master_key: String,
    /// Base64url commitment to the client's first rotation key.
    pub next_commit: String,
}

impl UserPrincipalRequest {
    /// Convert to the shared JSON value used by the client codec.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut object = Object::new();
        object.insert("master_key".into(), self.master_key.clone().into());
        object.insert("next_commit".into(), self.next_commit.clone().into());
        Value::Object(object)
    }
}

impl RotationKey {
    /// Generate a rotation key using a caller-provided cryptographic RNG.
    ///
    /// Use an operating-system-backed CSPRNG supplied by the client platform;
    /// deterministic or shared room keys such as Megolm keys are not suitable.
    #[must_use]
    pub fn generate(rng: &mut impl CryptoRng) -> Self {
        let mut seed = [0; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// Wrap 32 bytes of caller-supplied CSPRNG output.
    ///
    /// The bytes are the Ed25519 private seed. Callers MUST use a
    /// cryptographically secure source and should destroy the key once its
    /// link is signed (§4, "Key destruction").
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            key: SigningKey::from(seed),
        }
    }

    /// The Ed25519 public key revealed when this key signs its link.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        <[u8; 32]>::from(self.key.verification_key())
    }

    /// `BLAKE3(ROT_TAG ‖ public_key)`, the value given to the custodian.
    #[must_use]
    pub fn commitment(&self) -> [u8; 32] {
        commitment(&self.public_key())
    }

    /// Build the public request sent to the custodian. The private rotation
    /// key is never included.
    #[must_use]
    pub fn principal_request(&self, master_key: &[u8; 32]) -> UserPrincipalRequest {
        UserPrincipalRequest {
            master_key: B64.encode(master_key),
            next_commit: B64.encode(self.commitment()),
        }
    }

    /// Borrow the underlying key for [`Link::sign_successor`].
    #[must_use]
    pub fn signing_key(&self) -> &SigningKey {
        &self.key
    }
}

/// Validate the response to `POST /principal` before the client accepts it.
///
/// Per §7 the response has a principal and a `links` array containing the
/// user-genesis link. The link must commit to the request's master key and
/// caller-held rotation key, and its digest must be the returned principal.
///
/// # Errors
/// Returns an error for malformed IDs/links, extra links, or any mismatch with
/// the requested master key or commitment.
pub fn verify_user_principal_response(
    rotation: &RotationKey,
    master_key: &[u8; 32],
    principal_id: &str,
    links: &[String],
) -> Result<Link, Error> {
    let principal = Principal::parse(principal_id)?;
    if principal.kind != Kind::User || principal.to_id() != principal_id {
        return Err(Error::Bootstrap("principal is not a canonical user ID"));
    }
    let [link_b64] = links else {
        return Err(Error::Bootstrap(
            "response must contain exactly one genesis link",
        ));
    };
    let link = Link::from_b64(link_b64)?;
    link.verify_genesis()?;
    if link.body.payload.kind() != Kind::User || link.principal() != principal {
        return Err(Error::Bootstrap("principal does not match user genesis"));
    }
    let Payload::User {
        master_key: committed_master,
        ..
    } = &link.body.payload
    else {
        return Err(Error::Bootstrap("response link is not a user genesis"));
    };
    if *committed_master != Some(*master_key) {
        return Err(Error::Bootstrap("genesis master key differs from request"));
    }
    if link.body.next_commit != rotation.commitment() {
        return Err(Error::Bootstrap("genesis commitment differs from request"));
    }
    Ok(link)
}

/// Build an unsigned user genesis link around the next rotation commitment.
///
/// `rotation` is `K_rot,1`: the client keeps it and gives only its
/// [`RotationKey::commitment`] to the server. The returned link carries no
/// signature, as required for a user genesis (§2.4).
///
/// # Errors
/// Propagates [`Link::user_genesis`] encoding errors.
pub fn user_genesis(
    rotation: &RotationKey,
    custodian: [u8; 32],
    master_key: [u8; 32],
    display_user_id: &str,
) -> Result<Link, Error> {
    Link::user_genesis(Body {
        root: [0; 32],
        height: 0,
        prev: [0; 32],
        next_commit: rotation.commitment(),
        payload: Payload::User {
            custodian,
            master_key: Some(master_key),
            display_user_id: display_user_id.to_owned(),
        },
    })
}

/// Build a signed server genesis link.
///
/// `rotation` is committed for the server's first successor, while
/// `online_key` proves possession of the key used to sign events at height 0.
///
/// # Errors
/// Propagates [`Link::sign_server_genesis`] encoding errors.
pub fn server_genesis(
    rotation: &RotationKey,
    online_key: &SigningKey,
    server_name: &str,
) -> Result<Link, Error> {
    Link::sign_server_genesis(
        Body {
            root: [0; 32],
            height: 0,
            prev: [0; 32],
            next_commit: rotation.commitment(),
            payload: Payload::Server {
                online_key: <[u8; 32]>::from(online_key.verification_key()),
                server_name: server_name.to_owned(),
            },
        },
        online_key,
    )
}

/// Extend a user chain with a link signed by the key committed by `parent`.
///
/// `current` is the key revealed by this link (it must match the parent's
/// commitment); `next` is committed for the following link. This is the
/// "client signs the next link with its own key" step after a handover.
///
/// # Errors
/// Returns [`Error::Commitment`] when `current` does not match the parent's
/// commitment, [`Error::Successor`] when the master key changes or the parent
/// is not a user link, and propagates encoding and signing errors.
pub fn user_successor(
    parent: &Link,
    current: &RotationKey,
    next: &RotationKey,
    custodian: [u8; 32],
    master_key: [u8; 32],
    display_user_id: &str,
) -> Result<Link, Error> {
    if !matches!(&parent.body.payload, Payload::User { .. }) {
        return Err(Error::Successor("kind"));
    }
    if let Payload::User {
        master_key: previous,
        ..
    } = &parent.body.payload
    {
        if previous.as_ref() != Some(&master_key) {
            return Err(Error::Successor("master_key"));
        }
    }
    let body = successor_body(
        parent,
        current,
        next,
        Payload::User {
            custodian,
            master_key: Some(master_key),
            display_user_id: display_user_id.to_owned(),
        },
    )?;
    Link::sign_successor(body, current.signing_key())
}

/// Extend a server chain with a link signed by the key committed by `parent`.
///
/// `current` must match the parent's commitment and `next` is committed for
/// the following link. `online_key` is the key that will sign events at the new
/// height.
///
/// # Errors
/// Returns [`Error::Commitment`] when `current` does not match the parent's
/// commitment, [`Error::Successor`] when the parent is not a server link, and
/// propagates encoding and signing errors.
pub fn server_successor(
    parent: &Link,
    current: &RotationKey,
    next: &RotationKey,
    online_key: &SigningKey,
    server_name: &str,
) -> Result<Link, Error> {
    if !matches!(&parent.body.payload, Payload::Server { .. }) {
        return Err(Error::Successor("kind"));
    }
    let body = successor_body(
        parent,
        current,
        next,
        Payload::Server {
            online_key: <[u8; 32]>::from(online_key.verification_key()),
            server_name: server_name.to_owned(),
        },
    )?;
    Link::sign_successor(body, current.signing_key())
}

/// Build a successor body, checking the parent's rotation commitment and that
/// the height does not overflow.
fn successor_body(
    parent: &Link,
    current: &RotationKey,
    next: &RotationKey,
    payload: Payload,
) -> Result<Body, Error> {
    if current.commitment() != parent.body.next_commit {
        return Err(Error::Commitment);
    }
    Ok(Body {
        root: parent.principal().root,
        height: parent
            .body
            .height
            .checked_add(1)
            .ok_or(Error::Field("height overflow"))?,
        prev: parent.digest(),
        next_commit: next.commitment(),
        payload,
    })
}
