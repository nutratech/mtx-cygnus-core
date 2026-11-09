//! I/O-free core for MSC00FC ("Cygnus") self-certifying identities.
//!
//! Servers and users are identified by the SHA-256 digest of the first link of
//! a pre-rotated Ed25519 key chain. This crate implements the link format and
//! its verification rules (spec §2). Later layers (device certificates, event
//! envelopes, tip bundles) build on these primitives.

pub mod auth;
pub mod binding;
pub mod bundle;
pub mod cert;
pub mod envelope;
pub mod error;
pub mod link;
pub mod principal;
#[cfg(feature = "state-res")]
pub mod rezzy_integration;
pub mod seal;

pub use cert::DeviceCertificate;
pub use error::Error;
pub use link::{Body, Kind, Link, Payload};
pub use principal::Principal;

/// Domain tag for rotation-key commitments (§2.1), including trailing NUL.
pub const ROT_TAG: &[u8] = b"matrix-cygnus-rot-v1\0";
/// Domain tag for link signatures (§2.4), including trailing NUL.
pub const LINK_TAG: &[u8] = b"matrix-cygnus-link-v1\0";
/// Domain tag for user-device certificates (§5.2.1), including trailing NUL.
pub const DEVICE_CERT_TAG: &[u8] = b"matrix-cygnus-device-cert-v1\0";

/// `SHA-256(ROT_TAG ‖ key)`: the commitment to a future rotation key.
#[must_use]
pub fn commitment(rotation_key: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(ROT_TAG);
    h.update(rotation_key);
    h.finalize().into()
}
