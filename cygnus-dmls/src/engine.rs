//! Stateless-by-call operations over the [`crate::registry::Registry`].
//!
//! Every function takes the device seed as an argument and builds a
//! `SignatureKeyPair` for the call; the seed is never stored, so it cannot
//! reach a persisted blob.

use cygnus_core::{Kind, Principal};
use openmls::prelude::{tls_codec::Serialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use rezzy_json::Value;

use crate::{
    content::{ContentError, KeyPackageContent},
    registry::{encode_secrets, RegistryError},
    wire::{self, MemberKey},
    MemberIdentity, CIPHERSUITE,
};

/// Errors from engine operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// The identity or seed is unusable.
    #[error("bad_argument: {0}")]
    BadArgument(&'static str),
    /// A content builder or parser failed.
    #[error(transparent)]
    Content(#[from] ContentError),
    /// A registry operation failed.
    #[error(transparent)]
    Registry(#[from] RegistryError),
    /// `OpenMLS` failed.
    #[error("crypto: {0}")]
    Mls(String),
}

fn mls<E: std::fmt::Debug>(error: E) -> EngineError {
    EngineError::Mls(format!("{error:?}"))
}

/// A device signer and credential built from the per-call seed.
pub struct Signer {
    pair: SignatureKeyPair,
    credential: CredentialWithKey,
    identity: MemberIdentity,
}

impl Signer {
    /// Build from an identity and the device seed. Nothing is stored.
    #[must_use]
    pub fn new(identity: MemberIdentity, seed: [u8; 32]) -> Self {
        let public = <[u8; 32]>::from(ed25519_zebra::SigningKey::from(seed).verification_key());
        let pair =
            SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), public.to_vec());
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity.credential_bytes()).into(),
            signature_key: public.to_vec().into(),
        };
        Self {
            pair,
            credential,
            identity,
        }
    }

    /// The member key (`principal:device`).
    #[must_use]
    pub fn member_key(&self) -> MemberKey {
        MemberKey {
            principal: self.identity.principal.clone(),
            device_id: self.identity.device_id.clone(),
        }
    }
}

/// Output of [`key_package`].
#[derive(Debug)]
pub struct KeyPackageOut {
    /// The `m.dmls.key_package` content.
    pub content: Value,
    /// `key_package_id`.
    pub key_package_id: [u8; 32],
    /// Private material to persist (encrypted) before publishing.
    pub secrets: Vec<u8>,
}

/// Build a key package and the secrets blob that lets this device redeem it.
///
/// # Errors
///
/// [`EngineError`] if `OpenMLS` or content building fails.
pub fn key_package(signer: &Signer, expires_ts: Option<u64>) -> Result<KeyPackageOut, EngineError> {
    // Validate once: the principal must be a user principal.
    if Principal::parse(&signer.identity.principal).map(|p| p.kind) != Ok(Kind::User) {
        return Err(EngineError::BadArgument("principal"));
    }
    let provider = OpenMlsRustCrypto::default();
    let bundle = KeyPackage::builder()
        .build(
            CIPHERSUITE,
            &provider,
            &signer.pair,
            signer.credential.clone(),
        )
        .map_err(mls)?;
    let key_package = bundle.key_package().tls_serialize_detached().map_err(mls)?;
    let content = KeyPackageContent {
        owner: signer.member_key(),
        key_package,
        expires_ts,
    };
    Ok(KeyPackageOut {
        key_package_id: wire::key_package_id(&content.key_package),
        content: content.to_value()?,
        secrets: encode_secrets(&provider),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::decode_secrets;

    const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";

    #[test]
    fn key_package_content_round_trips_and_secrets_hold_no_seed() {
        let seed = [0x5A_u8; 32];
        let signer = Signer::new(MemberIdentity::new(ALICE, "D1").unwrap(), seed);
        let out = key_package(&signer, Some(1_800_000_000_000)).unwrap();

        let parsed = KeyPackageContent::parse(&out.content, &signer.member_key()).unwrap();
        assert_eq!(parsed.key_package_id(), out.key_package_id);

        let needle = &seed[..];
        assert!(!out.secrets.windows(needle.len()).any(|w| w == needle));
        assert!(decode_secrets(&out.secrets).is_ok());
        let mut cut = out.secrets.clone();
        cut.pop();
        assert_eq!(decode_secrets(&cut).unwrap_err().code(), "bad_state");
    }
}
