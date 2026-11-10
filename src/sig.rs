//! Signatures: fixed-depth Merkle trees of WOTS+ one-time keys over SHA-256.
//!
//! A public key is the 32-byte tree root. A signature is
//! `leaf_index(4, BE) ‖ pub_seed ‖ salt ‖ chains ‖ auth_path`. A
//! [`SigningKey`] hands out each leaf once and panics when the tree is spent,
//! so a leaf cannot be signed twice through this API.

use crate::{
    wots::{self, Hash32, Profile, Signature as Wots, Tree, HASH_LEN, SALT_LEN},
    Error,
};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Merkle depth: each key signs `2^TREE_DEPTH` messages.
pub const TREE_DEPTH: usize = 4;
const PROFILE: Profile = Profile::Bytes;
/// Length of every signature in bytes.
pub const SIGNATURE_LEN: usize = 4 + PROFILE.signature_len() + TREE_DEPTH * HASH_LEN;

/// A 32-byte public key (a Merkle root).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerificationKey([u8; 32]);

impl VerificationKey {
    /// The key bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl From<VerificationKey> for [u8; 32] {
    fn from(key: VerificationKey) -> Self {
        key.0
    }
}

impl From<[u8; 32]> for VerificationKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// An encoded signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(Vec<u8>);

impl Signature {
    /// The encoded bytes, [`SIGNATURE_LEN`] long.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }
}

/// A signing key: a tree of one-time keys and the next unused leaf.
#[derive(Debug)]
pub struct SigningKey {
    tree: Tree,
    next: AtomicUsize,
}

impl Clone for SigningKey {
    /// Clones the unused-leaf position too. Signing with both copies reuses
    /// leaves, so never sign with two clones.
    fn clone(&self) -> Self {
        Self {
            tree: self.tree.clone(),
            next: AtomicUsize::new(self.next.load(Ordering::SeqCst)),
        }
    }
}

impl From<[u8; 32]> for SigningKey {
    fn from(seed: [u8; 32]) -> Self {
        Self {
            tree: Tree::new(PROFILE, seed, TREE_DEPTH),
            next: AtomicUsize::new(0),
        }
    }
}

impl SigningKey {
    /// The public key.
    #[must_use]
    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey(self.tree.root())
    }

    /// Sign with the next unused leaf.
    ///
    /// # Panics
    /// Panics when all `2^TREE_DEPTH` leaves are spent; rotate the key.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        let leaf = self.next.fetch_add(1, Ordering::SeqCst);
        assert!(leaf < 1 << TREE_DEPTH, "signing key exhausted; rotate");
        let (sig, path) = self.tree.sign(leaf, msg);
        let mut out = Vec::with_capacity(SIGNATURE_LEN);
        out.extend_from_slice(&u32::try_from(leaf).expect("small").to_be_bytes());
        out.extend_from_slice(&sig.pub_seed);
        out.extend_from_slice(&sig.salt);
        for chain in &sig.chains {
            out.extend_from_slice(chain);
        }
        for node in &path {
            out.extend_from_slice(node);
        }
        debug_assert_eq!(out.len(), SIGNATURE_LEN);
        Signature(out)
    }
}

fn hash32(bytes: &[u8]) -> Hash32 {
    bytes.try_into().expect("32")
}

/// Verify `sig` over `msg` under the 32-byte `key`.
///
/// # Errors
/// [`Error::PublicKey`] for a key that is not 32 bytes and
/// [`Error::Signature`] for a malformed or invalid signature.
pub fn verify(key: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let root: Hash32 = key.try_into().map_err(|_| Error::PublicKey)?;
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::Signature);
    }
    let index = u32::from_be_bytes(sig[..4].try_into().expect("4")) as usize;
    let body = &sig[4..];
    let wots_sig = Wots {
        pub_seed: hash32(&body[..HASH_LEN]),
        salt: body[HASH_LEN..HASH_LEN + SALT_LEN].try_into().expect("16"),
        chains: body[HASH_LEN + SALT_LEN..PROFILE.signature_len()]
            .chunks_exact(HASH_LEN)
            .map(hash32)
            .collect(),
    };
    let path: Vec<Hash32> = body[PROFILE.signature_len()..]
        .chunks_exact(HASH_LEN)
        .map(hash32)
        .collect();
    if wots::verify_tree(PROFILE, &root, index, &wots_sig, &path, msg) {
        Ok(())
    } else {
        Err(Error::Signature)
    }
}
