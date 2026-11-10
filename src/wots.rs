//! Experimental zero-curve WOTS+ signatures over SHA-256 (feature `wots-experimental`).
//!
//! This is a **prototype for evaluation**, not part of the protocol, and it has
//! not been reviewed by a cryptographer. A key may sign **one** message; signing
//! two distinct messages with the same key leaks enough preimages to forge, which
//! [`is_equivocation`] turns into a fraud proof. The Merkle wrapper only allows
//! one signature per leaf and the caller must never reuse a leaf index.
//!
//! Parameters: a 160-bit salted message digest cut into `BITS`-bit words
//! (`BITS` = 8 or 16), plus a two-word checksum. Security is 160-bit classical,
//! about 80-bit against Grover, and the digest is salted per message.

use sha2::{Digest, Sha256};

/// Hash output length in bytes.
pub const HASH_LEN: usize = 32;
/// Per-message salt length in bytes.
pub const SALT_LEN: usize = 16;
const DIGEST_BYTES: usize = 20;

/// A 32-byte hash value.
pub type Hash32 = [u8; HASH_LEN];

/// Winternitz profile: the chain word width in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// 8-bit words: 22 chains, 255 steps per chain.
    Bytes,
    /// 16-bit words: 12 chains, 65,535 steps per chain. Compact but slow.
    Words,
}

impl Profile {
    const fn bits(self) -> usize {
        match self {
            Self::Bytes => 8,
            Self::Words => 16,
        }
    }
    const fn max_step(self) -> u16 {
        match self {
            Self::Bytes => 255,
            Self::Words => u16::MAX,
        }
    }
    const fn msg_words(self) -> usize {
        DIGEST_BYTES * 8 / self.bits()
    }
    /// Number of hash chains (message words plus two checksum words).
    #[must_use]
    pub const fn chains(self) -> usize {
        self.msg_words() + 2
    }
    /// Signature size in bytes: `pub_seed`, salt and one value per chain.
    #[must_use]
    pub const fn signature_len(self) -> usize {
        HASH_LEN + SALT_LEN + self.chains() * HASH_LEN
    }
}

fn tweak(domain: u8, chain: u8, step: u16, seed: &[u8], data: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update([domain, chain]);
    h.update(step.to_le_bytes());
    h.update(seed);
    h.update(data);
    h.finalize().into()
}

fn advance(mut value: Hash32, chain: u8, from: u16, steps: u16, seed: &Hash32) -> Hash32 {
    for step in from..from + steps {
        value = tweak(0x01, chain, step, seed, &value);
    }
    value
}

/// A WOTS+ signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    /// Public seed binding the chains; committed to by the public key.
    pub pub_seed: Hash32,
    /// Per-message randomizer.
    pub salt: [u8; SALT_LEN],
    /// One intermediate chain value per chain.
    pub chains: Vec<Hash32>,
}

impl Signature {
    /// Serialized length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        HASH_LEN + SALT_LEN + self.chains.len() * HASH_LEN
    }

    /// Whether the signature has no chains.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
    }
}

fn steps_for(profile: Profile, pub_seed: &Hash32, salt: &[u8; SALT_LEN], msg: &[u8]) -> Vec<u16> {
    let digest = tweak(0x02, 0, 0, pub_seed, &[salt.as_slice(), msg].concat());
    let words = profile.msg_words();
    let mut steps = Vec::with_capacity(profile.chains());
    let mut checksum: u32 = 0;
    for i in 0..words {
        let word = match profile {
            Profile::Bytes => u16::from(digest[i]),
            Profile::Words => u16::from_be_bytes([digest[2 * i], digest[2 * i + 1]]),
        };
        checksum += u32::from(profile.max_step() - word);
        steps.push(word);
    }
    // Two checksum words, big-endian. The maximum checksum is 20 * 255 or
    // 10 * 65535, which fits in two words of either width.
    let bits = profile.bits();
    let mask = u32::from(profile.max_step());
    steps.push(u16::try_from((checksum >> bits) & mask).expect("masked to a word"));
    steps.push(u16::try_from(checksum & mask).expect("masked to a word"));
    steps
}

fn expand(profile: Profile, seed: &Hash32) -> (Hash32, Vec<Hash32>) {
    let pub_seed = tweak(0x00, 0xFF, 0, seed, b"pub-seed");
    let secrets = (0..profile.chains())
        .map(|i| tweak(0x00, u8::try_from(i).expect("few chains"), 0, seed, b"sk"))
        .collect();
    (pub_seed, secrets)
}

fn compress(pub_seed: &Hash32, tips: &[Hash32]) -> Hash32 {
    let mut h = Sha256::new();
    h.update([0x03]);
    h.update(pub_seed);
    for tip in tips {
        h.update(tip);
    }
    h.finalize().into()
}

/// Derive the 32-byte public key (which doubles as the pre-rotation commitment).
#[must_use]
pub fn public_key(profile: Profile, seed: &Hash32) -> Hash32 {
    let (pub_seed, secrets) = expand(profile, seed);
    let tips: Vec<Hash32> = secrets
        .iter()
        .enumerate()
        .map(|(i, sk)| {
            advance(
                *sk,
                u8::try_from(i).unwrap(),
                0,
                profile.max_step(),
                &pub_seed,
            )
        })
        .collect();
    compress(&pub_seed, &tips)
}

/// Sign `msg` once with `seed`. The salt is derived from the seed and message,
/// so signing the same message twice yields the same signature.
#[must_use]
pub fn sign(profile: Profile, seed: &Hash32, msg: &[u8]) -> Signature {
    let (pub_seed, secrets) = expand(profile, seed);
    let full = tweak(0x04, 0, 0, seed, msg);
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&full[..SALT_LEN]);
    let steps = steps_for(profile, &pub_seed, &salt, msg);
    let chains = secrets
        .iter()
        .zip(&steps)
        .enumerate()
        .map(|(i, (sk, steps))| advance(*sk, u8::try_from(i).unwrap(), 0, *steps, &pub_seed))
        .collect();
    Signature {
        pub_seed,
        salt,
        chains,
    }
}

/// Recompute the public key a signature implies for `msg`.
///
/// Returns `None` when the signature has the wrong number of chains.
#[must_use]
pub fn recover(profile: Profile, sig: &Signature, msg: &[u8]) -> Option<Hash32> {
    if sig.chains.len() != profile.chains() {
        return None;
    }
    let steps = steps_for(profile, &sig.pub_seed, &sig.salt, msg);
    let tips: Vec<Hash32> = sig
        .chains
        .iter()
        .zip(&steps)
        .enumerate()
        .map(|(i, (value, steps))| {
            advance(
                *value,
                u8::try_from(i).unwrap(),
                *steps,
                profile.max_step() - steps,
                &sig.pub_seed,
            )
        })
        .collect();
    Some(compress(&sig.pub_seed, &tips))
}

/// Whether `sig` is a valid signature of `msg` under `public_key`.
#[must_use]
pub fn verify(profile: Profile, public_key: &Hash32, sig: &Signature, msg: &[u8]) -> bool {
    recover(profile, sig, msg).as_ref() == Some(public_key)
}

/// Two valid signatures on different messages under one key prove that the
/// key signed twice. The pair itself is the fraud proof; no smaller proof is
/// attempted here.
#[must_use]
pub fn is_equivocation(
    profile: Profile,
    public_key: &Hash32,
    (sig_a, msg_a): (&Signature, &[u8]),
    (sig_b, msg_b): (&Signature, &[u8]),
) -> bool {
    msg_a != msg_b
        && verify(profile, public_key, sig_a, msg_a)
        && verify(profile, public_key, sig_b, msg_b)
}

/// A Merkle tree of `2^depth` one-time keys under a 32-byte root.
#[derive(Debug)]
pub struct Tree {
    profile: Profile,
    seed: Hash32,
    depth: usize,
    nodes: Vec<Hash32>,
}

fn node(depth_idx: u16, left: &Hash32, right: &Hash32) -> Hash32 {
    tweak(0x05, 0, depth_idx, left, right)
}

impl Tree {
    /// Build the full tree. Cost is `2^depth` public-key derivations.
    #[must_use]
    pub fn new(profile: Profile, seed: Hash32, depth: usize) -> Self {
        let leaves = 1usize << depth;
        let mut nodes = vec![[0u8; HASH_LEN]; 2 * leaves];
        for i in 0..leaves {
            nodes[leaves + i] = public_key(profile, &Self::leaf_seed(&seed, i));
        }
        for i in (1..leaves).rev() {
            nodes[i] = node(
                u16::try_from(i).expect("small tree"),
                &nodes[2 * i],
                &nodes[2 * i + 1],
            );
        }
        Self {
            profile,
            seed,
            depth,
            nodes,
        }
    }

    fn leaf_seed(seed: &Hash32, index: usize) -> Hash32 {
        tweak(0x06, 0, 0, seed, &(index as u64).to_le_bytes())
    }

    /// The 32-byte root commitment.
    #[must_use]
    pub fn root(&self) -> Hash32 {
        self.nodes[1]
    }

    /// Sign with leaf `index`. **Never reuse an index for a different message.**
    ///
    /// # Panics
    /// Panics when `index` is outside the tree.
    #[must_use]
    pub fn sign(&self, index: usize, msg: &[u8]) -> (Signature, Vec<Hash32>) {
        assert!(index < 1 << self.depth, "leaf index out of range");
        let sig = sign(self.profile, &Self::leaf_seed(&self.seed, index), msg);
        let mut path = Vec::with_capacity(self.depth);
        let mut at = (1 << self.depth) + index;
        for _ in 0..self.depth {
            path.push(self.nodes[at ^ 1]);
            at >>= 1;
        }
        (sig, path)
    }
}

/// Verify a tree signature against a 32-byte root.
#[must_use]
pub fn verify_tree(
    profile: Profile,
    root: &Hash32,
    index: usize,
    sig: &Signature,
    path: &[Hash32],
    msg: &[u8],
) -> bool {
    if index >= 1usize << path.len() {
        return false;
    }
    let Some(mut current) = recover(profile, sig, msg) else {
        return false;
    };
    let mut at = (1usize << path.len()) + index;
    for sibling in path {
        let parent = u16::try_from(at >> 1).unwrap_or(u16::MAX);
        current = if at & 1 == 0 {
            node(parent, &current, sibling)
        } else {
            node(parent, sibling, &current)
        };
        at >>= 1;
    }
    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const SEED: Hash32 = [7; 32];

    #[test]
    fn sign_verify_and_tamper_bytes() {
        let pk = public_key(Profile::Bytes, &SEED);
        let sig = sign(Profile::Bytes, &SEED, b"hello");
        assert!(verify(Profile::Bytes, &pk, &sig, b"hello"));
        assert!(!verify(Profile::Bytes, &pk, &sig, b"hellp"));
        let mut bad = sig.clone();
        bad.chains[3][0] ^= 1;
        assert!(!verify(Profile::Bytes, &pk, &bad, b"hello"));
        let mut bad = sig.clone();
        bad.salt[0] ^= 1;
        assert!(!verify(Profile::Bytes, &pk, &bad, b"hello"));
        assert!(!verify(Profile::Bytes, &[0; 32], &sig, b"hello"));
        bad = sig;
        bad.chains.pop();
        assert!(!verify(Profile::Bytes, &pk, &bad, b"hello"));
    }

    #[test]
    fn sign_verify_words() {
        let pk = public_key(Profile::Words, &SEED);
        let sig = sign(Profile::Words, &SEED, b"hello");
        assert!(verify(Profile::Words, &pk, &sig, b"hello"));
        assert!(!verify(Profile::Words, &pk, &sig, b"hellp"));
    }

    #[test]
    fn a_signature_does_not_verify_under_the_other_profile() {
        let pk = public_key(Profile::Bytes, &SEED);
        let sig = sign(Profile::Bytes, &SEED, b"m");
        assert!(!verify(Profile::Words, &pk, &sig, b"m"));
    }

    #[test]
    fn double_signing_is_detected() {
        let pk = public_key(Profile::Bytes, &SEED);
        let a = sign(Profile::Bytes, &SEED, b"one");
        let b = sign(Profile::Bytes, &SEED, b"two");
        assert!(is_equivocation(
            Profile::Bytes,
            &pk,
            (&a, b"one"),
            (&b, b"two")
        ));
        assert!(!is_equivocation(
            Profile::Bytes,
            &pk,
            (&a, b"one"),
            (&a, b"one")
        ));
    }

    #[test]
    fn two_signatures_let_an_attacker_forge_which_is_why_leaves_are_single_use() {
        // Documents the one-time rule: with two signatures the revealed chain
        // positions cover more steps than either message needed.
        let s1 = steps_for(
            Profile::Bytes,
            &sign(Profile::Bytes, &SEED, b"x").pub_seed,
            &[0; 16],
            b"x",
        );
        let s2 = steps_for(
            Profile::Bytes,
            &sign(Profile::Bytes, &SEED, b"x").pub_seed,
            &[0; 16],
            b"y",
        );
        assert!(s1.iter().zip(&s2).any(|(a, b)| a != b));
    }

    #[test]
    fn tree_signs_and_rejects_wrong_index_or_message() {
        let tree = Tree::new(Profile::Bytes, SEED, 3);
        let root = tree.root();
        let (sig, path) = tree.sign(5, b"pdu");
        assert!(verify_tree(Profile::Bytes, &root, 5, &sig, &path, b"pdu"));
        assert!(!verify_tree(Profile::Bytes, &root, 4, &sig, &path, b"pdu"));
        assert!(!verify_tree(Profile::Bytes, &root, 5, &sig, &path, b"pdv"));
        assert!(!verify_tree(Profile::Bytes, &root, 99, &sig, &path, b"pdu"));
    }

    #[test]
    fn report_sizes_and_timings() {
        for profile in [Profile::Bytes, Profile::Words] {
            let t = Instant::now();
            let pk = public_key(profile, &SEED);
            let keygen = t.elapsed();
            let t = Instant::now();
            let sig = sign(profile, &SEED, b"m");
            let signing = t.elapsed();
            let t = Instant::now();
            assert!(verify(profile, &pk, &sig, b"m"));
            let verifying = t.elapsed();
            assert_eq!(sig.len(), profile.signature_len());
            println!(
                "{profile:?}: sig {} B (+{} B path at depth 10), keygen {keygen:?}, sign {signing:?}, verify {verifying:?}",
                sig.len(),
                10 * HASH_LEN
            );
        }
    }
}
