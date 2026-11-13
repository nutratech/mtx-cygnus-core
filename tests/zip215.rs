//! ZIP-215 edge cases for the verification backend. Cygnus requires the
//! cofactored, non-strict rules so that every implementation agrees on
//! which signatures are valid: non-canonical point encodings are accepted,
//! while a scalar `s >= l` is rejected.

use ed25519_zebra::{Signature, VerificationKey};

/// Little-endian group order l.
const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];

/// Identity point, canonical (y = 1).
fn identity() -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 1;
    p
}

/// Identity point, non-canonical (y = p + 1 = 2^255 - 18).
fn identity_noncanonical() -> [u8; 32] {
    let mut p = [0xffu8; 32];
    p[0] = 0xee;
    p[31] = 0x7f;
    p
}

fn sig(r: [u8; 32], s: [u8; 32]) -> Signature {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&r);
    b[32..].copy_from_slice(&s);
    Signature::from(b)
}

fn verify(a: [u8; 32], r: [u8; 32], s: [u8; 32], msg: &[u8]) -> bool {
    VerificationKey::try_from(a)
        .map(|vk| vk.verify(&sig(r, s), msg).is_ok())
        .unwrap_or(false)
}

#[test]
fn identity_key_with_zero_scalar_verifies_any_message() {
    assert!(verify(identity(), identity(), [0; 32], b"anything"));
    assert!(verify(identity(), identity(), [0; 32], b""));
}

#[test]
fn non_canonical_point_encodings_are_accepted() {
    assert!(verify(identity_noncanonical(), identity(), [0; 32], b"m"));
    assert!(verify(identity(), identity_noncanonical(), [0; 32], b"m"));
    assert!(verify(
        identity_noncanonical(),
        identity_noncanonical(),
        [0; 32],
        b"m"
    ));
}

#[test]
fn scalar_at_or_above_group_order_is_rejected() {
    assert!(!verify(identity(), identity(), L, b"m"));
    let mut above = L;
    above[0] += 1;
    assert!(!verify(identity(), identity(), above, b"m"));
    assert!(!verify(identity(), identity(), [0xff; 32], b"m"));
}

#[test]
fn scalar_just_below_group_order_is_parsed() {
    // l - 1 is a valid scalar encoding; with identity A and R the equation
    // (l-1)B = 0 does not hold, so verification fails on the equation, not
    // on encoding.
    let mut below = L;
    below[0] -= 1;
    assert!(!verify(identity(), identity(), below, b"m"));
}
