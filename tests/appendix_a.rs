//! MSC00FC Appendix A vectors: keys from repeated-byte seeds.

use cygnus_core::{commitment, link::verify_slice, Link, Principal};
use ed25519_consensus::SigningKey;

fn key(b: u8) -> SigningKey {
    SigningKey::from([b; 32])
}
fn pubkey(b: u8) -> [u8; 32] {
    key(b).verification_key().to_bytes()
}

const A0: &str = "AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACn43blzT6rgsVNzZYO7Q2Rty6Gui6qDEtLT9KTxg_8UIqI4910CfGV_VLbLTy6XXLKZwm_HZQSG_N0iAG0D29cABBjaGF0LmV4YW1wbGUub3Jn2Q1TtCiz1ePkElNMfK781u9YMaFhnLO0hG8z6K_y2aSahTHRknkQ8MVLscIBbzf0LtD98Jfza5nXkVQuh_K0CQ";
const A1: &str = "AQGygRTH2GK15mgvH07AEn3j4YK5WsOSxdE6Qhi4ufwtvQAAAAAAAAABsoEUx9hiteZoLx9OwBJ94-GCuVrDksXROkIYuLn8Lb01Nmw5cTdJ5i-8iyk2_ucSDxdQdO6gPdbzTa9bC_blH-1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfRABBjaGF0LmV4YW1wbGUub3JngTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5SxA7F2pH-iNJh8RCmwbClk188UfWoteisDrefjnO4Wcxjg6D_r5fzgWl4cY8xqkAxfEuhqoj3hZQxNf3P2ZfkK";
const ALICE0: &str = "AQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA4kBxguvojRXkm6JtORb1xDcBb37XlTZ9vN8bcmesKPLKBFMfYYrXmaC8fTsASfePhgrlaw5LF0TpCGLi5_C29AW4ywZdB8K-CYGEq6Z_RPYo4lEci4Ilk3SOXOPVSphU7ABdAYWxpY2U6Y2hhdC5leGFtcGxlLm9yZw";
const ALICE1: &str = "AQIKXms8aCPazskczAXFIQ4d8Vgz8rQ8OmeFcQxjAyBC6gAAAAAAAAABCl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo649E4EjrjmhOanIHIuTLppWYxG7SWxBFrLHRhtQjhexG709vz38lJA2ZWzLBWXgKf3t9LrbRJCn8EWkbqkeTEAW4ywZdB8K-CYGEq6Z_RPYo4lEci4Ilk3SOXOPVSphU7ABlAYWxpY2U6c2Vjb25kLmV4YW1wbGUubmV0iEuIV_TqoWE8YVBNs01L6vNGUXoOMd483dTZtCAdnQtyRd0w4wzGGK8ZO6MOJzxLDeTFpmz9Dap0bNCSlaaem79i4YumEN5sfrFdV8z8kYg0m5Fy466DasRnm58DfRYH";

#[test]
fn commitments() {
    assert_eq!(
        hex::encode(commitment(&pubkey(0x02))),
        "a7e376e5cd3eab82c54dcd960eed0d91b72e86ba2eaa0c4b4b4fd293c60ffc50"
    );
    assert_eq!(
        hex::encode(commitment(&pubkey(0x21))),
        "38901c60bafa23457926e89b4e45bd710dc05bdfb5e54d9f6f37c6dc99eb0a3c"
    );
}

#[test]
fn server_a_chain() {
    let (g, r) = (Link::from_b64(A0).unwrap(), Link::from_b64(A1).unwrap());
    g.verify_genesis().unwrap();
    assert_eq!(
        hex::encode(g.digest()),
        "b28114c7d862b5e6682f1f4ec0127de3e182b95ac392c5d13a4218b8b9fc2dbd"
    );
    assert_eq!(
        g.principal().to_id(),
        "~soEUx9hiteZoLx9OwBJ94-GCuVrDksXROkIYuLn8Lb0"
    );
    r.verify_successor(&g).unwrap();
    assert_eq!(r.principal(), g.principal());
    assert_eq!(g.to_b64(), A0);
    assert_eq!(r.to_b64(), A1);
}

#[test]
fn alice_move_and_principal_roundtrip() {
    let (g, m) = (
        Link::from_b64(ALICE0).unwrap(),
        Link::from_b64(ALICE1).unwrap(),
    );
    g.verify_genesis().unwrap();
    verify_slice(&g, std::slice::from_ref(&m)).unwrap();
    let id = g.principal().to_id();
    assert_eq!(id, "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo");
    assert_eq!(Principal::parse(&id).unwrap(), g.principal());
}

#[test]
fn rebuilding_reproduces_vectors() {
    // Ed25519 is deterministic, so signing with the seeds must match exactly.
    let g = Link::from_b64(ALICE0).unwrap();
    let m = Link::from_b64(ALICE1).unwrap();
    let rebuilt = Link::sign_successor(m.body.clone(), &key(0x21)).unwrap();
    assert_eq!(rebuilt, m);
    let a0 = Link::from_b64(A0).unwrap();
    assert_eq!(
        Link::sign_server_genesis(a0.body.clone(), &key(0x01)).unwrap(),
        a0
    );
    assert_eq!(Link::user_genesis(g.body.clone()).unwrap(), g);
}

#[test]
fn tampering_is_rejected() {
    let g = Link::from_b64(ALICE0).unwrap();
    let mut m = Link::from_b64(ALICE1).unwrap();
    // Wrong parent.
    let other = Link::from_b64(A0).unwrap();
    assert!(m.verify_successor(&other).is_err());
    // Flip a signature byte.
    let n = m.trailer.len();
    m.trailer[n - 1] ^= 1;
    assert!(m.verify_successor(&g).is_err());
}
