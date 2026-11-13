//! MSC00FC Appendix A vectors: keys from repeated-byte seeds.

use cygnus_core::{commitment, link::verify_slice, Link, Principal};
use ed25519_zebra::SigningKey;

fn key(b: u8) -> SigningKey {
    SigningKey::from([b; 32])
}
fn pubkey(b: u8) -> [u8; 32] {
    <[u8; 32]>::from(key(b).verification_key())
}

const A0: &str = "AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB_LjVaIv-BYnAih7bnqYkqlByvjgze1oFBXRvUvcl0b4qI4910CfGV_VLbLTy6XXLKZwm_HZQSG_N0iAG0D29cABBjaGF0LmV4YW1wbGUub3JnCK-nYNDic0Z89Ec_a2PGm3aq70QCRMlNp6PWikK9QAAUe3uL7tSPsdpcdmItB3XSgmkl9uP7p5zRTfGF1hfVDw";
const A1: &str = "AQHUCt4cY_sK_sQxmSETcKGd8f-ZHqmoOYEv0I-kGvzvIAAAAAAAAAAB1AreHGP7Cv7EMZkhE3ChnfH_mR6pqDmBL9CPpBr87yCKugXi5WhUkH8s2il7gpcAwEd6SJBdTaBMuPyGTjjVY-1JKMYo0cLG6ukDOJBZlWEpWSc6XGP5NjbBRhSshzfRABBjaGF0LmV4YW1wbGUub3JngTl3Dqh9F19Wo1Rmw0x-zMuNipG07jeiXfYPW4_Js5R_TYGHVQw9Gxe6s_WWRrk0LN-Up85Q5Mi6p5VlMumtQT01Mg8_o3W8rUuTCtPEbLFP5_Ck_aN1STehH6yNT54C";
const ALICE0: &str = "AQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABy6iILWoFoOE2EAX0t6CZlC2DPbWvaHgkZZa_PY5nW-tQK3hxj-wr-xDGZIRNwoZ3x_5keqag5gS_Qj6Qa_O8gAW4ywZdB8K-CYGEq6Z_RPYo4lEci4Ilk3SOXOPVSphU7ABdAYWxpY2U6Y2hhdC5leGFtcGxlLm9yZw";
const ALICE1: &str = "AQJ0j81vylrMxQwBbInjMwUO0md-00pjBC7am4YSQ8FwpgAAAAAAAAABdI_Nb8pazMUMAWyJ4zMFDtJnftNKYwQu2puGEkPBcKbWM2pymNf5kt-kkMMGkTlwXbeuhynyPavISmKxeUa1FQuR-FG3Hm6M3GOOf0vbjhd7uSUOJsxNtkN6OxV1MIp6AW4ywZdB8K-CYGEq6Z_RPYo4lEci4Ilk3SOXOPVSphU7ABlAYWxpY2U6c2Vjb25kLmV4YW1wbGUubmV0iEuIV_TqoWE8YVBNs01L6vNGUXoOMd483dTZtCAdnQuwqA7GGyvLxic_AkEcUPz0AZZwZGAhi3uaQR4W43K6R-3Nth2oaeyfZU2US7MIpGSKrfeOUBT_1kRUCUAQMxMA";

#[test]
fn commitments() {
    assert_eq!(
        hex::encode(commitment(&pubkey(0x02))),
        "7f2e355a22ff8162702287b6e7a9892a941caf8e0cded681415d1bd4bdc9746f"
    );
    assert_eq!(
        hex::encode(commitment(&pubkey(0x21))),
        "72ea220b5a8168384d84017d2de826650b60cf6d6bda1e091965afcf6399d6fa"
    );
}

#[test]
fn server_a_chain() {
    let (g, r) = (Link::from_b64(A0).unwrap(), Link::from_b64(A1).unwrap());
    g.verify_genesis().unwrap();
    assert_eq!(
        hex::encode(g.digest()),
        "d40ade1c63fb0afec43199211370a19df1ff991ea9a839812fd08fa41afcef20"
    );
    assert_eq!(
        g.principal().to_id(),
        "~1AreHGP7Cv7EMZkhE3ChnfH_mR6pqDmBL9CPpBr87yA"
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
    assert_eq!(id, "@dI_Nb8pazMUMAWyJ4zMFDtJnftNKYwQu2puGEkPBcKY");
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
