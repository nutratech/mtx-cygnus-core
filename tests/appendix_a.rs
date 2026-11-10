//! MSC00FC Appendix A vectors: keys from repeated-byte seeds.

use cygnus_core::sig::SigningKey;
use cygnus_core::{commitment, link::verify_slice, Link, Principal};

fn key(b: u8) -> SigningKey {
    SigningKey::from([b; 32])
}
fn pubkey(b: u8) -> [u8; 32] {
    key(b).verification_key().to_bytes()
}

const A0: &str = "AQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC32MZixoPMgDH-lSweAJQcn7wcjfUdGTUZBVEiTTtvqmqNW7cPFLoVLxjAU0YFqLavtAcj1cyKgHHnxO_HKmR1ABBjaGF0LmV4YW1wbGUub3JnAAAAAG_Oo-n-u9BnYXdVjC4xpLfeuGi7cvjFrf24iMK3EQku5LSkOuOVnJrKDTTuxVHgam4m7iY-l6aCDwAZRhFWI08o6aqmw-ix8JnnN9Sxz3mdu9tuR0_8r3YhIkyctnefd92Md-_4qNlaLhz3yAQjl4JmbviRbIdRAdJ_XL2Kk8whSdmXscRO359YxeS_lGwC4_fEDY6dFUZCIA_uMTZE8YudfaVXfjWP3Fa6GDDWg5YqdzxNLt5YbFb5WhwFs1YsTVT7gBrpUjeqBn-XeIp8pr_PNjE5HdM4FZUSpJk3_ZylOZI_Tt5oxrE2JVFfhQXnVQAuOZSz7IUV_Y1AKRzGTbClGIi7vnUJJ4OexFgtG9qYr4vgzZlbVF5XXR3ragaaIh4SUVOdN7g4JnzAO1KFdqMzc_XRipWaJ1uMH-DwjkllhU1gksm5N3lXO5cuqQreZfETtHLfbSLiUqCeCDjKYhJO1DD8ONLeVJLQX_Ncrt2iCRAUVh_Yq3LEWmy4Yr36avypf44n4QGtrl8SLzsJFG9Vi0vDe48dYs9H9nb8o0rxu07U5h96sHvo4AATunhKV7jgHd1R_phT8xDoWbwXm25-hLSxmOU2amNk3RR1GjXcH7S4m9DVJtwWUrTce0qE1DDEGK-l6bf6kparu8O538OHy7CBmvCV1NZBBpVq7njFb4KNnTxMGWnKj97J_n4Uv627YVHKiql4I5z0D4rwhNybgqnEuJhl7GrsUtFX0O3iy4Wh0vnY0jXIkscS7STB6D-QsS8o3YWvBAotj3Z8Q-dL4VBY6E6MYxmr5g6Dw8eSnzWOpkFFKP25L2ZyCw26wKBEEYpRNF_R8x1NdQjJQokEaa36f66ZlRDFTCl3Q2Z7fzPiZSekfSVdgYKHgvsYxPA1XnN0q_tgftC21OJwaZSmtQK4U1EBRjN9giQ5Y8kN2ioZK5FfxWSpTlI19-F_8IzKcOOeqTuDtcPYCXlaqYVTXmst8mMqPZLMy43SXpa4sqK8wpkSqwA-zdYuPztNyqmmrrLemXZ1bOj15QaRKLlXZDFWTbRSRukGkIsKKi--zCqheEc5jwykFGzsv8_P5m816M4k_hQtm0LzQ-Ca67wM4xqvyp75AxjkEhPVlWbqQxegSxvpWzwfWgyK_4kHJ7-tWeKKiO5MhMkfagiCzGv0LamREaGpC8tjNZjFmGTo8GNuguTeo59gUTzDrv3TJccuztfG9ytGWLJJQUMYxHN2g7QWp5JozztQ7bErAKoA";
const A1: &str = "AQEIzW73lAdp9B8VbqetDRP74A_Wi-9pvs1NOeLC1r90TgAAAAAAAAABCM1u95QHafQfFW6nrQ0T--AP1ovvab7NTTniwta_dE6wdfTkEWCYXgSIe7HdNPlpNrXNPBWmPYsaJbyAxfg4sq15hxtiguLivt-gC29ohAVsiAi5TIGR-WB412_ij-0yABBjaGF0LmV4YW1wbGUub3Jn85cAv37PUhXUhvHXYSc9itGM8_oJThsvssCe8X9TjkMAAAAAsr7BLeAAtT6AgZvKp5KWDdXMVuZ03p_yVpJF6euHFXJbcx_wfe8fy4YkYQXHflmfkKcboyEbvKnr63Y6npVTy8lCJy0S7f4L8fhFGHovF9pxyR-oMslY3pm-TP3ZjRuRwF2LZ30tWEypqWCF7KVgIiaX7MiiCreHjutw4UihhmLWUq6JR5wglJOvLZLozZmnyLdeswPuabQFSLJ2pUz-J6dn5Q_BmVrkS8GPMqiZd4OW1CpQDgowMlaXbXC3lHLaaBtrTbIDf-HSTjlwghBuih5YBl1OS8R0eyJFyK_VItRZ4lMcZZc-kCSrrjz9eXZG2_e6dr6HDyts2WRhHaUjpJMLNHmbLC2ViCCgfSigju3YQpYi6ZKm9w5LWXzwVvCQr34RucDiAidoZNMs-MzFCX0ltVjQmhVZR_qpUkYRz0vq5qv9ialZMG10NWbQlLHW-rHwSQzrip8Bh4Xpk0ACHU9oVBTylCTgsW_ierT9YPVzfL3p7aOBjfvOqIGZppdiFYVrJm3keABro-uqNXsvSuWEExzfBjy352tXxgVh5EHCb-ymcW1A5Xo7La70zFAL5k9O9Xusd1xkVeCQqQE8w2mKl3KoBzK9496S5TKcaLtqP2Uihqc_dmHzPUDr5acymSGsVPo683r07dT2Kjm4mE_cThhEVfcfwqGANmg5SwzPhsHDrA35L9Ign3g5u-XnXnkpaICvTv7zfXi8VKVFEMM7PDoGJ7cCYeGpsRE0Xoke27k5k7CgySch9oLxTAr4uJL_RUC5pbLO-TQvNFv0Su4vOcscVKBeXcQ2a-Mfrn7IGR7OQaDuUwF6j-SNiNTULII4A7KnMMSVtO3MEHGesIQv-0Ms256Yx6RKYw9GhgUw55ovcUW2Nn_BEyvTnbelisVLZfHz2GYPty93KiFdzw6VdhUEfokS_MWyF-_6IRemtGBkDPhc8ssAnraVx6Of3BzT72gzbNCVKoKoprm41c4dS4P-lrEqRyAY4xeR7CYslJy5GHenjwa7Y0xVD4e8tmmrVwA428TfxxsmJ7MVdzWveMXczDdE05adLhUGX5Uj-9uBVBJQ74zKB7y83JeCgT67UTx6h0DmiZmGaxLc6WAkmkvzeZKBIDSHTchGkjkJKUglyO_wl-5kG0LnFJMpFnt3bXDYy907mLpknm1av3t615YtLIKVnbfMLNznFw2RCwlRl67Tm-yQIkxuSyml0sp3qww0lfA_H3W4mWNqB8O5zyZCKwpfF_u2zwq1BWg";
const ALICE0: &str = "AQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANMhgFO5LSdHNG32ouHJPo0soEo_ZrPbLP1C_iSBDikwjNbveUB2n0HxVup60NE_vgD9aL72m-zU054sLWv3ROAYSWaqhLlQ0giOXvaOKmPSqnW0jEupZC1k9vuWQzGLszABdAYWxpY2U6Y2hhdC5leGFtcGxlLm9yZw";
const ALICE1: &str = "AQKDPcpvZAoYDb1wvvY3NOeLc6iwX11hCY0-Ri15rbV4hAAAAAAAAAABgz3Kb2QKGA29cL72NzTni3OosF9dYQmNPkYtea21eIQQWfd1vq4y2ijkphX7X_CGNdM87Z7OKQORZcs_3HczTNJg8poBZlNIQZGKdIMdSuASnP2b4p_9K5TJsiv4xaeJAYSWaqhLlQ0giOXvaOKmPSqnW0jEupZC1k9vuWQzGLszABlAYWxpY2U6c2Vjb25kLmV4YW1wbGUubmV0xmlvIJamUIGcjMbvpSYL-hEhbC_uBhqfpwKsrfcccs4AAAAAEI_3FjAk6ZzFSx1dSWon7IcIOWmycQtfNN9nOFRn5NejaXgKQU5FVkrAiSvGs13XExr-xr1kSbYeJJ4F199eBcl8LMdqBFZ6XP3lveUJDMaRN5FnUOw2ZRswIWNN4uUWtxK1lZ7z3xL05ou8ZrsNXaIVR1bpmwNX2_5bFqzAV4hJDApwVj0jbdSS4avmfOmikaSEtzAapWRkN6Nz8rZ6veEjryeQRzNmQb5l0JS4Oq5qNe0xSe1NBTDA9gJGHf7GMls3F5qRmcotDsfXW1QMCl6zQ5uWuvBS_dB33RDIUNz2H5aFBaoDe0owK0w0RjqJgXRVM74Gz8eeslC7-np_pkAuih_JZ6bPq_bRl8YIo-6dxm0gRqxwKmJCG9SM9E7lVoKLNL9AgkQxp5emnaqPPH0S0Pqi3KzwF-METW7ZZbefymUECjsOPHBnEDBQoEc2nZBlgJb0VuMrL-XmcfuEe4O4If4_9hqYSXVCS1f88cUtPAHIc6VSKAmshn-UWPf9Ufhw7Fyn4UQNhdV29t7VkVo8enbaMJsqfRwuXWWh7gc9xE6GiygHoE2Ufyazsunuchu70bu1E6a3hic09yRgTEJKmMXQf1IOajoZh7PflFVD_d7Xnl_P07G0BnwcvHobTIo0Ef4CB-R5F80pVgkFI3MGccGxuDYVlp6u-5hoQuLTFo4RtdbUBXZbqc9L49j4_7eo8VV96uEisY27CAKVEWB6aeGm7PU1Wpvih-h6_aN56aokyHx9MHrq7FBRkF9OLtFZ2-uOfs00OnY3PQlHtOS-WKfRM3zslWT_sVl-bdPYK2pC6nCFVs_SKPzTzPo9hLAoblW_AKfsQvZ1f0wbOUALvGTT2XBkLwTanfRR-bqfuJAVdhmwkH_yXsT-otwjglODeZKMCnE5a1pfWf4S9Awx40MpWY4NNoAu8anqZmyewHlkaEz0fgBH5k9to2OXXWXhqjIBhx85NR8npnzeQ9JTHJ5pIpnX1JZF9ZltB2nwcbHGu1Ir1iNf2BMu8erpFiL3dvhhfzCJKqKhhBQy8FpJXWP30iDBMWxPx4zyCI70GJrvOW2FgxOTDxtORGL3r_t7cvVHcRUGgNtXAls2thSXeagth4NM8uFeUiiusZyNERU319CppvFv2bd5gGEDLeUMzF62wElmLprccGgJiFY7gMEnS4CWHTDi0NidbDjBYj5DeYBxumZt9_8Ccy19R-jNk_k9xX-Vs__0S45v2dDZshMFUG15qMZM4Et9i1o";

#[test]
fn commitments() {
    assert_eq!(
        hex::encode(commitment(&pubkey(0x02))),
        "b7d8c662c683cc8031fe952c1e00941c9fbc1c8df51d1935190551224d3b6faa"
    );
    assert_eq!(
        hex::encode(commitment(&pubkey(0x21))),
        "0d3218053b92d2747346df6a2e1c93e8d2ca04a3f66b3db2cfd42fe24810e293"
    );
}

#[test]
fn server_a_chain() {
    let (g, r) = (Link::from_b64(A0).unwrap(), Link::from_b64(A1).unwrap());
    g.verify_genesis().unwrap();
    assert_eq!(
        hex::encode(g.digest()),
        "08cd6ef7940769f41f156ea7ad0d13fbe00fd68bef69becd4d39e2c2d6bf744e"
    );
    assert_eq!(
        g.principal().to_id(),
        "~CM1u95QHafQfFW6nrQ0T--AP1ovvab7NTTniwta_dE4"
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
    assert_eq!(id, "@gz3Kb2QKGA29cL72NzTni3OosF9dYQmNPkYtea21eIQ");
    assert_eq!(Principal::parse(&id).unwrap(), g.principal());
}

#[test]
fn rebuilding_reproduces_vectors() {
    // WOTS+ signing is deterministic for a seed, message, and leaf index.
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
