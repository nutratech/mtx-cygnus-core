//! Spike: an `OpenMLS` group can be snapshotted from, and restored into, a
//! fresh `OpenMlsRustCrypto` by copying `MemoryStorage::values`, and the
//! device seed never enters that map when the signer is not `store`d.

use openmls::prelude::{tls_codec::Serialize, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn snapshot(p: &OpenMlsRustCrypto) -> Vec<(Vec<u8>, Vec<u8>)> {
    let map = p.storage().values.read().expect("lock");
    let mut v: Vec<_> = map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    v.sort();
    v
}

fn restore(entries: &[(Vec<u8>, Vec<u8>)]) -> OpenMlsRustCrypto {
    let p = OpenMlsRustCrypto::default();
    p.storage()
        .values
        .write()
        .expect("lock")
        .extend(entries.iter().cloned());
    p
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn group_round_trips_through_a_values_snapshot_without_the_seed() {
    let seed = [0x5A_u8; 32];
    let pk = <[u8; 32]>::from(ed25519_zebra::SigningKey::from(seed).verification_key());
    let signer = SignatureKeyPair::from_raw(SignatureScheme::ED25519, seed.to_vec(), pk.to_vec());
    // Deliberately no signer.store(...).
    let cred = CredentialWithKey {
        credential: BasicCredential::new(b"@a:x\0D1".to_vec()).into(),
        signature_key: pk.to_vec().into(),
    };

    let a = OpenMlsRustCrypto::default();
    let cfg = MlsGroupCreateConfig::builder().ciphersuite(SUITE).build();
    let gid = GroupId::from_slice(&[7_u8; 32]);
    let mut g = MlsGroup::new_with_group_id(&a, &signer, &cfg, gid.clone(), cred).expect("new");
    g.self_update(&a, &signer, LeafNodeParameters::default())
        .expect("update");
    g.merge_pending_commit(&a).expect("merge");
    let epoch = g.epoch();

    let snap = snapshot(&a);
    assert!(!snap.is_empty());
    for (k, v) in &snap {
        assert!(!contains(k, &seed) && !contains(v, &seed), "seed leaked");
    }

    let b = restore(&snap);
    let mut g2 = MlsGroup::load(b.storage(), &gid)
        .expect("load")
        .expect("present");
    assert_eq!(g2.epoch(), epoch);
    let m = g2.create_message(&b, &signer, b"hi").expect("encrypt");
    assert!(!m.tls_serialize_detached().expect("ser").is_empty());
}
