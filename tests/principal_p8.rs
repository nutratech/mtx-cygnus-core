//! P8 principal-encoding checks from `pid_pdu_vectors.json`: only the
//! canonical unpadded base64url, 43-character payload is accepted.

use cygnus_core::principal::Principal;

const ROOT: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 zero bytes

#[test]
fn canonical_principal_encoding_is_accepted() {
    for sigil in ["~", "@"] {
        let id = format!("{sigil}{ROOT}");
        let p = Principal::parse(&id).unwrap();
        assert_eq!(p.to_id(), id);
    }
}

#[test]
fn rejects_padded_encoding() {
    assert!(Principal::parse(&format!("~{ROOT}=")).is_err());
}

#[test]
fn rejects_42_and_44_character_payloads() {
    assert!(Principal::parse(&format!("~{}", &ROOT[..42])).is_err());
    assert!(Principal::parse(&format!("~{ROOT}A")).is_err());
}

#[test]
fn rejects_standard_base64_alphabet() {
    let plus = format!("~{}+", &ROOT[..42]);
    let slash = format!("~{}/", &ROOT[..42]);
    assert!(Principal::parse(&plus).is_err());
    assert!(Principal::parse(&slash).is_err());
}

#[test]
fn rejects_nonzero_trailing_bits() {
    // The 43rd character carries 4 meaningful bits; 'B' sets a trailing bit.
    assert!(Principal::parse(&format!("~{}B", &ROOT[..42])).is_err());
}

#[test]
fn rejects_missing_or_unknown_sigil() {
    assert!(Principal::parse(ROOT).is_err());
    assert!(Principal::parse(&format!("#{ROOT}")).is_err());
}
