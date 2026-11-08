//! Provenance and shape checks for all vendored MSC00FC/DMLS fixtures.

use rezzy_json::Value;
use sha2::{Digest, Sha256};

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"))
}

#[test]
fn vendored_sources_and_fixtures_match_the_provenance_manifest() {
    let manifest =
        Value::parse(std::str::from_utf8(&read("tests/vectors/provenance.json")).unwrap()).unwrap();
    let files = manifest.as_object().expect("provenance object");
    assert!(!files.is_empty());
    for (path, expected) in files {
        let expected = expected.as_str().expect("sha256 string");
        let actual = hex::encode(Sha256::digest(read(path)));
        assert_eq!(
            actual, expected,
            "{path} differs from its recorded provenance"
        );
    }
}

#[test]
fn all_vector_fixtures_are_valid_json_with_expected_shape() {
    for path in [
        "tests/vectors/pid_vectors.json",
        "tests/vectors/pid_pdu_vectors.json",
        "tests/vectors/pid_known_gaps.json",
        "tests/vectors/dmls/dmls_vectors.json",
        "tests/vectors/dmls/dmls_tree_math_vectors.json",
    ] {
        let bytes = read(path);
        let text = std::str::from_utf8(&bytes).unwrap();
        Value::parse(text).unwrap_or_else(|error| panic!("{path} is not valid JSON: {error:?}"));
    }

    let links = parse("tests/vectors/pid_vectors.json");
    assert!(links.get("seeds").and_then(Value::as_object).is_some());
    assert!(links.get("links").and_then(Value::as_object).is_some());
    assert!(links.get("checks").and_then(Value::as_array).is_some());

    let pdus = parse("tests/vectors/pid_pdu_vectors.json");
    assert!(pdus.get("events").and_then(Value::as_array).is_some());
    assert!(pdus.get("checks").and_then(Value::as_array).is_some());
    assert!(pdus.get("room_version").and_then(Value::as_str).is_some());

    let gaps = parse("tests/vectors/pid_known_gaps.json");
    assert_eq!(
        gaps.get("vectors").and_then(Value::as_array).unwrap().len(),
        7
    );
}

fn parse(path: &str) -> Value {
    Value::parse(std::str::from_utf8(&read(path)).unwrap())
        .unwrap_or_else(|error| panic!("{path}: {error:?}"))
}
