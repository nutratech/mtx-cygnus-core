//! Round-trips the DMLS wasm exports natively: create, add, join, encrypt,
//! decrypt, external join, apply, reboot, and received-reboot checks.
//!
//! The registry is process-wide, as it is per wasm instance. To model separate
//! devices in one test process, each party's blob is exported, the registry is
//! cleared, and the next device imports only its own state. The success paths
//! never construct a `JsError`, so these run without a JS host.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use cygnus_wasm::{
    dmls_apply_commit, dmls_check_reboot, dmls_commit, dmls_create_group, dmls_decrypt,
    dmls_encrypt, dmls_export_group, dmls_external_commit, dmls_forget, dmls_has_group,
    dmls_import_group, dmls_join_welcome, dmls_key_package, dmls_reboot, dmls_welcome_content,
};
use rezzy_json::Value;

const ALICE: &str = "@Cl5rPGgj2s7JHMwFxSEOHfFYM_K0PDpnhXEMYwMgQuo";
const BOB: &str = "@AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CAROL: &str = "@AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM";

fn seed(byte: u8) -> String {
    B64.encode([byte; 32])
}

fn identity(principal: &str, device: &str) -> String {
    format!(r#"{{"deviceId":"{device}","principal":"{principal}"}}"#)
}

fn parse(json: &str) -> Value {
    Value::parse_strict(json).expect("canonical JSON")
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{field}"))
}

fn canonical(value: &Value) -> String {
    rezzy_json::to_canonical_string(value).unwrap()
}

/// Start from an empty registry, discarding every group the test has used.
fn clear(groups: &[String]) {
    for group in groups {
        let _ = dmls_forget(group);
    }
}

struct Party {
    identity: String,
    seed: String,
}

impl Party {
    fn new(principal: &str, device: &str, byte: u8) -> Self {
        Self {
            identity: identity(principal, device),
            seed: seed(byte),
        }
    }
}

/// `(keyPackageId, keyPackage bytes, secretsB64)` for a fresh package.
fn key_package(party: &Party) -> (String, String, String) {
    let out = parse(&dmls_key_package(&party.identity, &party.seed).unwrap());
    let package = out
        .get("content")
        .and_then(|content| content.get("key_package"))
        .and_then(Value::as_str)
        .expect("key_package");
    (
        text(&out, "keyPackageId").to_owned(),
        package.to_owned(),
        text(&out, "secretsB64").to_owned(),
    )
}

fn welcome_content(
    group_id: &str,
    commit_event_id: &str,
    commit_id: &str,
    key_package_id: &str,
    welcome_b64: &str,
) -> String {
    let out = parse(
        &dmls_welcome_content(
            group_id,
            commit_event_id,
            commit_id,
            key_package_id,
            welcome_b64,
        )
        .unwrap(),
    );
    canonical(out.get("content").unwrap())
}

#[test]
fn create_add_join_encrypt_decrypt_and_round_trip_the_blob() {
    let room = "!dmls-wasm-e2e:example.org";
    let alice = Party::new(ALICE, "ALICE1", 1);
    let bob = Party::new(BOB, "BOB1", 2);
    let (bob_key_package_id, bob_key_package, bob_secrets) = key_package(&bob);
    let mut groups = Vec::new();

    clear(&groups);
    let created = parse(&dmls_create_group(&alice.identity, &alice.seed, room).unwrap());
    let group_id = text(&created, "groupId").to_owned();
    let genesis = text(&created, "commitId").to_owned();
    groups.push(group_id.clone());
    let alice_state = dmls_export_group(&group_id).unwrap();
    assert!(dmls_has_group(&group_id).unwrap());

    // Alice adds Bob while she is the only device loaded.
    clear(&groups);
    dmls_import_group(&alice_state).unwrap();
    let base = format!(r#"{{"commit_id":"{genesis}","mls_epoch":0}}"#);
    let ops = format!(r#"{{"keyPackage":"{bob_key_package}","op":"add"}}"#);
    let commit = parse(&dmls_commit(&group_id, &alice.seed, &ops, Some(base)).unwrap());
    let commit_id = text(&commit, "commitId").to_owned();
    let welcome_b64 = text(&commit, "welcome").to_owned();
    let recipients = commit.get("recipients").unwrap().as_array().unwrap();
    assert_eq!(text(&recipients[0], "keyPackageId"), bob_key_package_id);
    let alice_state = dmls_export_group(&group_id).unwrap();

    // Bob joins from that Welcome.
    clear(&groups);
    let joined = parse(
        &dmls_join_welcome(
            &bob.identity,
            &bob.seed,
            &welcome_content(
                &group_id,
                "$add-bob",
                &commit_id,
                &bob_key_package_id,
                &welcome_b64,
            ),
            Some(bob_secrets),
        )
        .unwrap(),
    );
    assert_eq!(text(&joined, "status"), "applied");
    assert_eq!(text(&joined, "groupId"), group_id);
    let bob_state = dmls_export_group(&group_id).unwrap();

    // Alice encrypts; Bob decrypts after importing his own advanced state.
    clear(&groups);
    dmls_import_group(&alice_state).unwrap();
    let encrypted = parse(
        &dmls_encrypt(
            &group_id,
            &alice.seed,
            room,
            "m.room.message",
            r#"{"body":"hello"}"#,
            None,
        )
        .unwrap(),
    );
    let ciphertext = canonical(encrypted.get("content").unwrap());

    clear(&groups);
    let imported = parse(&dmls_import_group(&bob_state).unwrap());
    assert_eq!(text(&imported, "groupId"), group_id);
    let decrypted = parse(&dmls_decrypt(&group_id, &ciphertext, room).unwrap());
    assert_eq!(text(&decrypted, "status"), "ok");
    assert_eq!(text(&decrypted, "senderMember"), format!("{ALICE}:ALICE1"));
    assert_eq!(text(&decrypted, "innerContentJson"), r#"{"body":"hello"}"#);
    clear(&groups);
}

#[test]
fn an_external_join_is_applied_and_decrypts_the_next_epoch() {
    let room = "!dmls-wasm-external:example.org";
    let alice = Party::new(ALICE, "ALICE1", 3);
    let bob = Party::new(BOB, "BOB1", 4);
    let carol = Party::new(CAROL, "CAROL1", 5);
    let (_, bob_key_package, _bob_secrets) = key_package(&bob);
    let mut groups = Vec::new();

    clear(&groups);
    let created = parse(&dmls_create_group(&alice.identity, &alice.seed, room).unwrap());
    let group_id = text(&created, "groupId").to_owned();
    let genesis = text(&created, "commitId").to_owned();
    groups.push(group_id.clone());
    let base = format!(r#"{{"commit_id":"{genesis}","mls_epoch":0}}"#);
    let ops = format!(r#"{{"keyPackage":"{bob_key_package}","op":"add"}}"#);
    let commit = parse(&dmls_commit(&group_id, &alice.seed, &ops, Some(base)).unwrap());
    let commit_content = commit.get("content").unwrap().clone();
    let commit_id = text(&commit, "commitId").to_owned();
    let epoch = commit.get("epoch").unwrap().as_u64().unwrap();
    let alice_state = dmls_export_group(&group_id).unwrap();

    // Carol joins by external Commit against Alice's epoch-1 GroupInfo.
    clear(&groups);
    let target =
        format!(r#"{{"commit_id":"{commit_id}","event_id":"$add-bob","mls_epoch":{epoch}}}"#);
    let external = parse(
        &dmls_external_commit(
            &carol.identity,
            &carol.seed,
            room,
            &target,
            &canonical(&commit_content),
        )
        .unwrap(),
    );
    assert_eq!(text(&external, "groupId"), group_id);
    let external_content = canonical(external.get("content").unwrap());
    let carol_state = dmls_export_group(&group_id).unwrap();

    // Alice applies it, then speaks in the joined epoch.
    clear(&groups);
    dmls_import_group(&alice_state).unwrap();
    let ctx = format!(r#"{{"ancestors":["$add-bob"],"senderMember":"{CAROL}:CAROL1"}}"#);
    let applied = parse(
        &dmls_apply_commit(
            &group_id,
            "m.dmls.external_commit",
            &external_content,
            &ctx,
            None,
        )
        .unwrap(),
    );
    assert_eq!(text(&applied, "status"), "applied");
    assert_eq!(applied.get("epoch").unwrap().as_u64(), Some(epoch + 1));
    let encrypted = parse(
        &dmls_encrypt(
            &group_id,
            &alice.seed,
            room,
            "m.room.message",
            r#"{"body":"after join"}"#,
            None,
        )
        .unwrap(),
    );
    let ciphertext = canonical(encrypted.get("content").unwrap());

    clear(&groups);
    dmls_import_group(&carol_state).unwrap();
    let decrypted = parse(&dmls_decrypt(&group_id, &ciphertext, room).unwrap());
    assert_eq!(text(&decrypted, "status"), "ok");
    assert_eq!(
        text(&decrypted, "innerContentJson"),
        r#"{"body":"after join"}"#
    );
    clear(&groups);
}

#[test]
fn reboot_creates_a_replacement_group_the_member_can_join() {
    let room = "!dmls-wasm-reboot:example.org";
    let alice = Party::new(ALICE, "ALICE1", 6);
    let bob = Party::new(BOB, "BOB1", 7);
    let (_, initial_package, _) = key_package(&bob);
    let mut groups = Vec::new();

    clear(&groups);
    let created = parse(&dmls_create_group(&alice.identity, &alice.seed, room).unwrap());
    let group_id = text(&created, "groupId").to_owned();
    let genesis = text(&created, "commitId").to_owned();
    groups.push(group_id.clone());
    let base = format!(r#"{{"commit_id":"{genesis}","mls_epoch":0}}"#);
    let ops = format!(r#"{{"keyPackage":"{initial_package}","op":"add"}}"#);
    let commit = parse(&dmls_commit(&group_id, &alice.seed, &ops, Some(base)).unwrap());
    let commit_id = text(&commit, "commitId").to_owned();
    let alice_state = dmls_export_group(&group_id).unwrap();

    // A fresh KeyPackage is what the reboot consumes.
    let (bob_key_package_id, bob_key_package, bob_secrets) = key_package(&bob);
    clear(&groups);
    dmls_import_group(&alice_state).unwrap();
    let base_json = format!(r#"{{"commit_id":"{commit_id}","event_id":"$add-bob","mls_epoch":1}}"#);
    let packages = format!(r#"["{bob_key_package}"]"#);
    let rebooted =
        parse(&dmls_reboot(&group_id, &alice.seed, "state-loss", &packages, &base_json).unwrap());
    let reboot_content = canonical(rebooted.get("rebootContent").unwrap());
    let new_group_id = text(&rebooted, "newGroupId").to_owned();
    let reboot_commit_id = text(&rebooted, "commitId").to_owned();
    let welcome_b64 = text(&rebooted, "welcome").to_owned();
    groups.push(new_group_id.clone());
    assert!(dmls_has_group(&new_group_id).unwrap());

    let recipients = rebooted.get("recipients").unwrap().as_array().unwrap();
    assert_eq!(text(&recipients[0], "keyPackageId"), bob_key_package_id);

    // A receiver authorizes the reboot against the old group before joining.
    let ctx = format!(r#"{{"ancestors":["$add-bob"],"senderMember":"{ALICE}:ALICE1"}}"#);
    let checked = parse(&dmls_check_reboot(&group_id, &reboot_content, &ctx).unwrap());
    assert_eq!(text(&checked, "status"), "accepted");
    assert_eq!(text(&checked, "newGroupId"), new_group_id);

    let alice_state = dmls_export_group(&new_group_id).unwrap();

    // The replacement is not room-derived, so joining uses the content's own
    // group id rather than a room id.
    clear(&groups);
    let joined = parse(
        &dmls_join_welcome(
            &bob.identity,
            &bob.seed,
            &welcome_content(
                &new_group_id,
                "$reboot",
                &reboot_commit_id,
                &bob_key_package_id,
                &welcome_b64,
            ),
            Some(bob_secrets),
        )
        .unwrap(),
    );
    assert_eq!(text(&joined, "status"), "applied");
    assert_eq!(text(&joined, "groupId"), new_group_id);
    let bob_state = dmls_export_group(&new_group_id).unwrap();

    clear(&groups);
    dmls_import_group(&alice_state).unwrap();
    let encrypted = parse(
        &dmls_encrypt(
            &new_group_id,
            &alice.seed,
            room,
            "m.room.message",
            r#"{"body":"new group"}"#,
            None,
        )
        .unwrap(),
    );
    let ciphertext = canonical(encrypted.get("content").unwrap());

    clear(&groups);
    dmls_import_group(&bob_state).unwrap();
    let decrypted = parse(&dmls_decrypt(&new_group_id, &ciphertext, room).unwrap());
    assert_eq!(text(&decrypted, "status"), "ok");
    clear(&groups);
}
