use super::{hex, parse_key, random_bytes, CredentialKind, Store, ENTRY_PREFIX, KEY_LEN};
use std::path::{Path, PathBuf};

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nexapipe-creds-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn store(name: &str) -> (PathBuf, Store) {
    let dir = scratch(name);
    let key = random_bytes::<KEY_LEN>().expect("a key");
    let store = Store::with_key(&dir, key);
    (dir, store)
}

/// Writes the fallback key file the way the app does — private — so the tests
/// that then loosen it are loosening a known-good file rather than whatever
/// the ambient umask happened to produce.
fn write_file_key(dir: &Path, key: &[u8; KEY_LEN]) {
    super::write_private(&dir.join(super::FALLBACK_KEY_FILE), &hex(key)).expect("written");
}

#[test]
fn a_written_credential_reads_back() {
    let (_dir, store) = store("roundtrip");

    store
        .put("totp:node-1", "JBSWY3DPEHPK3PXP")
        .expect("the write succeeds");

    assert_eq!(
        store
            .get("totp:node-1")
            .expect("the read succeeds")
            .as_deref(),
        Some("JBSWY3DPEHPK3PXP")
    );
}

#[test]
fn an_unwritten_credential_is_absent_rather_than_an_error() {
    let (_dir, store) = store("absent");

    assert_eq!(store.get("totp:nothing").expect("the read succeeds"), None);
    // So is removing one that was never there.
    store.remove("totp:nothing").expect("the removal succeeds");
}

#[test]
fn two_credentials_are_stored_side_by_side() {
    let (_dir, store) = store("two");

    store.put("totp:node-1", "first").expect("written");
    store.put("totp:node-2", "second").expect("written");

    assert_eq!(store.get("totp:node-1").unwrap().as_deref(), Some("first"));
    assert_eq!(store.get("totp:node-2").unwrap().as_deref(), Some("second"));
}

/// The point of encrypting: the file on disk must not contain the secret.
#[test]
fn the_secret_is_not_in_the_file() {
    let (dir, store) = store("on-disk");

    store
        .put("totp:node-1", "JBSWY3DPEHPK3PXP")
        .expect("written");

    let raw = std::fs::read_to_string(dir.join(super::STORE_FILE)).expect("the file is there");
    assert!(!raw.contains("JBSWY3DPEHPK3PXP"), "{raw}");
    assert!(raw.contains(ENTRY_PREFIX), "{raw}");
}

/// A different master key must not produce the plaintext: this is what a
/// copied credential file comes to when the key does not come with it.
#[test]
fn another_master_key_cannot_read_the_store() {
    let dir = scratch("wrong-key");
    let original = Store::with_key(&dir, random_bytes::<KEY_LEN>().expect("a key"));
    original.put("totp:node-1", "secret").expect("written");

    let other = Store::with_key(&dir, random_bytes::<KEY_LEN>().expect("another key"));
    assert!(other.get("totp:node-1").is_err());
}

/// An entry moved under another key must not decrypt. The key is authenticated
/// as well as used to look the value up, so re-labelling a secret is not a
/// way to make it readable somewhere else.
#[test]
fn an_entry_does_not_decrypt_under_another_key() {
    let (_dir, store) = store("rebound");

    store.put("totp:node-1", "secret").expect("written");
    let blob = store
        .load()
        .expect("parsed")
        .entries
        .get("totp:node-1")
        .expect("the entry is there")
        .clone();

    assert!(store.decrypt("totp:node-2", &blob).is_err());
}

#[test]
fn a_tampered_entry_is_refused() {
    let (_dir, store) = store("tampered");

    store.put("totp:node-1", "secret").expect("written");
    let mut blob = store
        .load()
        .expect("parsed")
        .entries
        .get("totp:node-1")
        .expect("the entry is there")
        .clone();
    // Flip the last hex character: the ciphertext no longer matches its tag.
    // The character has to be read before it is replaced. Pushing back a
    // fixed `a` or `b` sometimes restores the one that was just popped —
    // whenever the last character was `a` and the one before it was not —
    // and an untampered entry decrypts, failing this test about one run in
    // four.
    let last = blob.pop().expect("the blob is not empty");
    blob.push(if last == 'a' { 'b' } else { 'a' });

    assert!(store.decrypt("totp:node-1", &blob).is_err());
}

#[test]
fn an_entry_in_an_unknown_format_is_refused() {
    let (_dir, store) = store("foreign");

    assert!(store.decrypt("totp:node-1", "not-ours").is_err());
    assert!(store
        .decrypt("totp:node-1", &format!("{ENTRY_PREFIX}zz"))
        .is_err());
}

#[test]
fn keys_are_listed_in_order() {
    let (_dir, store) = store("listed");

    store.put("totp:node-2", "b").expect("written");
    store.put("totp:node-1", "a").expect("written");

    assert_eq!(
        store.keys().expect("the keys are read"),
        vec!["totp:node-1".to_string(), "totp:node-2".to_string()]
    );
}

/// A store is only ever written `0600`: another account must not be able to
/// read what the keychain key protects.
#[cfg(unix)]
#[test]
fn the_store_file_is_private() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, store) = store("permissions");
    store.put("totp:node-1", "secret").expect("written");

    let mode = std::fs::metadata(dir.join(super::STORE_FILE))
        .expect("the file is there")
        .permissions()
        .mode();

    assert_eq!(mode & 0o777, 0o600, "mode {mode:o}");
}

/// An install that ran without a keychain backend — Linux, before this build
/// — has its master key in a file, and every stored credential is sealed
/// under it. `file_key` is what finds it, so the same key can move into the
/// keychain rather than being replaced by a fresh one.
#[test]
fn a_master_key_left_in_a_file_is_read_back() {
    let dir = scratch("file-key");
    let key = random_bytes::<KEY_LEN>().expect("a key");
    write_file_key(&dir, &key);

    assert_eq!(
        super::MasterKey::file_key(&dir).expect("readable"),
        Some(key)
    );
}

/// The ordinary case on every platform with a keychain: nothing was ever
/// written to the file, so there is nothing to move.
#[test]
fn a_first_run_has_no_file_key() {
    let dir = scratch("no-file-key");

    assert_eq!(super::MasterKey::file_key(&dir).expect("readable"), None);
}

/// A file that is there but is not a key must not be read as one: a key made
/// of zeroes, or a truncated one, would silently orphan the whole store.
///
/// Written privately, because the check that runs before the parse is about
/// permissions — a `0644` file would be refused for that instead, and the
/// parse never reached.
#[test]
fn a_file_that_is_not_a_key_is_absent_rather_than_a_short_key() {
    let dir = scratch("bad-file-key");
    super::write_private(&dir.join(super::FALLBACK_KEY_FILE), "not-a-key").expect("written");

    assert_eq!(super::MasterKey::file_key(&dir).expect("readable"), None);
}

/// The master key file *is* every credential in the store, on the platforms
/// where it lives in a file. One that other accounts can read is therefore
/// refused outright rather than warned about — and refused as an error, not
/// as "absent", because "absent" is what makes the caller mint a fresh key
/// and orphan the store sealed under the readable one.
#[cfg(unix)]
#[test]
fn a_master_key_other_accounts_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("loose-key-file");
    let key = random_bytes::<KEY_LEN>().expect("a key");
    let path = dir.join(super::FALLBACK_KEY_FILE);
    write_file_key(&dir, &key);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosened");

    let error =
        super::MasterKey::file_key(&dir).expect_err("a world-readable master key is not read");

    assert!(
        error.to_string().contains("chmod 600"),
        "the error does not say how to fix it: {error}"
    );
}

/// The store file gets the same refusal, and it is checked *before* the read
/// rather than after: the point is not to decrypt a store another account
/// could read while it was sitting there.
#[cfg(unix)]
#[test]
fn a_store_other_accounts_can_read_is_not_decrypted() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, store) = store("loose-store");
    store.put("totp:node-1", "secret").expect("written");
    let path = dir.join(super::STORE_FILE);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("loosened");

    assert!(
        store.load().is_err(),
        "a world-readable store was decrypted anyway"
    );
}

/// A group-readable file is refused too. "Other accounts" is not only the
/// `o` bits: a shared machine puts the user's own group on the path.
#[cfg(unix)]
#[test]
fn a_group_readable_master_key_is_refused_too() {
    use std::os::unix::fs::PermissionsExt;

    let dir = scratch("group-key-file");
    let path = dir.join(super::FALLBACK_KEY_FILE);
    write_file_key(&dir, &random_bytes::<KEY_LEN>().expect("a key"));
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).expect("loosened");

    assert!(super::MasterKey::file_key(&dir).is_err());
}

/// A minted key reaches the file whole, or the file is not written at all.
///
/// `file_key` rejects a file that is not 32 bytes, and the macOS migration
/// takes the file's mere existence as "already moved out" — so a write that
/// died halfway would leave an installation that can neither read its key
/// nor read the keychain copy it still has. What is observable from outside
/// is that the file under its own name is a whole key, and that nothing was
/// left beside it under the name the bytes were written to first.
#[test]
fn a_minted_key_is_published_whole_and_leaves_no_temporary() {
    let dir = scratch("minted-key");

    let key = super::MasterKey::from_file(&dir).expect("a key is minted");

    assert_eq!(
        super::MasterKey::file_key(&dir).expect("readable"),
        Some(key)
    );
    let temporary = dir.join(format!("{}.tmp", super::FALLBACK_KEY_FILE));
    assert!(
        !temporary.exists(),
        "{} was left beside the key",
        temporary.display()
    );
}

/// A mask is not a shortening: none of the original characters of a short
/// value may survive it, because a 16-character TOTP secret shortened by
/// four characters is still a working TOTP secret on screen.
#[test]
fn a_short_value_is_replaced_whole() {
    let secret = "JBSWY3DPEHPK3PXP";

    let masked = super::mask(secret);
    assert!(!masked.is_empty(), "an empty mask reads as no credential");
    for part in ["JBSW", "3DPE", "PXP"] {
        assert!(!masked.contains(part), "{masked} still shows {part}");
    }
}

/// A long value keeps its ends, because "which of my nodes is this" is the
/// question the mask exists to answer, and drops everything between them.
#[test]
fn a_long_value_keeps_its_ends_and_nothing_between() {
    let ticket = "e4f1c9a0b2d3e5f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3";

    let masked = super::mask(ticket);
    assert!(masked.starts_with("e4f1c9a0"), "{masked} lost its head");
    assert!(masked.ends_with("2d3"), "{masked} lost its tail");
    assert!(
        !masked.contains("b2d3e5f7a8b9c0d1"),
        "{masked} kept the middle of the ticket"
    );
}

/// Empty stays empty: "no credential" is a different thing from "a
/// credential I am not showing you", and the UI says so differently.
#[test]
fn nothing_to_mask_is_an_empty_mask() {
    assert_eq!(super::mask(""), "");
}

/// A connection string is a credential, so it is keyed per node like the
/// other two — a ticket written under one node's id and read under another's
/// is a ticket nobody can spend.
#[test]
fn a_connection_string_is_keyed_by_the_node_it_connects() {
    assert_eq!(
        super::secret_key(CredentialKind::Ticket, "node-1"),
        "ticket:node-1"
    );
    assert_eq!(
        super::secret_key(CredentialKind::EndpointId, "node-1"),
        "endpoint:node-1"
    );
}

/// A device key is a credential like the secret beside it, and it is filed
/// under its node the same way: a key that outlived the node it belonged to
/// would be handed to whatever node reuses that id.
///
/// It is filed under the machine as well, because a key belongs to the machine
/// rather than to the node: the server files a credential under the machine's
/// name, and that name outlives every server the machine comes back to.
#[test]
fn a_key_is_per_node_and_a_relay_token_is_global() {
    assert_eq!(
        super::secret_key(CredentialKind::TotpSecret, "node-1"),
        "totp:node-1"
    );
    assert_eq!(
        super::secret_key(CredentialKind::EnrollmentToken, "node-1"),
        "enrollment:node-1"
    );
    assert_eq!(
        super::secret_key(CredentialKind::DeviceKey, "node-1"),
        "devicekey:node-1"
    );
    assert_eq!(
        super::secret_key(CredentialKind::RelayToken, "ignored"),
        "relay:global"
    );
}

/// A machine that has no key of its own adopts the key of a node that has
/// one: that is the key the server holds under this machine's name, and
/// adopting it is what keeps the two the same. Without it, a machine that
/// comes back to a rebuilt server would offer a new key and be refused as a
/// takeover.
#[test]
fn a_machine_adopts_the_key_of_a_node_that_has_one() {
    let (_dir, store) = store("adopt");

    super::device_key::file_device_key(&store, "node-1", "aa").expect("filed");

    assert_eq!(
        super::device_key::machine_device_key(&store)
            .expect("readable")
            .as_deref(),
        Some("aa")
    );
}

/// The machine's key is never replaced once it exists: the servers holding it
/// are the ones that would stop recognising this machine.
#[test]
fn the_machine_key_is_not_replaced() {
    let (_dir, store) = store("keep");

    super::device_key::file_device_key(&store, "node-1", "aa").expect("filed");
    super::device_key::file_device_key(&store, "node-2", "bb").expect("filed");

    assert_eq!(
        super::device_key::machine_device_key(&store)
            .expect("readable")
            .as_deref(),
        Some("aa"),
        "the machine kept the key it had"
    );
}

/// A node that enrolled with a key answers with that key, whatever the
/// machine does afterwards: the server holds it under this machine's name.
#[test]
fn a_node_answers_with_its_own_key_first() {
    let (_dir, store) = store("own");

    super::device_key::file_device_key(&store, "node-1", "aa").expect("filed");
    super::device_key::file_device_key(&store, "node-2", "bb").expect("filed");

    assert_eq!(
        super::device_key::effective_device_key(&store, "node-1")
            .expect("readable")
            .as_deref(),
        Some("aa")
    );
    assert_eq!(
        super::device_key::effective_device_key(&store, "node-2")
            .expect("readable")
            .as_deref(),
        Some("bb")
    );
}

/// A node without a key of its own answers with the machine's — the same key
/// every other server this machine comes back to is answered with.
#[test]
fn a_node_without_one_answers_with_the_machine_key() {
    let (_dir, store) = store("fallback");

    super::device_key::file_device_key(&store, "node-1", "aa").expect("filed");

    assert_eq!(
        super::device_key::effective_device_key(&store, "node-2")
            .expect("readable")
            .as_deref(),
        Some("aa")
    );
}

/// A machine that has never had a key has none to answer with: it is not a
/// key that is looked up wrongly, it is the absence of one.
#[test]
fn a_machine_with_no_key_at_all_has_none() {
    let (_dir, store) = store("empty");

    assert_eq!(
        super::device_key::machine_device_key(&store)
            .expect("readable")
            .as_deref(),
        None
    );
    assert_eq!(
        super::device_key::effective_device_key(&store, "node-1")
            .expect("readable")
            .as_deref(),
        None
    );
}

/// The machine's own entry is not filed under a node id, so it cannot be
/// mistaken for one of a node's own — the ids are `node-<hex>` or a
/// 64-character Node ID.
#[test]
fn the_machine_key_is_filed_under_a_scope_of_its_own() {
    let (_dir, store) = store("scope");

    super::device_key::file_device_key(&store, "node-1", "aa").expect("filed");

    assert!(
        store
            .keys()
            .expect("the keys are read")
            .contains(&"devicekey:global".to_string()),
        "the machine's key is filed under its own scope: {:?}",
        store.keys().expect("the keys are read")
    );
}

#[test]
fn hex_round_trips_and_a_wrong_length_is_not_a_key() {
    let bytes = random_bytes::<KEY_LEN>().expect("random bytes");
    let encoded = hex(&bytes);

    assert_eq!(encoded.len(), KEY_LEN * 2);
    assert_eq!(parse_key(&encoded), Some(bytes));
    assert_eq!(parse_key(&encoded[..KEY_LEN * 2 - 1]), None);
}
