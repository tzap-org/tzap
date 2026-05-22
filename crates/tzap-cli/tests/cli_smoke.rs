use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use tzap_core::format::{
    BOOTSTRAP_SIDECAR_HEADER_LEN, MANIFEST_FOOTER_LEN, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use tzap_core::wire::{BootstrapSidecarHeader, VolumeHeader};
use tzap_core::{crypto::compute_hmac, HmacDomain, MasterKey, Subkeys};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const BAD_KEY_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const SIDECAR_HMAC_COVERED_LEN: usize = 92;

fn master_key_from_hex(hex: &str) -> Vec<u8> {
    let mut out = [0u8; 32];
    for (idx, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        out[idx] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    out.to_vec()
}

#[test]
fn cli_subcommand_help_paths_are_available() {
    for command in ["create", "extract", "list", "verify", "keygen"] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args([command, "--help"])
            .assert()
            .success();
    }
}

#[test]
fn cli_aliases_for_command_shorthands_are_not_enabled() {
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("c")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));

    Command::cargo_bin("tzap")
        .unwrap()
        .arg("x")
        .assert()
        .failure()
        .stderr(predicate::str::contains("error:"));
}

#[test]
fn cli_top_level_help_contains_product_description_and_commands() {
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Create, list, verify, and extract v36 archives",
        ))
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("extract"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("keygen"))
        .stdout(predicate::str::contains("K/KB/KiB"))
        .stdout(predicate::str::contains("Exit codes"));
}

#[test]
fn cli_create_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Create a new archive"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--output <ARCHIVE>"));
    assert!(stdout.contains("--volumes <COUNT>"));
    assert!(stdout.contains("--volume-size <SIZE>"));
    assert!(stdout.contains("--volume-loss-tolerance <COUNT>"));
    assert!(stdout.contains("--bit-rot-buffer-pct <PERCENT>"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--argon2-t-cost <COUNT>"));
    assert!(stdout.contains("--argon2-m-cost-kib <KIB>"));
    assert!(stdout.contains("--argon2-parallelism <COUNT>"));
    assert!(stdout.contains("--dictionary <FILE>"));
    assert!(stdout.contains("--bootstrap-out <FILE>"));
    assert!(stdout.contains("--compression-level <LEVEL>"));
    assert!(stdout.contains("--chunk-size <SIZE>"));
    assert!(stdout.contains("--envelope-size <SIZE>"));
    assert!(stdout.contains("--block-size <SIZE>"));
}

#[test]
fn cli_extract_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Extract one or many archive members"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--directory"));
    assert!(stdout.contains("--stdout"));
    assert!(stdout.contains("--overwrite"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--bootstrap"));
    assert!(stdout.contains("--volume"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
}

#[test]
fn cli_list_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("List archive members in plain format"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--bootstrap"));
    assert!(stdout.contains("--volume"));
    assert!(stdout.contains("--long"));
}

#[test]
fn cli_verify_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Verify archive signatures"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--bootstrap"));
}

#[test]
fn cli_keygen_help_includes_output_and_force_flags() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--help"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Generate a random 32-byte raw key"));
    assert!(stdout.contains("--output <KEYFILE>"));
    assert!(stdout.contains("--stdout"));
    assert!(stdout.contains("--force"));
}

#[test]
fn cli_create_requires_key_source_before_running() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_create_requires_exactly_one_key_source() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--password-stdin",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_create_rejects_conflicting_volume_flags() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-size",
            "1M",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_create_rejects_password_source_conflicts() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let output = temp.path().join("sample.tzap");
    let input = temp.path().join("hello.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--password",
            "--password-stdin",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_create_with_interactive_password_requires_matching_confirmation() {
    let temp = tempdir().unwrap();
    let output = temp.path().join("password.tzap");
    let input = temp.path().join("secret.txt");

    fs::write(&input, b"interactive secret\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("mismatch\nsecret\nsecret\nsecret\n")
        .assert()
        .success()
        .stderr(predicate::str::contains("Passphrases do not match"));
}

#[test]
fn cli_extract_requires_key_source_before_running() {
    let temp = tempdir().unwrap();
    let archive = temp.path().join("sample.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", archive.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_list_requires_key_source_before_running() {
    let temp = tempdir().unwrap();
    let archive = temp.path().join("sample.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", archive.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_verify_requires_key_source_before_running() {
    let temp = tempdir().unwrap();
    let archive = temp.path().join("sample.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", archive.to_str().unwrap()])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_verify_key_mode_and_archive_input_are_required() {
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", "key.hex"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_create_list_verify_and_extract_with_keyfile() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");
    let extract_dir = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("created 1 file(s), 1 volume(s)"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hello.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-C",
            extract_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(
        fs::read(extract_dir.join("hello.txt")).unwrap(),
        b"hello from tzap\n"
    );
}

#[test]
fn cli_reports_wrong_key_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_keyfile = temp.path().join("bad-key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_keyfile, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            bad_keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_create_and_verify_with_password_stdin_argon2id() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");

    fs::write(&input, b"password protected\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("correct horse battery staple\n")
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin("correct horse battery staple\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn cli_extract_stdout_writes_exact_single_file_payload() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"stdout payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stdout(predicate::eq("stdout payload\n"));
}

#[test]
fn cli_reports_corrupt_archive_after_header_authentication_succeeds() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&archive).unwrap();
    let manifest_hmac_offset = bytes.len() - VOLUME_TRAILER_LEN - MANIFEST_FOOTER_LEN + 104;
    bytes[manifest_hmac_offset] ^= 0x01;
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-archive"));
}

#[test]
fn cli_reports_wrong_key_for_password_mode_on_raw_key_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin("not the raw key\n")
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"))
        .stderr(predicate::str::contains(
            "raw-key archives require --keyfile",
        ));
}

#[test]
fn cli_reports_wrong_passphrase_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("secret.tzap");
    let passphrase = "correct horse battery staple\n";

    fs::write(&input, b"secret data\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin("wrong passphrase\n")
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_reports_unsupported_revision_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let mut bytes = fs::read(&archive).unwrap();
    let mut header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
    header.volume_format_rev = 35;
    bytes[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(12)
        .stderr(predicate::str::contains("unsupported-revision"));
}

#[test]
fn cli_reports_missing_bootstrap_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("dict.txt");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");
    let stripped_bootstrap = temp.path().join("sample.tzap.bootstrap.stripped");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"dictionary payload bytes").unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "--bootstrap-out",
            bootstrap.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let archive_bytes = fs::read(&archive).unwrap();
    let volume_header = VolumeHeader::parse(&archive_bytes[..VOLUME_HEADER_LEN]).unwrap();
    let bootstrap_original = fs::read(&bootstrap).unwrap();
    let mut bootstrap_header =
        BootstrapSidecarHeader::parse(&bootstrap_original[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
    bootstrap_header.flags &= !0x04;
    bootstrap_header.dictionary_records_offset = 0;
    bootstrap_header.dictionary_records_length = 0;

    let master_key = MasterKey::from_raw_key(&master_key_from_hex(KEY_HEX)).unwrap();
    let subkeys = Subkeys::derive(
        &master_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
    )
    .unwrap();
    let stripped_header = bootstrap_header.to_bytes();
    let sidecar_hmac = compute_hmac(
        HmacDomain::BootstrapSidecar,
        &subkeys.mac_key,
        &bootstrap_header.archive_uuid,
        &bootstrap_header.session_id,
        &stripped_header[..SIDECAR_HMAC_COVERED_LEN],
    );
    bootstrap_header.sidecar_hmac = sidecar_hmac;
    let stripped = bootstrap_header.to_bytes();

    let mut payload_end = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    if bootstrap_header.has_manifest_footer() {
        assert_eq!(bootstrap_header.manifest_footer_offset, payload_end);
        payload_end = payload_end
            .checked_add(bootstrap_header.manifest_footer_length as u64)
            .unwrap();
    }
    if bootstrap_header.has_index_root_records() {
        assert_eq!(bootstrap_header.index_root_records_offset, payload_end);
        payload_end = payload_end
            .checked_add(bootstrap_header.index_root_records_length as u64)
            .unwrap();
    }

    let mut stripped_bootstrap_bytes = stripped.to_vec();
    stripped_bootstrap_bytes
        .extend_from_slice(&bootstrap_original[BOOTSTRAP_SIDECAR_HEADER_LEN..payload_end as usize]);
    fs::write(&stripped_bootstrap, stripped_bootstrap_bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            stripped_bootstrap.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .code(14)
        .stderr(predicate::str::contains("missing-bootstrap"));
}

#[test]
fn cli_reports_unsafe_path_as_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--stdout",
            archive.to_str().unwrap(),
            "../evil.txt",
        ])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));
}

#[test]
fn cli_reports_unsupported_feature_with_stable_category_and_exit_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let dictionary = temp.path().join("empty.dict");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&dictionary, b"").unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--dictionary",
            dictionary.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(16)
        .stderr(predicate::str::contains("unsupported-feature"));
}

#[test]
fn cli_create_missing_input_returns_io_error_code() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("missing.txt");
    let output = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("io-error"));
}

#[test]
fn cli_reports_invalid_size_suffix_with_bad_value_in_message() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "10Q",
            "-o",
            output.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "invalid size '10Q': unsupported suffix 'Q'",
        ))
        .stderr(predicate::str::contains("supported: K/KB/KiB"));
}

#[test]
fn cli_create_and_verify_multi_volume_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("striped.txt");
    let output_base = temp.path().join("striped.tzap");
    let volume_0 = temp.path().join("striped.tzap.000");
    let volume_1 = temp.path().join("striped.tzap.001");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"multi-volume payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("2 volume(s)"));

    assert!(volume_0.exists());
    assert!(volume_1.exists());

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            volume_1.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume",
            volume_1.to_str().unwrap(),
            volume_0.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("striped.txt\n"));
}

#[test]
fn cli_create_with_volume_size_splits_archive_by_target_size() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("sized.bin");
    let output_base = temp.path().join("sized.tzap");
    let target_size = 8 * 1024u64;

    fs::write(&keyfile, KEY_HEX).unwrap();
    let mut data = Vec::with_capacity(64 * 1024);
    let mut state = 0x1234_5678u32;
    for _ in 0..64 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 24) as u8);
    }
    fs::write(&input, data).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volume-size",
            "8K",
            "--volume-loss-tolerance",
            "1",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "128K",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("volume(s)"));

    let mut volumes = Vec::new();
    for index in 0.. {
        let volume = temp.path().join(format!("sized.tzap.{index:03}"));
        if !volume.exists() {
            break;
        }
        assert!(
            fs::metadata(&volume).unwrap().len() <= target_size,
            "{} exceeded target volume size",
            volume.display()
        );
        volumes.push(volume);
    }
    assert!(volumes.len() > 1);

    let mut args = vec![
        "verify".to_owned(),
        "--keyfile".to_owned(),
        keyfile.to_str().unwrap().to_owned(),
    ];
    args.extend(
        volumes
            .iter()
            .map(|volume| volume.to_str().unwrap().to_owned()),
    );
    Command::cargo_bin("tzap")
        .unwrap()
        .args(args)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

fn is_lower_hex_byte(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

fn is_lower_hex_str(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[test]
fn cli_keygen_stdout_emits_hex_key_and_newline() {
    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--stdout"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(output.len(), 65, "expected 64 hex chars plus newline");
    assert_eq!(output.last(), Some(&b'\n'));
    assert!(output[..64].iter().all(|byte| is_lower_hex_byte(*byte)));
}

#[test]
fn cli_keygen_writes_keyfile_output_with_force_semantics() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("seed.hex");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success();
    assert!(keyfile.exists());
    let written = fs::read_to_string(&keyfile).unwrap();
    assert_eq!(written.len(), 65);
    assert_eq!(written.as_bytes()[64], b'\n');
    assert!(is_lower_hex_str(&written[..64]));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--output", keyfile.to_str().unwrap()])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--force", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success();
}

#[test]
fn cli_keygen_rejects_missing_output_path_without_stdout_or_output() {
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("required"));
}

#[test]
fn cli_create_with_password_stdin_strips_line_endings_and_preserves_spaces() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("secret.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"secret\n").unwrap();

    for (pass, args) in [
        (
            "linefeed pass\n",
            vec![
                "create",
                "--password-stdin",
                "--argon2-t-cost",
                "1",
                "--argon2-m-cost-kib",
                "8",
                "--argon2-parallelism",
                "1",
                "-o",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
            ],
        ),
        (
            "crlf-pass\r\n",
            vec![
                "create",
                "--password-stdin",
                "--argon2-t-cost",
                "1",
                "--argon2-m-cost-kib",
                "8",
                "--argon2-parallelism",
                "1",
                "-o",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
            ],
        ),
        (
            "in tern al spaces\n",
            vec![
                "create",
                "--password-stdin",
                "--argon2-t-cost",
                "1",
                "--argon2-m-cost-kib",
                "8",
                "--argon2-parallelism",
                "1",
                "-o",
                archive.to_str().unwrap(),
                input.to_str().unwrap(),
            ],
        ),
    ] {
        Command::cargo_bin("tzap")
            .unwrap()
            .args(args.clone())
            .write_stdin(pass)
            .assert()
            .success();

        Command::cargo_bin("tzap")
            .unwrap()
            .args(["verify", "--password-stdin", archive.to_str().unwrap()])
            .write_stdin(pass)
            .assert()
            .success()
            .stdout(predicate::str::contains("OK"));

        fs::remove_file(&archive).unwrap();
    }
}

#[test]
fn cli_create_with_password_stdin_rejects_empty_passphrase() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("secret.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"secret\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("passphrase must not be empty"));
}

#[test]
fn cli_create_rejects_invalid_argon2_parameters_as_usage_error() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("password.tzap");
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-m-cost-kib",
            "4194305",
            "--argon2-t-cost",
            "1",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin("secret\n")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("invalid-arguments"));
}

#[test]
fn cli_keyfile_raw_bytes_and_hex_with_whitespace_are_accepted() {
    let temp = tempdir().unwrap();
    let raw_keyfile = temp.path().join("raw.key");
    let hex_keyfile = temp.path().join("spaced.hex");
    let input = temp.path().join("hello.txt");
    let output_raw = temp.path().join("raw.tzap");
    let output_hex = temp.path().join("hex.tzap");

    fs::write(&raw_keyfile, [0x42u8; 32]).unwrap();
    fs::write(&hex_keyfile, format!("  {}\n", KEY_HEX)).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            raw_keyfile.to_str().unwrap(),
            "-o",
            output_raw.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            hex_keyfile.to_str().unwrap(),
            "-o",
            output_hex.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
}

#[test]
fn cli_keyfile_with_invalid_hex_and_wrong_length_is_rejected() {
    let temp = tempdir().unwrap();
    let invalid_hex = temp.path().join("invalid-hex.txt");
    let invalid_len = temp.path().join("invalid-len.txt");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    let mut invalid_hex_bytes = [b'0'; 64];
    invalid_hex_bytes[63] = b'g';
    fs::write(&invalid_hex, invalid_hex_bytes).unwrap();
    fs::write(&invalid_len, [0x42u8; 31]).unwrap();
    fs::write(&input, b"hello\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            invalid_hex.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("non-hex"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            invalid_len.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "keyfile must contain either 32 raw bytes or 64 hex characters",
        ));
}

#[test]
fn cli_extract_with_password_prompt_and_stdin_fallback() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let output_dir = temp.path().join("out");
    let passphrase = "prompt backup phrase\n";

    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--password",
            "-C",
            output_dir.to_str().unwrap(),
            archive.to_str().unwrap(),
            "secret.txt",
        ])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stderr(predicate::str::contains("Passphrase:"));

    assert_eq!(
        fs::read(output_dir.join("secret.txt")).unwrap(),
        b"payload\n"
    );
}

#[test]
fn cli_list_with_password_prompt_and_stdin_fallback() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let passphrase = "prompt backup phrase\n";

    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--password", archive.to_str().unwrap()])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stdout(predicate::str::contains("secret.txt\n"));
}

#[test]
fn cli_verify_with_password_prompt_and_stdin_fallback() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("secret.txt");
    let archive = temp.path().join("password.tzap");
    let passphrase = "prompt backup phrase\n";

    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--password-stdin",
            "--argon2-t-cost",
            "1",
            "--argon2-m-cost-kib",
            "8",
            "--argon2-parallelism",
            "1",
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .write_stdin(passphrase)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password", archive.to_str().unwrap()])
        .write_stdin(passphrase)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}
