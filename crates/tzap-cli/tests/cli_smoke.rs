use std::fs;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;
use tzap_core::format::{MANIFEST_FOOTER_LEN, VOLUME_TRAILER_LEN};

const KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const BAD_KEY_HEX: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

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
