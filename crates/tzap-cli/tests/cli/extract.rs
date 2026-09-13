// Tests for the `tzap extract` CLI surface.
use super::*;

#[test]
fn cli_extract_help_includes_examples_and_flags() {
    let output = Command::cargo_bin("tzap").unwrap().args(["extract", "--help"]).assert().success().get_output().stdout.clone();
    let stdout = String::from_utf8_lossy(&output);

    assert!(stdout.contains("Extract one or many archive members"));
    assert!(stdout.contains("Examples:"));
    assert!(stdout.contains("--directory"));
    assert!(stdout.contains("--stdout"));
    assert!(stdout.contains("--dry-run"));
    assert!(stdout.contains("--overwrite"));
    assert!(stdout.contains("--fsync"));
    assert!(stdout.contains("--password"));
    assert!(stdout.contains("--bootstrap"));
    assert!(stdout.contains("--volume"));
    assert!(stdout.contains("--jobs <N>"));
    assert!(stdout.contains("--password-stdin"));
    assert!(stdout.contains("--keyfile <KEYFILE>"));
    assert!(stdout.contains("--recipient-key <FILE>"));
    assert!(!stdout.contains("--insecure-zero-key"));
}

#[test]
fn cli_extract_reads_unencrypted_archive_without_key_source() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("sample.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");
    fs::write(&input, b"plaintext v45\n").unwrap();

    Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), input.to_str().unwrap()]).assert().success();

    Command::cargo_bin("tzap").unwrap().args(["extract", "-C", output.to_str().unwrap(), archive.to_str().unwrap()]).assert().success();

    assert_eq!(fs::read(output.join("sample.txt")).unwrap(), b"plaintext v45\n");
}

#[test]
fn cli_extract_selected_hardlink_pulls_in_its_target() {
    // The hardlink pre-scan in `extract_selected_files_to` reads `kind` and
    // `link_target` straight from index metadata. Naming only the alias must
    // still pull its canonical target in as a restore dependency.
    let temp = tempdir().unwrap();
    let source = temp.path().join("src");
    let archive = temp.path().join("links.tzap");
    fs::create_dir(&source).unwrap();
    fs::write(source.join("original.txt"), b"shared inode payload\n").unwrap();
    fs::hard_link(source.join("original.txt"), source.join("alias.txt")).unwrap();

    Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), source.to_str().unwrap()]).assert().success();

    // Whichever member the writer recorded as the alias, selecting it alone must
    // restore readable content, and selecting both must agree with it.
    for selected in ["src/original.txt", "src/alias.txt"] {
        let output = temp.path().join(format!("out-{}", selected.replace('/', "-")));
        Command::cargo_bin("tzap").unwrap().args(["extract", "-C", output.to_str().unwrap(), archive.to_str().unwrap(), selected]).assert().success();
        assert_eq!(fs::read(output.join(selected)).unwrap(), b"shared inode payload\n", "selecting {selected} did not restore its content");
    }

    let both = temp.path().join("out-both");
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "-C", both.to_str().unwrap(), archive.to_str().unwrap(), "src/original.txt", "src/alias.txt"])
        .assert()
        .success();
    assert_eq!(fs::read(both.join("src/original.txt")).unwrap(), b"shared inode payload\n");
    assert_eq!(fs::read(both.join("src/alias.txt")).unwrap(), b"shared inode payload\n");
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
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .success()
        .stdout(predicate::eq("stdout payload\n"));
}

#[test]
fn cli_extract_stdout_outputs_binary_data_only_to_stdout() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.bin");
    let archive = temp.path().join("sample.tzap");
    let payload: Vec<u8> = (0..=255u8).collect();

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "hello.bin"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(output.stdout, payload);
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_extract_stdout_emits_no_payload_when_archive_authentication_fails() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_key = temp.path().join("bad.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_key, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"stdout payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", bad_key.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(10)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_extract_with_global_quiet_suppresses_success_summary() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--quiet", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"hello from tzap\n");
}

#[test]
fn cli_extract_with_global_quiet_still_emits_errors_to_stderr() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"hello from tzap\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--quiet", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "missing.txt"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("missing archive path: missing.txt"));
}

#[test]
fn cli_extract_with_global_quiet_still_outputs_stdout_payload() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.bin");
    let archive = temp.path().join("sample.tzap");
    let payload: Vec<u8> = (0u8..=254u8).collect();

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let output = Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--quiet", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "hello.bin"])
        .assert()
        .success()
        .get_output()
        .clone();
    assert_eq!(output.stdout, payload);
    assert!(output.stderr.is_empty());
}

#[test]
fn cli_extract_selected_path_uses_core_unicode_normalization() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let archive = temp.path().join("unicode-selection.tzap");
    let input = temp.path().join("café.txt");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"normalized payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "cafe\u{301}.txt"])
        .assert()
        .success()
        .stdout(predicate::eq(b"normalized payload\n".to_vec()));
}

#[cfg(unix)]
#[test]
fn cli_extract_allow_absolute_symlinks_toggle() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let archive = temp.path().join("abs_symlink.tzap");
    let link = temp.path().join("abs_link");
    let extract_disallowed = temp.path().join("extract_disallowed");
    let extract_allowed = temp.path().join("extract_allowed");

    fs::write(&keyfile, KEY_HEX).unwrap();
    std::os::unix::fs::symlink("/tmp/abs_target", &link).unwrap();

    Command::cargo_bin("tzap").unwrap().arg("create").arg("--output").arg(&archive).arg(&link).arg("--keyfile").arg(&keyfile).assert().success();

    // Default extraction rejects absolute symlink
    Command::cargo_bin("tzap").unwrap().arg("extract").arg(&archive).arg("-C").arg(&extract_disallowed).arg("--keyfile").arg(&keyfile).assert().failure();

    // Extraction with --allow-absolute-symlinks succeeds
    Command::cargo_bin("tzap")
        .unwrap()
        .arg("extract")
        .arg(&archive)
        .arg("-C")
        .arg(&extract_allowed)
        .arg("--allow-absolute-symlinks")
        .arg("--keyfile")
        .arg(&keyfile)
        .assert()
        .success();

    let restored_link = extract_allowed.join("abs_link");
    assert_eq!(fs::read_link(&restored_link).unwrap(), Path::new("/tmp/abs_target"));
}

#[test]
fn cli_extracts_archive_created_with_volume_size_split() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("sized-extract.bin");
    let output_base = temp.path().join("sized-extract.tzap");
    let output = temp.path().join("out");
    let expected = (0..64 * 1024).map(|idx| ((idx * 37 + 11) % 251) as u8).collect::<Vec<_>>();

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &expected).unwrap();

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
        .success();

    let mut volume_args = Vec::new();
    for index in 0.. {
        let volume = numbered_volume_path(&output_base, index);
        if !volume.exists() {
            break;
        }
        volume_args.push(volume);
    }
    assert!(volume_args.len() > 1);

    let mut args = vec![
        "extract".to_owned(),
        "--keyfile".to_owned(),
        keyfile.to_str().unwrap().to_owned(),
        "--directory".to_owned(),
        output.to_str().unwrap().to_owned(),
        volume_args[0].to_str().unwrap().to_owned(),
    ];
    for volume in &volume_args[1..] {
        args.push("--volume".to_owned());
        args.push(volume.to_str().unwrap().to_owned());
    }
    args.push("sized-extract.bin".to_owned());

    Command::cargo_bin("tzap").unwrap().args(args).assert().success().stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(fs::read(output.join("sized-extract.bin")).unwrap(), expected);
}

#[test]
fn cli_extract_fsync_flag_round_trips_content() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");
    let payload = b"fsync round trip\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--fsync", "-C", output.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), payload);
}

#[test]
fn cli_extract_all_files_to_default_directory() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let input = input_root.join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output_dir = temp.path().join("extract");
    let payload = b"destination default\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::create_dir_all(&input_root).unwrap();
    fs::write(&input, payload).unwrap();
    fs::create_dir(&output_dir).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap").unwrap().current_dir(&output_dir).args(["extract", "--keyfile", keyfile.to_str().unwrap(), "../sample.tzap"]).assert().success();

    assert_eq!(fs::read(output_dir.join("hello.txt")).unwrap(), payload);
}

#[test]
fn cli_extract_all_files_to_specified_directory() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input-dir");
    let archive = temp.path().join("tree.tzap");
    let output = temp.path().join("out");
    let expected = b"tree extraction\n";

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), expected).unwrap();
    fs::write(input_root.join("b.txt"), b"skip this\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input_root.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("input-dir").join("a.txt")).unwrap(), expected);
}

#[test]
fn cli_extract_selected_file_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("selected.tzap");
    let output = temp.path().join("out");

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), b"a\n").unwrap();
    fs::write(input_root.join("b.txt"), b"b\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input_root.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), archive.to_str().unwrap(), "input/a.txt"])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("input").join("a.txt")).unwrap(), b"a\n");
    assert!(!output.join("input").join("b.txt").exists());
}

#[test]
fn cli_extract_multiple_selected_file_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("selected.tzap");
    let output = temp.path().join("out");

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), b"a\n").unwrap();
    fs::write(input_root.join("b.txt"), b"b\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input_root.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "input/a.txt",
            "input/b.txt",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("input").join("a.txt")).unwrap(), b"a\n");
    assert_eq!(fs::read(output.join("input").join("b.txt")).unwrap(), b"b\n");
}

#[test]
fn cli_extract_to_stdout_with_valid_single_file() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let payload = b"stdout payload\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, payload).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .success()
        .stdout(predicate::eq(payload.to_vec()));
}

#[test]
fn cli_extract_with_overwrite_enabled() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"updated payload\n").unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("hello.txt"), b"already there").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--overwrite",
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"updated payload\n");
}

#[test]
fn cli_extract_with_bootstrap_sidecar() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let bootstrap = temp.path().join("sample.tzap.bootstrap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"bootstrap payload\n").unwrap();

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
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap",
            bootstrap.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"bootstrap payload\n");
}

#[test]
fn cli_extract_multi_volume_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output_base = temp.path().join("multi.tzap");
    let output = temp.path().join("out");
    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
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
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            v0.to_str().unwrap(),
            "--volume",
            v1.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(fs::read(output.join("hello.txt")).unwrap(), b"multi-volume payload\n");
}

#[test]
fn cli_extract_recovers_when_one_volume_is_missing_but_tolerance_allows_it() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.bin");
    let output_base = temp.path().join("recoverable.tzap");
    let output = temp.path().join("out");
    let mut data = vec![0u8; 64 * 1024];
    for (idx, byte) in data.iter_mut().enumerate() {
        *byte = (idx % 251) as u8;
    }

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &data).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "3",
            "--volume-loss-tolerance",
            "1",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();

    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    let v2 = numbered_volume_path(&output_base, 2);

    fs::remove_file(&v1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            v0.to_str().unwrap(),
            "--volume",
            v2.to_str().unwrap(),
            "payload.bin",
        ])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("payload.bin")).unwrap(), data);
}

#[test]
fn cli_bit_rot_buffer_recovers_corrupted_payload_blocks_in_split_archive() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("bitrot.bin");
    let output_base = temp.path().join("bitrot.tzap");
    let output = temp.path().join("out");
    let mut expected = Vec::with_capacity(512 * 1024);
    let mut state = 0x1234_5678_9abc_def0u64;
    for _ in 0..512 * 1024 {
        state = state.wrapping_mul(2_862_933_555_777_941_757).wrapping_add(3_037_000_493);
        expected.push((state >> 56) as u8);
    }

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, &expected).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "3",
            "--bit-rot-buffer-pct",
            "5",
            "--block-size",
            "4K",
            "--chunk-size",
            "4K",
            "--envelope-size",
            "1M",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("bit-rot buffer 5%"));

    let volume_paths = vec![numbered_volume_path(&output_base, 0), numbered_volume_path(&output_base, 1), numbered_volume_path(&output_base, 2)];
    for path in &volume_paths {
        assert!(path.exists(), "{} should exist", path.display());
    }
    let (corrupted_blocks, payload_blocks) = zero_deterministic_payload_blocks(&volume_paths, 4);
    assert!(corrupted_blocks * 100 <= payload_blocks * 5, "test must stay within the configured bit-rot buffer");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_paths[0].to_str().unwrap(),
            volume_paths[1].to_str().unwrap(),
            volume_paths[2].to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("(3 volume(s), 1 file(s))"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            volume_paths[0].to_str().unwrap(),
            "--volume",
            volume_paths[1].to_str().unwrap(),
            "--volume",
            volume_paths[2].to_str().unwrap(),
            "bitrot.bin",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));

    assert_eq!(fs::read(output.join("bitrot.bin")).unwrap(), expected);
}

#[test]
fn cli_extract_reports_missing_archive_path_and_lists_missing_paths() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "missing.txt"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("missing archive path: missing.txt"));
}

#[test]
fn cli_extract_stdout_requires_exactly_one_path() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("missing-key.hex");
    let archive = temp.path().join("missing-archive.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap()])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains("--stdout requires exactly one archive path"))
        .stderr(predicate::str::contains("failed to read").not());

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "hello.txt", "hello.txt"])
        .assert()
        .code(16)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("unsupported-feature"))
        .stderr(predicate::str::contains("--stdout requires exactly one archive path"))
        .stderr(predicate::str::contains("failed to read").not());
}

#[test]
fn cli_extract_dry_run_conflicts_with_stdout() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--dry-run", "--stdout", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(2)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn cli_extract_wrong_key_fails_with_stable_category() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let bad_key = temp.path().join("bad.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&bad_key, BAD_KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", bad_key.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(10)
        .stderr(predicate::str::contains("wrong-key"));
}

#[test]
fn cli_extract_corrupt_archive_reports_corruption() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    let mut bytes = fs::read(&archive).unwrap();
    corrupt_first_record_of_kind(&mut bytes, BlockKind::PayloadData);
    fs::write(&archive, bytes).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("corrupt-payload"));
}

#[test]
fn cli_extract_without_overwrite_when_destination_exists_is_rejected() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();
    fs::create_dir(&output).unwrap();
    fs::write(output.join("hello.txt"), b"existing\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));
}

#[test]
fn cli_extract_unsafe_path_is_rejected_for_stdout() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--stdout", archive.to_str().unwrap(), "../outside.txt"])
        .assert()
        .code(13)
        .stderr(predicate::str::contains("unsafe-path"));
}

#[test]
fn cli_extract_missing_bootstrap_file_is_an_io_error() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    let missing = temp.path().join("sample.tzap.bootstrap");

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--bootstrap-out",
            missing.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&missing).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--bootstrap", missing.to_str().unwrap(), archive.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(3)
        .stderr(predicate::str::contains("failed to read bootstrap sidecar"));
}

#[test]
fn cli_extract_missing_volume_tolerates_recovery_when_loss_tolerance_allows() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output_base = temp.path().join("recoverable.tzap");
    let output = temp.path().join("out");
    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"recovery check\n").unwrap();

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
        .success();
    fs::remove_file(&v1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), v0.to_str().unwrap(), "hello.txt"])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));
}

#[test]
fn cli_extract_missing_volume_without_tolerance_is_reported_as_corruption() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let output_base = temp.path().join("unrecoverable.tzap");
    let output = temp.path().join("out");
    let v0 = numbered_volume_path(&output_base, 0);
    let v1 = numbered_volume_path(&output_base, 1);
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, vec![0x42u8; 1_000_000]).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--volumes",
            "2",
            "--volume-loss-tolerance",
            "0",
            "--bit-rot-buffer-pct",
            "0",
            "-o",
            output_base.to_str().unwrap(),
            input.to_str().unwrap(),
        ])
        .assert()
        .success();
    fs::remove_file(&v0).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), v1.to_str().unwrap(), "hello.txt"])
        .assert()
        .code(11)
        .stderr(predicate::str::contains("missing-volume"));
}

#[test]
fn cli_extract_dry_run_prints_planned_members_and_rejects_missing_selection() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("hello.txt");
    let archive = temp.path().join("sample.tzap");
    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, b"payload\n").unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--dry-run",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            temp.path().join("out").to_str().unwrap(),
            archive.to_str().unwrap(),
            "hello.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extract dry-run summary"))
        .stderr(predicate::str::contains("hello.txt"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--dry-run", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap(), "missing.txt"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("missing archive path: missing.txt"));
}

#[test]
fn cli_extract_summary_reports_counts() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input_root = temp.path().join("input");
    let archive = temp.path().join("sample.tzap");
    let output = temp.path().join("out");

    fs::create_dir_all(&input_root).unwrap();
    fs::write(input_root.join("a.txt"), b"a\n").unwrap();
    fs::write(input_root.join("b.txt"), b"b\n").unwrap();
    fs::write(&keyfile, KEY_HEX).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input_root.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "--directory",
            output.to_str().unwrap(),
            archive.to_str().unwrap(),
            "input/a.txt",
            "input/b.txt",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 2 file(s)"));
}

#[test]
fn cli_extract_preserves_crlf_payload_bytes() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    let input = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let output = temp.path().join("out");
    let expected = b"line1\r\nline2\r\n";

    fs::write(&keyfile, KEY_HEX).unwrap();
    fs::write(&input, expected).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", output.to_str().unwrap(), archive.to_str().unwrap(), "payload.txt"])
        .assert()
        .success();

    assert_eq!(fs::read(output.join("payload.txt")).unwrap(), expected);
}

#[test]
fn cli_extract_various_loss_tolerance_redundancy_and_bit_rot_levels() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let input = temp.path().join("payload.bin");
    let payload_bytes: Vec<u8> = (0..500_000).map(|i| (i % 251) as u8).collect();
    fs::write(&input, &payload_bytes).unwrap();

    // Test volume loss tolerance counts: 1, 2 (out of 4 volumes)
    for tolerance_count in [1, 2] {
        let output_base = temp.path().join(format!("archive_tol_{tolerance_count}.tzap"));
        let out_dir = temp.path().join(format!("out_tol_{tolerance_count}"));

        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "create",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "--volumes",
                "4",
                "--volume-loss-tolerance",
                &tolerance_count.to_string(),
                "--bit-rot-buffer-pct",
                "10",
                "-o",
                output_base.to_str().unwrap(),
                input.to_str().unwrap(),
            ])
            .assert()
            .success();

        // 1. Verify clean extraction without missing volumes
        Command::cargo_bin("tzap")
            .unwrap()
            .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "-C", out_dir.to_str().unwrap(), numbered_volume_path(&output_base, 0).to_str().unwrap()])
            .assert()
            .success();
        assert_eq!(fs::read(out_dir.join("payload.bin")).unwrap(), payload_bytes);

        // 2. Corrupt one byte in a payload volume and test bit-rot recovery
        let vol1 = numbered_volume_path(&output_base, 1);
        let mut vol1_bytes = fs::read(&vol1).unwrap();
        let flip_idx = vol1_bytes.len() / 2;
        vol1_bytes[flip_idx] ^= 0xff;
        fs::write(&vol1, &vol1_bytes).unwrap();

        let out_corrupt_dir = temp.path().join(format!("out_corrupt_{tolerance_count}"));
        Command::cargo_bin("tzap")
            .unwrap()
            .args([
                "extract",
                "--keyfile",
                keyfile.to_str().unwrap(),
                "-C",
                out_corrupt_dir.to_str().unwrap(),
                numbered_volume_path(&output_base, 0).to_str().unwrap(),
            ])
            .assert()
            .success();
        assert_eq!(fs::read(out_corrupt_dir.join("payload.bin")).unwrap(), payload_bytes);
    }
}

#[test]
fn cli_extract_cross_os_restore_policy_matrix() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("key.hex");
    fs::write(&keyfile, KEY_HEX).unwrap();

    let input = temp.path().join("doc.txt");
    fs::write(&input, b"cross-os policy content\n").unwrap();

    let archive = temp.path().join("cross_os.tzap");
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), input.to_str().unwrap()])
        .assert()
        .success();

    for policy in ["content", "portable", "same-os"] {
        let out_dir = temp.path().join(format!("out_policy_{policy}"));
        Command::cargo_bin("tzap")
            .unwrap()
            .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--restore", policy, "-C", out_dir.to_str().unwrap(), archive.to_str().unwrap()])
            .assert()
            .success();

        assert_eq!(fs::read(out_dir.join("doc.txt")).unwrap(), b"cross-os policy content\n");
    }
}

/// A real capture -> archive -> restore round trip for times, which is what the
/// port of zmanager's `preserves_all_metadata_in_tzap_round_trip` lost: that
/// test drove the whole path and compared the restored tree, while the version
/// kept here only asserted what capture produced.
///
/// Nothing below the capture layer was covered end to end, which is how three
/// separate timestamp conversions disagreed at once -- a producer on one
/// convention, a parser on another, and a restore path on a third -- while every
/// test stayed green. Pre-epoch times are the case that distinguishes them;
/// a positive mtime is identical under all three.
#[cfg(unix)]
#[test]
fn cli_round_trip_restores_pre_epoch_times_exactly() {
    fn set_times(path: &std::path::Path, seconds: i64, nanoseconds: i64) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        let raw = CString::new(path.as_os_str().as_bytes()).unwrap();
        let times = [libc::timespec { tv_sec: seconds, tv_nsec: nanoseconds }, libc::timespec { tv_sec: seconds, tv_nsec: nanoseconds }];
        // SAFETY: `raw` is NUL-terminated and `times` holds exactly two entries.
        let code = unsafe { libc::utimensat(libc::AT_FDCWD, raw.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(code, 0, "failed to set times on {}: {}", path.display(), std::io::Error::last_os_error());
    }

    fn observed_times(path: &std::path::Path) -> (i64, i64) {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.mtime(), metadata.mtime_nsec())
    }

    // `(-2, 750_000_000)` is 1.25s before the epoch and encodes as `-1.25`.
    // A conversion applied twice lands on `-2.75`; one skipped lands on `-2.75`
    // in the other direction. Only the exact instant passes.
    for (seconds, nanoseconds) in [(-2i64, 750_000_000i64), (-5, 0), (-3, 250_000_000), (1_700_000_000, 123_456_789)] {
        let temp = tempdir().unwrap();
        let input = temp.path().join("dated.txt");
        let archive = temp.path().join("dated.tzap");
        let output = temp.path().join("out");
        fs::write(&input, b"dated payload\n").unwrap();
        set_times(&input, seconds, nanoseconds);

        // Some filesystems cannot hold the exact value; compare against what the
        // source actually ended up with, so this tests the round trip and not the
        // host's timestamp resolution.
        let expected = observed_times(&input);

        Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), input.to_str().unwrap()]).assert().success();
        Command::cargo_bin("tzap").unwrap().args(["extract", "-C", output.to_str().unwrap(), archive.to_str().unwrap()]).assert().success();

        let restored = output.join("dated.txt");
        assert_eq!(fs::read(&restored).unwrap(), b"dated payload\n");
        assert_eq!(observed_times(&restored), expected, "mtime round trip for ({seconds}, {nanoseconds})");
    }
}

/// The same instants through `tzap list`, which renders the stored value rather
/// than re-reading the filesystem.
///
/// `Display` wrote the two struct fields literally, so a pre-epoch time listed
/// as `-2.75` for an archive holding `-1.25`. The archive was right and the
/// listing was wrong, which is the harder version of the bug to notice.
#[cfg(unix)]
#[test]
fn cli_list_renders_pre_epoch_times_as_the_archive_stores_them() {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let temp = tempdir().unwrap();
    let input = temp.path().join("dated.txt");
    let archive = temp.path().join("dated.tzap");
    fs::write(&input, b"dated payload\n").unwrap();

    let raw = CString::new(input.as_os_str().as_bytes()).unwrap();
    let times = [libc::timespec { tv_sec: -2, tv_nsec: 750_000_000 }, libc::timespec { tv_sec: -2, tv_nsec: 750_000_000 }];
    // SAFETY: `raw` is NUL-terminated and `times` holds exactly two entries.
    assert_eq!(unsafe { libc::utimensat(libc::AT_FDCWD, raw.as_ptr(), times.as_ptr(), 0) }, 0);

    use std::os::unix::fs::MetadataExt as _;
    let source = fs::symlink_metadata(&input).unwrap();
    if (source.mtime(), source.mtime_nsec()) != (-2, 750_000_000) {
        return; // the filesystem cannot hold the instant this test is about
    }

    Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), input.to_str().unwrap()]).assert().success();
    let listed = Command::cargo_bin("tzap").unwrap().args(["list", "--long", archive.to_str().unwrap()]).assert().success().get_output().stdout.clone();
    let listed = String::from_utf8_lossy(&listed);

    assert!(listed.contains("-1.25"), "listing must show the instant the archive holds, got: {listed}");
    assert!(!listed.contains("-2.75"), "listing must not show the raw timespec fields, got: {listed}");
}

/// Owner and group *names* reach the archive, not just the numeric ids.
///
/// §16.7.1 and §16.18.1 both call for them, and zmanager's round-trip test has
/// always asserted them. This host never resolved them at all -- it passed
/// `uname: None`/`gname: None` at every call site -- until the capture moved to
/// tzap-core. Nothing here proved the fix reached an actual archive, so a
/// regression to the old behaviour would have been invisible on this side.
#[cfg(unix)]
#[test]
fn cli_archive_carries_resolved_owner_and_group_names() {
    let temp = tempdir().unwrap();
    let input = temp.path().join("owned.txt");
    let archive = temp.path().join("owned.tzap");
    fs::write(&input, b"owned payload\n").unwrap();

    Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), input.to_str().unwrap()]).assert().success();
    let listed = Command::cargo_bin("tzap").unwrap().args(["list", "--long", archive.to_str().unwrap()]).assert().success().get_output().stdout.clone();
    let listed = String::from_utf8_lossy(&listed);
    let row = listed.lines().find(|line| line.ends_with("owned.txt")).expect("the member must be listed");
    let columns: Vec<&str> = row.split('\t').collect();

    // size, kind, mode, mtime, created, accessed, uid, gid, uname, gname, ...
    let (uid, gid, uname, gname) = (columns[6], columns[7], columns[8], columns[9]);
    assert_ne!(uid, "null", "uid must be recorded");
    assert_ne!(gid, "null", "gid must be recorded");
    assert_ne!(uname, "null", "owner name must be resolved, not left absent: {row}");
    assert_ne!(gname, "null", "group name must be resolved, not left absent: {row}");

    // The name is a label; §16.7.1 requires it never to change the numeric
    // identity, which is what restore actually applies.
    use std::os::unix::fs::MetadataExt as _;
    let source = fs::symlink_metadata(&input).unwrap();
    assert_eq!(uid.parse::<u32>().unwrap(), source.uid());
    assert_eq!(gid.parse::<u32>().unwrap(), source.gid());
}

// ---------------------------------------------------------------------------
// Comprehensive metadata round trip, ported from zmanager's
// `preserves_all_metadata_in_tzap_round_trip`.
//
// That test is the best-exercised metadata fixture across the two projects and
// it drives the whole path: build a tree carrying every metadata class the host
// supports, archive it, read the listing back, extract under each restore
// policy, and compare the restored tree against the source on disk.
//
// The version that reached tzap-core asserted only what *capture* produced, on
// macOS alone. Nothing compared the restored tree, which is why an encode bug, a
// parse bug and two separate restore bugs all coexisted with a green suite.
// These drive the real binary, so the writer, the reader and the OS restore
// paths are all in scope on every platform.
// ---------------------------------------------------------------------------

/// The metadata the host under test can actually set, so each platform asserts
/// what it supports rather than skipping wholesale.
struct MetadataFixture {
    root: PathBuf,
    file: PathBuf,
    directory: PathBuf,
    #[cfg(unix)]
    link: PathBuf,
    payload: Vec<u8>,
}

fn build_metadata_fixture(root: &Path) -> MetadataFixture {
    let file = root.join("data.bin");
    let directory = root.join("folder");
    let payload = b"round-trip payload".to_vec();
    fs::create_dir_all(root).unwrap();
    fs::write(&file, &payload).unwrap();
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("child.txt"), b"child payload").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o750)).unwrap();
    }
    #[cfg(unix)]
    let link = {
        let link = root.join("link.txt");
        std::os::unix::fs::symlink("data.bin", &link).unwrap();
        link
    };

    // Extended attributes, where the host has them. A `user.`/`com.` name is
    // restorable without privilege on both platforms that support xattrs.
    #[cfg(target_os = "linux")]
    {
        xattr::set(&file, "user.tzap.test", b"file metadata").unwrap();
        xattr::set(&directory, "user.tzap.test", b"directory metadata").unwrap();
    }
    #[cfg(target_os = "macos")]
    {
        xattr::set(&file, "com.tzap.test", b"file metadata").unwrap();
        xattr::set(&directory, "com.tzap.test", b"directory metadata").unwrap();
        xattr::set(&file, "com.apple.FinderInfo", &[0x5a; 32]).unwrap();
        xattr::set(&directory, "com.apple.FinderInfo", &[0x5b; 32]).unwrap();
        // Deliberately larger than the inline PAX budget, so the resource fork
        // takes the streamed auxiliary path. §16.18.2's corpus names this case.
        fs::write(file.join("..namedfork/rsrc"), vec![0x6b; 2 * 1024 * 1024 + 31]).unwrap();
        let _ = std::process::Command::new("/bin/chmod").args(["+a", "everyone deny delete"]).arg(&file).status();
        let _ = std::process::Command::new("/usr/bin/chflags").arg("hidden").arg(&file).status();
    }
    #[cfg(windows)]
    {
        // An alternate data stream is the Windows metadata class that travels as
        // a streamed auxiliary, which is exactly the path that had no host-side
        // reader outside tzap-cli.
        let mut stream = file.clone().into_os_string();
        stream.push(":tzap-test");
        fs::write(PathBuf::from(stream), b"alternate stream payload").unwrap();
    }

    MetadataFixture {
        root: root.to_path_buf(),
        file,
        directory,
        #[cfg(unix)]
        link,
        payload,
    }
}

fn create_archive(source: &Path, archive: &Path) {
    Command::cargo_bin("tzap").unwrap().args(["create", "--no-encryption", "-o", archive.to_str().unwrap(), source.to_str().unwrap()]).assert().success();
}

fn extract_archive(archive: &Path, destination: &Path, policy: &str, allow_degraded: bool) -> bool {
    let mut command = Command::cargo_bin("tzap").unwrap();
    command.args(["extract", "-C", destination.to_str().unwrap(), "--restore", policy]);
    if allow_degraded {
        command.arg("--allow-degraded");
    }
    command.arg(archive.to_str().unwrap()).assert().try_success().is_ok()
}

/// Every metadata class the host supports, captured, listed, restored, compared.
#[test]
fn cli_comprehensive_metadata_round_trip_preserves_every_supported_class() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("tree");
    let archive = temp.path().join("tree.tzap");
    let fixture = build_metadata_fixture(&source);

    create_archive(&fixture.root, &archive);

    // --- the listing describes what was captured -------------------------
    let listed = Command::cargo_bin("tzap").unwrap().args(["list", "--long", archive.to_str().unwrap()]).assert().success().get_output().stdout.clone();
    let listed = String::from_utf8_lossy(&listed);
    let row = |suffix: &str| -> Vec<String> {
        listed
            .lines()
            .find(|line| line.ends_with(suffix))
            .unwrap_or_else(|| panic!("no listing row for {suffix}; listing was:\n{listed}"))
            .split('\t')
            .map(str::to_owned)
            .collect()
    };
    // size, kind, mode, mtime, created, accessed, uid, gid, uname, gname, attributes, link_target, path
    let file_row = row("data.bin");
    assert_eq!(file_row[0].parse::<u64>().unwrap(), fixture.payload.len() as u64, "file size");
    assert_eq!(file_row[1], "file", "file kind");
    assert_ne!(file_row[3], "null", "mtime must be recorded");
    assert_ne!(file_row[4], "null", "creation time must be recorded (ctime fallback where there is no birth time)");
    assert_ne!(file_row[5], "null", "access time must be recorded");

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let source_metadata = fs::symlink_metadata(&fixture.file).unwrap();
        // `tzap list --long` prints the mode as a decimal u32.
        assert_eq!(file_row[2].parse::<u32>().unwrap() & 0o7777, 0o640, "file mode");
        assert_eq!(file_row[6].parse::<u32>().unwrap(), source_metadata.uid(), "uid");
        assert_eq!(file_row[7].parse::<u32>().unwrap(), source_metadata.gid(), "gid");
        assert_ne!(file_row[8], "null", "owner name must be resolved from the uid");
        assert_ne!(file_row[9], "null", "group name must be resolved from the gid");

        let directory_row = row("folder");
        assert_eq!(directory_row[1], "directory", "directory kind");
        assert_eq!(directory_row[6], file_row[6], "directory uid");
        assert_eq!(directory_row[8], file_row[8], "directory owner name");

        let link_row = row("link.txt");
        assert_eq!(link_row[1], "symlink", "symlink kind");
        assert_eq!(link_row[11], "data.bin", "symlink target");
    }

    // --- portable restore: payload, modes, times, and NO native metadata --
    let portable = temp.path().join("portable-extract");
    assert!(extract_archive(&archive, &portable, "portable", false), "portable extraction must accept native metadata it will not apply");
    let restored_root = portable.join("tree");
    assert_eq!(fs::read(restored_root.join("data.bin")).unwrap(), fixture.payload);
    assert!(restored_root.join("folder").is_dir());
    assert_eq!(fs::read(restored_root.join("folder/child.txt")).unwrap(), b"child payload");

    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        assert_eq!(fs::symlink_metadata(restored_root.join("data.bin")).unwrap().permissions().mode() & 0o7777, 0o640, "restored file mode");
        assert_eq!(fs::symlink_metadata(restored_root.join("folder")).unwrap().permissions().mode() & 0o7777, 0o750, "restored directory mode");
        assert_eq!(fs::read_link(restored_root.join("link.txt")).unwrap(), Path::new("data.bin"), "restored symlink target");

        // The bug class that had no coverage: the restored instant must equal
        // the source instant, nanoseconds included.
        let restored = fs::symlink_metadata(restored_root.join("data.bin")).unwrap();
        let source_metadata = fs::symlink_metadata(&fixture.file).unwrap();
        assert_eq!((restored.mtime(), restored.mtime_nsec()), (source_metadata.mtime(), source_metadata.mtime_nsec()), "restored mtime must match exactly");
        let _ = &fixture.link;
    }
    // Portable restore must not apply native metadata.
    #[cfg(target_os = "linux")]
    assert_eq!(xattr::get(restored_root.join("data.bin"), "user.tzap.test").unwrap(), None, "portable restore must not apply native xattrs");
    #[cfg(target_os = "macos")]
    assert_eq!(xattr::get(restored_root.join("data.bin"), "com.tzap.test").unwrap(), None, "portable restore must not apply native xattrs");

    // --- same-OS restore: the native classes come back --------------------
    let native = temp.path().join("native-extract");
    // Linux birth time is captured where available but is not assignable by the
    // kernel, so that platform needs the degraded allowance to restore natively.
    let allow_degraded = cfg!(target_os = "linux");
    assert!(extract_archive(&archive, &native, "same-os", allow_degraded), "same-OS extraction must succeed");
    let native_root = native.join("tree");
    assert_eq!(fs::read(native_root.join("data.bin")).unwrap(), fixture.payload);

    #[cfg(target_os = "linux")]
    {
        assert_eq!(xattr::get(native_root.join("data.bin"), "user.tzap.test").unwrap().as_deref(), Some(b"file metadata".as_slice()));
        assert_eq!(xattr::get(native_root.join("folder"), "user.tzap.test").unwrap().as_deref(), Some(b"directory metadata".as_slice()));
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::macos::fs::MetadataExt as _;
        assert_eq!(xattr::get(native_root.join("data.bin"), "com.tzap.test").unwrap().as_deref(), Some(b"file metadata".as_slice()));
        assert_eq!(xattr::get(native_root.join("folder"), "com.tzap.test").unwrap().as_deref(), Some(b"directory metadata".as_slice()));
        assert_eq!(xattr::get(native_root.join("data.bin"), "com.apple.FinderInfo").unwrap().as_deref(), Some([0x5a; 32].as_slice()));
        assert_eq!(xattr::get(native_root.join("folder"), "com.apple.FinderInfo").unwrap().as_deref(), Some([0x5b; 32].as_slice()));
        // The streamed auxiliary path, end to end.
        assert_eq!(fs::read(native_root.join("data.bin").join("..namedfork/rsrc")).unwrap(), vec![0x6b; 2 * 1024 * 1024 + 31], "resource fork");
        assert_eq!(fs::metadata(native_root.join("data.bin")).unwrap().st_flags(), fs::metadata(&fixture.file).unwrap().st_flags(), "Darwin flags");
        assert_eq!(
            (fs::metadata(native_root.join("data.bin")).unwrap().st_birthtime(), fs::metadata(native_root.join("data.bin")).unwrap().st_birthtime_nsec()),
            (fs::metadata(&fixture.file).unwrap().st_birthtime(), fs::metadata(&fixture.file).unwrap().st_birthtime_nsec()),
            "birth time"
        );
        let acl = std::process::Command::new("/bin/ls").args(["-lde"]).arg(native_root.join("data.bin")).output().unwrap();
        if String::from_utf8_lossy(&std::process::Command::new("/bin/ls").args(["-lde"]).arg(&fixture.file).output().unwrap().stdout)
            .contains("everyone deny delete")
        {
            assert!(String::from_utf8_lossy(&acl.stdout).contains("everyone deny delete"), "native ACL must be restored");
        }
    }
    #[cfg(windows)]
    {
        let alternate = |base: &Path| {
            let mut stream = base.to_path_buf().into_os_string();
            stream.push(":tzap-test");
            PathBuf::from(stream)
        };
        // Against the source, not a literal: this is the streamed-auxiliary path
        // that had no reader outside tzap-cli, so it must survive byte for byte.
        assert_eq!(
            fs::read(alternate(&native_root.join("data.bin"))).unwrap(),
            fs::read(alternate(&fixture.file)).unwrap(),
            "alternate data stream must be restored"
        );
    }

    let _ = &fixture.directory;
}
