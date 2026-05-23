use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

const PASS_PHRASE: &str = "docs-passphrase\n";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn workspace_file(path: &str) -> PathBuf {
    workspace_root().join("..").join(path)
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_file(path)).unwrap()
}

fn write_file(path: &Path, data: &[u8]) {
    fs::write(path, data).unwrap();
}

#[test]
fn milestone11_readme_documents_required_workflows() {
    let readme = read_workspace_file("README.md");

    assert!(readme.contains("## Quick start (passphrase mode)"));
    assert!(readme.contains("## Quick start (raw key)"));
    assert!(readme.contains("## Multi-volume workflow (recoverable)"));
    assert!(readme.contains("## Safety notes"));
    assert!(readme.contains("## Exit codes"));
    assert!(!readme.contains("## Known limitations"));

    assert!(readme.contains("tzap create --password-stdin"));
    assert!(readme.contains("tzap keygen --output"));
    assert!(readme.contains("tzap create --keyfile project.key"));
    assert!(readme.contains("tzap create --keyfile project.key --volumes"));
}

#[test]
fn milestone11_readme_has_exit_code_and_platform_sections() {
    let readme = read_workspace_file("README.md");

    assert!(readme.contains("Supported target artifacts:"));
    assert!(readme.contains("| Linux x86_64 |"));
    assert!(readme.contains("| Windows x86_64 |"));

    assert!(readme.contains("| 2 | usage | Invalid args / command-line usage |"));
    assert!(readme.contains("| 10 | wrong-key | Wrong passphrase or key for archive |"));
    assert!(readme
        .contains("| 16 | unsupported-feature | Unsupported archive feature or writer shape |"));
}

#[test]
fn milestone11_reference_file_exists_and_covers_commands() {
    let reference = read_workspace_file("docs/tzap-cli-reference.md");

    for command in ["create", "extract", "list", "verify", "keygen"] {
        assert!(reference.contains(&format!("## Command: {command}")));
    }

    assert!(reference.contains("--password-stdin"));
    assert!(reference.contains("--volume"));
    assert!(reference.contains("--dry-run"));
    assert!(reference.contains("JSON output"));
}

#[test]
fn milestone11_readme_passphrase_quickstart_commands_execute() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("project");
    let archive = temp.path().join("backup.tzap");
    let restored = temp.path().join("restored");

    write_file(&source, b"docs passphrase payload\n");

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
            source.to_str().unwrap(),
        ])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("project\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--password-stdin", archive.to_str().unwrap()])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    let payload = Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--password-stdin",
            "--stdout",
            archive.to_str().unwrap(),
            "project",
        ])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(payload, b"docs passphrase payload\n");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "extract",
            "--password-stdin",
            "--directory",
            restored.to_str().unwrap(),
            archive.to_str().unwrap(),
            "project",
        ])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));
    assert_eq!(
        fs::read(restored.join("project")).unwrap(),
        b"docs passphrase payload\n"
    );
}

#[test]
fn milestone11_readme_raw_key_workflow_commands_execute() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("project.key");
    let source = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let restored = temp.path().join("restored");

    write_file(&source, b"raw key payload\n");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "create",
            "--keyfile",
            keyfile.to_str().unwrap(),
            "-o",
            archive.to_str().unwrap(),
            source.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "list",
            "--keyfile",
            keyfile.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("payload.txt\n"));

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
            restored.to_str().unwrap(),
            archive.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        fs::read(restored.join("payload.txt")).unwrap(),
        b"raw key payload\n"
    );
}

#[test]
fn milestone11_readme_multivolume_recovery_example_executes() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("project.key");
    let source = temp.path().join("project.bin");
    let archive_base = temp.path().join("project.tzap");
    let extract_dir = temp.path().join("restored");

    write_file(&source, b"recovery payload\n");
    Command::cargo_bin("tzap")
        .unwrap()
        .args(["keygen", "--output", keyfile.to_str().unwrap()])
        .assert()
        .success();

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
            archive_base.to_str().unwrap(),
            source.to_str().unwrap(),
        ])
        .assert()
        .success();

    let volume_0 = temp.path().join("project.tzap.000");
    let volume_1 = temp.path().join("project.tzap.001");

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
        .stdout(predicate::str::contains("OK (2 volume(s), 1 file(s))"));

    fs::remove_file(&volume_1).unwrap();

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
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
            extract_dir.to_str().unwrap(),
            volume_0.to_str().unwrap(),
            "project.bin",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));
    assert_eq!(
        fs::read(extract_dir.join("project.bin")).unwrap(),
        b"recovery payload\n"
    );
}

#[test]
fn milestone11_reference_file_mentions_unsupported_feature_limits() {
    let reference = read_workspace_file("docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("docs/tzap-operational-boundaries.md");

    assert!(reference.contains("## Operational boundaries"));
    assert!(reference.contains("tzap-operational-boundaries.md"));
    assert!(boundaries.contains("Writer shape validation"));
    assert!(boundaries.contains("unsupported-feature"));
    assert!(boundaries.contains("Bootstrap sidecars and multi-volume inputs"));
    assert!(boundaries.contains("Multi-volume recovery budget"));
    assert!(reference.contains("Global options"));
}

#[test]
fn milestone11_docs_pin_current_g01_boundaries() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("docs/tzap-operational-boundaries.md");
    let implementation_plan = read_workspace_file("docs/tzap-v36-implementation-plan.md");

    assert!(
        implementation_plan.contains("multi-IndexShard emission for large regular-file archives")
    );
    assert!(implementation_plan
        .contains("directory hint shard emission for large regular-file archives"));
    assert!(implementation_plan
        .contains("`tzap create --bootstrap-out FILE` writes the v0.36 bootstrap sidecar"));
    assert!(implementation_plan.contains("single-volume archives"));
    assert!(!implementation_plan.contains("writer layouts not emitted yet"));
    assert!(!implementation_plan
        .contains("explicit M6 rejection guard for archives that would require"));
    assert!(!implementation_plan
        .contains("archives that would require directory hint shards or more than one IndexShard"));

    assert!(boundaries.contains("Large regular-file input sets are supported"));
    assert!(boundaries.contains("multiple\n  IndexShard objects"));
    assert!(
        boundaries.contains("Do not request `--bootstrap-out` while creating multi-volume output")
    );
    assert!(boundaries.contains("Do not combine `--bootstrap` with a multi-volume open input set"));
    assert!(boundaries.contains("Archive paths, not archive stdin"));
    assert!(boundaries.contains("`-`\nas archive stdin"));
    assert!(boundaries.contains("# exit 16: unsupported-feature"));
    assert!(boundaries.contains("# exit 3: io"));
    assert!(boundaries.contains("Empty directory inputs"));
    assert!(boundaries.contains("empty directories\nare omitted"));
    assert!(!boundaries.contains("writer layouts not emitted yet"));

    assert!(reference
        .contains("`--bootstrap-out`: sidecar output path for single-volume archives only"));
    assert!(reference.contains("`-` is not an archive stdin sentinel"));
    assert!(reference.contains("volume-loss tolerance and FEC budget"));

    assert!(!readme.contains("Archive paths, not archive stdin"));
    assert!(!readme.contains("Empty directory inputs"));
    assert!(!readme.contains("writer layouts not emitted yet"));
}

#[test]
fn milestone11_v36_conformance_matrix_covers_section_29_obligations() {
    let matrix = read_workspace_file("docs/tzap-v36-conformance-matrix.md");

    assert!(matrix.contains("## Writer Obligations"));
    assert!(matrix.contains("## Reader Obligations"));
    assert!(matrix.contains(
        "| Obligation ID | Short requirement | Code path | Positive tests | Negative/mutation tests | Status | Notes/follow-up |"
    ));

    for id in 1..=38 {
        assert_matrix_row_count(&matrix, &format!("W{id:02}"), 1);
    }
    for id in 1..=31 {
        assert_matrix_row_count(&matrix, &format!("R{id:02}"), 1);
    }
}

#[test]
fn milestone11_v36_conformance_matrix_uses_reviewable_statuses() {
    let matrix = read_workspace_file("docs/tzap-v36-conformance-matrix.md");
    let allowed = ["`complete`", "`partial`", "`unsupported`", "`deferred`"];
    let vague_evidence_phrases = [
        "smoke tests",
        "corpus tests",
        "parser mutations",
        "mutation cases",
        "tamper tests",
        "metadata cap tests",
        "seekable open tests",
        "wrong-key reader tests",
        "round trips",
        "exact-set mutations",
        "object extent reader mutations",
        "parser mutation tests",
        "parse mutations",
        "version validation",
        "tests in `",
    ];
    let mut checked_rows = 0usize;

    for line in matrix
        .lines()
        .filter(|line| line.starts_with("| W") || line.starts_with("| R"))
    {
        let columns: Vec<_> = line.split('|').map(str::trim).collect();
        assert_eq!(columns.len(), 9, "malformed matrix row: {line}");
        let status = columns[6];
        assert!(
            allowed.contains(&status),
            "unreviewable matrix status {status:?} in row: {line}"
        );
        assert_ne!(
            status, "`unknown`",
            "matrix row uses unknown status: {line}"
        );
        checked_rows += 1;
    }

    for phrase in vague_evidence_phrases {
        assert!(
            !matrix.contains(phrase),
            "matrix should cite exact evidence instead of vague phrase {phrase:?}"
        );
    }

    assert_eq!(
        checked_rows,
        38 + 31,
        "unexpected number of conformance obligation rows"
    );
}

fn assert_matrix_row_count(matrix: &str, id: &str, expected: usize) {
    let prefix = format!("| {id} |");
    let actual = matrix
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .count();
    assert_eq!(
        actual, expected,
        "expected {expected} row(s) for {id}, found {actual}"
    );
}
