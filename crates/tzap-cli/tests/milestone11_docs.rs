use std::fs;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

const PASS_PHRASE: &str = "docs-passphrase\n";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path))
        .unwrap()
        .replace("\r\n", "\n")
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

    assert!(readme.contains("public-docs/tzap-cli-reference.md"));
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
fn milestone11_public_reference_file_exists_and_covers_commands() {
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");
    let gitignore = read_workspace_file(".gitignore");

    for command in ["create", "extract", "list", "verify", "keygen"] {
        assert!(reference.contains(&format!("## Command: {command}")));
    }

    assert!(reference.contains("--password-stdin"));
    assert!(reference.contains("--volume"));
    assert!(reference.contains("--dry-run"));
    assert!(reference.contains("JSON output"));
    assert!(reference.contains("tzap-operational-boundaries.md"));
    assert!(reference.contains("## Operational boundaries"));
    assert!(boundaries.contains("Writer shape validation"));
    assert!(boundaries.contains("unsupported-feature"));
    assert!(boundaries.contains("Bootstrap sidecars and multi-volume inputs"));
    assert!(boundaries.contains("Multi-volume recovery budget"));

    assert!(root_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(cli_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(gitignore.contains("/docs/"));
    assert!(gitignore.contains("/implementation-docs/"));
    assert!(!gitignore.contains("/public-docs/"));
}

#[test]
fn milestone11_public_spec_file_remains_linked() {
    let spec = read_workspace_file("specs/tzap-format-revisedv36.md");
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");

    assert!(spec.contains("### 28.1 Test corpus additions"));
    assert!(spec.contains("## 29. Conformance"));
    assert!(root_readme.contains("specs/tzap-format-revisedv36.md"));
    assert!(cli_readme.contains("specs/tzap-format-revisedv36.md"));
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
fn milestone11_public_docs_keep_boundaries_out_of_readme_marketing() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let writer = read_workspace_file("crates/tzap-core/src/writer.rs");
    let reader = read_workspace_file("crates/tzap-core/src/reader.rs");
    let cli = read_workspace_file("crates/tzap-cli/src/main.rs");

    assert!(boundaries.contains("Large regular-file input sets are supported"));
    assert!(boundaries.contains("Create outputs are archive files, not stdout"));
    assert!(boundaries.contains("Archive paths, not archive stdin"));
    assert!(boundaries.contains("Sequential reader and provisional output"));
    assert!(boundaries.contains("in-memory archive artifact builder"));
    assert!(writer.contains("not a sink-based streaming writer"));
    assert!(reader.contains("not a live provisional-output API"));
    assert!(cli.contains("--output - is not archive stdout"));
    assert!(cli.contains("--bootstrap-out - is not sidecar stdout"));

    assert!(reference
        .contains("`--bootstrap-out`: sidecar output path for single-volume archives only"));
    assert!(reference.contains("`-` is not an archive stdin sentinel"));
    assert!(reference.contains("`-o -` is not archive stdout"));
    assert!(reference.contains("No append-only sink or multipart-upload create"));

    let readme_lower = readme.to_lowercase();
    for phrase in [
        "archive stdin",
        "live stdout streaming",
        "append-only sink",
        "multipart sink",
        "cloud/object-store optimized",
        "writer layouts not emitted yet",
    ] {
        assert!(
            !readme_lower.contains(phrase),
            "README must keep operational boundary details out of marketing copy via {phrase:?}"
        );
    }
}

#[test]
fn milestone11_public_docs_pin_tar_metadata_profile() {
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");

    assert!(boundaries.contains("## Tar metadata profile"));
    assert!(boundaries.contains("regular-file tar member groups"));
    assert!(boundaries.contains("local PAX `path`, `linkpath`, and `size` records"));
    assert!(boundaries.contains("local GNU long name and long link records"));
    assert!(boundaries.contains("Mode or mtime application"));
    assert!(boundaries.contains("Global PAX headers and global GNU state are rejected"));
    assert!(reference
        .contains("Unsupported local tar metadata profiles and mode/mtime restoration failures"));
    assert!(reference.contains("Verification reports unsupported local tar metadata profiles"));
}
