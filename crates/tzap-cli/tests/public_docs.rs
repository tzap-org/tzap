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
fn readme_documents_required_workflows() {
    let readme = read_workspace_file("README.md");

    assert!(readme.contains("# tzap - the only open source archive you need"));
    assert!(readme.contains("Backups should survive real life."));
    assert!(readme.contains("## Why people choose tzap"));
    assert!(readme.contains("## Try it in two minutes"));
    assert!(readme.contains("## Recovery in plain English"));
    assert!(readme.contains("One command. One archive."));
    assert!(!readme.contains("## Quick start (raw key)"));
    assert!(!readme.contains("## Safety notes"));
    assert!(!readme.contains("## Exit codes"));
    assert!(!readme.contains("## Known limitations"));

    assert!(readme.contains("public-docs/tzap-installation.md"));
    assert!(readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(readme.contains("public-docs/tzap-development.md"));
    assert!(readme.contains("tzap create --password-stdin"));
    assert!(readme.contains("--volumes 3"));
    assert!(readme.contains("--volume-loss-tolerance 1"));
}

#[test]
fn readme_has_exit_code_and_platform_sections() {
    let install = read_workspace_file("public-docs/tzap-installation.md");
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");

    assert!(install.contains("Supported target artifacts:"));
    assert!(install.contains("| Linux x86_64 static/musl |"));
    assert!(install.contains("| Linux aarch64 static/musl |"));
    assert!(install.contains("| Windows x86_64 |"));
    assert!(install.contains("| Windows aarch64 |"));

    assert!(reference.contains("| 2 | usage | Invalid args / command-line usage |"));
    assert!(reference.contains("| 10 | wrong-key | Wrong passphrase or key for archive |"));
    assert!(reference
        .contains("| 16 | unsupported-feature | Unsupported archive feature or writer shape |"));
}

#[test]
fn public_reference_file_exists_and_covers_commands() {
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let security = read_workspace_file("public-docs/tzap-security-model.md");
    let recovery = read_workspace_file("public-docs/tzap-recovery-matrix.md");
    let benchmarks = read_workspace_file("public-docs/tzap-benchmark-guide.md");
    let installation = read_workspace_file("public-docs/tzap-installation.md");
    let development = read_workspace_file("public-docs/tzap-development.md");
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");
    let gitignore = read_workspace_file(".gitignore");

    for command in [
        "create",
        "extract",
        "list",
        "verify",
        "keygen",
        "signing-keygen",
    ] {
        assert!(reference.contains(&format!("## Command: {command}")));
    }

    assert!(reference.contains("--password-stdin"));
    assert!(reference.contains("--signing-key"));
    assert!(reference.contains("--signing-cert"));
    assert!(reference.contains("--trusted-public-key"));
    assert!(reference.contains("--trusted-ca-cert"));
    assert!(reference.contains("--public-no-key"));
    assert!(reference.contains("--volume"));
    assert!(reference.contains("--dry-run"));
    assert!(reference.contains("JSON output"));
    assert!(reference.contains("For selected-file workflows, use a file-backed archive path"));
    assert!(reference.contains("the random-access reader uses the authenticated index"));
    assert!(reference.contains("tzap-operational-boundaries.md"));
    assert!(reference.contains("## Operational boundaries"));
    assert!(boundaries.contains("Writer shape validation"));
    assert!(boundaries.contains("unsupported-feature"));
    assert!(boundaries.contains("Bootstrap sidecars and multi-volume inputs"));
    assert!(boundaries.contains("Multi-volume recovery budget"));
    assert!(security.contains("Plain-English promise"));
    assert!(security.contains("What is encrypted"));
    assert!(security.contains("Recovery is for accidents"));
    assert!(recovery.contains("Quick matrix"));
    assert!(recovery.contains("What \"5% bit-rot buffer\" means"));
    assert!(benchmarks.contains("What to measure"));
    assert!(benchmarks.contains("Suggested comparison set"));
    assert!(installation.contains("From GitHub release assets"));
    assert!(development.contains("Project layout"));
    assert!(development.contains("Format overview"));
    assert!(development.contains("Library usage"));

    assert!(root_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(root_readme.contains("public-docs/tzap-installation.md"));
    assert!(root_readme.contains("public-docs/tzap-security-model.md"));
    assert!(root_readme.contains("public-docs/tzap-recovery-matrix.md"));
    assert!(root_readme.contains("public-docs/tzap-benchmark-guide.md"));
    assert!(root_readme.contains("public-docs/tzap-development.md"));
    assert!(cli_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(cli_readme.contains("public-docs/tzap-security-model.md"));
    assert!(cli_readme.contains("public-docs/tzap-recovery-matrix.md"));
    assert!(cli_readme.contains("public-docs/tzap-benchmark-guide.md"));
    assert!(gitignore.contains("/docs/"));
    assert!(gitignore.contains("/implementation-docs/"));
    assert!(!gitignore.contains("/public-docs/"));
}

#[test]
fn public_spec_file_remains_linked() {
    let spec = read_workspace_file("specs/tzap-format-revisedv41.md");
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");

    assert!(spec.contains("### 28.1 Test corpus additions through v0.41"));
    assert!(spec.contains("## 29. Conformance"));
    assert!(root_readme.contains("specs/tzap-format-revisedv41.md"));
    assert!(cli_readme.contains("specs/tzap-format-revisedv41.md"));
}

#[test]
fn readme_passphrase_quickstart_commands_execute() {
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
fn readme_raw_key_workflow_commands_execute() {
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
fn readme_multivolume_recovery_example_executes() {
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

    let volume_0 = temp.path().join("project.vol000.tzap");
    let volume_1 = temp.path().join("project.vol001.tzap");

    Command::cargo_bin("tzap")
        .unwrap()
        .args([
            "verify",
            "--keyfile",
            keyfile.to_str().unwrap(),
            volume_0.to_str().unwrap(),
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
fn public_docs_keep_boundaries_out_of_readme_marketing() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let writer = read_workspace_file("crates/tzap-core/src/writer.rs");
    let reader = read_workspace_file("crates/tzap-core/src/reader.rs");
    let cli = read_workspace_file("crates/tzap-cli/src/main.rs");

    assert!(boundaries.contains("Large regular-file input sets are supported"));
    assert!(boundaries.contains("Create outputs are archive files, not stdout"));
    assert!(boundaries.contains("Archive stdin and file paths"));
    assert!(boundaries.contains("Sequential reader and provisional output"));
    assert!(boundaries.contains("tzap list --keyfile project.key"));
    assert!(boundaries.contains("tzap extract --keyfile project.key -C restored -"));
    assert!(!boundaries.contains("current live core stream API is verify-only"));
    assert!(!boundaries.contains("future API, not current CLI behavior"));
    assert!(boundaries.contains("lower-level core writer also exposes a sink API"));
    assert!(writer.contains("sink writer when archive bytes should be delivered incrementally"));
    assert!(reader.contains("not a live provisional-output API"));
    assert!(cli.contains("--output - is not archive stdout"));
    assert!(cli.contains("--bootstrap-out - is not sidecar stdout"));

    assert!(reference
        .contains("`--bootstrap-out`: sidecar output path for single-volume archives only"));
    assert!(reference.contains("`-` is archive stdin"));
    assert!(reference.contains("`-o -` is not archive stdout"));
    assert!(reference.contains("append-only sink or multipart-upload create mode is exposed"));

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
fn public_docs_pin_tar_metadata_profile() {
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

#[test]
fn traceability_materials_live_under_requested_folder_and_cover_claim_gates() {
    let root = workspace_root()
        .join("implmentation-docs")
        .join("traceability");
    assert!(root.is_dir());

    let index = read_workspace_file("implmentation-docs/traceability/README.md");
    let v41 = read_workspace_file("implmentation-docs/traceability/v41-core-traceability.md");
    let signing =
        read_workspace_file("implmentation-docs/traceability/signing-plugin-traceability.md");
    let runbook = read_workspace_file("implmentation-docs/traceability/verification-runbook.md");

    assert!(index.contains("v41-compliant for the documented supported archive workflows"));
    assert!(index.contains("implmentation-docs/traceability"));
    assert!(index.contains("cargo fmt --check"));
    assert!(index.contains("cargo clippy --workspace --all-targets -- -D warnings"));
    assert!(index.contains("cargo test --workspace"));
    assert!(index.contains("cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked"));
    assert!(index.contains("cargo audit"));

    for required in [
        "V41-001",
        "V41-014",
        "V41-019",
        "V41-022",
        "Unsupported and documented",
        "No implementation gap is recorded",
    ] {
        assert!(
            v41.contains(required),
            "missing v41 traceability marker {required}"
        );
    }

    for required in [
        "SIGN-001",
        "SIGN-004",
        "SIGN-011",
        "X.509",
        "Ed25519",
        "Signing profile boundaries",
    ] {
        assert!(
            signing.contains(required),
            "missing signing traceability marker {required}"
        );
    }

    for required in [
        "Required local gate",
        "Bounded fuzz extension",
        "Dependency audit",
        "Traceability audit",
        "Current record",
    ] {
        assert!(
            runbook.contains(required),
            "missing runbook traceability marker {required}"
        );
    }
}
