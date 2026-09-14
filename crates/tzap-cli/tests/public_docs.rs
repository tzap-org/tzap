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
    fs::read_to_string(workspace_root().join(path)).unwrap().replace("\r\n", "\n")
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
    // `create` exits 4 when it writes a valid archive that is missing something.
    // The code is part of the published contract, so the table has to carry it.
    assert!(reference.contains("| 4 | incomplete-archive |"), "the exit-code table must document incomplete-archive");
    assert!(reference.contains("| 10 | wrong-key | Wrong passphrase or key for archive |"));
    assert!(reference.contains("| 16 | unsupported-feature | Unsupported archive feature or writer shape |"));
}

#[test]
fn public_reference_file_exists_and_covers_commands() {
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let security = read_workspace_file("public-docs/tzap-security-model.md");
    let recovery = read_workspace_file("public-docs/tzap-recovery-matrix.md");
    let benchmarks = read_workspace_file("public-docs/tzap-benchmark-guide.md");
    let benchmark_results = read_workspace_file("public-docs/tzap-benchmark-results.md");
    let installation = read_workspace_file("public-docs/tzap-installation.md");
    let development = read_workspace_file("public-docs/tzap-development.md");
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");
    let gitignore = read_workspace_file(".gitignore");

    for command in ["create", "extract", "list", "verify", "keygen", "signing-keygen", "trust-info"] {
        assert!(reference.contains(&format!("## Command: {command}")));
    }

    assert!(reference.contains("--password-stdin"));
    assert!(reference.contains("--signing-key"));
    assert!(reference.contains("--signing-cert"));
    assert!(reference.contains("--trusted-public-key"));
    assert!(reference.contains("--trusted-ca-cert"));
    assert!(reference.contains("--public-no-key"));
    assert!(reference.contains("embedded official TZAP"));
    assert!(reference.contains("root certificate by default"));
    assert!(reference.contains("tzap trust-info --json"));
    assert!(reference.contains("--volume"));
    assert!(reference.contains("--jobs"));
    assert!(reference.contains("--timings"));
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
    assert!(benchmarks.contains("Public metrics table"));
    assert!(benchmarks.contains("tzap-benchmark-results.md"));
    assert!(benchmarks.contains("Selected-file restore"));
    assert!(benchmarks.contains("Missing volume"));
    assert!(benchmarks.contains("Rotten payload"));
    assert!(benchmarks.contains("Repair data rot"));
    assert!(benchmarks.contains("No repair path"));
    assert!(benchmarks.contains("No repair data"));
    assert!(benchmarks.contains("Archive-native"));
    assert!(benchmarks.contains("External PAR2"));
    assert!(benchmarks.contains("Sidecar risk"));
    assert!(benchmarks.contains("scripts/tzap_benchmark.py"));
    assert!(benchmarks.contains("size-20mb"));
    assert!(benchmarks.contains("size-20gb"));
    assert!(benchmarks.contains("--runs 30"));
    assert!(benchmarks.contains("--recovery-runs 1"));
    assert!(benchmarks.contains("--file-count 64"));
    assert!(benchmarks.contains("--file-count 6000"));
    assert!(benchmarks.contains("--dataset-sizes 1MB,20MB,1GB,20GB"));
    assert!(benchmarks.contains("--dataset-sizes 1GB"));
    assert!(benchmarks.contains("--selected-file-position last"));
    assert!(benchmarks.contains("--selected-file-index 4000"));
    assert!(benchmarks.contains("--tzap-verify-fast"));
    assert!(benchmarks.contains("--benchmark-password tzap-benchmark-password"));
    assert!(benchmarks.contains("--par2-redundancy-pct 5"));
    assert!(benchmarks.contains("--quiet"));
    assert!(benchmarks.contains("--recovery-volumes 3"));
    assert!(benchmarks.contains("--bitrot-corruption-bytes 4096"));
    assert!(benchmarks.contains("Command-line benchmark knobs"));
    assert!(benchmarks.contains("first-file bias"));
    assert!(benchmarks.contains("average timing cells without `+/-` standard"));
    assert!(benchmarks.contains("tzap-no-password-no-bitrot"));
    assert!(benchmarks.contains("human-size columns"));
    assert!(benchmarks.contains("charts/*.svg"));
    assert!(benchmarks.contains("repair-data path"));
    assert!(benchmarks.contains("tar-zstd-age-par2"));
    assert!(benchmarks.contains("PAR2 recovery files"));
    assert!(benchmarks.contains("`zip` | Zip archive with password mode"));
    assert!(benchmarks.contains("`7z` | LZMA2 archive with password"));
    assert!(benchmarks.contains("20 GB uses `--block-size 64K"));
    assert!(benchmark_results.contains("tzap Benchmark Results"));
    assert!(benchmark_results.contains("2.24x faster"));
    assert!(benchmark_results.contains("0.910s"));
    assert!(benchmark_results.contains("0.012s"));
    assert!(benchmark_results.contains("--selected-file-index 4000"));
    assert!(benchmark_results.contains("tzap verify --fast --keyfile bench.key"));
    assert!(benchmark_results.contains("Repair data rot"));
    assert!(benchmark_results.contains("❌ Sidecar risk"));
    assert!(benchmark_results.contains("✅ Recovered"));
    assert!(workspace_root().join("scripts/tzap_benchmark.py").is_file());
    assert!(installation.contains("From GitHub release assets"));
    assert!(development.contains("Project layout"));
    assert!(development.contains("Format overview"));
    assert!(development.contains("Library usage"));

    assert!(root_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(root_readme.contains("public-docs/tzap-installation.md"));
    assert!(root_readme.contains("public-docs/tzap-security-model.md"));
    assert!(root_readme.contains("public-docs/tzap-recovery-matrix.md"));
    assert!(root_readme.contains("public-docs/tzap-benchmark-results.md"));
    assert!(root_readme.contains("public-docs/tzap-development.md"));
    assert!(cli_readme.contains("public-docs/tzap-cli-reference.md"));
    assert!(cli_readme.contains("public-docs/tzap-security-model.md"));
    assert!(cli_readme.contains("public-docs/tzap-recovery-matrix.md"));
    assert!(cli_readme.contains("public-docs/tzap-benchmark-results.md"));
    assert!(gitignore.contains("/docs/"));
    assert!(gitignore.contains("/implementation-docs/"));
    assert!(!gitignore.contains("/public-docs/"));
}

#[test]
fn public_spec_file_remains_linked() {
    let spec = read_workspace_file("specs/tzap-format-revisedv45.md");
    let root_readme = read_workspace_file("README.md");
    let cli_readme = read_workspace_file("crates/tzap-cli/README.md");

    assert!(spec.contains("## 29. Conformance"));
    assert!(spec.contains("## 30. Critical Metadata Recovery and Root Authentication"));
    assert!(root_readme.contains("specs/tzap-format-revisedv45.md"));
    assert!(cli_readme.contains("specs/tzap-format-revisedv45.md"));
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
        .args(["extract", "--password-stdin", "--stdout", archive.to_str().unwrap(), "project"])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    assert_eq!(payload, b"docs passphrase payload\n");

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--password-stdin", "--directory", restored.to_str().unwrap(), archive.to_str().unwrap(), "project"])
        .write_stdin(PASS_PHRASE)
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));
    assert_eq!(fs::read(restored.join("project")).unwrap(), b"docs passphrase payload\n");
}

#[test]
fn readme_raw_key_workflow_commands_execute() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("project.key");
    let source = temp.path().join("payload.txt");
    let archive = temp.path().join("payload.tzap");
    let restored = temp.path().join("restored");

    write_file(&source, b"raw key payload\n");

    Command::cargo_bin("tzap").unwrap().args(["keygen", "--output", keyfile.to_str().unwrap()]).assert().success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["create", "--keyfile", keyfile.to_str().unwrap(), "-o", archive.to_str().unwrap(), source.to_str().unwrap()])
        .assert()
        .success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["list", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("payload.txt\n"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "-C", restored.to_str().unwrap(), archive.to_str().unwrap()])
        .assert()
        .success();
    assert_eq!(fs::read(restored.join("payload.txt")).unwrap(), b"raw key payload\n");
}

#[test]
fn readme_multivolume_recovery_example_executes() {
    let temp = tempdir().unwrap();
    let keyfile = temp.path().join("project.key");
    let source = temp.path().join("project.bin");
    let archive_base = temp.path().join("project.tzap");
    let extract_dir = temp.path().join("restored");

    write_file(&source, b"recovery payload\n");
    Command::cargo_bin("tzap").unwrap().args(["keygen", "--output", keyfile.to_str().unwrap()]).assert().success();

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
        .args(["verify", "--keyfile", keyfile.to_str().unwrap(), volume_0.to_str().unwrap()])
        .assert()
        .success()
        .stdout(predicate::str::contains("(2 volume(s), 1 file(s))"));

    fs::remove_file(&volume_1).unwrap();

    Command::cargo_bin("tzap").unwrap().args(["verify", "--keyfile", keyfile.to_str().unwrap(), volume_0.to_str().unwrap()]).assert().success();

    Command::cargo_bin("tzap")
        .unwrap()
        .args(["extract", "--keyfile", keyfile.to_str().unwrap(), "--directory", extract_dir.to_str().unwrap(), volume_0.to_str().unwrap(), "project.bin"])
        .assert()
        .success()
        .stderr(predicate::str::contains("extracted 1 file(s)"));
    assert_eq!(fs::read(extract_dir.join("project.bin")).unwrap(), b"recovery payload\n");
}

#[test]
fn public_docs_keep_boundaries_out_of_readme_marketing() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let writer = read_workspace_file("crates/tzap-core/src/writer/mod.rs");
    let reader = read_workspace_file("crates/tzap-core/src/reader/mod.rs");
    let create = read_workspace_file("crates/tzap-cli/src/commands/create.rs");

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
    assert!(create.contains("--output - is not archive stdout"));
    assert!(create.contains("--bootstrap-out - is not sidecar stdout"));

    assert!(reference.contains("`--bootstrap-out`: sidecar output path for single-volume archives only"));
    assert!(reference.contains("`-` is archive stdin"));
    assert!(reference.contains("`-o -` is not archive stdout"));
    assert!(reference.contains("append-only sink or multipart-upload create mode is exposed"));

    let readme_lower = readme.to_lowercase();
    for phrase in
        ["archive stdin", "live stdout streaming", "append-only sink", "multipart sink", "cloud/object-store optimized", "writer layouts not emitted yet"]
    {
        assert!(!readme_lower.contains(phrase), "README must keep operational boundary details out of marketing copy via {phrase:?}");
    }
}

#[test]
fn public_docs_pin_tar_metadata_profile() {
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");

    assert!(boundaries.contains("## Tar metadata profile"));
    assert!(boundaries.contains("complete `portable-v1` regular-file,"));
    assert!(boundaries.contains("symlink emission plus the declared Linux native records"));
    assert!(boundaries.contains("Linux project IDs"));
    assert!(boundaries.contains("Linux FIFO/device/whiteout objects"));
    assert!(boundaries.contains("mandatory canonical"));
    assert!(boundaries.contains("streamed"));
    assert!(boundaries.contains("auxiliary hashes"));
    assert!(boundaries.contains("Global PAX/GNU state"));
    assert!(boundaries.contains("Published revision-45 conformance classes"));
    assert!(boundaries.contains("Native capture"));
    assert!(boundaries.contains("Windows auxiliary payloads"));
    assert!(boundaries.contains("Windows comparison with 7-Zip 26.01"));
    assert!(boundaries.contains("Capture parity"));
    assert!(boundaries.contains("SACL when `SeSecurityPrivilege`"));
    assert!(boundaries.contains("raw EFS"));
    assert!(boundaries.contains("Same-OS restore applies"));
    assert!(boundaries.contains("alternate data stream"));
    assert!(reference.contains("--restore {content,portable,same-os,system}"));
    assert!(reference.contains("Verification reports authenticated partial-capture"));
}

#[test]
fn cli_reference_explains_degraded_metadata_diagnostics() {
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");

    assert!(reference.contains("### Reading degraded-metadata diagnostics"));
    assert!(reference.contains("PATH: PROFILE: CLASS: OPERATION/STATUS"));
    assert!(reference.contains("Restore phases are:"));
    assert!(reference.contains("| `1` | Regular files |"));
    assert!(reference.contains("birth time or `btime`"));
    assert!(reference.contains("it does not suppress command"));
    assert!(boundaries.contains("#reading-degraded-metadata-diagnostics"));
}

#[test]
fn traceability_materials_live_under_requested_folder_and_cover_claim_gates() {
    let root = workspace_root().join("public-docs").join("traceability");
    assert!(root.is_dir());

    let index = read_workspace_file("public-docs/traceability/README.md");
    let signing = read_workspace_file("public-docs/traceability/signing-plugin-traceability.md");
    let runbook = read_workspace_file("public-docs/traceability/verification-runbook.md");

    assert!(index.contains("v45-compliant reference implementation"));
    assert!(index.contains("documented supported"));
    assert!(index.contains("Legacy"));
    assert!(index.contains("archives fail closed as unsupported revisions"));
    assert!(index.contains("public-docs/traceability"));
    assert!(index.contains("cargo fmt --check"));
    assert!(index.contains("cargo clippy --workspace --all-targets -- -D warnings"));
    assert!(index.contains("cargo test --workspace"));
    assert!(index.contains("cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked"));
    assert!(index.contains("cargo audit"));

    for required in ["SIGN-001", "SIGN-004", "SIGN-011", "X.509", "Ed25519", "Signing profile boundaries"] {
        assert!(signing.contains(required), "missing signing traceability marker {required}");
    }

    for required in ["Required local gate", "Bounded fuzz extension", "Dependency audit", "Traceability audit", "Current record"] {
        assert!(runbook.contains(required), "missing runbook traceability marker {required}");
    }
}

/// §16.17 requires an implementation to publish its conformance classes, and
/// §16.18 requires the project to publish its required-corpus fixtures before
/// v45 is declared stable. Both are publication obligations, so they are only
/// discharged by a tracked file: `/implementation-docs/` is gitignored, and a
/// working document there reaches nobody.
///
/// This test pins the published document's load-bearing content — the six class
/// rows, and the gap disclosure. The gap section matters most: a future edit
/// that quietly drops it would turn a bounded claim into an unbounded one,
/// which is exactly what the claim boundary in README.md forbids.
/// `AGENTS.md` requires unsupported-feature behavior to be documented in
/// `public-docs/` with concrete examples, expected exit labels, and user
/// actions. `--tar-stdin` accepts regular files, directories, and symlinks only
/// (`streaming_writer.rs`), and that boundary went undocumented while every
/// sibling `--tar-stdin` limit — flag conflicts, `-o -`, volume options — was
/// written down, with the headline example piping an arbitrary project tree.
#[test]
fn tar_stdin_entry_kind_boundary_is_documented_with_its_exit_label_and_remedy() {
    let boundaries = read_workspace_file("public-docs/tzap-operational-boundaries.md");
    let reference = read_workspace_file("public-docs/tzap-cli-reference.md");

    assert!(boundaries.contains("Entry kinds `--tar-stdin` accepts"));
    assert!(boundaries.contains("regular files, directories, and symlinks only"));
    for kind in ["hardlink", "FIFO", "character / block device"] {
        assert!(boundaries.contains(kind), "the typeflag table must name {kind}");
    }
    // The exit label and the remedy are what make this actionable rather than
    // merely true.
    assert!(boundaries.contains("unsupported-feature"));
    assert!(boundaries.contains("exit `16`"));
    assert!(boundaries.contains("tzap create --keyfile project.key -o project.tzap ./project"));

    assert!(reference.contains("`--tar-stdin` accepts regular files, directories, and symlinks only"));
    assert!(reference.contains("`unsupported-feature`"));
}

#[test]
fn published_v45_conformance_declares_classes_and_discloses_corpus_gaps() {
    let conformance = read_workspace_file("public-docs/traceability/v45-conformance.md");
    let index = read_workspace_file("public-docs/traceability/README.md");

    assert!(index.contains("v45-conformance.md"), "the traceability index must link the conformance document");

    // Every §16.17 class is named, so none is advertised only by implication.
    for class in [
        "16.17.1 Core reader",
        "16.17.2 Portable reader/writer",
        "16.17.3 POSIX backup reader/writer",
        "16.17.4 Linux backup reader/writer",
        "16.17.5 macOS backup reader/writer",
        "16.17.6 Windows backup reader/writer",
    ] {
        assert!(conformance.contains(class), "missing §16.17 class row: {class}");
    }

    // The two obligations this document exists to discharge.
    assert!(conformance.contains("MUST publish its conformance classes"));
    assert!(conformance.contains("MUST publish deterministic fixtures") || conformance.contains("MUST publish"));

    // Gaps stay disclosed. These are the exclusions that keep the class claims
    // honest; dropping them silently widens the claim.
    // APFS clone hints are implemented now, so the macOS class carries no
    // exclusion. What must not regress is the disclosure itself: a conformance
    // page that quietly drops its gap table turns a bounded claim into an
    // unbounded one, which the claim boundary in README.md forbids.
    // The corpus is fully covered now, so there is no gap table to protect.
    // What must not regress is the calibration around that: clearing §16.18 is a
    // floor, not a claim of total conformance, and the page has to keep saying
    // so or "no open gaps" reads as "fully conformant".
    assert!(conformance.contains("Open gaps"), "the disclosure section must survive even when empty");
    assert!(conformance.contains("§16.18 is a floor") || conformance.contains("16.18\nis a floor"), "the floor caveat must stay stated");
    assert!(conformance.contains("external conformance program"), "the page must keep deferring total conformance to an external program");
    assert!(conformance.contains("clone hints"), "the macOS class must still account for clone hints one way or the other");
}
