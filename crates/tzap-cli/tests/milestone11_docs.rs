use std::collections::BTreeMap;
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
    fs::read_to_string(workspace_file(path))
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
    assert!(boundaries.contains("Create outputs are archive files, not stdout"));
    assert!(boundaries.contains("`-o -` is rejected"));
    assert!(boundaries.contains("--bootstrap-out -"));
    assert!(boundaries.contains("Empty directory inputs"));
    assert!(boundaries.contains("empty directories\nare omitted"));
    assert!(boundaries.contains("Cloud directory-prefix optimization"));
    assert!(boundaries.contains("does not claim optimized directory-prefix operations"));
    assert!(!boundaries.contains("writer layouts not emitted yet"));

    assert!(reference
        .contains("`--bootstrap-out`: sidecar output path for single-volume archives only"));
    assert!(reference.contains("`-` is not an archive stdin sentinel"));
    assert!(reference.contains("`-o -` is not archive stdout"));
    assert!(reference.contains("No append-only sink or multipart-upload create"));
    assert!(reference.contains("volume-loss tolerance and FEC budget"));

    assert!(!readme.contains("Archive paths, not archive stdin"));
    assert!(!readme.contains("Empty directory inputs"));
    assert!(!readme.contains("Cloud directory-prefix optimization"));
    assert!(!readme.contains("directory-prefix"));
    assert!(!readme.contains("cloud/object-store optimized"));
    assert!(!readme.contains("forced-hints"));
    assert!(!readme.contains("writer layouts not emitted yet"));

    assert!(!reference.contains("directory-prefix"));
    assert!(!reference.contains("cloud/object-store optimized"));
    assert!(!reference.contains("forced-hints"));
    assert!(!reference.contains("--cloud-directory-prefix"));
}

#[test]
fn milestone11_docs_pin_current_g03_streaming_boundary() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("docs/tzap-operational-boundaries.md");
    let writer = read_workspace_file("crates/tzap-core/src/writer.rs");
    let cli = read_workspace_file("crates/tzap-cli/src/main.rs");

    assert!(boundaries.contains("in-memory archive artifact builder"));
    assert!(boundaries.contains("does not expose archive stdout"));
    assert!(boundaries.contains("append-only sink"));
    assert!(boundaries.contains("multipart-upload sink"));
    assert!(boundaries.contains("pipe output modes"));
    assert!(writer.contains("in-memory archive artifact builder"));
    assert!(writer.contains("not a sink-based streaming writer"));
    assert!(cli.contains("--output - is not archive stdout"));
    assert!(cli.contains("--bootstrap-out - is not sidecar stdout"));

    let readme_forbidden = [
        "cloud-streaming",
        "single-pass",
        "append-only",
        "streaming writes",
        "streaming storage",
        "pipe-like",
        "pipe workflows",
        "sink-based",
        "multipart uploads",
    ];
    let public_cli_forbidden = [
        "streaming create",
        "true streaming",
        "append-only writes",
        "pipe-like",
        "pipe workflows",
        "s3 multipart",
    ];

    let readme_lower = readme.to_lowercase();
    for phrase in readme_forbidden {
        assert!(
            !readme_lower.contains(phrase),
            "README must not claim unsupported streaming writer behavior via {phrase:?}"
        );
    }

    for (surface, text) in [("CLI reference", reference), ("CLI help source", cli)] {
        let lower = text.to_lowercase();
        for phrase in public_cli_forbidden {
            assert!(
                !lower.contains(phrase),
                "{surface} must not claim unsupported streaming writer behavior via {phrase:?}"
            );
        }
    }
}

#[test]
fn milestone11_docs_pin_current_g04_non_seekable_boundary() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("docs/tzap-operational-boundaries.md");
    let matrix = read_workspace_file("docs/tzap-v36-conformance-matrix.md");
    let cli = read_workspace_file("crates/tzap-cli/src/main.rs");
    let reader = read_workspace_file("crates/tzap-core/src/reader.rs");

    assert!(boundaries.contains("Sequential reader and provisional output"));
    assert!(boundaries.contains("whole-buffer helper"));
    assert!(boundaries
        .contains("only after the terminal ManifestFooter and VolumeTrailer authenticate"));
    assert!(boundaries.contains("a live stdout or filesystem extraction API"));
    assert!(boundaries.contains("does not expose archive stdin or live non-seekable extraction"));
    assert!(boundaries.contains("future API, not current CLI behavior"));
    assert!(reference
        .contains("`--stdout` writes one selected regular-file member after the archive has been"));
    assert!(reference.contains("not live non-seekable archive\n  streaming"));
    assert!(reader.contains("not a live provisional-output API"));
    assert!(reader.contains("Callers receive no decoded bytes if terminal authentication fails"));
    assert!(!cli.contains("sequential_extract_tar_stream"));
    assert!(matrix.contains("| R04 |"));
    assert!(matrix.contains("| `partial` | Core has a whole-buffer sequential helper"));
    assert!(matrix.contains("true live sequential API would be future product work"));
    assert!(matrix.contains("| R20 |"));
    assert!(matrix.contains("| `partial` | Whole-buffer API returns decoded bytes"));
    assert!(matrix.contains("Skipped-metadata, non-authoritative terminal, and multi-envelope CRC-boundary fixtures remain G12"));

    let forbidden_claims = [
        "archive stdin",
        "live provisional stdout",
        "live non-seekable extraction",
        "staged filesystem extraction",
    ];
    let readme_lower = readme.to_lowercase();
    let cli_lower = cli.to_lowercase();
    for phrase in forbidden_claims {
        assert!(
            !readme_lower.contains(phrase),
            "README must not claim unsupported sequential reader behavior via {phrase:?}"
        );
        assert!(
            !cli_lower.contains(phrase),
            "CLI help source must not claim unsupported sequential reader behavior via {phrase:?}"
        );
    }
}

#[test]
fn milestone11_docs_pin_current_g10_cli_api_boundaries() {
    let readme = read_workspace_file("README.md");
    let reference = read_workspace_file("docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("docs/tzap-operational-boundaries.md");
    let matrix = read_workspace_file("docs/tzap-v36-conformance-matrix.md");
    let tracker = read_workspace_file("docs/tzap-v36-corpus-tracker.md");
    let plan = read_workspace_file("docs/tzap-v36-gap-implementation-plan.md");
    let cli = read_workspace_file("crates/tzap-cli/src/main.rs");

    assert!(reference.contains("Archive input comes from file paths"));
    assert!(reference.contains("`-` is not an archive stdin sentinel"));
    assert!(reference.contains("combining multiple archive inputs"));
    assert!(reference.contains("rejects before reading archive files"));
    assert!(boundaries.contains("preflight CLI rejection"));
    assert!(boundaries.contains("before archive paths, sidecar\npaths, or key material are read"));
    assert!(boundaries.contains("Create outputs are archive files, not stdout"));
    assert!(boundaries.contains("Empty directory inputs"));
    assert!(cli.contains("multi-volume inputs with --bootstrap are not supported"));
    assert!(cli.contains("--output - is not archive stdout"));
    assert!(cli.contains("--bootstrap-out - is not sidecar stdout"));
    assert!(matrix.contains("| G10 CLI/API boundaries | `complete` |"));
    assert!(matrix.contains(
        "cli_smoke::cli_open_commands_reject_multi_volume_bootstrap_before_archive_reads"
    ));
    assert!(matrix.contains(
        "cli_smoke::cli_extract_stdout_emits_no_payload_when_archive_authentication_fails"
    ));
    assert!(
        tracker.contains("cli_smoke::cli_help_does_not_advertise_archive_stdin_or_create_stdout")
    );
    assert!(!tracker.contains("[G10]"));
    assert!(plan.contains("## G10 - CLI and API Boundaries"));
    assert!(plan.contains("Status: complete."));

    let readme_lower = readme.to_lowercase();
    for phrase in [
        "archive stdin",
        "live stdout streaming",
        "append-only sink",
        "multipart sink",
        "multi-volume sidecar",
    ] {
        assert!(
            !readme_lower.contains(phrase),
            "README must keep G10 boundary details out of marketing copy via {phrase:?}"
        );
    }
}

#[test]
fn milestone11_docs_pin_current_g08_tar_metadata_profile() {
    let reference = read_workspace_file("docs/tzap-cli-reference.md");
    let boundaries = read_workspace_file("docs/tzap-operational-boundaries.md");
    let matrix = read_workspace_file("docs/tzap-v36-conformance-matrix.md");
    let tracker = read_workspace_file("docs/tzap-v36-corpus-tracker.md");
    let plan = read_workspace_file("docs/tzap-v36-gap-implementation-plan.md");

    assert!(boundaries.contains("## Tar metadata profile"));
    assert!(boundaries.contains("regular-file tar member groups"));
    assert!(boundaries.contains("local PAX `path`, `linkpath`, and `size` records"));
    assert!(boundaries.contains("local GNU long name and long link records"));
    assert!(boundaries.contains("applied to restored regular files"));
    assert!(boundaries.contains("Mode or mtime application"));
    assert!(boundaries.contains("failures are reported as degraded metadata diagnostics"));
    assert!(boundaries.contains("Global PAX headers and global GNU state are rejected"));
    assert!(boundaries.contains("not a best-effort metadata-warning\nmode"));
    assert!(boundaries.contains("`extract_file`, which is explicitly\npayload-only"));
    assert!(boundaries.contains("`extract_file_with_diagnostics`"));
    assert!(reference
        .contains("Unsupported local tar metadata profiles and mode/mtime restoration failures"));
    assert!(reference.contains("Verification reports unsupported local tar metadata profiles"));
    assert!(matrix.contains("| W13 |"));
    assert!(matrix.contains("| R13 |"));
    assert!(matrix.contains("| R23 |"));
    assert!(matrix.contains("| G08 tar metadata profile | `complete` |"));
    assert!(tracker.contains("| C084 | Metadata profiles |"));
    assert!(tracker.contains("| C113 | Metadata warnings |"));
    assert!(plan.contains("## G08 - Tar Metadata Profile"));
    assert!(plan.contains("Status: complete."));
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

#[test]
fn milestone11_v36_corpus_tracker_covers_representative_section_28_cases() {
    let spec = read_workspace_file("specs/tzap-format-revisedv36.md");
    let tracker = read_workspace_file("docs/tzap-v36-corpus-tracker.md");
    let gitignore = read_workspace_file(".gitignore");

    assert!(tracker.contains("Primary spec: `specs/tzap-format-revisedv36.md`, section 28.1"));
    assert!(tracker.contains(
        "| ID | Case name | Spec intent | Positive fixture/test | Mutation/negative fixture/test | Status | Follow-up/gap |"
    ));
    assert!(gitignore.contains("!/docs/tzap-v36-corpus-tracker.md"));

    for (id, case) in [
        ("C001", "Minimal FileEntry frame ranges"),
        ("C002", "Exact file versus directory-prefix hints"),
        ("C015", "Sequential provisional output"),
        ("C063", "Large-index root bound"),
        ("C088", "Directory hints"),
        ("C097", "Single-sink streaming rejection"),
        ("C098", "Streaming IndexRoot FEC preselection"),
        ("C099", "Non-seekable sequential extract"),
        ("C102", "Bootstrap sidecar"),
        ("C104", "Sidecar cap arithmetic"),
        ("C109", "S3 round-trip"),
        ("C113", "Metadata warnings"),
    ] {
        let row_prefix = format!("| {id} | {case} |");
        assert!(
            tracker.contains(&row_prefix),
            "corpus tracker missing required row prefix {row_prefix:?}"
        );
    }

    let spec_cases = section_28_case_names(&spec);
    let tracker_cases = corpus_tracker_case_names(&tracker);
    assert_eq!(
        spec_cases.len(),
        113,
        "v0.36 section 28.1 named corpus case count changed"
    );
    assert_eq!(
        tracker_cases, spec_cases,
        "corpus tracker rows must exactly match v0.36 section 28.1 case names"
    );
}

#[test]
fn milestone11_v36_corpus_tracker_uses_reviewable_statuses() {
    let tracker = read_workspace_file("docs/tzap-v36-corpus-tracker.md");
    let allowed = ["covered", "partial", "missing", "deferred"];
    let mut status_counts = BTreeMap::<&str, usize>::new();

    assert!(!tracker.contains("| unknown |"));
    assert!(!tracker.contains("| unsupported |"));
    assert!(!tracker.contains("| TODO |"));
    assert!(!tracker.contains("| TBD |"));

    for row in corpus_tracker_rows(&tracker) {
        assert_eq!(row.len(), 9, "malformed corpus tracker row: {row:?}");
        for column in 1..=7 {
            assert!(
                !row[column].is_empty(),
                "empty corpus tracker column {column} in row: {row:?}"
            );
        }

        let status = row[6];
        assert!(
            allowed.contains(&status),
            "unreviewable corpus tracker status {status:?} in row: {row:?}"
        );
        *status_counts.entry(status).or_insert(0) += 1;

        if status == "covered" {
            assert!(
                !row[4].starts_with("Missing") && !row[5].starts_with("Missing"),
                "covered corpus row still has missing evidence: {row:?}"
            );
        } else {
            assert!(
                row[7].contains("[G"),
                "open corpus row must link to a follow-up gap: {row:?}"
            );
        }
    }

    for status in allowed {
        assert!(
            status_counts.get(status).copied().unwrap_or(0) > 0,
            "expected at least one corpus tracker row with status {status:?}"
        );
    }
    assert!(
        status_counts.get("partial").copied().unwrap_or(0) > 0
            && status_counts.get("missing").copied().unwrap_or(0) > 0,
        "known v36 gaps must remain visible until implemented"
    );
}

#[test]
fn milestone11_v36_corpus_tracker_references_existing_tests() {
    let tracker = read_workspace_file("docs/tzap-v36-corpus-tracker.md");
    let search_roots = [
        "crates/tzap-core/src/compression.rs",
        "crates/tzap-core/src/crypto.rs",
        "crates/tzap-core/src/fec.rs",
        "crates/tzap-core/src/metadata.rs",
        "crates/tzap-core/src/padding.rs",
        "crates/tzap-core/src/reader.rs",
        "crates/tzap-core/src/tar_model.rs",
        "crates/tzap-core/src/wire.rs",
        "crates/tzap-core/src/writer.rs",
        "crates/tzap-cli/src/main.rs",
        "crates/tzap-core/tests/v36_corpus.rs",
        "crates/tzap-cli/tests/cli_smoke.rs",
        "crates/tzap-cli/tests/milestone11_docs.rs",
    ];
    let test_sources = search_roots
        .iter()
        .map(|path| read_workspace_file(path))
        .collect::<Vec<_>>()
        .join("\n");

    for reference in backticked_test_references(&tracker) {
        let test_name = reference
            .rsplit("::")
            .next()
            .expect("test reference contains ::");
        assert!(
            test_sources.contains(&format!("fn {test_name}")),
            "corpus tracker references missing test function {reference:?}"
        );
    }
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

fn corpus_tracker_rows(tracker: &str) -> Vec<Vec<&str>> {
    tracker
        .lines()
        .filter(|line| line.starts_with("| C"))
        .map(|line| line.split('|').map(str::trim).collect())
        .collect()
}

fn corpus_tracker_case_names(tracker: &str) -> Vec<String> {
    corpus_tracker_rows(tracker)
        .into_iter()
        .map(|row| row[2].to_owned())
        .collect()
}

fn section_28_case_names(spec: &str) -> Vec<String> {
    let mut in_section = false;
    let mut names = Vec::new();

    for line in spec.lines() {
        if line.starts_with("### 28.1 Test corpus additions") {
            in_section = true;
            continue;
        }
        if in_section && line.starts_with("---") {
            break;
        }
        if !in_section || !line.starts_with("- **") {
            continue;
        }
        if let Some((name, _)) = line[4..].split_once("**:") {
            names.push(name.to_owned());
        }
    }

    names
}

fn backticked_test_references(markdown: &str) -> Vec<String> {
    markdown
        .split('`')
        .enumerate()
        .filter_map(|(index, chunk)| {
            if index % 2 == 1
                && (chunk.contains("::tests::")
                    || chunk.contains("v36_corpus::")
                    || chunk.contains("cli_smoke::")
                    || chunk.contains("milestone11_docs::"))
            {
                Some(chunk.to_owned())
            } else {
                None
            }
        })
        .collect()
}
