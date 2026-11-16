use std::fs;
use std::path::{Path, PathBuf};

const RELEASE_ARTIFACT_ACTION: &str = ".github/actions/build-release-artifact/action.yml";
const USE_RELEASE_ARTIFACT_ACTION: &str = "uses: ./.github/actions/build-release-artifact";
const USE_OPENSSL_SETUP_ACTION: &str = "uses: ./.github/actions/setup-openssl";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path)).unwrap().replace("\r\n", "\n")
}

fn assert_contains_in_order(text: &str, labels: &[&str]) {
    let mut offset = 0usize;
    for label in labels {
        let relative = text[offset..].find(label).unwrap_or_else(|| panic!("missing {label:?} after byte offset {offset}"));
        offset += relative + label.len();
    }
}

#[test]
fn ci_workflow_has_cross_platform_matrix() {
    let workflow = read_workspace_file(".github/workflows/ci.yml");
    let artifact_action = read_workspace_file(RELEASE_ARTIFACT_ACTION);

    assert!(workflow.contains("include:"));
    assert!(workflow.contains("os: ubuntu-22.04"));
    assert!(workflow.contains("os: macos-15-intel"));
    assert!(workflow.contains("os: macos-15"));
    assert!(workflow.contains("os: windows-2022"));
    assert!(workflow.contains("release-artifacts:"));
    assert!(workflow.contains("Release artifact ${{ matrix.name }}"));
    assert!(workflow.contains("x86_64-unknown-linux-musl"));
    assert!(workflow.contains("aarch64-unknown-linux-musl"));
    assert!(workflow.contains("x86_64-pc-windows-msvc"));
    assert!(workflow.contains("aarch64-pc-windows-msvc"));
    assert!(workflow.contains(USE_RELEASE_ARTIFACT_ACTION));
    assert!(artifact_action.contains("musl-tools"));
    assert!(artifact_action.contains("CC_x86_64_unknown_linux_musl=musl-gcc"));
    assert!(artifact_action.contains("qemu-user-static"));
    assert!(workflow.contains("qemu-aarch64-static"));
    assert!(artifact_action.contains("cargo install cross --locked"));
    assert!(artifact_action.contains("cross build --locked --release -p tzap --target \"$TZAP_TARGET\""));
    assert!(artifact_action.contains("scripts/smoke-release.py"));
    assert!(workflow.contains("matrix.run_fmt"));
    assert!(workflow.contains("cargo fmt --all -- --check"));
    assert!(workflow.contains("cargo check --workspace --all-targets --locked"));
    assert!(workflow.contains("cargo test --workspace --locked"));
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("macos-latest"));
    assert!(!workflow.contains("windows-latest"));
}

#[test]
fn release_workflow_has_all_release_archives() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("tzap-${{ github.ref_name }}-linux-x86_64-musl.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-linux-aarch64-musl.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-macos-x86_64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-macos-aarch64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-windows-x86_64.zip"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-windows-aarch64.zip"));
    assert!(!workflow.contains("tzap-${{ github.ref_name }}-linux-x86_64.tar.gz"));
}

#[test]
fn release_workflow_targets_distinct_build_triples() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("x86_64-unknown-linux-musl"));
    assert!(workflow.contains("aarch64-unknown-linux-musl"));
    assert!(workflow.contains("x86_64-apple-darwin"));
    assert!(workflow.contains("aarch64-apple-darwin"));
    assert!(workflow.contains("x86_64-pc-windows-msvc"));
    assert!(workflow.contains("aarch64-pc-windows-msvc"));
    assert!(!workflow.contains("x86_64-unknown-linux-gnu"));
}

#[test]
fn release_workflow_uses_pinned_baseline_runners() {
    let workflow = read_workspace_file(".github/workflows/release.yml");
    let artifact_action = read_workspace_file(RELEASE_ARTIFACT_ACTION);

    assert!(workflow.contains("os: ubuntu-22.04"));
    assert!(workflow.contains("os: macos-15-intel"));
    assert!(workflow.contains("os: macos-15"));
    assert!(workflow.contains("os: windows-2022"));
    assert!(workflow.contains("runs-on: ubuntu-22.04"));
    assert!(workflow.contains(USE_RELEASE_ARTIFACT_ACTION));
    assert!(workflow.contains("macosx_deployment_target: ${{ matrix.macosx_deployment_target }}"));
    assert!(artifact_action.contains("MACOSX_DEPLOYMENT_TARGET: ${{ inputs.macosx_deployment_target }}"));
    assert!(workflow.contains(r#"macosx_deployment_target: "10.12""#));
    assert!(workflow.contains(r#"macosx_deployment_target: "11.0""#));
    assert!(workflow.contains("target-feature=+crt-static"));
    assert!(workflow.contains("rustflags: ${{ matrix.rustflags }}"));
    assert!(artifact_action.contains("RUSTFLAGS: ${{ inputs.rustflags }}"));
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("macos-latest"));
    assert!(!workflow.contains("windows-latest"));
}

#[test]
fn release_workflow_has_smoke_checks() {
    let workflow = read_workspace_file(".github/workflows/release.yml");
    let artifact_action = read_workspace_file(RELEASE_ARTIFACT_ACTION);
    let smoke_script = read_workspace_file("scripts/smoke-release.py");

    assert!(workflow.contains("preflight:"));
    assert!(workflow.contains("needs: preflight"));
    assert_eq!(workflow.matches("run_smoke: true").count(), 5);
    for command in [
        "cargo fmt --all -- --check",
        "cargo check --workspace --all-targets --locked",
        "cargo test --workspace --locked",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked",
        "cargo check --manifest-path fuzz/Cargo.toml --bins --features libfuzzer --locked",
        "cargo install cargo-audit --locked",
        "cargo audit --file Cargo.lock",
        "cargo audit --file fuzz/Cargo.lock",
    ] {
        assert!(workflow.contains(command), "release workflow missing preflight command {command:?}");
    }

    assert!(workflow.contains("archive: ${{ matrix.archive }}"));
    assert!(workflow.contains("run_smoke: ${{ matrix.run_smoke }}"));
    assert!(artifact_action.contains("--inspect-only"));
    assert_contains_in_order(&workflow, &[USE_RELEASE_ARTIFACT_ACTION, "Generate checksum (Unix)", "Generate checksum (Windows)", "Upload asset"]);
    assert_contains_in_order(&artifact_action, &["Package Unix", "Package Windows", "Check the packaged binary", "scripts/smoke-release.py"]);
    assert_contains_in_order(
        &smoke_script,
        &[
            "def smoke(",
            "trust-info",
            "openssl_version",
            "\"--version\"",
            "\"--help\"",
            "\"create\", \"--password-stdin\"",
            "\"list\", \"--password-stdin\"",
            "\"verify\", \"--password-stdin\"",
            "\"extract\", \"--password-stdin\"",
            "source.read_bytes() != (out / source.name).read_bytes()",
        ],
    );
    assert_contains_in_order(&smoke_script, &["shutil.unpack_archive", "check_linkage(binary, args.target)", "smoke(binary, work, version, args.emulator)"]);
}

#[test]
fn native_workflows_set_up_static_openssl_before_building() {
    for (workflow, build_step) in [
        ("bump-version", "Run version bump script"),
        ("ci", "Check workspace"),
        ("compatibility", "Build the candidate"),
        ("publish-crates", "Publish crates\n"),
        ("quality", "Check workspace"),
        ("release", "Check workspace"),
    ] {
        let workflow = read_workspace_file(&format!(".github/workflows/{workflow}.yml"));
        assert_contains_in_order(&workflow, &[USE_OPENSSL_SETUP_ACTION, build_step]);
    }
    let quality_workflow = read_workspace_file(".github/workflows/quality.yml");
    assert_contains_in_order(&quality_workflow, &["fuzz:", USE_OPENSSL_SETUP_ACTION, "Run deterministic fuzz smoke"]);
    let artifact_action = read_workspace_file(RELEASE_ARTIFACT_ACTION);
    assert_contains_in_order(&artifact_action, &[USE_OPENSSL_SETUP_ACTION, "cargo build --locked"]);
}

#[test]
fn cargo_builds_use_the_pinned_openssl_without_vendoring() {
    for path in ["Cargo.lock", "fuzz/Cargo.lock"] {
        let lockfile = read_workspace_file(path);
        assert!(!lockfile.contains("\"openssl-src\""), "vendored OpenSSL in {path}");
    }

    // Each crate ships its own guard so it works when installed from crates.io.
    let cli_guard = read_workspace_file("crates/tzap-cli/build.rs");
    for name in ["tzap-plugin-keywrap", "tzap-plugin-signing"] {
        assert_eq!(read_workspace_file(&format!("crates/{name}/build.rs")), cli_guard);
    }
}

#[test]
fn release_workflow_uploads_checksum_artifacts() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("permissions:\n  contents: read\n\njobs:"));
    assert_contains_in_order(&workflow, &["build:", "permissions:", "contents: read", "id-token: write", "attestations: write", "strategy:"]);
    assert_contains_in_order(&workflow, &["publish:", "permissions:", "contents: write", "id-token: write", "attestations: write", "steps:"]);
    assert!(workflow.contains("id-token: write"));
    assert!(workflow.contains("attestations: write"));
    assert!(!workflow.contains("artifact-metadata: write"));
    assert!(workflow.contains("Generate checksum (Unix)"));
    assert!(workflow.contains("Generate checksum (Windows)"));
    assert!(workflow.contains("${{ matrix.archive }}.sha256"));
    assert!(workflow.contains("dist/${{ matrix.archive }}.sha256"));
    assert!(workflow.contains("Merge checksum manifest"));
    assert!(workflow.contains("SHA256SUMS"));
    assert!(workflow.contains("Attest release artifact"));
    assert!(workflow.contains("uses: actions/attest@v4"));
    assert!(workflow.contains("subject-path: dist/*"));
    assert!(workflow.contains("Install cosign"));
    assert!(workflow.contains("uses: sigstore/cosign-installer@v3"));
    assert!(workflow.contains("cosign sign-blob --yes --bundle SHA256SUMS.sigstore.json SHA256SUMS"));
    assert!(workflow.contains("Attest checksum manifest"));
    assert!(workflow.contains("subject-path: dist/SHA256SUMS"));
    assert_contains_in_order(&workflow, &["homebrew:", "needs: build", "brew install --formula"]);
    assert!(workflow.contains("tzap-org/tzap-release-test"));
    assert!(!workflow.contains("frankmanzhu/tzap-release-test"));
    assert!(workflow.contains("HOMEBREW_NO_SANDBOX_LINUX: 1"));
    assert_contains_in_order(
        &workflow,
        &["publish:", "needs:", "- build", "- homebrew", "Merge checksum manifest", "Sign checksum manifest", "Attest checksum manifest", "Publish release"],
    );
}

#[test]
fn internal_docs_are_not_public_release_inputs() {
    let gitignore = read_workspace_file(".gitignore");
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(gitignore.contains("/docs/"));
    assert!(gitignore.contains("/implementation-docs/"));
    assert!(!gitignore.contains("!/docs/"));
    assert!(!workflow.contains("docs/tzap-"));
}
