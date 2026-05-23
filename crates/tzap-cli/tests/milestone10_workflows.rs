use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path))
        .unwrap()
        .replace("\r\n", "\n")
}

#[test]
fn milestone10_ci_workflow_has_cross_platform_matrix() {
    let workflow = read_workspace_file(".github/workflows/ci.yml");

    assert!(workflow.contains("include:"));
    assert!(workflow.contains("os: ubuntu-22.04"));
    assert!(workflow.contains("os: macos-15-intel"));
    assert!(workflow.contains("os: macos-14"));
    assert!(workflow.contains("os: windows-2022"));
    assert!(workflow.contains("matrix.run_fmt"));
    assert!(workflow.contains("cargo fmt --all -- --check"));
    assert!(workflow.contains("cargo check --workspace --all-targets --locked"));
    assert!(workflow.contains("cargo test --workspace --locked"));
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("macos-latest"));
    assert!(!workflow.contains("windows-latest"));
}

#[test]
fn milestone10_release_workflow_has_all_release_archives() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("tzap-${{ github.ref_name }}-linux-x86_64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-linux-x86_64-musl.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-macos-x86_64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-macos-aarch64.tar.gz"));
    assert!(workflow.contains("tzap-${{ github.ref_name }}-windows-x86_64.zip"));
}

#[test]
fn milestone10_release_workflow_targets_distinct_build_triples() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("x86_64-unknown-linux-gnu"));
    assert!(workflow.contains("x86_64-unknown-linux-musl"));
    assert!(workflow.contains("x86_64-apple-darwin"));
    assert!(workflow.contains("aarch64-apple-darwin"));
    assert!(workflow.contains("x86_64-pc-windows-msvc"));
}

#[test]
fn milestone10_release_workflow_uses_pinned_baseline_runners() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("os: ubuntu-22.04"));
    assert!(workflow.contains("os: macos-15-intel"));
    assert!(workflow.contains("os: macos-14"));
    assert!(workflow.contains("os: windows-2022"));
    assert!(workflow.contains("runs-on: ubuntu-22.04"));
    assert!(workflow.contains("MACOSX_DEPLOYMENT_TARGET"));
    assert!(workflow.contains(r#"macosx_deployment_target: "10.12""#));
    assert!(workflow.contains(r#"macosx_deployment_target: "11.0""#));
    assert!(workflow.contains("musl-tools"));
    assert!(workflow.contains("CC_x86_64_unknown_linux_musl=musl-gcc"));
    assert!(workflow.contains("target-feature=+crt-static"));
    assert!(!workflow.contains("ubuntu-latest"));
    assert!(!workflow.contains("macos-latest"));
    assert!(!workflow.contains("windows-latest"));
}

#[test]
fn milestone10_release_workflow_has_smoke_checks() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("Smoke test build"));
    assert!(workflow.contains("--version"));
    assert!(workflow.contains("--help"));
    assert!(workflow.contains("tzap.exe"));
}

#[test]
fn milestone10_release_workflow_uploads_checksum_artifacts() {
    let workflow = read_workspace_file(".github/workflows/release.yml");

    assert!(workflow.contains("Generate checksum (Unix)"));
    assert!(workflow.contains("Generate checksum (Windows)"));
    assert!(workflow.contains("${{ matrix.archive }}.sha256"));
    assert!(workflow.contains("dist/${{ matrix.archive }}.sha256"));
    assert!(workflow.contains("Merge checksum manifest"));
    assert!(workflow.contains("SHA256SUMS"));
}

#[test]
fn milestone10_milestone_status_marked_done() {
    let plan = read_workspace_file("docs/tzap-cli-ux-production-readiness-plan.md");
    assert!(plan.contains("## Milestone 10: Cross-Platform CI And Release Builds\n\nStatus: done."));
}
