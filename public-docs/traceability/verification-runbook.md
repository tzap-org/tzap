# Verification runbook and record

Review date: 2026-07-14

This runbook defines the reproducible gate for the traceability matrices in
this folder.

## Required local gate

Run these commands from the repository root:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked
cargo audit
```

Expected result: every command exits successfully. `cargo audit` requires the
`cargo-audit` tool.

## Bounded fuzz extension

The deterministic fuzz-smoke command above is the minimum in-repo fuzz gate.
For a stronger release assertion, install `cargo-fuzz` and run:

```sh
cargo fuzz run --features libfuzzer parse_fixed_structures -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_metadata -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_compressed_and_padding -- -max_total_time=60
```

Expected result: each job completes the bounded time window without crashes or
new corpus artifacts that represent unreduced failures.

## Audit pass

The audit pass has two layers:

- Dependency vulnerability scan: `cargo audit`.
- Traceability audit: confirm every row in the signing matrix has a status,
  implementation pointer, and evidence pointer; confirm
  supported v45 workflow evidence in the public docs and verification record;
  and confirm all unsupported rows point to public operational docs or stable
  tests.

If `cargo audit` is unavailable, install it before treating the dependency
audit gate as passed:

```sh
cargo install cargo-audit --locked
```

## Current record

This record is updated by the 2026-07-14 revision-45 implementation review.

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | Passed |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| Workspace tests | `cargo test --workspace --all-features` | Passed: 705 tests across workspace suites; doc tests also passed |
| Deterministic fuzz smoke | `cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked` | Passed: 39 deterministic seeds |
| Dependency audit | `cargo audit` | Passed: 1160 advisories loaded, 231 locked dependencies scanned, no vulnerabilities or warnings reported after updating `anyhow` and `memmap2` |
| Bounded libFuzzer extension | `cargo +nightly fuzz run --features libfuzzer <target> -- -max_total_time=60` | Host-limited in this review: Windows ARM64 lacks AddressSanitizer support; the emulated Windows x64 target compiled through the fuzz crates but could not link because `clang_rt.asan_dynamic_runtime_thunk-x86_64.lib` is not installed. The earlier 2026-06-20 results predate the current v45 metadata changes and are not treated as current evidence. |

Tools installed during this local pass:

- `cargo-audit v0.22.2` (Windows x64 binary under ARM64 emulation)
- `cargo-fuzz v0.13.2`
- `nightly-aarch64-pc-windows-msvc` `rustc 1.99.0-nightly (daf2e5e18 2026-07-13)`
- `nightly` Windows x64 standard library target for the bounded-fuzz fallback attempt

## Claim decision

When all required local gates pass and the matrices still have no
`Evidence gap` or `Implementation gap` rows, the supported-workflow v45
compliance claim in [the root README](../../README.md) and
[traceability README](README.md) may be used.

The stronger bounded-fuzz result should be recorded before using the claim for a
release announcement or external certification package.
