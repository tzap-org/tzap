# Verification runbook and record

Review date: 2026-06-20

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
- Traceability audit: confirm every row in the v43 and signing matrices has a
  status, implementation pointer, and evidence pointer, and that all
  unsupported rows point to public operational docs or stable tests.

If `cargo audit` is unavailable, install it before treating the dependency
audit gate as passed:

```sh
cargo install cargo-audit --locked
```

## Current record

This record is updated by the 2026-06-20 release-readiness pass.

| Gate | Command | Result |
|---|---|---|
| Format | `cargo fmt --check` | Passed |
| Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | Passed |
| Workspace tests | `cargo test --workspace` | Passed: 666 tests across workspace suites and doc tests |
| Deterministic fuzz smoke | `cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked` | Passed: 39 deterministic seeds |
| Dependency audit | `cargo audit` | Passed: 1134 advisories loaded, 219 locked dependencies scanned, no vulnerabilities reported |
| Bounded libFuzzer extension | `cargo +nightly fuzz run --features libfuzzer <target> -- -max_total_time=60` for all three parser targets | Passed: `parse_fixed_structures` 3569750 runs, `parse_metadata` 15079282 runs, `parse_compressed_and_padding` 16725498 runs |

Tools installed during this local pass:

- `cargo-audit v0.22.1`
- `cargo-fuzz v0.13.1`
- `nightly-aarch64-apple-darwin` `rustc 1.98.0-nightly (57d06900f 2026-05-27)`

## Claim decision

When all required local gates pass and the matrix still has no
`Evidence gap` or `Implementation gap` rows, the supported-workflow compliance
claim in [README.md](README.md) may be used.

The stronger bounded-fuzz result should be recorded before using the claim for a
release announcement or external certification package.
