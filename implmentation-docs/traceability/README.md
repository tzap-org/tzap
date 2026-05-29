# tzap v41 traceability pack

This folder is the working evidence set for v41 and RootAuth signing-plugin
compliance. The root README stays product-facing; this folder carries the
review map, verification gates, and audit notes.

The folder name is intentionally `implmentation-docs/traceability` because that
is the path requested for this pass.

## Claim boundary

Allowed after all required gates pass:

```text
tzap is v41-compliant for the documented supported archive workflows, including
the RootAuth signing plugin profiles covered by this matrix.
```

Avoid without a separate external conformance program:

```text
tzap is completely v41-compliant for every optional, future, or unsupported
profile described by the specification.
```

## Materials

- [v41-core-traceability.md](v41-core-traceability.md): core archive-format
  requirement map.
- [signing-plugin-traceability.md](signing-plugin-traceability.md): Ed25519 and
  X.509 RootAuth profile map.
- [verification-runbook.md](verification-runbook.md): required commands, fuzz
  and audit expectations, and current local verification record.

## Status terms

- `Implemented and tested`: code exists and is covered by unit, integration,
  documentation, or deterministic fuzz-smoke evidence.
- `Unsupported and documented`: behavior is intentionally outside the current
  supported surface, rejects with a stable error, and is documented in
  `public-docs/`.
- `Evidence gap`: code may exist, but the matrix does not yet point at enough
  tests or verification output to support the claim.
- `Implementation gap`: the implementation does not yet satisfy the mapped
  requirement.

## Required gates

The compliance claim above requires all of these to pass for the reviewed
revision:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked
cargo audit
```

For a stronger release assertion, also run the bounded libFuzzer jobs in
[verification-runbook.md](verification-runbook.md). If `cargo-audit` or
`cargo-fuzz` is not installed, install the tool before treating the gate as
complete.
