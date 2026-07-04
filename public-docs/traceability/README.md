# tzap traceability pack

This folder is the working evidence set for the v44-compliant reference
implementation, RootAuth signing-plugin compliance, and RecipientWrap support.
The root README stays product-facing; this folder carries the review map,
verification gates, and audit notes.

The folder name is `public-docs/traceability`.

## Claim boundary

Allowed after all required gates pass:

```text
tzap is a v44-compliant reference implementation for documented supported
writer, reader, recovery, RootAuth, and RecipientWrap workflows. Legacy v43
archives fail closed as unsupported revisions.
```

Avoid without a separate external conformance program:

```text
tzap is completely compliant for every optional, future, historical, or
unsupported profile described by every specification.
```

## Materials

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
