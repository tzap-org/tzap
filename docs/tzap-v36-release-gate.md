# tzap v0.36 Release Gate

Status: active gate
Primary spec: `specs/tzap-format-revisedv36.md`

This document is the pre-tag gate for any release that mentions v0.36 support.
It is intentionally technical; the README stays focused on successful user
workflows.

## Required Pre-Tag Checks

Run these from the repository root before creating a v0.36 release tag:

```sh
cargo fmt --check
cargo check --workspace --all-targets --locked
cargo test --workspace --locked
cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked
cargo check --manifest-path fuzz/Cargo.toml --bins --features libfuzzer --locked
```

The GitHub CI workflow must run the same workspace checks and the fuzz smoke on
pushes to `main`.

## Evidence Documents

Before tagging, verify these documents are current:

- `docs/tzap-v36-conformance-matrix.md` has no `unknown` row status.
- `docs/tzap-v36-corpus-tracker.md` has no untriaged row and every non-covered
  row links to a follow-up gap.
- `docs/tzap-v36-gap-implementation-plan.md` has every P0 gap complete or
  explicitly closed as an unsupported current-release boundary with tests and
  technical docs.
- `fuzz/corpus/manifest.tsv` maps deterministic fuzz seeds to v0.36 section
  28.1 corpus cases.

Open `partial`, `missing`, or `deferred` corpus rows are release blockers for a
"fully v0.36 conformant" claim. They may remain only when release wording uses
the narrower supported-surface language below and no public docs claim the
missing surface works.

## Release Wording

Acceptable while P1/P2 rows remain open:

- "implements the v0.36 archive layout with documented unsupported surfaces"
- "v0.36-compatible for the supported CLI/API workflows"

Do not use until every P0/P1 conformance row is complete or formally deferred
without a public feature claim:

- "fully v0.36 conformant"
- "complete v0.36 implementation"

## Artifact Gate

The release workflow must produce checksummed artifacts for every platform the
README claims:

- Linux x86_64 GNU
- Linux x86_64 musl
- macOS x86_64
- macOS arm64
- Windows x86_64

Each artifact must smoke-test `tzap --version` plus a create/list/verify/extract
round trip during the release workflow or before promotion.

## Distribution Gate

Homebrew or Linuxbrew installation can be advertised only after the formula path
is tested for the claimed platform. The release owner should run the formula
test against the final tag or release artifact, not a local checkout-only path.
