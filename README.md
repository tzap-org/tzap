# tzap - the only open source archive you need

[![CI](https://github.com/tzap-org/tzap/actions/workflows/ci.yml/badge.svg)](https://github.com/tzap-org/tzap/actions/workflows/ci.yml)
[![Release](https://github.com/tzap-org/tzap/actions/workflows/release.yml/badge.svg)](https://github.com/tzap-org/tzap/actions/workflows/release.yml)
[![Release version](https://img.shields.io/github/v/release/tzap-org/tzap?include_prereleases&label=release)](https://github.com/tzap-org/tzap/releases)
[![Downloads](https://img.shields.io/github/downloads/tzap-org/tzap/total)](https://github.com/tzap-org/tzap/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Backups should survive real life.

`tzap` is a fast, self-healing archive tool for serious long-term storage. It
can encrypt private archives, publish explicit plaintext archives, add recovery
data for damaged storage, split cleanly across drives or cloud objects, and
restore one file from a huge archive without unpacking everything else.

One command. One archive. No duct-taping together tar, compression, encryption,
checksums, parity files, split-volume naming, and restore logic.

## Why people choose tzap

- **It protects the stuff that matters.** Choose passphrase or raw-key
  encryption for private archives, or explicit no-encryption mode for public
  recovery-focused archives.
- **It is built for ugly storage reality.** Bit rot, missing volumes, old drives,
  cloud copies, and cold archives are part of the design.
- **It gets you one file fast.** Pull a photo, contract, source file, or record
  out of a giant archive without restoring the whole thing first.
- **It keeps big archives manageable.** Split archives into practical volume
  files for drives, discs, object storage, or offline sets.
- **It is open source and inspectable.** The Rust implementation, format spec,
  tests, and fuzz targets are in this repository.

## Built for

- personal photo, video, and document vaults
- private project and source archives
- legal, research, media, and records storage
- cold backups that need privacy and recovery
- huge datasets spread across drives, discs, or cloud buckets
- teams that need repeatable verification before restore

## Try it in two minutes

Install:

```sh
cargo install tzap
```

Create an encrypted archive:

```sh
export TZAP_PASSPHRASE='correct horse battery staple'
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin \
  -o backup.tzap \
  ./project
```

Create an explicit plaintext archive:

```sh
tzap create --no-encryption -o public.tzap ./public-project
```

Check it before you trust it:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin backup.tzap
```

Restore one file:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap extract --password-stdin --stdout backup.tzap project/readme.txt
```

Homebrew, GitHub release assets, and source builds are covered in the
[installation guide](public-docs/tzap-installation.md).

## Recovery in plain English

`tzap` can add recovery data when the archive is created. Later, if ordinary
storage damage happens, `tzap verify` or `tzap extract` can rebuild damaged
pieces within that recovery budget and then check the result before trusting it.

For split archives, `tzap` can also survive missing volume files when you choose
a matching volume-loss tolerance:

```sh
tzap create \
  --keyfile project.key \
  --volumes 3 \
  --volume-loss-tolerance 1 \
  -o project.tzap \
  ./project
```

See the [recovery matrix](public-docs/tzap-recovery-matrix.md) for the simple
"what happens if..." version.

## Proof for serious storage

- [Security model](public-docs/tzap-security-model.md): what is private, what is
  checked, how keys work, and how safe restores behave.
- [Recovery matrix](public-docs/tzap-recovery-matrix.md): bit rot, damaged
  blocks, missing volumes, and user actions.
- [Benchmark results](public-docs/tzap-benchmark-results.md): measured create,
  verify, extract, selected-file restore, and recovery performance.
- [CLI reference](public-docs/tzap-cli-reference.md): every command, option, and
  exit label.
- [Operational boundaries](public-docs/tzap-operational-boundaries.md): concrete
  behavior for automation and production workflows.

## For developers and implementers

- CLI crate: [crates.io/crates/tzap](https://crates.io/crates/tzap)
- Core library: [crates.io/crates/tzap-core](https://crates.io/crates/tzap-core)
- Signing plugin: [crates.io/crates/tzap-plugin-signing](https://crates.io/crates/tzap-plugin-signing)
- Format spec: [specs/tzap-format-revisedv43.md](specs/tzap-format-revisedv43.md)
- Development guide: [public-docs/tzap-development.md](public-docs/tzap-development.md)

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
