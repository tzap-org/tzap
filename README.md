# tzap - the only open source archive you need

[![CI](https://github.com/frankmanzhu/tzap/actions/workflows/ci.yml/badge.svg)](https://github.com/frankmanzhu/tzap/actions/workflows/ci.yml)
[![Release](https://github.com/frankmanzhu/tzap/actions/workflows/release.yml/badge.svg)](https://github.com/frankmanzhu/tzap/actions/workflows/release.yml)
[![Release version](https://img.shields.io/github/v/release/frankmanzhu/tzap?include_prereleases&label=release)](https://github.com/frankmanzhu/tzap/releases)
[![Downloads](https://img.shields.io/github/downloads/frankmanzhu/tzap/total)](https://github.com/frankmanzhu/tzap/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Rust reference implementation of the **tzap archive format**: fast compression,
fast encryption, fast self-healing recovery, and instant random-access restores
for serious long-term storage.

tzap is built for real archives: huge backups, private datasets, cold storage,
cloud object storage, split volumes, and immediate single-file restores. It
combines packing, fast compression, strong encryption, authenticated metadata,
and recovery in one practical format.

The implementation currently targets the v0.41 format specification:
[specs/tzap-format-revisedv41.md](specs/tzap-format-revisedv41.md).
See the full command guide in
[public-docs/tzap-cli-reference.md](public-docs/tzap-cli-reference.md).

## Why tzap

- **Super fast.** Rust, zstd, indexed metadata, and volume-aware layouts keep
  big archives moving.
- **Security baked in.** Contents, file names, metadata, and indexes are
  encrypted; headers, manifests, trailers, indexes, and payloads are
  authenticated.
- **Self-healing.** Reed-Solomon FEC adds configurable recovery capacity across
  volumes and long-term storage media.
- **Instant targeted restores.** Jump straight to a photo inside a 10 TB archive
  while the rest stays packed.
- **Splittable.** Break archives into practical volumes for drives, discs, or
  cloud objects by volume count or target volume size.
- **Cloud-volume friendly.** Split archives into deterministic volume files for
  object storage, removable media, and long-lived backups.
- **Reference implementation.** Clean Rust core, thin CLI, readable spec, tests,
  and fuzz targets.

## Use cases

- cold backups that need privacy and recovery
- source, legal, media, research, and records archives
- huge datasets spread across drives, discs, or cloud objects
- cloud object storage and offline media sets
- instant single-file restores from massive archives
- implementers who want the canonical Rust reference

Focused on archive creation, verification, listing, extraction, storage, and
recovery workflows.

## Install

From Homebrew:

```sh
brew tap frankmanzhu/tzap https://github.com/frankmanzhu/tzap
brew install frankmanzhu/tzap/tzap
```

From crates.io:

```sh
cargo install tzap
```

From a checkout:

```sh
cargo build --release -p tzap
```

The binary will be available at:

```sh
target/release/tzap
```

From GitHub:

```sh
cargo install --git https://github.com/frankmanzhu/tzap tzap
```

## Install from GitHub release

From published assets:

```sh
VERSION=vX.Y.Z
case "$(uname -s)" in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *)
    echo "unsupported OS: $(uname -s)"
    exit 1
    ;;
esac

ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
  x86_64) ARCH=x86_64 ;;
  arm64 | aarch64) ARCH=aarch64 ;;
  *)
    echo "unsupported architecture: ${ARCH_RAW}"
    exit 1
    ;;
esac

if [ "$OS" = linux ]; then
  ASSET="tzap-${VERSION}-linux-${ARCH}-musl.tar.gz"
else
  ASSET="tzap-${VERSION}-${OS}-${ARCH}.tar.gz"
fi
# On Windows, pick the ".zip" artifact name from the table below.
curl -L -o tzap.tar.gz \
  "https://github.com/frankmanzhu/tzap/releases/download/${VERSION}/${ASSET}"
tar -xzf tzap.tar.gz
chmod +x tzap
./tzap --version
```

Supported target artifacts:

| Platform | Artifact |
| --- | --- |
| Linux x86_64 static/musl | `tzap-vX.Y.Z-linux-x86_64-musl.tar.gz` |
| Linux aarch64 static/musl | `tzap-vX.Y.Z-linux-aarch64-musl.tar.gz` |
| macOS x86_64 | `tzap-vX.Y.Z-macos-x86_64.tar.gz` |
| macOS aarch64 | `tzap-vX.Y.Z-macos-aarch64.tar.gz` |
| Windows x86_64 | `tzap-vX.Y.Z-windows-x86_64.zip` |
| Windows aarch64 | `tzap-vX.Y.Z-windows-aarch64.zip` |

Release artifacts are built on pinned baseline runners instead of moving
`*-latest` labels: `ubuntu-22.04`, `macos-15-intel`, `macos-14`, and
`windows-2022`. macOS builds set `MACOSX_DEPLOYMENT_TARGET=10.12` for
x86_64 and `MACOSX_DEPLOYMENT_TARGET=11.0` for aarch64. Linux publishes
static musl artifacts for x86_64 and aarch64; Windows release builds use the
static CRT.

tzap requires Rust 1.85 or newer.

## Quick start (passphrase mode)

Create and verify a backup archive from a passphrase:

```sh
export TZAP_PASSPHRASE='correct horse battery staple'
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin \
  -o backup.tzap \
  ./project
```

Run a safety-aware inspection flow:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | tzap list --password-stdin backup.tzap
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin backup.tzap
```

Extract content:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap extract --password-stdin --directory restored backup.tzap
```

And extract a single file:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap extract --password-stdin --stdout backup.tzap project/readme.txt
```

## Quick start (raw key)

```sh
tzap keygen --output project.key
tzap create --keyfile project.key -o project.tzap ./project
tzap verify --keyfile project.key project.tzap
tzap list --keyfile project.key project.tzap
tzap extract --keyfile project.key -C restored project.tzap
```

## Signed RootAuth workflow

```sh
tzap signing-keygen --secret-output root.signing.hex --public-output root.public.hex
tzap create --keyfile project.key --signing-key root.signing.hex -o signed.tzap ./project
tzap verify --keyfile project.key --trusted-public-key root.public.hex signed.tzap
tzap verify --public-no-key --trusted-public-key root.public.hex signed.tzap
```

## Multi-volume workflow (recoverable)

```sh
tzap create --keyfile project.key --volumes 3 --volume-loss-tolerance 1 -o project.tzap ./project
tzap verify --keyfile project.key project.tzap.000 project.tzap.001 project.tzap.002
tzap extract --keyfile project.key project.tzap.000 --volume project.tzap.002 --directory restored project
```

If one volume is missing and tolerance allows, verification and extraction still work:

```sh
tzap verify --keyfile project.key project.tzap.000 project.tzap.002
tzap extract --keyfile project.key --volume project.tzap.002 project.tzap.000 --directory restored project
```

## Safety notes

- `tzap` does not overwrite existing files by default. Use `--overwrite` when restore should replace files.
- Archive members are safe-checked before write; unsafe paths such as `../evil.txt` are rejected.
- Use `--password-stdin` for non-interactive workflows and `--password` for interactive prompt mode.
- Format and wire behavior align with the published v0.41 specification at
  [specs/tzap-format-revisedv41.md](specs/tzap-format-revisedv41.md).

## Exit codes

| Exit code | Label | Meaning |
| --- | --- | --- |
| 0 | success | Command completed successfully |
| 1 | error | Unexpected runtime or internal error |
| 2 | usage | Invalid args / command-line usage |
| 3 | io-error | Filesystem I/O or permission problem |
| 10 | wrong-key | Wrong passphrase or key for archive |
| 11 | corrupt-archive | Archive integrity or payload problem |
| 12 | unsupported-revision | Unsupported archive revision |
| 13 | unsafe-path | Unsafe extraction path |
| 14 | missing-bootstrap | Bootstrap sidecar required |
| 16 | unsupported-feature | Unsupported archive feature or writer shape |

## Password mode

Password mode derives the master key from a passphrase with Argon2id. The CLI
reads the passphrase from stdin so shell history stays clean.

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin -o secrets.tzap ./secrets

printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap verify --password-stdin secrets.tzap
```

Argon2id parameters are configurable:

```sh
tzap create \
  --password-stdin \
  --argon2-t-cost 3 \
  --argon2-m-cost-kib 262144 \
  --argon2-parallelism 4 \
  -o secrets.tzap \
  ./secrets
```

## Multi-volume archives

Split an archive by volume count:

```sh
tzap create \
  --keyfile tzap.key \
  --volumes 4 \
  --volume-loss-tolerance 1 \
  -o backup.tzap \
  ./backup
```

This writes:

```text
backup.tzap.000
backup.tzap.001
backup.tzap.002
backup.tzap.003
```

Tune the self-healing budget:

```sh
tzap create \
  --keyfile tzap.key \
  --volumes 4 \
  --volume-loss-tolerance 1 \
  --bit-rot-buffer-pct 10 \
  -o vault.tzap \
  ./vault
```

Or split by target volume size:

```sh
tzap create \
  --keyfile tzap.key \
  --volume-size 4G \
  -o backup.tzap \
  ./backup
```

Verify the volume set:

```sh
tzap verify \
  --keyfile tzap.key \
  backup.tzap.000 backup.tzap.001 backup.tzap.002 backup.tzap.003
```

Extract with additional volumes:

```sh
tzap extract \
  --keyfile tzap.key \
  --volume backup.tzap.001 \
  --volume backup.tzap.002 \
  --volume backup.tzap.003 \
  -C restored \
  backup.tzap.000
```

## Bootstrap sidecars

Bootstrap sidecars carry startup metadata for workflows that benefit from
separate bootstrap material and random-access-oriented read paths.

```sh
tzap create \
  --keyfile tzap.key \
  --bootstrap-out archive.tzap.bootstrap \
  -o archive.tzap \
  ./archive

tzap list \
  --keyfile tzap.key \
  --bootstrap archive.tzap.bootstrap \
  archive.tzap
```

## Dictionary compression

For collections with repeated structure, tzap can include a zstd dictionary:

```sh
tzap create \
  --keyfile tzap.key \
  --dictionary corpus.dict \
  --bootstrap-out corpus.tzap.bootstrap \
  -o corpus.tzap \
  ./corpus
```

Dictionary archives are still encrypted and authenticated. The dictionary object
lives inside the protected archive data model.

## CLI

```text
tzap create   [options] --output <output> <paths>...
tzap extract  [options] <archive> [path]...
tzap list     [options] <archive>
tzap verify   [options] <archives>...
tzap signing-keygen --secret-output <path> --public-output <path>
```

Important `create` options:

- `--keyfile <path>`: read a 32-byte raw key or 64-character hex key
- `--password-stdin`: derive the archive key from a passphrase with Argon2id
- `--signing-key <path>`: sign v41 RootAuth with an Ed25519 signing seed
- `--volumes <n>`: write a striped multi-volume archive
- `--volume-size <size>`: choose the number of volumes from a target size
- `--volume-loss-tolerance <n>`: add enough parity for volume recovery
- `--bit-rot-buffer-pct <n>`: set additional FEC as a percentage of data capacity
- `--dictionary <path>`: include a zstd dictionary
- `--bootstrap-out <path>`: write a bootstrap sidecar
- `--compression-level <n>`: choose the zstd compression level
- `--chunk-size`, `--envelope-size`, `--block-size`: tune archive layout

Important `verify` options:

- `--trusted-public-key <path>`: require Ed25519 RootAuth verification
- `--public-no-key`: verify signed public RootAuth commitments without the
  archive key
- `--json`: emit machine-readable verification status

Stable diagnostics cover key validation, archive integrity, revision
compatibility, path safety, bootstrap sidecars, and feature negotiation.

## Library usage

`tzap-core` exposes the reference read/write primitives for applications that
want direct access to the format from application code.

```rust
use tzap_core::{
    open_archive, write_archive, MasterKey, RegularFile, WriterOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = MasterKey::from_raw_key(&[0x42; 32])?;
    let files = [RegularFile::new("notes/readme.txt", b"hello from tzap")];
    let options = WriterOptions {
        stripe_width: 1,
        volume_loss_tolerance: 0,
        ..WriterOptions::default()
    };

    let written = write_archive(&files, &key, options)?;
    let opened = open_archive(&written.bytes, &key)?;

    assert_eq!(
        opened.extract_file("notes/readme.txt")?,
        Some(b"hello from tzap".to_vec())
    );

    Ok(())
}
```

## Format overview

The archive pipeline is:

```text
tar member groups -> zstd frames -> pack -> pad -> AEAD -> FEC -> stripe -> split
```

The format stores encrypted payload objects, encrypted indexes, authenticated
headers and trailers, and enough metadata to support random access after the
archive is opened. The v0.41 spec defines the wire structures, algorithm
registry, integrity model, FEC layout, bootstrap behavior, and reader/writer
requirements.

## Project layout

```text
crates/tzap-core   Format parsing, validation, crypto, compression, FEC, reader,
                   writer, metadata, and safe extraction primitives.
crates/tzap-cli    Command-line interface for create, extract, list, and verify.
crates/tzap-plugin-signing
                   RootAuth signing profiles, including Ed25519 raw signing.
specs/             tzap archive format specification.
fuzz/              Parser fuzz targets, deterministic seeds, and fuzz smoke.
```

## Development

Run the test suite:

```sh
cargo test
```

Run the CLI locally:

```sh
cargo run -p tzap -- --help
```

Run the bounded parser fuzz smoke:

```sh
cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked
```

Run longer fuzz targets with `cargo-fuzz` installed:

```sh
cargo fuzz run --features libfuzzer parse_fixed_structures -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_metadata -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_compressed_and_padding -- -max_total_time=60
```

## Security model

tzap is serious security engineering: encrypted names, encrypted metadata,
encrypted payloads, authenticated structure, Argon2id password mode, raw-key
mode, nonce-domain separation, and integrity checks before clean extraction.
The format is written to stand up to independent cryptographic review.

Keep keys and passphrases separate from archives, verify archives after copying
or uploading them, and preserve enough volumes to satisfy your chosen recovery
tolerance. Raw-key archives require the original 32-byte key; password archives
require the original passphrase and the stored Argon2id parameters.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
