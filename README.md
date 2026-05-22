# tzap

Rust reference implementation of the **tzap archive format**: fast, encrypted,
self-healing, random-access archives for serious long-term storage.

tzap is built for real archives: huge backups, private datasets, cold storage,
S3-style object storage, split volumes, and restores where you need one file
now, not after unpacking everything. It combines tar-style packing, zstd
compression, AEAD encryption, authenticated metadata, and Reed-Solomon recovery
in one practical format.

The implementation currently targets the v0.36 format specification:
[specs/tzap-format-revisedv36.md](specs/tzap-format-revisedv36.md).

## Why tzap

- **Super fast.** Rust, zstd, indexed metadata, and single-pass writes keep big
  archives moving.
- **Security baked in.** Contents, file names, metadata, and indexes are
  encrypted; headers, manifests, trailers, indexes, and payloads are
  authenticated.
- **Self-healing.** Reed-Solomon FEC repairs bit rot and can survive configured
  volume loss.
- **Instant targeted restores.** Jump straight to a photo inside a 10 TB archive
  without unpacking the rest.
- **Splittable.** Break archives into practical volumes for drives, discs, or
  cloud objects; the format supports size planning and the CLI supports volume
  count today.
- **Cloud-streaming friendly.** Designed for single-pass append-only writes,
  S3-style storage, multipart uploads, and pipe-like workflows.
- **Reference implementation.** Clean Rust core, thin CLI, readable spec, tests,
  and fuzz targets.

## Use cases

- cold backups that need privacy and recovery
- source, legal, media, research, and records archives
- huge datasets spread across drives, discs, or cloud objects
- S3-style storage where streaming writes matter
- instant single-file restores from massive archives
- implementers who want the canonical Rust reference

Not for live filesystems, deduplication, network transport, or in-place editing.

## Install

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

tzap requires Rust 1.82 or newer.

## Quick start

Create a raw 256-bit key:

```sh
openssl rand -hex 32 > tzap.key
```

Create an archive:

```sh
tzap create --keyfile tzap.key -o project.tzap ./project
```

Verify it:

```sh
tzap verify --keyfile tzap.key project.tzap
```

List files:

```sh
tzap list --keyfile tzap.key --long project.tzap
```

Extract everything:

```sh
tzap extract --keyfile tzap.key -C restored project.tzap
```

Extract one file to stdout:

```sh
tzap extract --keyfile tzap.key --stdout project.tzap project/notes.txt
```

## Password mode

Instead of a raw key file, tzap can derive the master key from a passphrase with
Argon2id. The CLI reads the passphrase from stdin so it does not need to appear
in shell history.

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

Split an archive into multiple volumes:

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
separate bootstrap material, including non-seekable or random-access-oriented
read paths.

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
is part of the archive data model, not an external plaintext dependency.

## CLI

```text
tzap create   [options] --output <output> <paths>...
tzap extract  [options] <archive> [path]...
tzap list     [options] <archive>
tzap verify   [options] <archives>...
```

Important `create` options:

- `--keyfile <path>`: read a 32-byte raw key or 64-character hex key
- `--password-stdin`: derive the archive key from a passphrase with Argon2id
- `--volumes <n>`: write a striped multi-volume archive
- `--volume-loss-tolerance <n>`: add enough parity for volume-loss recovery
- `--bit-rot-buffer-pct <n>`: reserve additional FEC for accidental corruption
- `--dictionary <path>`: include a zstd dictionary
- `--bootstrap-out <path>`: write a bootstrap sidecar
- `--compression-level <n>`: choose the zstd compression level
- `--chunk-size`, `--envelope-size`, `--block-size`: tune archive layout

Stable diagnostic categories include `wrong-key`, `corrupt-archive`,
`unsupported-revision`, `unsafe-path`, `missing-bootstrap`, and
`unsupported-feature`.

## Library usage

`tzap-core` exposes the reference read/write primitives for applications that
want the format without shelling out to the CLI.

```rust
use tzap_core::{
    open_archive, write_archive, MasterKey, RegularFile, WriterOptions,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = MasterKey::from_raw_key(&[0x42; 32])?;
    let files = [RegularFile::new("notes/readme.txt", b"hello from tzap")];

    let written = write_archive(&files, &key, WriterOptions::default())?;
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
archive is opened. The v0.36 spec defines the wire structures, algorithm
registry, integrity model, FEC layout, bootstrap behavior, and reader/writer
requirements.

## Project layout

```text
crates/tzap-core   Format parsing, validation, crypto, compression, FEC, reader,
                   writer, metadata, and safe extraction primitives.
crates/tzap-cli    Command-line interface for create, extract, list, and verify.
specs/             tzap archive format specification.
fuzz/              cargo-fuzz targets for fixed structures and metadata parsing.
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

Run fuzz targets with `cargo-fuzz` installed:

```sh
cargo fuzz run parse_fixed_structures
cargo fuzz run parse_metadata
```

## Security model

tzap is serious security engineering: encrypted names, encrypted metadata,
encrypted payloads, authenticated structure, Argon2id password mode, raw-key
mode, nonce-domain separation, and corruption detection before clean extraction.
The format is written to stand up to independent cryptographic review.

Keep keys and passphrases separate from archives, verify archives after copying
or uploading them, and preserve enough volumes to satisfy your chosen recovery
tolerance. Raw-key archives require the original 32-byte key; password archives
require the original passphrase and the stored Argon2id parameters.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
