# tzap Development Guide

This document keeps contributor and implementation details out of the root
README.

## Project layout

```text
crates/tzap-core   Format parsing, validation, crypto, compression, FEC, reader,
                   writer, metadata, and safe extraction primitives.
crates/tzap-cli    Command-line interface for create, extract, list, and verify.
crates/tzap-plugin-signing
                   RootAuth signing profiles, including Ed25519 raw and X.509.
specs/             tzap archive format specification.
fuzz/              Parser fuzz targets, deterministic seeds, and fuzz smoke.
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

## Local development

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
