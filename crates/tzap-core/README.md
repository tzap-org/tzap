# tzap-core

`tzap-core` is the Rust library implementation of the tzap v0.41 archive format.
It owns wire parsing, metadata validation, compression, encryption, FEC recovery
structures, archive writing, archive opening, and safe extraction primitives.

Use this crate as the direct Rust API for tzap archives in applications,
services, backup tools, and custom workflows. Add companion RootAuth signing
crates when origin-authenticated signatures are part of your product.

## Install

```toml
[dependencies]
tzap-core = "0.1.1"
```

## What It Provides

- v41 archive writing and opening
- AEAD encryption, HMAC authentication, and KDF handling
- zstd compression and dictionary support
- multi-volume layout and FEC recovery
- bootstrap sidecar parsing and verification
- safe extraction and tar metadata normalization
- RootAuth writer request, footer, and verifier callback surfaces

## Example

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

## RootAuth Integration

`tzap-core` is the standalone archive foundation. It exposes writer request,
footer, and verification callback surfaces, so signing profiles compose cleanly
through companion crates.

For Ed25519 RootAuth signing, pair this crate with
[`tzap-plugin-signing`](https://crates.io/crates/tzap-plugin-signing). The core
crate recomputes archive roots and gates when a plugin verifier may claim full
RootAuth or public no-key verification.

## More Information

- Repository: <https://github.com/frankmanzhu/tzap>
- Format specification: <https://github.com/frankmanzhu/tzap/blob/main/specs/tzap-format-revisedv41.md>
- CLI crate: <https://crates.io/crates/tzap>
