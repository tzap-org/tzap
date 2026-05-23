# tzap-core

`tzap-core` is the Rust library implementation of the tzap v0.36 archive format.
It owns wire parsing, metadata validation, compression, encryption, FEC recovery
structures, archive writing, archive opening, and safe extraction primitives.

Use this crate when an application needs direct access to tzap archives without
shelling out to the `tzap` CLI.

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

## Scope

The crate provides the reference behavior for the v0.36 format. It is designed
for archive creation, verification, metadata inspection, random-access file
restore, sequential reading, multi-volume recovery, and bootstrap sidecar flows.

## More Information

- Repository: <https://github.com/frankmanzhu/tzap>
- Format specification: <https://github.com/frankmanzhu/tzap/blob/main/specs/tzap-format-revisedv36.md>
- CLI crate: <https://crates.io/crates/tzap>
