# tzap

Rust reference implementation for the tzap archive format specification.

The current implementation target is the v0.36 specification in
`specs/tzap-format-revisedv36.md`.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE`.

## Workspace

- `crates/tzap-core`: wire format, validation, crypto, compression, FEC,
  and archive read/write primitives.
- `crates/tzap-cli`: CLI entry point for `create`, `extract`, `list`, and
  `verify`.

## First Implementation Slices

1. Fixed wire constants and algorithm IDs.
2. VolumeHeader/CryptoHeader parsing with CRC and HMAC validation.
3. Empty archive fixture writer/reader.
4. Dictionary-free single-volume create/extract.
5. Bootstrap sidecar and dictionary bootstrap.
6. Multi-volume striping and ReedSolomonGF16 repair.
