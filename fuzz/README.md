# tzap fuzz targets

These targets are intentionally kept outside the main workspace so normal
`cargo test` does not pull `libfuzzer-sys` into the reference implementation's
default dependency graph.

Run manually with cargo-fuzz:

```sh
cargo fuzz run parse_fixed_structures
cargo fuzz run parse_metadata
```

