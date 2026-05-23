# tzap fuzz targets

These targets are intentionally kept outside the main workspace so normal
`cargo test` does not pull `libfuzzer-sys` into the reference implementation's
default dependency graph.

## CI smoke

The release smoke path is a normal Cargo binary and does not require
`cargo-fuzz` or network access:

```sh
cargo run --manifest-path fuzz/Cargo.toml --bin fuzz_smoke --locked
```

It runs deterministic seeds from `fuzz/corpus/` and embedded boundary seeds
through every parser harness. Add minimized repro bytes to the matching
`fuzz/corpus/<target>/` directory before turning a fuzz failure into a
regression test.

The seed manifest at `fuzz/corpus/manifest.tsv` maps each target to the v0.36
section 28.1 corpus cases it is intended to keep warm. Structured seeds are
built deterministically in `fuzz/fuzz_targets/seeds.rs`; small file seeds live
under `fuzz/corpus/<target>/`.

## Longer local fuzzing

Install `cargo-fuzz` locally, then run bounded parser jobs:

```sh
cargo fuzz run --features libfuzzer parse_fixed_structures -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_metadata -- -max_total_time=60
cargo fuzz run --features libfuzzer parse_compressed_and_padding -- -max_total_time=60
```

Targets:

- `parse_fixed_structures`: VolumeHeader, CryptoHeader, extension TLVs,
  BlockRecord, ManifestFooter, VolumeTrailer, and BootstrapSidecarHeader.
- `parse_metadata`: IndexRoot, IndexShard, and DirectoryHintTable.
- `parse_compressed_and_padding`: exact zstd frame validation/decompression and
  suffix depadding.
