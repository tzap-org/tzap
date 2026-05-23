# tzap

`tzap` is the command-line interface for the tzap v0.36 archive format. It
creates, lists, verifies, and extracts encrypted archives with authenticated
metadata, zstd compression, safe extraction defaults, and optional multi-volume
recovery.

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

The CLI requires Rust 1.82 or newer when installing from source.

## Quick Start

Create a raw key and archive a directory:

```sh
tzap keygen --output project.key
tzap create --keyfile project.key -o project.tzap ./project
```

Inspect and verify the archive:

```sh
tzap list --keyfile project.key project.tzap
tzap verify --keyfile project.key project.tzap
```

Extract files safely into a destination directory:

```sh
tzap extract --keyfile project.key --directory restored project.tzap
```

Passphrase mode is available for scripted workflows:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin -o secrets.tzap ./secrets
```

## Multi-Volume Recovery

```sh
tzap create \
  --keyfile project.key \
  --volumes 3 \
  --volume-loss-tolerance 1 \
  -o project.tzap \
  ./project

tzap verify --keyfile project.key project.tzap.000 project.tzap.001 project.tzap.002
```

## Safety

`tzap extract` rejects unsafe archive paths and does not overwrite existing files
unless `--overwrite` is provided. Keep passphrases and raw keyfiles separate from
archive data; raw-key archives require the original 32-byte key.

## More Information

- Repository: <https://github.com/frankmanzhu/tzap>
- CLI reference: <https://github.com/frankmanzhu/tzap/blob/main/docs/tzap-cli-reference.md>
- Format specification: <https://github.com/frankmanzhu/tzap/blob/main/specs/tzap-format-revisedv36.md>
- Library crate: <https://crates.io/crates/tzap-core>
