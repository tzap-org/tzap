# tzap

`tzap` is the command-line interface for the tzap v0.41 archive format. It
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

The CLI requires Rust 1.85 or newer when installing from source.

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

Create a signed v41 RootAuth archive:

```sh
tzap signing-keygen --secret-output root.signing.hex --public-output root.public.hex
tzap create --keyfile project.key --signing-key root.signing.hex -o signed.tzap ./project
tzap verify --keyfile project.key --trusted-public-key root.public.hex signed.tzap
tzap verify --public-no-key --trusted-public-key root.public.hex signed.tzap
tzap create --keyfile project.key --signing-cert signer.pem --signing-private-key signer.key -o signed-x509.tzap ./project
tzap verify --keyfile project.key --trusted-ca-cert root-ca.pem signed-x509.tzap
tzap verify --public-no-key --trusted-ca-cert root-ca.pem signed-x509.tzap
```

The CLI composes `tzap-core` with `tzap-plugin-signing` for Ed25519 and X.509
RootAuth signing. Library users can choose `tzap-core` for archive workflows or
compose it with `tzap-plugin-signing` for signed RootAuth workflows.

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

`tzap extract` applies safe path validation and overwrite protection;
`--overwrite` enables explicit replacement. Keep passphrases and raw keyfiles
separate from archive data; raw-key archives require the original 32-byte key.

## More Information

- Repository: <https://github.com/frankmanzhu/tzap>
- CLI reference: <https://github.com/frankmanzhu/tzap/blob/main/public-docs/tzap-cli-reference.md>
- Format specification: <https://github.com/frankmanzhu/tzap/blob/main/specs/tzap-format-revisedv41.md>
- Library crate: <https://crates.io/crates/tzap-core>
- Signing plugin crate: <https://crates.io/crates/tzap-plugin-signing>
