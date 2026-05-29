# tzap

Fast encrypted archives that can heal.

`tzap` is the archive CLI for people who want backups to be private, fast,
recoverable, and easy to restore. It packs zstd compression, authenticated
encryption, safe extraction defaults, multi-volume recovery, and instant
selected-file restores into one practical command.

Use it for project folders, private datasets, media collections, cold storage,
cloud object storage, and long-lived backup sets where "just zip it" is not
enough.

## Why use it

- **Fast archives.** Rust, zstd, and indexed metadata keep large backups moving.
- **Private archives.** File contents, file names, metadata, and indexes are
  encrypted.
- **Self-healing archives.** Recovery data can repair accidental damage within
  the budget chosen at create time.
- **Instant targeted restores.** Restore one file from a large archive without
  unpacking everything else.
- **Split-volume storage.** Write deterministic volume files for drives, discs,
  and cloud object storage.
- **Signed roots.** Ed25519 and X.509 RootAuth workflows are available when
  archives need origin authentication.

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

## Quick start: passphrase archive

Create an encrypted archive from a passphrase:

```sh
export TZAP_PASSPHRASE='correct horse battery staple'
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin \
  -o backup.tzap \
  ./project
```

Inspect and verify it:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | tzap list --password-stdin backup.tzap
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin backup.tzap
```

Restore everything:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap extract --password-stdin --directory restored backup.tzap
```

Restore one file:

```sh
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap extract --password-stdin --stdout backup.tzap project/readme.txt
```

## Quick start: key file archive

```sh
tzap keygen --output project.key
tzap create --keyfile project.key -o project.tzap ./project
tzap verify --keyfile project.key project.tzap
tzap list --keyfile project.key project.tzap
tzap extract --keyfile project.key -C restored project.tzap
```

## Recoverable multi-volume archive

Create three volumes that can survive one missing volume:

```sh
tzap create \
  --keyfile project.key \
  --volumes 3 \
  --volume-loss-tolerance 1 \
  -o project.tzap \
  ./project
```

This writes:

```text
project.vol000.tzap
project.vol001.tzap
project.vol002.tzap
```

Verify or restore from any discovered volume:

```sh
tzap verify --keyfile project.key project.vol000.tzap
tzap extract --keyfile project.key --directory restored project.vol001.tzap
```

## Signed RootAuth workflow

```sh
tzap signing-keygen --secret-output root.signing.hex --public-output root.public.hex
tzap create --keyfile project.key --signing-key root.signing.hex -o signed.tzap ./project
tzap verify --keyfile project.key --trusted-public-key root.public.hex signed.tzap
tzap verify --public-no-key --trusted-public-key root.public.hex signed.tzap
```

X.509 RootAuth signing is available with `--signing-cert` and
`--signing-private-key`.

## Safety defaults

`tzap extract` validates archive paths and does not overwrite existing files
unless `--overwrite` is supplied. Keep passphrases and key files separate from
archive data; raw-key archives require the original 32-byte key.

## Trust material

- Security model: <https://github.com/frankmanzhu/tzap/blob/main/public-docs/tzap-security-model.md>
- Recovery matrix: <https://github.com/frankmanzhu/tzap/blob/main/public-docs/tzap-recovery-matrix.md>
- Benchmark guide: <https://github.com/frankmanzhu/tzap/blob/main/public-docs/tzap-benchmark-guide.md>
- CLI reference: <https://github.com/frankmanzhu/tzap/blob/main/public-docs/tzap-cli-reference.md>
- Operational boundaries: <https://github.com/frankmanzhu/tzap/blob/main/public-docs/tzap-operational-boundaries.md>

## More information

- Repository: <https://github.com/frankmanzhu/tzap>
- Format specification: <https://github.com/frankmanzhu/tzap/blob/main/specs/tzap-format-revisedv41.md>
- Library crate: <https://crates.io/crates/tzap-core>
- Signing plugin crate: <https://crates.io/crates/tzap-plugin-signing>
