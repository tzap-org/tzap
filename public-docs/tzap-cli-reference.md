# tzap CLI Reference

This document is a compact command reference for `tzap` operators and automation.

- **Version**: from binary metadata (`tzap --version`)
- **Revision**: format v0.36

## Global options

- `--quiet`: suppress success summaries and standard success output
- `--verbose`: emit verbose diagnostics
- `--help`: usage for current context

## Command: create

Create one archive (single or multi-volume):

```sh
# Passphrase source
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin -o backup.tzap ./project

# Raw key source
tzap create --keyfile project.key -o backup.tzap ./project

# Multi-volume recovery settings
tzap create --keyfile project.key --volumes 3 --volume-loss-tolerance 1 -o backup.tzap ./project
```

Useful flags:

- `--output -o`: base archive path
- `--volumes`: fixed number of output volumes
- `--volume-size`: split by target bytes (e.g. `8M`, `512KiB`)
- `--volume-loss-tolerance`: allowed missing-volume recoverability
- `--bit-rot-buffer-pct`: recovery budget as percentage
- `--argon2-*`: passphrase derivation tuning
- `--dictionary`: optional zstd dictionary
- `--bootstrap-out`: sidecar output path for single-volume archives only
- `--compression-level`, `--chunk-size`, `--envelope-size`, `--block-size`
- `--dry-run`: print planned actions without writing bytes
- `--force`: allow overwrite of outputs and bootstrap

Notes:

- `--bootstrap-out` rejects `--volumes > 1` and `--volume-size` with
  `unsupported-feature`.
- Create writes archive files to explicit paths. `-o -` is not archive stdout;
  the current CLI rejects that sentinel with `unsupported-feature`.
- The current core writer returns completed in-memory archive artifacts before
  the CLI writes output paths. No append-only sink or multipart-upload create
  mode is exposed.
- Create emits regular-file tar member groups only. Long or non-ASCII archive
  paths use local path-specific PAX metadata; global PAX/GNU state and tar EOF
  zero blocks are not emitted into the encrypted tar stream.
- Multi-volume recovery is available only within the `--volume-loss-tolerance`
  and FEC budget chosen when the archive is created.

## Command: extract

Extract selected paths or all members:

```sh
tzap extract --keyfile project.key -C restored project.tzap
# Single file to stdout
tzap extract --keyfile project.key --stdout project.tzap project/readme.txt
```

Useful flags:

- `--directory -C`: output directory
- `--stdout`: emit a single file payload to stdout
- `--overwrite`: replace existing files
- `--dry-run`: show what would be extracted
- `--bootstrap`: bootstrap sidecar path
- `--volume`: additional multi-volume input paths

Notes:

- Archive input comes from file paths. `-` is not an archive stdin sentinel.
- `--stdout` writes one selected regular-file member after the archive has been
  opened and authenticated from file paths; it is not live non-seekable archive
  streaming.
- `--bootstrap` is for single-volume open paths. Multi-volume open paths should
  pass volume files and omit the sidecar; combining multiple archive inputs
  with `--bootstrap` rejects before reading archive files with
  `unsupported-feature`.
- Unsupported local tar metadata profiles and mode/mtime restoration failures
  are reported to stderr as `tzap: degraded-metadata: ...`. Global PAX/GNU state
  is rejected.

## Command: list

Inspect archive content paths:

```sh
tzap list --keyfile project.key project.tzap
printf '%s\n' "$TZAP_PASSPHRASE" | tzap list --password-stdin project.tzap

tzap list --keyfile project.key --long project.tzap
tzap list --keyfile project.key --json project.tzap
```

Useful flags:

- `--long`: human-readable long listing
- `--json`: machine-readable JSON output
- `--bootstrap`: bootstrap sidecar path
- `--volume`: additional multi-volume input paths

Notes:

- Archive input comes from file paths. `-` is not an archive stdin sentinel.
- `--bootstrap` is for single-volume open paths. Multi-volume open paths should
  pass volume files and omit the sidecar; combining multiple archive inputs
  with `--bootstrap` rejects before reading archive files with
  `unsupported-feature`.
- Long listing and JSON output expose the parsed tar kind, size, ustar mode, and
  integer mtime. Unsupported local tar metadata profiles are reported to stderr
  as `tzap: degraded-metadata: ...`; global PAX/GNU state is rejected.

## Command: verify

Validate archive integrity and recovery profile:

```sh
tzap verify --keyfile project.key project.tzap project.tzap.001
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin project.tzap

tzap verify --json --keyfile project.key backup.tzap.000 backup.tzap.001 backup.tzap.002
```

Useful flags:

- `--json`: machine-readable status output
- `--quiet`: suppress success summary
- `--bootstrap`: bootstrap sidecar path

Notes:

- Verification reports unsupported local tar metadata profiles to stderr as
  `tzap: degraded-metadata: ...` after the archive structure and content verify.
- Archive input comes from file paths. `-` is not an archive stdin sentinel.
- `--bootstrap` is for single-volume open paths. Multi-volume open paths should
  pass volume files and omit the sidecar; combining multiple archive inputs
  with `--bootstrap` rejects before reading archive files with
  `unsupported-feature`.
- Multi-volume recovery succeeds only when available inputs stay within the
  archive's configured volume-loss tolerance and FEC budget.

## Command: keygen

Generate raw key material for offline workflows:

```sh
tzap keygen --output project.key
# Print hex key to stdout
tzap keygen --stdout
```

Useful flags:

- `--output`: write keyfile to disk
- `--stdout`: print 64 lowercase hex chars plus newline
- `--force`: replace existing keyfile output

## Operational boundaries

Writer validation, bootstrap sidecar combinations, sequential reader boundaries,
and multi-volume recovery budget examples are documented in
[tzap-operational-boundaries.md](tzap-operational-boundaries.md).
