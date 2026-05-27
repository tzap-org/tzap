# tzap CLI Reference

This document is a compact command reference for `tzap` operators and automation.

- **Version**: from binary metadata (`tzap --version`)
- **Revision**: format v0.41

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

# Signed RootAuth archive
tzap create --keyfile project.key --signing-key root.signing.hex -o backup.tzap ./project

# Multi-volume recovery settings
tzap create --keyfile project.key --volumes 3 --volume-loss-tolerance 1 -o backup.tzap ./project

# Future streaming-create shapes; currently reject with unsupported-feature
tar cf - ./project | tzap create --tar-stdin --keyfile project.key -o project.tzap -
producer | tzap create --raw-stdin --stdin-name data/export.bin --keyfile project.key -o export.tzap -
```

Useful flags:

- `--output -o`: base archive path
- `--volumes`: fixed number of output volumes
- `--volume-size`: split by target bytes (e.g. `8M`, `512KiB`)
- `--volume-loss-tolerance`: allowed missing-volume recoverability
- `--bit-rot-buffer-pct`: recovery budget as percentage
- `--argon2-*`: passphrase derivation tuning
- `--dictionary`: optional zstd dictionary
- `--signing-key`: Ed25519 signing seed for v41 RootAuth
- `--bootstrap-out`: sidecar output path for single-volume archives only
- `--tar-stdin`: future create mode where input path `-` is a tar stream
- `--raw-stdin`: future create mode where input path `-` is one raw member
- `--stdin-name`: archive member path for `--raw-stdin`
- `--stdin-size`: known byte size for raw stdin
- `--spool-stdin`: future plaintext spool mode for unknown-size raw stdin
- `--compression-level`, `--chunk-size`, `--envelope-size`, `--block-size`
- `--dry-run`: print planned actions without writing bytes
- `--force`: allow overwrite of outputs and bootstrap

Notes:

- `--bootstrap-out` rejects `--volumes > 1` and `--volume-size` with
  `unsupported-feature`.
- Create writes archive files to explicit paths. `-o -` is not archive stdout;
  the current CLI rejects that sentinel with `unsupported-feature`.
- Streaming-create flags are present for future tar/raw stdin support, but the
  current CLI public surface still returns `unsupported-feature` for
  accepted-looking stdin create shapes. Incompatible combinations reject before
  stdin, keyfiles, dictionaries, or ordinary input paths are read.
- The convenience core writer APIs return completed in-memory archive artifacts.
  A lower-level core append-only sink API exists for re-openable sources, but no
  append-only sink or multipart-upload create mode is exposed by the CLI.
- Create emits regular-file tar member groups only. Long or non-ASCII archive
  paths use local path-specific PAX metadata; global PAX/GNU state and tar EOF
  zero blocks are not emitted into the encrypted tar stream.
- Multi-volume recovery is available only within the `--volume-loss-tolerance`
  and FEC budget chosen when the archive is created.

## Command: extract

Extract selected paths or all members:

```sh
tzap extract --keyfile project.key -C restored project.tzap
cat project.tzap | tzap extract --keyfile project.key -C restored -
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

- `-` is archive stdin for staged extract-all of single-volume streams with
  `--keyfile`. Dictionary-compressed streams require `--bootstrap`. It rejects
  selected paths, `--stdout`, extra `--volume` inputs, and passphrase modes
  because stdin is the archive byte stream.
- For selected-file workflows, use a file-backed archive path. This is the fast
  path: the random-access reader uses the authenticated index to read only the
  selected member's metadata and payload envelopes instead of streaming through
  unrelated archive content.
- Key-holding extract opens archive files through the core file-backed
  random-access reader. Selecting one path reads the authenticated terminal,
  index metadata, and the payload envelopes needed for that path; it does not
  load the whole archive into memory first.
- Selected regular-file payloads stream from the needed envelopes to stdout or
  the destination file with memory bounded by the current envelope, current
  frame, and small tar metadata buffers.
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
cat project.tzap | tzap list --keyfile project.key -

tzap list --keyfile project.key --long project.tzap
tzap list --keyfile project.key --json project.tzap
```

Useful flags:

- `--long`: human-readable long listing
- `--json`: machine-readable JSON output
- `--bootstrap`: bootstrap sidecar path
- `--volume`: additional multi-volume input paths

Notes:

- `-` is archive stdin for single-volume streams with `--keyfile`.
  Dictionary-compressed streams require `--bootstrap`. Listing is emitted only
  after EOF, terminal authentication, and metadata/content conformance checks
  succeed.
- For file-backed archives, default `list` output reads encrypted index entries
  and prints archive paths. It does not decode payload envelopes for tar kind,
  mode, mtime, or metadata diagnostics.
- Key-holding list opens archive files through the core file-backed
  random-access reader. Default output reads terminal and index metadata rather
  than loading every payload block.
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
tzap verify --keyfile project.key project.tzap
cat project.tzap | tzap verify --keyfile project.key -
tzap verify --keyfile project.key project.tzap project.tzap.001
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin project.tzap

tzap verify --json --keyfile project.key backup.tzap.000 backup.tzap.001 backup.tzap.002
tzap verify --keyfile project.key --trusted-public-key root.public.hex backup.tzap
tzap verify --public-no-key --trusted-public-key root.public.hex backup.tzap
```

Useful flags:

- `--json`: machine-readable status output
- `--quiet`: suppress success summary
- `--trusted-public-key`: verify Ed25519 RootAuth with a trusted public key
- `--public-no-key`: verify public v41 RootAuth commitments without the archive key
- `--bootstrap`: bootstrap sidecar path

Notes:

- Key-holding verification uses `--keyfile`, `--password`, or
  `--password-stdin`. Add `--trusted-public-key` to require RootAuth content
  verification after ordinary archive integrity verification.
- Key-holding verification opens archive files through the core file-backed
  random-access reader, then intentionally walks the payload and metadata needed
  to validate the full archive.
- Public no-key verification requires `--public-no-key --trusted-public-key`.
  It does not use archive key material or bootstrap sidecars, and reports the
  public v41 diagnostics `public_data_block_commitment_verified`,
  `public_physical_completeness_unverified`, and
  `public_recovery_margin_unchecked` on success.
- Verification reports unsupported local tar metadata profiles to stderr as
  `tzap: degraded-metadata: ...` after the archive structure and content verify.
- `-` is archive stdin for single-volume key-holding verification with
  `--keyfile`. Dictionary-compressed streams require `--bootstrap`. Archive
  stdin does not support `--password-stdin`, passphrase KDF discovery,
  `--trusted-public-key`, `--public-no-key`, or multi-volume recovery.
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

## Command: signing-keygen

Generate an Ed25519 RootAuth signing keypair:

```sh
tzap signing-keygen --secret-output root.signing.hex --public-output root.public.hex
```

Useful flags:

- `--secret-output`: write the 32-byte signing seed as 64 lowercase hex chars
- `--public-output`: write the 32-byte public key as 64 lowercase hex chars
- `--force`: replace existing keypair outputs

## Operational boundaries

Writer validation, bootstrap sidecar combinations, sequential reader boundaries,
and multi-volume recovery budget examples are documented in
[tzap-operational-boundaries.md](tzap-operational-boundaries.md).
