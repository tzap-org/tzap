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

# Explicit no-secret convenience archive
tzap create --insecure-zero-key --signing-key root.signing.hex -o public.tzap ./project

# Signed RootAuth archive
tzap create --keyfile project.key --signing-key root.signing.hex -o backup.tzap ./project
tzap create --keyfile project.key --signing-cert signer.pem --signing-private-key signer.key -o backup.tzap ./project

# Multi-volume recovery settings
tzap create --keyfile project.key --volumes 3 --volume-loss-tolerance 1 -o backup.tzap ./project

# Tar stream from stdin, single-volume or fixed multi-volume
tar cf - ./project | tzap create --tar-stdin --keyfile project.key -o project.tzap -
tar cf - ./project | tzap create --tar-stdin --volumes 3 --keyfile project.key -o project.tzap -

# Raw stream from stdin with a known size, single-volume or fixed multi-volume
cat disk.img | tzap create --raw-stdin --stdin-name disk.img --stdin-size "$(stat -c%s disk.img)" --keyfile project.key -o disk.tzap -
cat disk.img | tzap create --raw-stdin --stdin-name disk.img --stdin-size "$(stat -c%s disk.img)" --volumes 3 --keyfile project.key -o disk.tzap -

# Explicit plaintext spool for unknown-size raw stdin
producer | tzap create --raw-stdin --stdin-name data/export.bin --spool-stdin --keyfile project.key -o export.tzap -
producer | tzap create --raw-stdin --stdin-name data/export.bin --spool-stdin --volumes 3 --keyfile project.key -o export.tzap -
```

Useful flags:

- `--output -o`: base archive path
- `--volumes`: fixed number of output volumes
- `--volume-size`: split by target bytes (e.g. `8M`, `512KiB`)
- `--volume-loss-tolerance`: allowed missing-volume recoverability. When omitted,
  file-backed multi-volume create defaults to 1; single-volume and stdin create
  modes default to 0.
- `--bit-rot-buffer-pct`: recovery budget as percentage
- `--argon2-*`: passphrase derivation tuning
- `--insecure-zero-key`: use a 32-byte all-zero raw key for explicit
  no-secret convenience archives
- `--dictionary`: optional zstd dictionary
- `--signing-key`: Ed25519 signing seed for v41 RootAuth
- `--signing-cert`: X.509 leaf certificate for RootAuth
- `--signing-private-key`: private key for `--signing-cert`
- `--signing-chain`: optional PEM or DER intermediate certificate chain
- `--bootstrap-out`: sidecar output path for single-volume archives only
- `--tar-stdin`: create an archive from a tar stream at input path `-`
- `--raw-stdin`: create from one raw stdin member at input path `-`
- `--stdin-name`: archive member path for `--raw-stdin`
- `--stdin-size`: known byte size for single-pass raw stdin
- `--spool-stdin`: explicit plaintext spool mode for unknown-size raw stdin
- `--compression-level`, `--chunk-size`, `--envelope-size`, `--block-size`
- `--dry-run`: print planned actions without writing bytes
- `--force`: allow overwrite of outputs and bootstrap

Notes:

- `--bootstrap-out` rejects `--volumes > 1` and `--volume-size` with
  `unsupported-feature`.
- `--insecure-zero-key` uses raw-key mode with 32 zero bytes, skips Argon2,
  and provides no confidentiality. Use it only when the archive is intended to
  behave like a convenience zip. RootAuth signing can still authenticate the
  archive, and readers must pass the same explicit flag.
- Create writes archive files to explicit paths. `-o -` is not archive stdout;
  the current CLI rejects that sentinel with `unsupported-feature`.
- `--tar-stdin` requires exactly one input path, `-`, and writes to a
  file-backed archive path. `-o -` is not supported; using a normal output file
  is also much faster for later selected-file workflows because readers can use
  random access. Add `--volumes N` for fixed-count multi-volume output.
- `--tar-stdin` rejects `--password`, `--password-stdin`, `--dictionary`,
  `--volume-size`, and `--volume-loss-tolerance > 0` before reading payload
  stdin.
- `--raw-stdin --stdin-size SIZE` streams exactly `SIZE` bytes into one
  regular-file member in the standard tar-member v41 profile. Add `--volumes N`
  for fixed-count multi-volume output. Short or overlong stdin is rejected and
  the temporary archive path or volume set is not published.
- `--raw-stdin --spool-stdin` writes stdin to an explicit plaintext temporary
  spool first, then archives it as the same tar-member v41 profile. Add
  `--volumes N` for fixed-count multi-volume output. After EOF the spool gives
  tzap a file-backed raw source with a known size, while `-o` still writes a
  normal file-backed archive path or volume set. That output shape is faster
  for later selected-file workflows because readers can use random access. The
  spool is plaintext, owner-only on Unix, and removed on normal success or
  normal error. The current CLI does not expose `--max-spool-size`, so the OS
  temp directory must be able to hold the full raw stream. A hard kill or host
  crash can leave the temp file behind in the OS temp directory. Use it only
  when the plaintext spool tradeoff is acceptable.
- `--raw-stdin` without `--stdin-size` or `--spool-stdin` is reserved for the
  future no-spool `raw_stream_v1` profile and exits with `unsupported-feature`.
- The convenience core writer APIs return completed in-memory archive artifacts.
  The `--tar-stdin` and raw stdin CLI paths use the core sink
  writer and publish the output file only after terminal metadata and optional
  RootAuth signing finish.
- No append-only sink or multipart-upload create mode is exposed by the CLI.
- Create emits regular-file tar member groups only. Long or non-ASCII archive
  paths use local path-specific PAX metadata; global PAX/GNU state and tar EOF
  zero blocks are not emitted into the encrypted tar stream.
- Multi-volume recovery is available only within the `--volume-loss-tolerance`
  and FEC budget chosen when the archive is created.

## Command: extract

Extract selected paths or all members:

```sh
tzap extract --keyfile project.key -C restored project.tzap
tzap extract --insecure-zero-key -C restored public.tzap
cat project.tzap | tzap extract --keyfile project.key -C restored -
# Single file to stdout
tzap extract --keyfile project.key --stdout project.tzap project/readme.txt
```

Useful flags:

- `--directory -C`: output directory
- `--stdout`: emit a single file payload to stdout
- `--overwrite`: replace existing files
- `--dry-run`: show what would be extracted
- `--insecure-zero-key`: open an explicit no-secret convenience archive
- `--bootstrap`: bootstrap sidecar path
- `--volume`: additional multi-volume input paths

Notes:

- `-` is archive stdin for staged extract-all of single-volume streams with
  `--keyfile` or `--insecure-zero-key`. Dictionary-compressed streams require
  `--bootstrap`. It rejects selected paths, `--stdout`, extra `--volume`
  inputs, and passphrase modes because stdin is the archive byte stream.
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
tzap list --insecure-zero-key public.tzap
cat project.tzap | tzap list --keyfile project.key -

tzap list --keyfile project.key --long project.tzap
tzap list --keyfile project.key --json project.tzap
```

Useful flags:

- `--long`: human-readable long listing
- `--json`: machine-readable JSON output
- `--insecure-zero-key`: open an explicit no-secret convenience archive
- `--bootstrap`: bootstrap sidecar path
- `--volume`: additional multi-volume input paths

Notes:

- `-` is archive stdin for single-volume streams with `--keyfile` or
  `--insecure-zero-key`.
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
tzap verify --insecure-zero-key --trusted-public-key root.public.hex public.tzap
cat project.tzap | tzap verify --keyfile project.key -
tzap verify --keyfile project.key project.tzap project.tzap.001
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin project.tzap

tzap verify --json --keyfile project.key backup.tzap.000 backup.tzap.001 backup.tzap.002
tzap verify --keyfile project.key --trusted-public-key root.public.hex backup.tzap
tzap verify --keyfile project.key --trusted-ca-cert root-ca.pem backup.tzap
tzap verify --public-no-key --trusted-public-key root.public.hex backup.tzap
```

Useful flags:

- `--json`: machine-readable status output
- `--quiet`: suppress success summary
- `--trusted-public-key`: verify Ed25519 RootAuth with a trusted public key
- `--trusted-ca-cert`: verify X.509 RootAuth with a trusted CA certificate
- `--trusted-system-roots`: allow OpenSSL default trust roots for X.509 RootAuth
- `--public-no-key`: verify public v41 RootAuth commitments without the archive key
- `--insecure-zero-key`: verify an explicit no-secret convenience archive
- `--bootstrap`: bootstrap sidecar path

Notes:

- Key-holding verification uses `--keyfile`, `--password`, `--password-stdin`,
  or `--insecure-zero-key`. Add `--trusted-public-key` to require RootAuth
  content verification after ordinary archive integrity verification for
  Ed25519, or add `--trusted-ca-cert` / `--trusted-system-roots` for X.509
  RootAuth.
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
  `--keyfile` or `--insecure-zero-key`. Dictionary-compressed streams require
  `--bootstrap`. Archive stdin does not support `--password-stdin`,
  passphrase KDF discovery, RootAuth external verification flags,
  `--public-no-key`, or multi-volume recovery.
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
