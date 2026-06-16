# tzap CLI Reference

This document is a compact command reference for `tzap` operators and automation.

- **Version**: from binary metadata (`tzap --version`)
- **Revision**: format v0.43

## Global options

- `--quiet`: suppress success summaries and standard success output
- `--verbose`: emit verbose diagnostics
- `--help`: usage for current context

## Exit codes

| Exit code | Label | Meaning |
| --- | --- | --- |
| 0 | success | Command completed successfully |
| 1 | error | Unexpected runtime or internal error |
| 2 | usage | Invalid args / command-line usage |
| 3 | io-error | Filesystem I/O or permission problem |
| 10 | wrong-key | Wrong passphrase or key for archive |
| 11 | corrupt-archive | Archive integrity or payload problem |
| 12 | unsupported-revision | Unsupported archive revision |
| 13 | unsafe-path | Unsafe extraction path |
| 14 | missing-bootstrap | Bootstrap sidecar required |
| 16 | unsupported-feature | Unsupported archive feature or writer shape |

## Command: create

Create one archive (single or multi-volume):

```sh
# Passphrase source
printf '%s\n' "$TZAP_PASSPHRASE" | \
  tzap create --password-stdin -o backup.tzap ./project

# Raw key source
tzap create --keyfile project.key -o backup.tzap ./project

# Explicit plaintext archive
tzap create --no-encryption --signing-key root.signing.hex -o public.tzap ./project

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
- `--no-encryption`: write an explicit plaintext archive with unkeyed v43
  integrity digests
- `--dictionary`: optional zstd dictionary
- `--signing-key`: Ed25519 signing seed for v43 RootAuth
- `--signing-cert`: X.509 leaf certificate for RootAuth
- `--signing-private-key`: private key for `--signing-cert`
- `--signing-chain`: optional PEM or DER intermediate certificate chain
- `--bootstrap-out`: sidecar output path for single-volume archives only
- `--tar-stdin`: create an archive from a tar stream at input path `-`
- `--raw-stdin`: create from one raw stdin member at input path `-`
- `--stdin-name`: archive member path for `--raw-stdin`
- `--stdin-size`: known byte size for single-pass raw stdin
- `--spool-stdin`: explicit plaintext spool mode for unknown-size raw stdin
- `--compression-level`, `--chunk-size`, `--envelope-size`, `--block-size`.
  When sizing flags are omitted, `create` chooses the payload layout from the
  input size: compact settings through 100 GiB and the large-data layout for
  larger or unknown-size stdin input.
- `--jobs`: worker count for reader/writer CPU work; defaults to the logical CPU
  count reported by the operating system
- `--timings`: print a create-stage timing breakdown for performance diagnosis
- `--dry-run`: print planned actions without writing bytes
- `--force`: allow overwrite of outputs and bootstrap

Notes:

- `--bootstrap-out` rejects `--volumes > 1` and `--volume-size` with
  `unsupported-feature`.
- `--no-encryption` stores payload and metadata without confidentiality. It
  uses `aead_algo = None`, `kdf_algo = None`, and unkeyed v43 integrity
  digests for fixed metadata. RootAuth signing can still authenticate the
  archive and signer provenance.
- `--insecure-zero-key` was removed in v43. Use `--no-encryption` when the
  archive is intentionally public plaintext.
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
  regular-file member in the standard tar-member v43 profile. Add `--volumes N`
  for fixed-count multi-volume output. Short or overlong stdin is rejected and
  the temporary archive path or volume set is not published.
- `--raw-stdin --spool-stdin` writes stdin to an explicit plaintext temporary
  spool first, then archives it as the same tar-member v43 profile. Add
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
tzap extract -C restored public.tzap
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
- `--jobs`: worker count for reader CPU work; defaults to the logical CPU count
  reported by the operating system

Notes:

- `-` is archive stdin for staged extract-all of single-volume streams with a
  raw `--keyfile` or no key for an unencrypted archive. Dictionary-compressed
  streams require `--bootstrap`. It rejects selected paths, `--stdout`, extra
  `--volume` inputs, and passphrase modes because stdin is the archive byte
  stream.
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
tzap list public.tzap
cat project.tzap | tzap list --keyfile project.key -

tzap list --keyfile project.key --long project.tzap
tzap list --keyfile project.key --json project.tzap
```

Useful flags:

- `--long`: human-readable long listing
- `--json`: machine-readable JSON output
- `--bootstrap`: bootstrap sidecar path
- `--volume`: additional multi-volume input paths
- `--jobs`: worker count for reader CPU work; defaults to the logical CPU count
  reported by the operating system

Notes:

- `-` is archive stdin for single-volume streams with a raw `--keyfile` or no
  key for an unencrypted archive.
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
tzap verify --trusted-public-key root.public.hex public.tzap
cat project.tzap | tzap verify --keyfile project.key -
tzap verify --keyfile project.key project.vol000.tzap
printf '%s\n' "$TZAP_PASSPHRASE" | tzap verify --password-stdin project.tzap

tzap verify --json --keyfile project.key backup.vol001.tzap
tzap verify --fast backup.tzap
tzap verify --keyfile project.key --trusted-public-key root.public.hex backup.tzap
tzap verify --keyfile project.key --trusted-ca-cert root-ca.pem backup.tzap
tzap verify --public-no-key --trusted-public-key root.public.hex backup.tzap
```

For multi-volume archives named `backup.vol000.tzap`,
`backup.vol001.tzap`, and so on, passing any one volume discovers matching
siblings in the same directory. Additional positional archive paths are treated
as the explicit input set.

Useful flags:

- `--json`: machine-readable status output
- `--quiet`: suppress success summary
- `--trusted-public-key`: verify Ed25519 RootAuth with a trusted public key
- `--trusted-ca-cert`: verify X.509 RootAuth with a trusted CA certificate
- `--trusted-system-roots`: allow OpenSSL default trust roots for X.509 RootAuth
- `--public-no-key`: verify public v43 RootAuth commitments without the archive key
- `--fast`: use the seekable archive fast-verification path. For plaintext,
  unsigned, dictionary-free archives with no recovery parity, this verifies
  metadata and payload block-record integrity without decompressing the payload
  and reports `payload_semantics_deferred`. For other seekable archives, it
  verifies readable archive content with repair-on-demand parity reads, but skips
  RootAuth and recovery-margin checks
- `--write-repaired`: write repaired sibling archive copies after successful
  key-holding verification when recoverable BlockRecord damage was found
- `--bootstrap`: bootstrap sidecar path
- `--jobs`: worker count for reader CPU work; defaults to the logical CPU count
  reported by the operating system

Notes:

- Key-holding verification uses `--keyfile`, `--password`, or
  `--password-stdin` for encrypted archives. Unencrypted v43 archives use no
  archive key. Add `--trusted-public-key` to require RootAuth content
  verification after ordinary archive integrity verification for Ed25519, or
  add `--trusted-ca-cert` / `--trusted-system-roots` for X.509 RootAuth.
- Key-holding verification opens archive files through the core file-backed
  random-access reader, then intentionally walks the payload and metadata needed
  to validate the full archive.
- Fast verification is available only for seekable archive paths, not archive
  stdin. For plaintext, unsigned, dictionary-free archives with no recovery
  parity, it validates metadata and payload BlockRecord integrity without
  decompressing the payload, and reports `payload_semantics_deferred`. For other
  seekable archives, fast verification uses the readable-content path but does
  not perform full RootAuth recomputation, trust-source verification, eager
  parity-margin inspection, or repair-copy output. Its JSON and text output use
  `verification_mode = "fast"` / `OK fast`; signed archives report
  `root_auth_deferred_full_archive_scan_required` instead of
  `root_auth_content_verified`.
- Public no-key verification requires `--public-no-key` plus one trust source:
  `--trusted-public-key`, `--trusted-ca-cert`, or `--trusted-system-roots`.
  It does not use archive key material or bootstrap sidecars, and reports the
  public v43 diagnostics `public_data_block_commitment_verified`,
  `public_physical_completeness_unverified`, and
  `public_recovery_margin_unchecked` on success.
- Verification reports unsupported local tar metadata profiles to stderr as
  `tzap: degraded-metadata: ...` after the archive structure and content verify.
- `-` is archive stdin for single-volume verification with a raw `--keyfile`
  or no key for an unencrypted archive. Dictionary-compressed streams require
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
