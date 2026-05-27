# tzap operational boundaries

This document keeps operator-facing boundary cases out of the project README.
The README is for the product promise, installation, and quick starts; this file
is for exact CLI behavior when a command asks for a shape outside the current
writer or reader path.

## Writer shape validation

The writer validates archive layout choices before writing bytes. If a request
cannot produce a valid v0.41 archive with this implementation, `tzap` exits with
`16 unsupported-feature`.

Examples:

```sh
tzap create --keyfile project.key --block-size 3 -o bad.tzap ./project
# exit 16: unsupported-feature
```

`--block-size` must be even and at least 4096 bytes.

```sh
tzap create \
  --keyfile project.key \
  --chunk-size 4M \
  --envelope-size 1M \
  -o bad.tzap \
  ./project
# exit 16: unsupported-feature
```

`--chunk-size` must be non-zero and no larger than `--envelope-size`.

```sh
tzap create \
  --keyfile project.key \
  --volume-size 1K \
  -o split.tzap \
  ./project
# exit 16: unsupported-feature
```

`--volume-size` must have room for per-volume metadata and at least one block.

What to do:

- Use the default `--block-size`, `--chunk-size`, and `--envelope-size` unless
  you need a specific profile.
- Keep `--chunk-size <= --envelope-size`.
- Increase very small `--volume-size` values.
- Large regular-file input sets are supported. The writer emits multiple
  IndexShard objects and directory-hint shards when the v0.41 layout requires
  them.
- If `tzap create` still returns `unsupported-feature`, check the exact resource
  choice in the diagnostic and the additional boundaries below.

## Bootstrap sidecars and multi-volume inputs

Bootstrap sidecars are created and consumed only with single-volume CLI paths:

```sh
tzap create \
  --keyfile project.key \
  --bootstrap-out archive.tzap.bootstrap \
  -o archive.tzap \
  ./project

tzap list \
  --keyfile project.key \
  --bootstrap archive.tzap.bootstrap \
  archive.tzap
```

Do not request `--bootstrap-out` while creating multi-volume output:

```sh
tzap create \
  --keyfile project.key \
  --volumes 2 \
  --bootstrap-out archive.tzap.bootstrap \
  -o archive.tzap \
  ./project
# exit 16: unsupported-feature
```

Do not combine `--bootstrap` with a multi-volume open input set:

```sh
tzap list \
  --keyfile project.key \
  --bootstrap archive.tzap.bootstrap \
  archive.tzap.000 \
  --volume archive.tzap.001
# exit 16: unsupported-feature
```

This is a preflight CLI rejection: it happens before archive paths, sidecar
paths, or key material are read. The diagnostic says multi-volume inputs with
`--bootstrap` are unsupported and tells callers to pass volume files without the
sidecar.

What to do:

- For single-volume workflows, use `--bootstrap-out` on create and `--bootstrap`
  on list, verify, or extract when the sidecar is useful.
- For multi-volume workflows, pass the available volume files and omit
  `--bootstrap-out` and `--bootstrap`.

## Root-authenticated v41 archives

The core library and CLI can create and verify root-authenticated v41 archives
with the Ed25519 helper profile or an X.509 certificate profile. CLI Ed25519
signing uses a 32-byte signing seed and writes the derived 32-byte public key
through `signing-keygen`. CLI X.509 signing uses a leaf certificate plus its
private key, and verification uses supplied CA roots or OpenSSL default roots.

Example CLI flow:

```text
tzap signing-keygen \
  --secret-output root.signing.hex \
  --public-output root.public.hex

tzap create \
  --keyfile project.key \
  --signing-key root.signing.hex \
  -o archive.tzap \
  ./project

tzap create \
  --insecure-zero-key \
  --signing-key root.signing.hex \
  -o public.tzap \
  ./project

tzap create \
  --keyfile project.key \
  --signing-cert signer.pem \
  --signing-private-key signer.key \
  --signing-chain intermediate.pem \
  -o archive-x509.tzap \
  ./project

tzap verify \
  --keyfile project.key \
  --trusted-public-key root.public.hex \
  archive.tzap

tzap verify \
  --public-no-key \
  --trusted-public-key root.public.hex \
  archive.tzap

tzap verify \
  --keyfile project.key \
  --trusted-ca-cert root-ca.pem \
  archive-x509.tzap
```

Operational shape:

- `--signing-key` may be combined with raw-key, passphrase,
  `--insecure-zero-key`, dictionary, and normal volume options.
- `--signing-cert` uses the leaf certificate as signer identity and stores the
  RootAuth signature plus optional `--signing-chain` intermediates in the
  authenticator value.
- Key-holding RootAuth verification is requested by adding
  `--trusted-public-key` to ordinary `tzap verify`.
- X.509 RootAuth verification is requested by adding `--trusted-ca-cert` and/or
  `--trusted-system-roots` to ordinary `tzap verify`.
- X.509 verification reports the certificate subject, issuer, serial number,
  certificate SHA-256, verified chain subjects, trust anchor subject, and the
  signer-claimed signing time.
- Public no-key verification is requested with
  `--public-no-key --trusted-public-key`. It does not use `--keyfile`,
  `--password`, `--password-stdin`, `--insecure-zero-key`, or `--bootstrap`.
- X.509 RootAuth signing time is a signer-claimed timestamp embedded in the
  authenticator and used for certificate validity checks. It is not a trusted
  timestamp token, transparency log proof, notarization receipt, or revocation
  proof.
- Successful public no-key verification reports
  `public_data_block_commitment_verified`,
  `public_physical_completeness_unverified`, and
  `public_recovery_margin_unchecked`.

## Explicit no-secret convenience archives

`--insecure-zero-key` is an explicit no-secret mode for workflows that want a
convenience archive without managing archive key material. It uses raw-key mode
with a 32-byte all-zero master key, stores `KdfParams::Raw`, and does not run
Argon2.

Example:

```text
tzap create \
  --insecure-zero-key \
  --signing-key root.signing.hex \
  -o public.tzap \
  ./project

tzap verify \
  --insecure-zero-key \
  --trusted-public-key root.public.hex \
  public.tzap

tzap verify \
  --public-no-key \
  --trusted-public-key root.public.hex \
  public.tzap
```

Operational shape:

- `--insecure-zero-key` provides no confidentiality. Anyone can reconstruct the
  archive key.
- RootAuth signing can still authenticate archive integrity and signer
  provenance for zero-key archives.
- Readers must pass `--insecure-zero-key` explicitly on `list`, `extract`, and
  key-holding `verify`; there is no silent no-key fallback.
- `--public-no-key` remains separate and rejects `--insecure-zero-key` because
  it verifies public RootAuth commitments without opening archive contents.

## Archive stdin and file paths

For `verify`, `list`, and extract-all, `-` is archive stdin for the live
non-seekable profile: single-volume archive streams with a raw `--keyfile` or
`--insecure-zero-key`. Dictionary-compressed streams require a matching
`--bootstrap` sidecar. `--password-stdin` reads passphrases for file-backed
archives; it cannot share stdin with archive bytes.

Example:

```sh
cat archive.tzap | tzap verify --keyfile project.key -
cat archive.tzap | tzap list --keyfile project.key -
cat archive.tzap | tzap extract --keyfile project.key -C restored -
cat public.tzap | tzap verify --insecure-zero-key -
cat dictionary.tzap | tzap verify --keyfile project.key --bootstrap dictionary.tzap.bootstrap -
```

Unsupported stdin combinations:

- Selected-path extraction from `-` rejects with `unsupported-feature`.
- `extract - --stdout` rejects with `unsupported-feature`.
- Additional `--volume` inputs, passphrase modes, RootAuth external
  verification, public no-key verification, and multi-volume recovery are
  file-backed only.
- A real file named `-` can still be addressed as `./-`.

## File-backed random access

Key-holding `list`, `extract`, and `verify` open archive paths through the core
file-backed `ArchiveReadAt` reader. Opening authenticates the fixed headers and
terminal metadata, then reads index objects through positional reads. It does
not copy the whole archive into memory before an operation starts.

Operational shape:

- Default `tzap list` reads terminal and encrypted index metadata only.
- `tzap extract archive.tzap path/in/archive` reads the selected member's index
  metadata and payload envelopes. Unselected payload envelopes are not read as
  part of that targeted extraction.
- `tzap verify` is intentionally a full archive walk: it reads all relevant
  payload and metadata blocks to validate integrity.
- Public no-key verification still needs a complete volume set and validates
  public RootAuth data-block commitments rather than providing keyed extraction.

## Sequential reader and provisional output

The core reader exposes live `Read` APIs for single-volume archive streams:
`verify_non_seekable_stream`, `list_non_seekable_stream`,
`extract_non_seekable_stream_to_dir`, and bootstrap-sidecar variants for
dictionary streams. They authenticate payload envelopes as bytes arrive, retain
bounded metadata and terminal-tail state, and return only after terminal
metadata and index content conformance pass.

Live filesystem extraction stages output in a private directory under the
destination parent. The final destination is committed only after terminal
verification and metadata/content conformance succeed. On payload, metadata, or
terminal failure, staged output is removed and final paths are not published.

The older `sequential_extract_tar_stream` helper remains a whole-buffer
compatibility API for dictionary-free single-volume non-seekable archive images.
That helper returns decoded tar bytes only after the terminal ManifestFooter and
VolumeTrailer authenticate. It is not a live stdout or filesystem extraction
API, so callers do not receive provisional bytes.

`tzap extract --stdout` remains file-backed only. It first opens and
authenticates an archive from file paths, then writes one selected regular-file
member to stdout.

For opened file-backed archives, selected regular-file payloads are streamed
from the selected payload envelopes to stdout or a destination file. The core
keeps extraction memory bounded by the current envelope plaintext, current
decompressed frame, and small tar metadata buffers; it still reads/decrypts
whole payload envelopes because envelopes are the authenticated AEAD/FEC object.

Examples:

```sh
tzap extract --keyfile project.key --stdout project.tzap project/readme.txt
# stdout receives bytes only after project.tzap has opened and authenticated

tzap verify --keyfile project.key -
# reads a single-volume archive stream from stdin and reports after EOF
```

What to do:

- Use `tzap verify --keyfile project.key -`, `tzap list --keyfile project.key
  -`, `tzap extract --keyfile project.key -C restored -`, or the same commands
  with `--insecure-zero-key` for live single-volume archive streams.
- Provide `--bootstrap <path>` for dictionary-compressed archive streams.
- Store archive bytes in files when you need selected-path extraction,
  `--stdout`, passphrase KDF discovery, public no-key verification,
  RootAuth external verification, or multi-volume recovery.

## Create outputs are archive files, not stdout

The convenience core writer APIs, such as `write_archive`, return completed
volume buffers. The lower-level core writer also exposes a sink API used by the
CLI's path-backed stdin create modes; those paths stream archive bytes into
temporary files and publish the final output path or volume set only after
terminal metadata and optional RootAuth signing finish. The CLI does not expose
archive stdout, multipart-upload sink, or pipe output modes for `tzap create`.
`-o -` is rejected instead of being treated as an archive stdout sentinel.

Example:

```sh
tzap create --keyfile project.key -o - ./project
# exit 16: unsupported-feature
```

## Streaming create stdin modes

The CLI supports tar stdin create, known-size raw stdin create, and explicit
spooled raw stdin create with either one output file or a fixed `--volumes N`
output set. Unknown-size raw stdin is supported only through the explicit
plaintext spool path:

```sh
tar cf - ./project | tzap create --tar-stdin --keyfile project.key -o project.tzap -
tar cf - ./project | tzap create --tar-stdin --volumes 3 --keyfile project.key -o project.tzap -
cat disk.img | tzap create --raw-stdin --stdin-name disk.img --stdin-size "$(stat -c%s disk.img)" --keyfile project.key -o disk.tzap -
cat disk.img | tzap create --raw-stdin --stdin-name disk.img --stdin-size "$(stat -c%s disk.img)" --volumes 3 --keyfile project.key -o disk.tzap -
producer | tzap create --raw-stdin --stdin-name data/export.bin --spool-stdin --keyfile project.key -o export.tzap -
producer | tzap create --raw-stdin --stdin-name data/export.bin --spool-stdin --volumes 3 --keyfile project.key -o export.tzap -
```

Use a file-backed archive path with `-o`; `-o -` is not archive stdout. The
file-backed path is also much faster for later selected-file workflows because
seekable readers can use random access.

Known-size raw stdin (`--stdin-size`) is consumed once and archived as one
regular-file member in the standard tar-member v41 profile. With `--volumes N`,
the same member is striped across the fixed output volume set. Short stdin or
extra bytes after the declared size reject the create and remove the temporary
archive output or volume set.

Unknown-size raw stdin is supported only with explicit `--spool-stdin`. That
mode writes plaintext stdin to a restrictive temporary file, then archives that
file as a regular tar-member v41 member. With `--volumes N`, tzap waits for EOF,
uses the file-backed spool size as the known raw member size, and stripes the
member across the fixed output volume set. The spool is removed after normal
success or normal failure, but the plaintext exists on local disk while the
command is running. The current CLI has no `--max-spool-size` flag, so the OS
temp directory must be able to hold the full raw stream. A hard kill, process
abort, or host crash can leave the plaintext temp file behind in the OS temp
directory.

The no-spool unknown-size raw profile remains reserved for future support:

```sh
producer | tzap create --raw-stdin --stdin-name data/export.bin --keyfile project.key -o export.tzap -
```

That accepted-looking no-spool raw stdin shape exits with
`16 unsupported-feature` until `raw_stream_v1` lands. Adding `--volumes > 1`
does not change that; no-spool unknown-size raw multi-volume remains future
work.

The following combinations are rejected before stdin payload bytes, keyfiles,
dictionaries, or ordinary input paths are read:

- `--password` or `--password-stdin` with `--tar-stdin` or `--raw-stdin`
- `--dictionary` with `--tar-stdin` or `--raw-stdin`
- `--volumes > 1` with no-size/no-spool `--raw-stdin`
- `--volume-size` with stdin create modes
- `--volume-loss-tolerance > 0` with stdin create modes
- ordinary input paths mixed with stdin create modes; use exactly one input
  path, `-`
- `-o -`; create output must remain a path-backed archive file

Raw stdin stores one archive member and therefore requires `--stdin-name PATH`.
`--stdin-size SIZE` declares a known raw stdin length. `--spool-stdin` is valid
only with unknown-size `--raw-stdin`; combining it with `--stdin-size` rejects.

Sidecar output is also file-path based:

```sh
tzap create \
  --keyfile project.key \
  --bootstrap-out - \
  -o archive.tzap \
  ./project
# exit 16: unsupported-feature
```

What to do:

- Write archive volumes to file paths, then copy or upload those files with
  tooling appropriate for the destination.
- Treat true append-only or multipart create output as a future writer API
  feature, not as behavior of the current CLI.

## Empty directory inputs

The current CLI scanner descends into directory inputs and archives regular file
members. It does not emit standalone directory FileEntries, so empty directories
are omitted from the created archive.

Example:

```sh
mkdir -p project/empty
tzap create --keyfile project.key -o project.tzap ./project
tzap list --keyfile project.key project.tzap
# project/empty is not listed unless it contains a regular file
```

What to do:

- Add a regular placeholder file if preserving an otherwise empty directory is
  required.

## Tar metadata profile

The current v0.41 CLI create path emits regular-file tar member groups. Archive
paths are normalized safe relative UTF-8 paths using `/` separators. Long paths
and non-ASCII paths are represented with a path-specific local PAX `path` record
inside the same member group as the file it modifies. The writer does not emit
global PAX headers, global GNU state, or the POSIX two-zero-block tar
end-of-archive marker into the encrypted tzap tar stream.

The supported reader profile is:

- ustar regular files, directories, symlinks, and hardlinks after safe-path
  validation;
- local PAX `path`, `linkpath`, and `size` records for the following main entry;
- local GNU long name and long link records for the following main entry;
- ustar mode and integer mtime parsed from the main tar header, exposed by
  list/API metadata, and applied to restored regular files when the platform
  filesystem API accepts them.

Filesystem extraction writes file payloads and supported links safely under the
destination root. It does not currently claim ownership, xattr, ACL, sparse-file,
nanosecond timestamp, or global tar-state restoration. Mode or mtime application
failures are reported as degraded metadata diagnostics.

Unsupported local metadata is reported as degraded metadata instead of looking
fully successful. `tzap list --long`, `tzap list --json`, `tzap verify`, and
payload-reading `tzap extract` operations write diagnostics such as:

```text
tzap: degraded-metadata: path/in/archive: gnu-sparse: unsupported sparse-file PAX metadata was ignored
```

Global PAX headers and global GNU state are rejected as malformed archive state.
GNU sparse entry records are rejected; GNU sparse PAX keys, xattr/ACL PAX keys,
PAX timestamp precision keys, and other unsupported local PAX keys are surfaced
through degraded metadata diagnostics. The global `--quiet` flag suppresses
success summaries where applicable; it is not a best-effort metadata-warning
mode.

Library callers that only need index paths and payload sizes may use
`list_index_entries` or `lookup_index_entry`. Library callers that only need
bytes may use `extract_file`, which is explicitly payload-only. Callers that
surface metadata fidelity should use `list_files`, `extract_member`,
`extract_file_with_diagnostics`, or `extract_file_to`.

## Cloud directory-prefix optimization

The v0.41 spec defines a cloud/object-store optimized directory-prefix mode
that requires directory hints even for small archives. The current CLI/API does
not expose that mode and does not claim optimized directory-prefix operations.
Directory hints are emitted automatically for large regular-file archives when
the v0.41 threshold requires them.

Example:

```sh
tzap create --keyfile project.key -o project.tzap ./project
# no --cloud-directory-prefix or forced-hints mode exists today
```

What to do:

- Use exact-path `list`, `verify`, and `extract` operations with the current
  CLI.
- Treat future cloud directory-prefix optimization as a separate product
  feature that must force directory hints below the large-archive threshold.

## Multi-volume recovery budget

Recovery capacity is chosen when the archive is created. A volume can be omitted
only when the archive was written with enough recovery budget for that loss.
The default reader behavior is strict about identity: it authenticates each
supplied volume, rejects duplicate authenticated `volume_index` values even when
the bytes are identical, and does not expose a duplicate-copy recovery mode.

Recovery modes in the current CLI/API are:

- Default strict open: all supplied headers, CryptoHeaders, and trailers must
  authenticate and match their stripe position; at least one ManifestFooter
  authority must authenticate for random-access bootstrap; BlockRecords must be
  structurally valid and match their stripe position; duplicate volume indexes
  reject.
- Missing-volume recovery: automatic only when the number of omitted volumes is
  no greater than `volume_loss_tolerance` and the per-object FEC records can
  repair the missing shards.
- Bit-rot repair: CRC-failed BlockRecords are treated as erasures and repaired
  only while the affected object stays within its parity budget. Authenticated
  payload tamper with a recomputed CRC still fails AEAD/HMAC before plaintext is
  released.
- Duplicate-copy recovery: not implemented or claimed. Supply at most one file
  for each authenticated volume index.

Example with one recoverable missing volume:

```sh
tzap create \
  --keyfile project.key \
  --volumes 3 \
  --volume-loss-tolerance 1 \
  -o project.tzap \
  ./project

tzap verify --keyfile project.key project.tzap.000 project.tzap.002
# success when the missing volume is within the configured tolerance
```

Example without enough recovery budget:

```sh
tzap create \
  --keyfile project.key \
  --volumes 2 \
  --bit-rot-buffer-pct 0 \
  -o project.tzap \
  ./project

tzap extract \
  --keyfile project.key \
  --directory restored \
  project.tzap.001 \
  project/file.txt
# exit 11: corrupt-archive, with a missing-volume diagnostic
```

What to do:

- Set `--volume-loss-tolerance N` to the number of whole volumes the archive
  should survive losing.
- Keep at least `N + 1` volumes available for recovery.
- Do not pass duplicate volume files as a recovery strategy; keep one trusted
  copy per volume index.
- Use `tzap verify` after copying, uploading, or moving volume sets.

Single-volume trusted bootstrap sidecars can recover random-access metadata
authority when that archive's terminal ManifestFooter/VolumeTrailer material is
corrupt or absent. Without a trusted sidecar, corrupt or missing terminal
ManifestFooter copies are corruption, not a recoverable condition.
Multi-volume archives can use another authenticated ManifestFooter copy when
one volume's footer copy is corrupt.
