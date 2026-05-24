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
with the Ed25519 helper profile. CLI signing uses a 32-byte Ed25519 signing seed
and writes the derived 32-byte public key through `signing-keygen`.

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

tzap verify \
  --keyfile project.key \
  --trusted-public-key root.public.hex \
  archive.tzap

tzap verify \
  --public-no-key \
  --trusted-public-key root.public.hex \
  archive.tzap
```

Operational shape:

- `--signing-key` may be combined with raw-key, passphrase, dictionary, and
  normal volume options.
- Key-holding RootAuth verification is requested by adding
  `--trusted-public-key` to ordinary `tzap verify`.
- Public no-key verification is requested with
  `--public-no-key --trusted-public-key`. It does not use `--keyfile`,
  `--password`, `--password-stdin`, or `--bootstrap`.
- Successful public no-key verification reports
  `public_data_block_commitment_verified`,
  `public_physical_completeness_unverified`, and
  `public_recovery_margin_unchecked`.

## Archive paths, not archive stdin

Archive inputs are opened from file paths. The current CLI does not expose `-`
as archive stdin, and it does not expose a streaming non-seekable archive input
mode. `--password-stdin` reads only the passphrase.

Example:

```sh
tzap list --keyfile project.key -
# exit 3: io, because "-" is treated as a literal file path
```

What to do:

- Store the archive bytes in a file and pass that path to `tzap`.
- Use `--bootstrap` only with a real single-volume archive path.

## Sequential reader and provisional output

The core reader exposes a whole-buffer helper for dictionary-free
single-volume non-seekable archive images. That helper returns decoded tar bytes
only after the terminal ManifestFooter and VolumeTrailer authenticate. It is not
a live stdout or filesystem extraction API, so callers do not receive
provisional bytes.

The CLI does not expose archive stdin or live non-seekable extraction. `tzap
extract --stdout` first opens and authenticates an archive from file paths, then
writes one selected regular-file member to stdout. The default filesystem
extractor also uses the opened authenticated archive; it does not stream
unauthenticated non-seekable bytes into the destination directory.

Examples:

```sh
tzap extract --keyfile project.key --stdout project.tzap project/readme.txt
# stdout receives bytes only after project.tzap has opened and authenticated

tzap verify --keyfile project.key -
# exit 3: io, because "-" is treated as a literal file path
```

What to do:

- Store archive bytes in a file before using the CLI.
- Treat live provisional stdout or staged filesystem extraction from a
  non-seekable archive stream as a future API, not current CLI behavior.

## Create outputs are archive files, not stdout

The current core writer is an in-memory archive artifact builder:
`write_archive` returns completed volume buffers, and the CLI then writes those
buffers to explicit archive paths. The CLI does not expose archive stdout,
append-only sink, multipart-upload sink, or pipe output modes for `tzap create`.
`-o -` is rejected instead of being treated as an archive stdout sentinel.

Example:

```sh
tzap create --keyfile project.key -o - ./project
# exit 16: unsupported-feature
```

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
fully successful. `tzap list`, `tzap verify`, and `tzap extract` write
diagnostics such as:

```text
tzap: degraded-metadata: path/in/archive: gnu-sparse: unsupported sparse-file PAX metadata was ignored
```

Global PAX headers and global GNU state are rejected as malformed archive state.
GNU sparse entry records are rejected; GNU sparse PAX keys, xattr/ACL PAX keys,
PAX timestamp precision keys, and other unsupported local PAX keys are surfaced
through degraded metadata diagnostics. The global `--quiet` flag suppresses
success summaries where applicable; it is not a best-effort metadata-warning
mode.

Library callers that only need bytes may use `extract_file`, which is explicitly
payload-only. Callers that surface metadata fidelity should use `list_files`,
`extract_member`, `extract_file_with_diagnostics`, or `extract_file_to`.

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
