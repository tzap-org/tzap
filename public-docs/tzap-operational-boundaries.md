# tzap operational boundaries

This document keeps operator-facing boundary cases out of the project README.
The README is for the product promise, installation, and quick starts; this file
is for exact CLI behavior when a command asks for a shape outside the current
writer or reader path.

## Unsupported archive revision

Readers inspect the fixed archive header before applying revision-specific
layout rules. If an archive was written by a newer tzap format revision than
the installed reader supports, `tzap` exits with `12 unsupported-revision`
instead of reporting a wrong key or corrupt archive.

Example with a future archive revision:

```sh
tzap list --keyfile project.key future-v45.tzap
# exit 12: unsupported-revision
```

What to do:

- Upgrade tzap or use a reader that supports the archive's
  `volume_format_rev`.
- Do not repair, rewrite, or re-save the archive with the older reader.
- Treat this as a reader capability mismatch, not as evidence that the key,
  passphrase, or archive bytes are bad.
- Automation should key on exit code `12` / label `unsupported-revision` and
  surface the required reader upgrade action to the operator.
- `tzap verify --json` does not emit partial authentication, decryption, or
  RootAuth status fields for unsupported revisions. Its error object is limited
  to the observed revision, supported reader maximum, and upgrade action.

## Writer shape validation

The writer validates archive layout choices before writing bytes. If a request
cannot produce a valid v0.44 archive with this implementation, `tzap` exits with
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
  IndexShard objects and directory-hint shards when the v0.44 layout requires
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
  archive.vol000.tzap \
  --volume archive.vol001.tzap
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

## Root-authenticated v44 archives

The core library and CLI can create and verify root-authenticated v44 archives
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
  --no-encryption \
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
  `--no-encryption`, dictionary, and normal volume options.
- `--signing-cert` uses the leaf certificate as signer identity and stores the
  RootAuth signature plus optional `--signing-chain` intermediates in the
  authenticator value.
- Key-holding RootAuth verification is requested by adding
  `--trusted-public-key` to ordinary `tzap verify`.
- X.509 RootAuth verification is requested by adding `--trusted-ca-cert` and/or
  `--trusted-system-roots` to ordinary `tzap verify`.
- X.509 verification reports the certificate subject, issuer, serial number,
  certificate SHA-256, verified chain subjects, trust anchor subject, signature
  scheme, signer-claimed signing time, chain validation time, and verifier
  policy labels.
- Public no-key verification is requested with `--public-no-key` plus
  `--trusted-public-key`, `--trusted-ca-cert`, or `--trusted-system-roots`. It
  does not use `--keyfile`, `--password`, `--password-stdin`, or `--bootstrap`.
- X.509 RootAuth signing time is a signer-claimed timestamp embedded in the
  authenticator. Verification uses verifier current time for certificate
  validity checks unless a future trusted-timestamp profile supplies separate
  evidence. The signer-claimed time is not a trusted timestamp token,
  transparency log proof, notarization receipt, or revocation proof.
- Successful public no-key verification reports
  `public_data_block_commitment_verified`,
  `public_physical_completeness_unverified`, and
  `public_recovery_margin_unchecked`.

## Explicit plaintext archives

`--no-encryption` is the v44 mode for workflows that intentionally publish
archive payloads and metadata without archive key material. It sets
`aead_algo = None`, `kdf_algo = None`, and uses unkeyed v44 integrity digests
for fixed metadata instead of HMAC.

Example:

```text
tzap create \
  --no-encryption \
  --signing-key root.signing.hex \
  -o public.tzap \
  ./project

tzap verify \
  --trusted-public-key root.public.hex \
  public.tzap

tzap verify \
  --public-no-key \
  --trusted-public-key root.public.hex \
  public.tzap
```

Operational shape:

- `--no-encryption` provides no confidentiality. Anyone with the archive bytes
  can read payloads and metadata.
- RootAuth signing can still authenticate archive integrity and signer
  provenance for plaintext archives.
- `tzap list`, `tzap extract`, and ordinary `tzap verify` open unencrypted
  archives without `--keyfile`, `--password`, or `--password-stdin`.
- `--public-no-key` remains separate because it verifies public RootAuth
  commitments without opening archive contents.
- The old `--insecure-zero-key` flag was removed in v43 and now exits with a
  usage error; use `--no-encryption` for plaintext archives.

## Archive stdin and file paths

For `verify`, `list`, and extract-all, `-` is archive stdin for the live
non-seekable profile: single-volume archive streams with a raw `--keyfile` or
no key for an unencrypted archive. Dictionary-compressed streams require a matching
`--bootstrap` sidecar. `--password-stdin` reads passphrases for file-backed
archives; it cannot share stdin with archive bytes.

Example:

```sh
cat archive.tzap | tzap verify --keyfile project.key -
cat archive.tzap | tzap list --keyfile project.key -
cat archive.tzap | tzap extract --keyfile project.key -C restored -
cat public.tzap | tzap verify -
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

Recovery order for the core file-backed key-holding reader is:

1. Locate enough layout authority from physical startup metadata, terminal CMRA,
   locators, or an allowed bootstrap authority.
2. Repair and validate critical metadata before trusting payload locations:
   startup headers, CMRA rows, terminal metadata, IndexRoot, index shards,
   directory hints, and dictionary metadata when present.
3. Build the archive map from the repaired metadata, including block size, slot
   boundaries, object extents, parity classes, and file indexes.
4. Repair the main payload objects within their object-local FEC budget, then
   authenticate/decrypt/decompress before data is returned or written.

This sequencing lives in `tzap-core`, not only the CLI wrapper. Downstream
projects using the normal key-holding open, verify, list, extract, and
file-backed `ArchiveReadAt` APIs benefit from the same repair behavior.

## Verify repaired copies

Key-holding `tzap verify` can write repaired sibling copies for volumes that
contain recoverable BlockRecord damage. For file-backed v44 inputs, this
includes CRC failures and malformed fixed slots such as a damaged `TZBK` marker
or reserved BlockRecord bytes after `tzap` has recovered the archive layout:

```sh
tzap verify --keyfile project.key --write-repaired archive.tzap
# writes archive.repaired.tzap when recoverable damage was found

tzap verify --keyfile project.key --write-repaired archive.vol003.tzap
# writes archive.repaired.vol003.tzap when that volume had recoverable damage
```

Operational shape:

- Original archive files are never modified.
- Only volumes with repaired BlockRecords are copied and patched.
- Existing repaired output paths are not overwritten.
- `--write-repaired` requires key-holding, file-backed verify.
- `--write-repaired` is rejected with archive stdin, `--public-no-key`, and
  `--bootstrap`.
- A complete volume set is required for repaired output. Missing-volume
  recovery can prove data is still recoverable, but it does not synthesize a
  replacement archive volume in this mode.

What to do:

- Run ordinary `tzap verify` first when you only need an integrity check.
- Add `--write-repaired` when verify succeeds through recovery and you want a
  clean sibling file to replace the damaged volume manually.
- For bootstrap-assisted single-volume damage, extract and recreate the archive
  until bootstrap repair output is added as a separate feature.

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
  -`, `tzap extract --keyfile project.key -C restored -`, or omit the archive
  key flags for unencrypted live single-volume archive streams.
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
regular-file member in the standard tar-member v44 profile. With `--volumes N`,
the same member is striped across the fixed output volume set. Short stdin or
extra bytes after the declared size reject the create and remove the temporary
archive output or volume set.

Unknown-size raw stdin is supported only with explicit `--spool-stdin`. That
mode writes plaintext stdin to a restrictive temporary file, then archives that
file as a regular tar-member v44 member. With `--volumes N`, tzap waits for EOF,
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

The current v0.44 CLI create path emits regular-file tar member groups. Archive
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

The v0.43 spec defines a cloud/object-store optimized directory-prefix mode
that requires directory hints even for small archives. The current CLI/API does
not expose that mode and does not claim optimized directory-prefix operations.
Directory hints are emitted automatically for large regular-file archives when
the v0.43 threshold requires them.

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

- Default strict open: recovery-enabled file-backed key-holding inputs recover
  startup metadata from terminal CMRA before trusting physical `VolumeHeader` or
  `CryptoHeader` copies; zero-budget archives keep strict physical-prefix error
  reporting. At least one terminal or CMRA-recovered ManifestFooter authority
  must authenticate for random-access bootstrap; BlockRecords must match their
  stripe position, and malformed known fixed slots are treated as repair
  erasures within the configured FEC budget; duplicate volume indexes reject.
- Missing-volume recovery: automatic only when the number of omitted volumes is
  no greater than `volume_loss_tolerance` and the per-object FEC records can
  repair the missing shards.
- Bit-rot repair: damaged physical headers on recovery-enabled archives, CMRA
  header/row slots, CRC-failed BlockRecords, and malformed known fixed
  BlockRecord slots are treated as erasures when an authenticated or CRC-valid
  recovery authority establishes the expected slot boundaries. Repair succeeds
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

tzap verify --keyfile project.key project.vol000.tzap project.vol002.tzap
# success when the missing volume is within the configured tolerance
```

When the archive files use the CLI volume naming pattern, such as
`project.vol000.tzap`, passing any one volume discovers matching siblings in the
same directory. Use explicit additional archive paths when the volume files live
outside that directory or when you intentionally want a partial input set.

Example without enough recovery budget:

```sh
tzap create \
  --keyfile project.key \
  --volumes 2 \
  --volume-loss-tolerance 0 \
  --bit-rot-buffer-pct 0 \
  -o project.tzap \
  ./project

tzap extract \
  --keyfile project.key \
  --directory restored \
  project.vol001.tzap \
  project/file.txt
# exit 11: corrupt-archive, with a missing-volume diagnostic
```

What to do:

- Set `--volume-loss-tolerance N` to the number of whole volumes the archive
  should survive losing.
- File-backed multi-volume create defaults to `N = 1`; pass
  `--volume-loss-tolerance 0` when a striped archive should not spend parity on
  whole-volume loss.
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
