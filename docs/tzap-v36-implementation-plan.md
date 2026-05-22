# tzap v0.36 Reference Implementation Plan

This document is the execution plan for the Rust reference implementation of
the tzap v0.36 archive format specification.

Implementation target:

- Spec: `specs/tzap-format-revisedv36.md`
- Workspace: Rust Cargo workspace
- Core crate: `crates/tzap-core`
- CLI crate: `crates/tzap-cli`
- License: Apache-2.0

## Goals

1. Build a clear, auditable reference implementation for v0.36.
2. Keep format logic in `tzap-core`; keep `tzap-cli` thin.
3. Prefer small vertical slices with executable checkpoints.
4. Treat the spec as the authority, especially around reject conditions.
5. Wrap third-party crates behind tzap-owned modules where wire semantics matter.

## Non-Goals For The First Pass

1. Highest compression performance.
2. Optimized cloud/object-store range planning.
3. Parallel encoding/decoding.
4. Backward compatibility with pre-v0.36 drafts.
5. Stabilized public Rust API beyond what the CLI needs.

## Implementation Principles

- **Spec-first validation:** parse structures into bounded raw forms, validate
  all fixed fields and caps, then expose typed values.
- **No implicit trust:** VolumeHeader, CryptoHeader, ManifestFooter,
  VolumeTrailer, BootstrapSidecarHeader, IndexRoot, and IndexShard each get
  explicit validation functions.
- **Codec isolation:** zstd, AEAD, KDF, FEC, tar, and path handling each live
  behind small internal modules.
- **Conformance gates:** an archive writer is not called conformant until it
  emits all mandatory v0.36 fields, algorithms, FEC profile, HMACs, AEADs, and
  trailer/footer structures.
- **Reject tests matter:** most serious bugs in archive formats are acceptance
  bugs, not happy-path failures.

## Proposed Module Layout

Inside `crates/tzap-core/src`:

- `format.rs`: constants, algorithm IDs, fixed sizes, shared errors.
- `wire/`: endian parsing, fixed structs, TLV parsing, raw byte validators.
- `crypto/`: KDF, HKDF schedule, HMAC domains, AEAD object operations.
- `compression/`: zstd frame encode/decode, dictionary handling, exact-frame
  validation.
- `padding.rs`: suffix-marker padding encode/decode.
- `block.rs`: BlockRecord parsing, block ordering, kind/flag validation.
- `fec/`: ReedSolomonGF16 profile, parity generation, repair, vectors.
- `metadata/`: ManifestFooter, VolumeTrailer, IndexRoot, IndexShard,
  DirectoryHintTable, BootstrapSidecarHeader.
- `tar_model/`: tar member group construction, metadata profile, safe path
  normalization, extraction safety rules.
- `writer/`: archive creation pipeline.
- `reader/`: open, list, verify, random extract, sequential extract.
- `fixtures/`: test fixture builders and mutation helpers.

Inside `crates/tzap-cli/src`:

- `main.rs`: argument parsing and dispatch.
- `commands/`: create, extract, list, verify command adapters.

## Milestone 0: Workspace Baseline

Status: complete.

Deliverables:

- Cargo workspace with `tzap-core` and `tzap-cli`.
- Apache-2.0 metadata and license.
- Initial CLI command shape.
- Initial v0.36 constants and algorithm IDs.

Acceptance:

- `cargo check` passes.
- README identifies this repo as the Rust reference implementation.

## Milestone 1: Wire Primitives And Fixed Structures

Status: complete.

Purpose: make the binary layout executable without crypto/compression yet.

Deliverables:

- Little-endian read/write helpers.
- Fixed-size parser/serializer for:
  - `VolumeHeader`
  - `CryptoHeaderFixed`
  - `BlockRecord`
  - `ManifestFooter`
  - `VolumeTrailer`
  - `BootstrapSidecarHeader`
- CRC32C verification for unauthenticated fixed headers.
- Reserved-field and magic-field validation.
- Reader caps data model.

Acceptance:

- Unit tests parse valid fixed structures.
- Mutation tests reject bad magic, bad lengths, non-zero reserved fields, bad
  CRC, unsupported `volume_format_rev`, and invalid algorithm IDs.

Completed implementation:

- `crates/tzap-core/src/wire.rs`
- Fixed parsers/serializers for VolumeHeader, CryptoHeaderFixed,
  BlockRecord, ManifestFooter, VolumeTrailer, and BootstrapSidecarHeader.
- Bounded CryptoHeader Extension TLV scanner.
- CRC32C checks for VolumeHeader, BlockRecord, and BootstrapSidecarHeader.
- v0.36 fixed-field validation for magic, version, reserved bytes, algorithm
  IDs, block flags, sidecar flags, and canonical sidecar layout.

## Milestone 2: Crypto Header, KDF, HMAC, And Key Schedule

Status: complete.

Purpose: authenticate the archive identity and derive all v0.36 keys.

Deliverables:

- Raw and Argon2id KDF parameter parsing.
- UTF-8 NFC passphrase handling.
- HKDF-SHA-256 subkey schedule.
- CryptoHeader HMAC verification and generation.
- HMAC domains for CryptoHeader, ManifestFooter, VolumeTrailer, and
  BootstrapSidecarHeader.
- Strict extension TLV parsing.

Acceptance:

- Test vectors for Raw and Argon2id modes.
- Reject tests for malformed KDF params, unsupported KDF algo, duplicate known
  extensions, forbidden extensions, unknown critical extensions, and HMAC
  mismatch.

Completed implementation:

- `crates/tzap-core/src/crypto.rs`
- Raw and Argon2id KdfParams parsing.
- NFC passphrase byte normalization.
- Raw master-key and Argon2id master-key derivation.
- Normative HKDF-SHA-256 subkey schedule.
- HMAC domains and verification helpers for CryptoHeader, ManifestFooter,
  VolumeTrailer, and BootstrapSidecarHeader.
- Whole CryptoHeader parse split into fixed header, KDF params, extension
  TLVs, HMAC-covered bytes, and header HMAC.
- Post-HMAC CryptoHeader extension semantic validation.

## Milestone 3: Padding, AEAD Objects, And Zstd Frame Codec

Status: complete.

Purpose: implement the authenticated object envelope used by payload and
metadata.

Deliverables:

- Suffix-marker padding encode/decode.
- AEAD object encrypt/decrypt for registered AEADs.
- Default AES-256-GCM-SIV path.
- Zstd frame codec for:
  - payload frames
  - metadata objects
  - dictionary object
- Exact metadata-frame validation:
  - one complete non-skippable zstd frame
  - no trailing bytes
  - no concatenated frames
  - decompressed size matches metadata

Acceptance:

- Padding edge-case tests, including exact-fit mandatory extra block.
- AEAD round-trip and tamper tests.
- zstd frame validity tests matching §28.1 corpus requirements.

Completed implementation:

- `crates/tzap-core/src/padding.rs`
- `crates/tzap-core/src/compression.rs`
- Suffix-marker padding encode/decode, including exact-fit extra block and
  wide-form parsing.
- AEAD nonce derivation and AAD construction.
- AEAD encrypt/decrypt helpers for AES-256-GCM-SIV, XChaCha20-Poly1305, and
  AES-256-GCM.
- Padded AEAD object encrypt/decrypt helper for later writer/reader slices.
- zstd one-frame compression/decompression wrapper with exact-frame validation
  and rejection for skippable frames, trailing bytes, and concatenated frames.

## Milestone 4: ReedSolomonGF16 FEC Profile

Status: complete.

Purpose: implement the exact v0.36 object-local FEC profile.

Deliverables:

- Complete: ReedSolomonGF16 module with spec-owned interface in
  `crates/tzap-core/src/fec.rs`.
- Complete: direct GF(2^16) arithmetic using primitive polynomial `0x1100B`
  with low reduction polynomial `0x100B`.
- Complete: Cauchy coefficient generation per §18.
- Complete: systematic parity generation.
- Complete: repair from any D available data/parity rows using GF(2^16)
  matrix inversion.
- Complete: shape validation for nonzero data shard count, even shard size,
  consistent shard sizes, enough available rows, and total shard count at or
  below 65,535.
- Complete: compatibility investigation for `reed-solomon-erasure`; not used
  because its core profile is Vandermonde-based rather than the v0.36 Cauchy
  profile.
- Complete: wire-profile vectors committed under tests for polynomial
  arithmetic, little-endian symbols, Cauchy parity bytes, repair behavior, and
  invalid shape rejection.

Acceptance:

- Core test suite passes with vectors proving polynomial, symbol byte order,
  Cauchy matrix, parity bytes, and repair behavior.
- Validation rejects odd block size, inconsistent shard sizes, too few
  available rows, zero data shards, and total shard count above 65,535.
- The parity vectors pin the v0.36 Cauchy/GF(2^16) profile so GF(2^8),
  Vandermonde, and wrong-polynomial implementations will not match.

Risk:

- Existing crates may not match the exact v0.36 wire profile. If not, implement
  the small required GF(2^16) profile directly in `tzap-core`.

## Milestone 5: Metadata Model And Index Validation

Status: complete.

Purpose: make the encrypted index structures real and searchable.

Deliverables:

- Complete: IndexRoot parser/serializer in `crates/tzap-core/src/metadata.rs`.
- Complete: IndexShard parser/serializer.
- Complete: DirectoryHintTable parser/serializer.
- Complete: ShardEntry hash-prefix candidate lookup algorithm with bounded
  collision-run scanning.
- Complete: FileEntry exact-path final-view lookup helper.
- Complete: Directory-prefix normalization and ancestor semantics.
- Complete: FileEntry and DirectoryHintEntry SHA-256 hash binding validation.
- Complete: canonical table cursor validation for IndexRoot, IndexShard, and
  DirectoryHintTable.
- Complete: FrameEntry and EnvelopeEntry structural validation, including
  exact shard-local frame/envelope sets and minimal FileEntry frame ranges.
- Complete: removed the unused `reed-solomon-erasure` dependency after M4
  implemented the exact GF(2^16) Cauchy profile directly.
- Complete: tests for empty IndexRoot parsing, single-shard file lookup, and
  resource-cap-bound hash-prefix scans.

Acceptance:

- Valid empty IndexRoot.
- Valid single-shard file lookup.
- Reject tests for count/offset mismatch, table overlap, unclaimed gaps,
  invalid hash bounds, duplicate rows, non-minimal FileEntry frame ranges, and
  unsafe directory-prefix lookup behavior.

## Milestone 6: Minimal Conformant Archive Writer

Status: complete.

Purpose: produce the first spec-conformant archive for a narrow case.

Scope:

- Single-volume.
- Dictionary-free.
- Small regular files.
- Default AES-256-GCM-SIV.
- ReedSolomonGF16 enabled.
- Authoritative ManifestFooter and VolumeTrailer.

Deliverables:

- Complete: Tar member group construction for small ustar regular files.
- Complete: zstd frame generation, one complete frame per member group.
- Complete: single payload envelope packing for small archives.
- Complete: BlockRecord emission with CRC and last-data flags via
  `wire::BlockRecord`.
- Complete: IndexShard and IndexRoot plaintext emission.
- Complete: ManifestFooter and VolumeTrailer emission with domain-separated
  HMACs.
- Complete: full HMAC/AEAD/suffix-padding/ReedSolomonGF16 path for payload,
  IndexShard, and IndexRoot objects.
- Complete: valid empty archive construction path.
- Complete: explicit M6 rejection guard for archives that would require
  directory hint shards or more than one IndexShard.
- Complete: writer smoke tests for empty archive bootstrap structures and M6
  scope guards.

Acceptance:

- Writer creates a valid empty archive.
- Writer creates a valid one-file archive.
- Reader can open, list, verify, and extract those archives.
- Mutating any authenticated byte causes clean rejection before plaintext
  release.

## Milestone 7: Minimal Reader, List, Verify, And Random Extract

Purpose: complete the first useful read path.

Deliverables:

- Seekable open algorithm from §17.1.
- Trailer-from-end lookup and optional trailing-garbage scan.
- ManifestFooter bootstrap.
- IndexRoot and IndexShard loading.
- Random file extraction.
- Full-archive verify for metadata and payload frame coverage.

Acceptance:

- `tzap list ARCHIVE`
- `tzap verify ARCHIVE`
- `tzap extract ARCHIVE path`
- Rejects wrong key, mixed volumes, corrupt trailer, corrupt footer, corrupt
  IndexRoot, corrupt IndexShard, corrupt payload, and non-authoritative
  ManifestFooter for random access.

## Milestone 8: Safe Extraction And Tar Metadata Profile

Purpose: make filesystem extraction conformant instead of library-default.

Deliverables:

- Path normalization and UTF-8 NFC checks.
- Platform-escape rejection set.
- No-follow ancestry checks.
- Hardlink target validation.
- Symlink escape behavior.
- Supported PAX/GNU metadata profile.
- Degraded metadata diagnostics.

Acceptance:

- Reject tests for absolute paths, `..`, empty components, backslash, colon,
  drive/UNC/device names, hardlink escapes, symlink escapes, global PAX state,
  and unsafe overwrite behavior.

## Milestone 9: Bootstrap Sidecar And Non-Seekable Sequential Read

Purpose: implement the v0.36 bootstrap decision matrix.

Deliverables:

- BootstrapSidecarHeader parser/serializer.
- Sidecar packed cursor validation.
- Sidecar HMAC and identity binding.
- Sidecar ManifestFooter handling.
- Sidecar IndexRoot BlockRecord handling.
- Sequential payload extraction for dictionary-free single-volume streams.
- Provisional-output handling model.

Acceptance:

- Sidecar can bootstrap non-seekable metadata.
- Dictionary-free sequential extraction works.
- Missing sidecar disables random access/listing on non-seekable inputs.
- Sidecar mutation tests reject bad flags, gaps, padding, trailing bytes,
  wrong volume index, non-authoritative footer, missing blocks, duplicate
  blocks, wrong kinds, and wrong last-data flag.

## Milestone 10: Dictionary Support

Purpose: implement zstd dictionary archives exactly as v0.36 defines them.

Deliverables:

- Dictionary object writer.
- Dictionary object reader.
- Payload frame compression with dictionary.
- Metadata compression without dictionary.
- Sidecar dictionary BlockRecord copy support.
- Non-seekable dictionary bootstrap behavior.

Acceptance:

- Dictionary archive create/list/extract/verify.
- Reader loads dictionary before payload frame decompression.
- Rejects `has_dictionary = 1` with missing/zero dictionary fields.
- Non-seekable dictionary archive rejects without required sidecar or buffers
  until dictionary bootstrap is complete.

## Milestone 11: Multi-Volume Striping And Recovery

Purpose: implement the multi-volume archive model and volume-loss recovery.

Deliverables:

- Block-to-volume striping.
- Concurrent/forward-only volume writing.
- Multi-volume open.
- Duplicate volume-index rejection.
- Volume-loss parity planning.
- Object repair using available volumes.

Acceptance:

- Create and read multi-volume archives.
- Recover from configured volume loss when parity allows.
- Reject mixed archive/session IDs.
- Reject duplicate authenticated volume indexes by default.
- Verify block index ordering, modulo placement, and missing global blocks.

## Milestone 12: CLI Hardening And UX

Purpose: make the reference implementation usable without hiding spec failures.

Deliverables:

- `tzap create`
- `tzap extract`
- `tzap list`
- `tzap verify`
- Password/keyfile handling.
- Bootstrap sidecar option.
- Clear diagnostic categories.
- Stable exit codes.

Acceptance:

- CLI smoke tests for all commands.
- Error messages distinguish wrong key, corrupt archive, unsupported revision,
  unsafe path, missing bootstrap, and degraded metadata.

## Milestone 13: Corpus, Mutation Tests, Fuzzing, And Interop

Purpose: lock down the reference implementation as the executable spec.

Deliverables:

- Golden fixtures.
- Mutation fixture generator.
- v0.36 §28.1 corpus coverage.
- `cargo fuzz` targets for parsers.
- Cross-platform path behavior tests.
- Round-trip property tests for writer/reader.

Acceptance:

- Every listed §28.1 case is represented or explicitly deferred with a tracked
  issue.
- Parser fuzz targets run without panics on malformed input.
- Golden fixtures remain stable across releases unless the spec changes.

## Recommended Execution Order

1. Milestone 1: wire primitives.
2. Milestone 2: CryptoHeader/KDF/HMAC.
3. Milestone 3: padding/AEAD/zstd.
4. Milestone 4: ReedSolomonGF16 vectors.
5. Milestone 5: metadata and index structures.
6. Milestone 6 and 7 together: first conformant single-volume archive.
7. Milestone 8: safe extraction.
8. Milestone 9: sidecar and sequential mode.
9. Milestone 10: dictionary.
10. Milestone 11: multivolume and recovery.
11. Milestone 12 and 13 continuously as CLI and corpus maturity.

## First Sprint Proposal

Focus: make the opening layer real.

Tasks:

1. Implement `wire` module with fixed-size little-endian parsing helpers.
2. Implement `VolumeHeader` parse/serialize/validate.
3. Implement algorithm ID validation and v0.36 conformance checks.
4. Implement `CryptoHeaderFixed` parser and bounded extension TLV scanner.
5. Add unit tests for valid and mutated headers.

Definition of done:

- `cargo test -p tzap-core wire` passes.
- `VolumeHeader` rejects bad magic, unsupported format version, unsupported
  `volume_format_rev`, bad CRC, non-canonical CryptoHeader offset, zero stripe
  width, out-of-range volume index, and non-zero reserved bytes.

## Key Risks

- **FEC exactness:** resolved in M4 by implementing the required GF(2^16)
  Cauchy wire profile directly in `tzap-core`.
- **Tar safety:** `tar` crate convenience extraction cannot be the conformance
  path. Safe extraction must be owned by tzap.
- **Zstd exact-frame validation:** high-level decompression may accept inputs
  that the spec must reject. Add lower-level validation if needed.
- **Path behavior:** Windows and Unix path safety must be host-independent
  where the spec says so.
- **Spec pressure:** implementation may reveal ambiguities. Track them as
  v0.37 candidates unless they block conformance.

## Conformance Milestones

- **Component-conformant:** wire, crypto, padding, zstd, and FEC modules pass
  their spec vectors.
- **Narrow archive-conformant:** single-volume, dictionary-free archives pass
  create/list/extract/verify.
- **Feature-conformant:** sidecar, dictionary, sequential mode, multivolume,
  and recovery are complete.
- **Reference-complete:** corpus, mutation tests, fuzzing, and diagnostics are
  mature enough for other implementations to compare against.
