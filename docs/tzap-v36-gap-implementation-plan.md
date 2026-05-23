# tzap v0.36 Gap Implementation Plan

Status: draft
Audience: tzap-core maintainers, tzap-cli maintainers, release owners, and
review agents
Primary spec: `specs/tzap-format-revisedv36.md`

## Purpose

This plan turns the current v0.36 implementation gap into concrete work. It is
not a marketing page. It is the engineering plan for closing, testing, or
explicitly deferring every area where the implementation, docs, and release
claims can drift from the v0.36 spec.

The rule for this document is simple: every spec obligation must eventually map
to one of these outcomes:

- implemented and covered by positive and negative tests
- intentionally unsupported at the CLI/API boundary with a stable diagnostic and
  a technical-doc example
- deferred with an owner-visible reason and no public claim that it works

## Current Baseline

Recent work closed important writer gaps:

- multiple IndexShard objects are now emitted instead of rejecting large file
  tables
- directory hint shards are emitted for large regular-file archives
- FrameEntry flags are serialized with the exact schema field, not a byte
  shortcut
- payload, IndexShard, and directory-hint objects are split before object/FEC
  limits
- full verify streams large archives instead of loading the whole reconstructed
  tar stream under the legacy cap
- `tzap create --bootstrap-out` is guarded as single-volume only

Those fixes mean older plan text and some operational docs are stale. They do
not prove full v0.36 conformance. The remaining gaps are mostly around live
sequential reader surfaces, recovery edge cases, broader mutation/fuzz coverage,
and explicit release gates.

## Priority Model

- P0: must be fixed or explicitly documented before any "v0.36 conformant"
  release claim.
- P1: needed for full spec coverage, but may be deferred if the API/CLI does
  not claim the feature and has tests for the unsupported path.
- P2: scale, interop, fuzzing, and release-hardening work that should be done
  before a broad public release.

## Gap Summary

| ID | Area | Current status | Priority | Required outcome |
| --- | --- | --- | --- | --- |
| G01 | Documentation and plan drift | complete | P0 | docs match actual code and no README drawbacks |
| G02 | Conformance matrix | complete | P0 | map all writer/reader obligations to code/tests/status |
| G03 | True streaming writer | complete/unsupported boundary | P0/P1 | no true streaming claim; future sink model is a new feature |
| G04 | Sequential non-seekable reader | complete/unsupported live boundary | P0/P1 | whole-buffer safe helper; no live provisional-output claim |
| G05 | Bootstrap sidecar authority | complete | P0 | sparse sections and authority precedence match spec |
| G06 | IndexRoot/dictionary sizing | complete | P0 | choose metadata FEC class before CryptoHeader HMAC |
| G07 | Directory hints and directory entries | complete | P0/P1 | exact hint map, directory entries, and cloud claims settled |
| G08 | Tar metadata profile | complete | P1 | supported metadata profile documented and tested |
| G09 | Recovery and duplicate volumes | partial | P1 | default rejection and recovery modes are explicit |
| G10 | CLI/API boundaries | partial | P0 | help/docs/tests do not imply unsupported behavior |
| G11 | v36 corpus coverage | complete | P0 | every section 28.1 case tracked as covered/missing/deferred |
| G12 | Fuzzing and mutation harness | partial | P1/P2 | fuzz targets and smoke gates cover parsers and mutations |
| G13 | Interop and release gate | missing | P0/P2 | release checklist blocks unverified conformance claims |

## G01 - Documentation and Plan Drift

Status: complete.

Spec anchors:

- v0.36 conformance section
- CLI synopsis section
- bootstrap sidecar sections
- operational limits/resource caps

Original gap:

- `docs/tzap-v36-implementation-plan.md` had stale milestone text for
  shard-heavy writer shapes that the writer now supports.
- The same plan described bootstrap sidecar emission too narrowly and needed to
  make the current CLI boundary explicit: `--bootstrap-out` is single-volume
  only.
- `docs/tzap-operational-boundaries.md` described large regular-file writer
  tables as unavailable even though that path now emits the required metadata.
- `docs/tzap-cli-reference.md` needed to separate implemented behavior from
  intentionally unsupported combinations.
- README should remain product/marketing oriented. Do not move drawbacks back
  into README.

Completed implementation:

1. Updated `docs/tzap-v36-implementation-plan.md` so completed milestones reflect
   the current writer:
   - multi-IndexShard support: complete
   - directory hints for large regular-file archives: complete
   - cap-aware metadata splitting: complete
   - bootstrap sidecar: single-volume CLI boundary
2. Updated `docs/tzap-operational-boundaries.md` with precise examples:
   - bootstrap sidecars with multi-volume open input sets are currently not a
     supported CLI path unless G05/G10 implement it
   - empty directory entries are omitted by current CLI/API scope
   - true archive stdin/live non-seekable streaming is not exposed; G04 closes
     this as an unsupported live-output boundary
3. Updated `docs/tzap-cli-reference.md`:
   - state that `--bootstrap-out` is single-volume only
   - state whether archive stdin is unsupported or implemented
   - state how multi-volume recovery depends on tolerance and FEC budget
4. Added docs tests so stale unsupported text cannot reappear unnoticed.

Tests added:

- CLI docs tests asserting `--bootstrap-out` single-volume boundary appears in
  technical docs, not in README.
- Docs tests asserting old "multi IndexShard unsupported" language is gone.
- Docs tests asserting technical docs include concrete examples for each
  unsupported feature.

Done criteria met:

- No technical doc says large regular-file tables are unsupported.
- No README section lists engineering drawbacks.
- Every unsupported CLI combination has a stable diagnostic and a docs example.

## G02 - Conformance Matrix and Evidence Table

Spec anchors:

- v0.36 writer obligations 1 through 38
- v0.36 reader obligations 1 through 31

Status: complete.

Original gap:

The repo has tests and a v36 implementation plan, but there is no durable matrix
that proves each conformance obligation has:

- code owner/entry point
- positive test
- mutation or negative test
- CLI/API boundary, if unsupported
- release status

Completed implementation:

1. Added `docs/tzap-v36-conformance-matrix.md`.
2. Added one row per writer obligation `W01` through `W38` and one row per
   reader obligation `R01` through `R31`.
3. Each row includes:
   - obligation ID
   - short spec requirement
   - code path
   - positive tests
   - negative/mutation tests
   - status: `complete`, `partial`, `unsupported`, or `deferred`
   - notes / follow-up issue
4. Marked broad or not-yet-claimed areas honestly:
   - true streaming writer: `W12` unsupported, `W38` complete for the
     in-memory writer, and no public sink-writer claim
  - live sequential/provisional output: `R04` and `R20` remain `partial`,
    while G04 is closed only as a current-release unsupported-live boundary
   - sparse sidecar authority: `R16` complete
   - directory entries and cloud mode: `W14` and `R31` complete by current
     CLI/API scope
   - tar metadata profile: `W13`, `R13`, and `R23` complete for the documented
     profile
   - duplicate-copy recovery: `R27` partial with the explicit mode deferred
   - fuzz and release gates: tracked in the non-section-29 release evidence
     table
5. Added `.gitignore` whitelist for the new tracked docs file.

Tests added:

- `milestone11_v36_conformance_matrix_covers_section_29_obligations` fails if
  the matrix is missing any `W01` through `W38` or `R01` through `R31` row, or
  if an obligation row appears more than once.
- `milestone11_v36_conformance_matrix_uses_reviewable_statuses` fails if a
  conformance row uses any status outside `complete`, `partial`, `unsupported`,
  or `deferred`.

Done criteria:

- Reviewers can answer "what is missing?" from one matrix, without reading the
  whole codebase.

## G03 - True Streaming Writer and Sink Model

Status: complete (unsupported boundary).

Spec anchors:

- single-stream streaming mode
- writer obligations 1, 12, 24, and 38
- writer sequence and no seek-back rules

Completed G03 scope:

The writer creates valid archive bytes in memory and returns
`WrittenArchive { bytes, volumes }`. It does not expose a sink-based writer that
proves true append-only streaming behavior. The current implementation may write
the final artifact in forward order, but it can still buffer the whole tar
stream, metadata, and output in memory before handing bytes to the caller.

That is not the same as a conforming true streaming writer.

G03 closes by choosing Option B: the current core writer remains an in-memory
archive artifact builder, and every public README/API/CLI surface must avoid
claiming true streaming, append-only sink, pipe, or multipart create output.

Implemented work:

1. Public writer API documentation states that `WrittenArchive` is produced by
   an in-memory archive artifact builder, not a sink-based streaming writer.
2. CLI create output is guarded:
   - `tzap create -o - ...` rejects before writing output bytes
   - `tzap create --bootstrap-out - ...` rejects before writing archive or
     sidecar bytes
   - both paths return `16 unsupported-feature`
3. README marketing language no longer claims single-pass, append-only,
   pipe-like, streaming storage, or multipart-upload create behavior.
4. Technical docs carry exact examples in `docs/tzap-operational-boundaries.md`
   and `docs/tzap-cli-reference.md`.
5. The conformance matrix marks true non-reopenable sink behavior as an
   unsupported boundary while keeping the current in-memory metadata-FEC
   planning evidence tied to W24/W38.

Tests:

- `cli_smoke::cli_create_rejects_archive_stdout_output_sentinel_before_writing`
- `cli_smoke::cli_create_rejects_sidecar_stdout_output_sentinel_before_writing`
- `milestone11_docs::milestone11_docs_pin_current_g03_streaming_boundary`
- `writer::tests::written_archive_authenticates_final_index_root_fec_class`

Deferred future sink-writer work:

- Define explicit sink capabilities: seekable file sink, append-only single
  sink, append-reopenable multi-volume sink, and any externally multiplexed
  multi-stream sink.
- For fully non-reopenable single-sink streaming, force `stripe_width = 1`,
  force `volume_loss_tolerance = 0`, require bootstrap sidecar emission when
  `has_dictionary = 1`, and choose IndexRoot/dictionary FEC maxima before the
  CryptoHeader HMAC.
- For non-reopenable multi-volume streaming without external multiplexing,
  reject before emitting any archive bytes or spool to bounded local storage.
- For unknown-size input sets, pre-scan, spool to a bounded temp area, choose
  conservative metadata FEC maxima, or reject.
- Add a streaming finalization path that fails rather than emitting a clean
  footer/trailer if final metadata cannot fit the authenticated class maxima.

Done criteria met:

- The repo does not have a tested sink-based writer.
- Every public API/CLI/README claim avoids true streaming writer support.
- Unsupported create-output sink sentinels have stable diagnostics and
  technical-doc examples.
- No code path advertises append-only streaming while buffering unbounded data
  behind the caller's back.

## G04 - Sequential Non-seekable Reader and Provisional Output

Status: complete/unsupported live boundary.

Spec anchors:

- non-seekable sequential extraction
- reader obligations 4 and 20
- terminal authentication and provisional-output rules

Completed implementation:

Option A is the current product/API stance. The core exposes only
`sequential_extract_tar_stream`, a whole-buffer helper for dictionary-free
single-volume archive images. It may decode payload envelopes internally, but it
does not return any decoded tar bytes to the caller until the terminal
ManifestFooter and VolumeTrailer authenticate. It is not a live
provisional-output API.

This closes G04 as a current-release boundary, not as full live sequential
reader conformance. The conformance matrix keeps R04/R20 `partial` because live
archive stdin/provisional output and the remaining sequential mutation fixtures
are deferred to G10/G12.

The CLI uses archive file paths for `list`, `verify`, and `extract`. It does not
expose archive stdin, live non-seekable extraction, provisional stdout events, or
staged filesystem extraction from an unauthenticated stream. `tzap extract
--stdout` opens and authenticates an archive from file paths, then writes one
selected regular-file member to stdout.

Dictionary-compressed non-seekable sequential extraction without bootstrap stays
unsupported with the stable "dictionary bootstrap required for non-seekable
sequential extraction" diagnostic. Non-seekable random access without sidecar
continues to reject with "non-seekable random access requires a bootstrap
sidecar".

Tests:

- `reader::tests::sequential_extracts_dictionary_free_tar_stream`
- `reader::tests::sequential_rejects_when_terminal_authentication_fails_without_returning_bytes`
- `reader::tests::sequential_rejects_dictionary_archive_without_bootstrap_before_payload_release`
- `reader::tests::sequential_rejects_crc_failed_payload_data_without_guaranteed_parity`
- `reader::tests::sequential_repairs_crc_failed_payload_data_when_parity_is_guaranteed`
- `reader::tests::sequential_zstd_stream_rejects_skippable_frame_segments`
- `cli_smoke::cli_commands_read_real_file_named_dash_as_archive_path`
- `cli_smoke::cli_list_treats_dash_as_literal_archive_path_not_stdin`
- `cli_smoke::cli_extract_treats_dash_as_literal_archive_path_not_stdin`
- `cli_smoke::cli_verify_treats_dash_as_literal_archive_path_not_stdin`
- `milestone11_docs::milestone11_docs_pin_current_g04_non_seekable_boundary`

Deferred future live-reader work:

- A live sequential API would need explicit provisional events, a terminal
  authenticated success event, and a terminal failure event that tells callers
  previously delivered bytes were not final.
- A future filesystem mode would need a staging/quarantine destination and an
  atomic commit only after terminal authentication succeeds.
- A future live stdout mode would need opt-in wording because stdout bytes cannot
  be recalled after terminal failure.
- A future CLI archive-stdin mode belongs with G10 and must not be implied by
  the current `--password-stdin` flag.

Done criteria met:

- The API stance is explicit.
- The whole-buffer sequential helper has tests proving terminal authentication
  failure does not return decoded bytes.
- No default CLI filesystem extractor can leave unauthenticated non-seekable
  stream bytes in the final destination because that path is not exposed.

## G05 - Bootstrap Sidecar Authority and Sparse Sections

Status: complete.

Spec anchors:

- bootstrap sidecar format
- sparse sidecar section rules
- bootstrap source precedence
- reader obligation 16
- writer obligation 35

Completed G05 scope:

The sidecar parser now separates optional section parsing from authority
decisions. A sidecar can carry any v0.36 sparse combination of sidecar
ManifestFooter, IndexRoot BlockRecords, and dictionary BlockRecords, subject to
the packed cursor/layout, flag, reserved-byte, CRC, HMAC, and size-cap checks.
The reader decides whether those copied BlockRecords are usable only after an
authenticated terminal ManifestFooter or sidecar ManifestFooter supplies the
IndexRoot extent, and only after an authenticated IndexRoot supplies any
dictionary extent.

The CLI still rejects bootstrap sidecars with multi-volume input sets as a
product boundary. That boundary is documented in the CLI reference and
operational-boundaries docs and covered by docs tests.

Implemented work:

1. Replace "all required sections or reject" parsing with a structured sidecar
   result:
   - optional sidecar ManifestFooter
   - optional IndexRoot BlockRecord section
   - optional dictionary BlockRecord section
   - validated header flags and packed cursor layout
2. Add a `BootstrapAuthority` decision layer:
   - terminal ManifestFooter authority
   - sidecar ManifestFooter authority
   - authenticated IndexRoot from terminal-located records
   - authenticated IndexRoot from sidecar records
   - dictionary records validated only after authenticated IndexRoot
3. Enforce sidecar rules:
   - non-seekable random-access bootstrap requires ManifestFooter and IndexRoot
     sections
   - dictionary-compressed non-seekable bootstrap also requires dictionary
     records
   - IndexRoot records without a sidecar ManifestFooter are usable only after an
     authenticated terminal ManifestFooter for the same archive/session exists
   - dictionary records are usable only after an authenticated IndexRoot says
     those records match the dictionary object fields
   - sidecar ManifestFooter must be freshly authenticated with
     `volume_index = 0` and `is_authoritative = 1`
   - do not compare the sidecar ManifestFooter's zero `volume_index` to the
     opened VolumeHeader's `volume_index`
   - conflicting archive UUID/session/bootstrap fields reject as mixed archive
4. Decide CLI multi-volume plus `--bootstrap`:
   - keep the unsupported CLI boundary with stable docs/tests
5. Revisit writer sidecar emission:
   - keep CLI single-volume only if that remains the boundary
   - writer sidecars remain packed, single-volume helpers with sidecar
     ManifestFooter volume index zero and matching shared bootstrap fields

Tests:

- Sidecar with ManifestFooter and IndexRoot records bootstraps a non-seekable
  dictionary-free archive.
- Dictionary sidecar includes and authenticates dictionary records before
  payload decompression.
- Full sidecars bootstrap non-seekable opens even when terminal trailer/footer
  material is corrupt or absent.
- IndexRoot-only sidecar rejects for non-seekable bootstrap.
- IndexRoot-only sidecar can help a seekable input only after a terminal
  ManifestFooter authenticates the same archive.
- Dictionary-only sidecar rejects until an authenticated IndexRoot has been
  established.
- Sidecar ManifestFooter copied from volume 0 bytes is accepted.
- Nonzero-volume ManifestFooter mutated to zero without recomputing HMAC
  rejects.
- Recomputed sidecar ManifestFooter with `volume_index = 0` accepts only when
  all other fields match.
- Unknown sidecar flags, nonzero reserved bytes, unclaimed gaps, trailing bytes,
  and cap violations reject before trust.
- Sidecar cap tests count only present sparse sections and reject sections above
  the authenticated metadata FEC class maxima.

Deferred related work:

- CLI support for multi-volume input sets plus `--bootstrap`, if ever desired,
  belongs to G10.
- Broad near-u64 arithmetic and boundary-byte mutation expansion remains in
  G12; the implemented reader path uses checked arithmetic and present-section
  cap accounting.

Done criteria:

- Sidecar parsing is separated from sidecar authority decisions.
- Sparse sidecar combinations match the v0.36 rules.
- CLI unsupported behavior, if any, is explicit and tested.

## G06 - IndexRoot and Dictionary Object Sizing

Status: complete.

Spec anchors:

- IndexRoot bounded root object
- metadata object zstd exactness
- GF16 per-object limit
- writer obligations 24, 26, 28, and 38
- reader obligations 11, 21, and 25

Completed G06 scope:

Payload, IndexShard, and directory-hint objects already split before object caps.
G06 covers the remaining single-object metadata sizing rule: IndexRoot remains a
non-splittable object, so the writer chooses `index_root_fec_data_shards` and
`index_root_fec_parity_shards` before the CryptoHeader HMAC. If the compressed
IndexRoot or dictionary object cannot fit, the writer rejects with a specific
"IndexRoot too large" or dictionary-size diagnostic instead of relying on a late
generic encrypted-object error.

Implemented work:

1. Add metadata sizing planning before CryptoHeader serialization:
   - estimate IndexRoot size from file/shard/hint/dictionary tables
   - estimate dictionary object size if present
   - select metadata data/parity class maxima that can contain both objects
   - ensure actual `data_block_count + parity_block_count <= 65535`
2. For in-memory writer:
   - allow an internal planning/retry loop before bytes are finalized
   - never serialize an authenticated CryptoHeader until the metadata class is
     selected
3. Add exact error categories:
   - `IndexRoot too large`
   - `dictionary object too large`

Deferred related work:

- True unknown-size streaming writer behavior is deferred outside the current
  release claim by the G03 unsupported boundary:
  choose conservative maxima, pre-scan/spool, or reject before first write; if
  final metadata exceeds the selected class, fail finalization with a clear
  error and no clean trailer/footer.
- Reader mutation-matrix expansion belongs to G12:
  encrypted size equals data blocks times block size with checked arithmetic,
  class maxima are enforced before FEC repair, and zero-data metadata objects
  reject before decrypt/decompress.

Tests:

- Writer chooses a larger IndexRoot FEC class when the root is larger than the
  default but within v0.36 limits.
- Writer rejects a root over the maximum with `IndexRoot too large`.
- Dictionary object over class maximum rejects with a dictionary-specific
  diagnostic.
- Actual metadata object where data plus parity exceeds 65,535 rejects even when
  the individual configured maxima fit in u16.
- Mutated ManifestFooter `index_root_encrypted_size` reader fixtures remain G12.
- Metadata object trailing zstd/skippable/concatenated/decompressed-size
  mutation expansion remains G12.

Done criteria:

- IndexRoot/dictionary sizing is an explicit pre-header decision.
- Late encrypted-object errors are not the only protection against invalid
  metadata class choices.

Completion notes:

- `writer.rs::plan_index_root_metadata_class` now selects the final
  `index_root_fec_*` class from the compressed IndexRoot and optional
  dictionary object before `writer.rs::build_crypto_header` computes the
  CryptoHeader HMAC.
- Metadata planning enforces actual object data blocks, parity blocks,
  ReedSolomonGF16 total-shard limit, and u32 encrypted-size limit for
  IndexRoot and dictionary objects before encryption.
- Oversized non-splittable IndexRoot payloads fail with `IndexRoot too large`;
  oversized dictionary objects fail with `dictionary object too large`.
- True unknown-size streaming writer behavior remains outside the current
  release claim under the G03 unsupported boundary.

## G07 - Directory Hints, Directory Entries, and Cloud Mode

Spec anchors:

- directory hint table semantics
- exact file versus directory-prefix lookup
- writer obligation 14
- reader obligations 7, 29, and 31

Resolution:

Complete by Option B. The current CLI/API archive input model intentionally
emits regular-file FileEntries only. The CLI scanner descends through directory
inputs but does not emit standalone directory FileEntries, so empty directories
are omitted. This is documented in `docs/tzap-operational-boundaries.md`, not
the README marketing page.

The current CLI/API also does not expose or claim the spec's
cloud/object-store optimized directory-prefix mode, and therefore has no forced
directory-hint mode for small archives. Directory hints are emitted in `auto`
form when `file_count > directory_hint_required_file_count`; small archives may
legally omit them because no cloud directory-prefix claim is made.

Implemented evidence:

1. Writer hint emission is explicit:
   - `writer.rs::should_emit_directory_hints` uses the strict v0.36 threshold
     `file_count > directory_hint_required_file_count`.
   - `writer.rs::build_directory_hint_plaintexts` includes the root and every
     regular-file ancestor directory and stores shard lists as IndexRoot
     ShardEntry row indexes.
2. Reader hint validation is exact:
   - `reader.rs::validate_directory_hint_tables_against_expected` compares the
     complete decoded hint map against recomputed FileEntry paths.
   - Full `verify` rejects missing hints before fallback when
     `IndexRoot.file_count` exceeds the v0.36 threshold.
3. Exact lookup remains authoritative:
   - `reader.rs::extract_member` searches the file table by exact normalized
     path before any directory-prefix concept.
   - Corpus tests keep misleading directory hints separate from exact-file
     lookup.
4. Foreign archive directory entries are not confused with regular files:
   - `tar_model.rs::parse_tar_member_group` canonicalizes directory tar paths
     without a trailing slash.
   - `reader.rs::add_expected_directory_hint_rows` includes a directory
     FileEntry path in the recomputed hint map when a decoded foreign tar
     member is a directory.

Tests:

- `writer::tests::writer_builds_directory_hint_rows_for_ancestor_directories`
- `writer::tests::directory_hints_are_required_only_above_v36_threshold`
- `reader::tests::verify_rejects_authenticated_archive_missing_required_directory_hints`
- `reader::tests::expected_directory_hint_rows_include_ancestors_and_directory_entries`
- `reader::tests::directory_hint_validation_requires_exact_global_map`
- `reader::tests::directory_hint_validation_rejects_global_order_mismatch`
- `metadata::tests::rejects_directory_hint_rows_sorted_by_old_v36_key_only`
- `v36_corpus::exact_file_lookup_is_independent_from_directory_hints`
- `v36_corpus::exact_directory_entry_and_descendant_hints_have_distinct_authority`
- `v36_corpus::directory_hint_counter_uniqueness_and_non_row_position_values`

Residual risk:

- Directory FileEntry emission and empty-directory preservation remain outside
  current CLI/API scope. Adding that later is a product feature, not an
  unfinished G07 conformance claim.
- Broad malformed DirectoryHintTable buffer generation and huge hint stress
  fixtures remain in G12.

## G08 - Tar Metadata Profile

Status: complete.

Spec anchors:

- writer obligation 13
- reader obligations 13 and 23
- metadata warnings corpus cases

Original gap:

The implementation is strongest for regular-file payloads and local path PAX
needed for long/unicode paths. The supported tar metadata profile is not yet
defined as a strict conformance surface. Unsupported PAX/GNU/xattr/ACL/sparse
cases need consistent diagnostics.

Closed implementation:

- `docs/tzap-operational-boundaries.md` and `docs/tzap-cli-reference.md`
  define the current supported tar metadata profile: regular-file create output,
  safe relative archive paths, local path-specific PAX for long/non-ASCII paths,
  local PAX `path`/`linkpath`/`size`, local GNU long name/link, parsed ustar
  mode and integer mtime, regular-file mode/mtime restoration with diagnostics
  on failure, no global PAX/GNU state, no tar EOF blocks in the encrypted tar
  stream, and no xattr/ACL/sparse/nanosecond timestamp restoration claim.
- `tar_model.rs::parse_tar_member_group` rejects global PAX and global GNU
  state and rejects unsupported GNU sparse entry records. Unsupported local PAX
  xattr/ACL, sparse, timestamp-precision, and unknown keys produce structured
  degraded metadata diagnostics.
- The CLI uses one degraded metadata formatter for list, verify, dry-run,
  stdout extraction, and filesystem extraction so unsupported local metadata does
  not look like silent success on a successful command surface.
- `writer.rs::build_regular_file_member_group` and `writer.rs::build_tar_stream`
  are pinned by tests to emit only path-specific local PAX when needed, no
  global metadata records, and no POSIX end-of-archive zero blocks.

Tests:

- `writer::tests::regular_file_writer_emits_no_global_metadata_or_tar_eof`
- `writer::tests::regular_file_writer_round_trips_mode_and_mtime`
- `writer::tests::regular_file_writer_uses_local_pax_path_for_long_and_non_ascii_paths`
- `tar_model::tests::rejects_global_pax_before_main_entry`
- `tar_model::tests::rejects_global_gnu_headers`
- `tar_model::tests::rejects_unsupported_gnu_sparse_entry_type`
- `tar_model::tests::applies_local_gnu_long_name_and_link_to_following_entry`
- `tar_model::tests::reports_degraded_diagnostics_for_xattr_and_acl_pax_profiles`
- `tar_model::tests::reports_degraded_diagnostics_for_pax_timestamp_precision`
- `tar_model::tests::reports_degraded_diagnostics_for_sparse_and_unknown_pax_profiles`
- `tar_model::tests::reports_degraded_diagnostics_for_unsupported_local_pax_profiles`
- `tar_model::tests::restore_applies_regular_file_mtime_metadata`
- `main.rs::tests::metadata_diagnostic_lines_use_stable_cli_warning_prefix`
- `milestone11_docs::milestone11_docs_pin_current_g08_tar_metadata_profile`
- existing safe-path and local PAX path/size tests remain the baseline coverage.

Remaining work:

- Broad mutation/fuzz expansion for tar metadata remains in G12.
- Future filesystem restoration of ownership, xattrs, ACLs, sparse files,
  nanosecond timestamps, or directory FileEntry creation would be new feature
  work and must update this profile and its diagnostics.

## G09 - Recovery, Duplicates, and FEC Edge Cases

Spec anchors:

- recovery and failure localization sections
- ReedSolomonGF16 profile
- writer obligations 15, 21, 22, 32
- reader obligations 19, 21, 24, 27

Current gap:

The CLI has multi-volume and bit-rot recovery tests, but the complete recovery
surface is broader. Duplicate supplied volume indexes should reject by default
unless an explicit duplicate-copy recovery mode proves byte-for-byte identity.
All FEC edge cases need mutation coverage.

Implementation work:

1. Define recovery modes:
   - default strict mode
   - missing-volume recovery within tolerance
   - bit-rot repair within parity budget
   - duplicate-copy recovery, only if explicitly implemented
2. Default behavior:
   - duplicate authenticated volume indexes reject
   - conflicting blocks reject
   - gaps inside object extents reject unless a repair mode can repair them
3. FEC verification:
   - exact GF16 Cauchy wire profile
   - odd block size rejects before FEC repair
   - data and parity BlockRecords ordered data-first then parity
   - bit 0 set on exactly one final data block per encrypted object
4. Bootstrap recovery:
   - all ManifestFooter copies corrupt or missing means random-access bootstrap
     fails unless a trusted sidecar supplies authority
   - IndexRoot block repair still requires authenticated bootstrap metadata to
     locate the extent

Tests:

- Duplicate volume index rejects by default.
- Duplicate-copy recovery accepts only byte-for-byte identical duplicate inputs,
  if that mode is implemented.
- Missing volume succeeds only within `volume_loss_tolerance`.
- Bit-rot repairs only within parity budget.
- Odd `block_size` rejects before FEC repair.
- Parity block with last-data bit rejects.
- Data object with missing or duplicate final-data bit rejects.
- All ManifestFooter copies corrupt fail without sidecar and succeed with a
  trusted sidecar, if G05 implements the sidecar path.

Done criteria:

- Recovery behavior is deterministic, documented, and mutation-tested.
- There is no silent arbitrary choice among duplicate volumes.

## G10 - CLI and API Boundaries

Spec anchors:

- CLI synopsis
- non-seekable read/write sections
- bootstrap sidecar sections

Current gap:

The CLI is the main user-facing conformance boundary. It should not imply
features that the core does not implement, and it should not hide unsupported
writer/reader shapes behind generic errors.

Implementation work:

1. Audit all CLI flags and help text:
   - `create`
   - `list`
   - `verify`
   - `extract`
   - `keygen`
2. For each unsupported combination, require:
   - preflight rejection before partial output
   - stable error category
   - actionable message
   - test
   - technical-doc example
3. Required boundaries to settle:
   - archive stdin / non-seekable archive input
   - live stdout streaming versus whole-buffer output
   - multi-volume plus `--bootstrap`
   - multi-volume plus `--bootstrap-out`
   - directory entry preservation
   - true append-only create output
4. Keep the README focused on successful workflows. Put limitations and examples
   in `docs/`.

Tests:

- Help text does not mention archive stdin unless implemented.
- `--bootstrap-out` with multi-volume rejects before creating output files.
- Multi-volume plus `--bootstrap` either works with G05 authority checks or
  rejects with the documented unsupported diagnostic.
- Unsupported streaming create shape rejects before first output byte.
- CLI reference tests cover the implemented/unsupported boundary.

Done criteria:

- Users get clear behavior at command boundaries.
- Technical docs carry limitations; README remains a marketing page.

## G11 - v36 Corpus and Mutation Coverage

Status: complete.

Spec anchors:

- section 28.1 test corpus additions through v0.36

Original gap:

`crates/tzap-core/tests/v36_corpus.rs` covers many v0.36 cases, but the repo
does not yet have a tracker proving every corpus item is covered, partially
covered, missing, or explicitly deferred.

Completed implementation:

1. Added `docs/tzap-v36-corpus-tracker.md`.
2. Tracked all 113 named section 28.1 corpus cases with:
   - case name
   - spec intent
   - positive fixture/test evidence
   - mutation or negative fixture/test evidence
   - status: `covered`, `partial`, `missing`, or `deferred`
   - follow-up gap link for every open case
3. Kept the tracker honest: cases with aspirational or incomplete evidence stay
   `partial`, `missing`, or `deferred` and link to G03 through G13.
4. Added docs tests in `crates/tzap-cli/tests/milestone11_docs.rs` that:
   - require representative section 28.1 cases to remain present
   - require exactly 113 tracker rows for the current v0.36 spec
   - reject vague status values such as `unknown`
   - require remaining `partial` and `missing` statuses while known gaps remain
   - require non-covered rows to link back to a follow-up gap
5. Whitelisted the tracker in `.gitignore`.

Done criteria:

- Every section 28.1 case has a status.
- Missing cases become work items, not reviewer folklore.
- Corpus tracker now carries the corpus-level evidence map. The conformance
  matrix remains the section 29 obligation map and can cite tracker rows as G03
  through G13 close.

## G12 - Fuzzing and Mutation Harness

Spec anchors:

- structural validation requirements
- parser/resource cap requirements
- sidecar and metadata object exactness

Current gap:

Fuzz targets may exist or be planned, but there is no visible release gate that
requires a fuzz smoke run or keeps fuzz seeds aligned with the v36 corpus.

Implementation work:

1. Inventory existing fuzz targets.
2. Add or update targets for:
   - VolumeHeader/CryptoHeader/Extension TLVs
   - BlockRecord
   - ManifestFooter/VolumeTrailer
   - BootstrapSidecar
   - IndexRoot
   - IndexShard
   - DirectoryHintTable
   - metadata zstd exactness
   - padding depad
3. Add deterministic corpus seeds generated from `v36_corpus.rs` helpers.
4. Add a CI/manual release smoke command:
   - short fuzz run for parser targets
   - no network dependency
   - bounded runtime
5. Ensure fuzz failures produce minimized repro bytes that can become regression
   tests.

Tests:

- CI or documented release checklist runs a bounded fuzz smoke.
- Mutation helper tests verify malformed fixtures reach the intended parser
  branch, not just authentication failure.

Done criteria:

- Fuzzing is part of the release checklist.
- Parser fuzz seeds track the v36 corpus.

## G13 - Interop and Release Gate

Spec anchors:

- all v0.36 conformance sections
- package/release workflows

Current gap:

The project can build and release artifacts, but format conformance and release
readiness need one gate that combines tests, docs, corpus, packaging, and
interop. Otherwise it is too easy to tag a release while a spec gap is known but
not documented.

Implementation work:

1. Add `docs/tzap-v36-release-gate.md` or extend the implementation plan with a
   release checklist:
   - conformance matrix has no `unknown`
   - P0 gaps closed or explicitly unsupported with tests/docs
   - v36 corpus tracker has no untriaged cases
   - full Rust tests pass
   - CLI docs tests pass
   - fuzz smoke passes
   - release workflow builds all target artifacts
   - generated checksums exist
   - Homebrew formula/test path verified for macOS and Linuxbrew if claimed
   - Linux and Windows portable artifacts are smoke-tested if claimed
2. Add release wording guidance:
   - "implements v0.36 archive layout with documented unsupported surfaces" is
     acceptable while P1/P2 work remains
   - "fully v0.36 conformant" requires all P0/P1 conformance rows complete or
     formally deferred without public feature claims
3. Add interop fixtures:
   - deterministic golden archives
   - dictionary archive with sidecar
   - multi-volume recoverable archive
   - large multi-shard archive
   - directory-hint archive
   - empty archive

Tests:

- Release workflow test confirms the cross-platform matrix includes all claimed
  targets.
- Artifact smoke tests run `tzap --version`, create/list/verify/extract on each
  claimed platform.
- Homebrew/Linuxbrew test is required only if the docs claim that install path.

Done criteria:

- A release owner can run one checklist and know whether a tag is safe.
- Public claims match verified behavior.

## Recommended Execution Order

1. G01 and G02: fix stale docs and add the conformance matrix first.
2. G11: add the corpus tracker and mark every v36 corpus case.
3. G06: close metadata sizing because it affects writer correctness and release
   claims.
4. G05: close sidecar authority because it affects recovery, dictionary, and
   non-seekable behavior.
5. G04: closed with an explicit whole-buffer reader stance and no live
   provisional-output claim. G03 is closed as an unsupported sink-writer boundary
   for the current release claim.
6. G08: settled with an explicit supported tar metadata profile.
7. G09, G12, and G13: harden recovery, fuzzing, interop, and release gates.

## Release Blocking Rule

Before the next release tag, every P0 item in this document must be one of:

- complete with tests
- explicitly unsupported with a CLI/API guard, stable diagnostic, docs example,
  and no README claim
- intentionally deferred in the conformance matrix with no public claim that the
  feature works

If a reviewer asks "what is the gap between the implementation and the v0.36
spec?", the answer should be this document plus the conformance matrix and
corpus tracker. No hidden tribal knowledge.
