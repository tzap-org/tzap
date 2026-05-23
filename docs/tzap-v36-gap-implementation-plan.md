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
not prove full v0.36 conformance. The remaining gaps are mostly around true
streaming surfaces, sidecar authority rules, sparse sidecar combinations,
directory-entry semantics, IndexRoot sizing before header authentication,
corpus coverage, and explicit release gates.

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
| G03 | True streaming writer | partial/in-memory only | P0/P1 | implement sink model or document no true streaming claim |
| G04 | Sequential non-seekable reader | partial/whole-buffer safe API | P0/P1 | safe provisional-output story and tests |
| G05 | Bootstrap sidecar authority | partial | P0 | sparse sections and authority precedence match spec |
| G06 | IndexRoot/dictionary sizing | partial | P0 | choose metadata FEC class before CryptoHeader HMAC |
| G07 | Directory hints and directory entries | partial | P0/P1 | exact hint map, directory entries, and cloud claims settled |
| G08 | Tar metadata profile | partial | P1 | supported metadata profile documented and tested |
| G09 | Recovery and duplicate volumes | partial | P1 | default rejection and recovery modes are explicit |
| G10 | CLI/API boundaries | partial | P0 | help/docs/tests do not imply unsupported behavior |
| G11 | v36 corpus coverage | partial | P0 | every section 28.1 case tracked as covered/missing/deferred |
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
   - empty directory entries are omitted unless G07 implements directory
     FileEntry support
   - true archive stdin/non-seekable streaming is not exposed unless G03/G04
     implement it
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
   - true streaming writer: `W12` unsupported, `W38` partial
   - live sequential/provisional output: `R04` and `R20` partial
   - sparse sidecar authority: `R16` partial
   - directory entries and cloud mode: `W14` and `R31` partial
   - tar metadata profile: `W13`, `R13`, and `R23` partial
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

Spec anchors:

- single-stream streaming mode
- writer obligations 1, 12, 24, and 38
- writer sequence and no seek-back rules

Current gap:

The writer creates valid archive bytes in memory and returns
`WrittenArchive { bytes, volumes }`. It does not expose a sink-based writer that
proves true append-only streaming behavior. The current implementation may write
the final artifact in forward order, but it can still buffer the whole tar
stream, metadata, and output in memory before handing bytes to the caller.

That is not the same as a conforming true streaming writer.

Implementation work:

1. Define sink capabilities explicitly:
   - seekable file sink
   - append-only single sink
   - append-reopenable multi-volume sink
   - externally multiplexed multi-stream sink, if ever supported
2. Add a writer API that accepts a sink capability, or explicitly document that
   the current core writer is an in-memory artifact builder and does not claim
   true streaming.
3. For fully non-reopenable single-sink streaming:
   - force `stripe_width = 1`
   - force `volume_loss_tolerance = 0`
   - require bootstrap sidecar emission if `has_dictionary = 1`
   - choose `index_root_fec_data_shards` and
     `index_root_fec_parity_shards` before CryptoHeader HMAC
4. For non-reopenable multi-volume streaming without an external multiplexing
   protocol:
   - reject before emitting any archive bytes
   - diagnostic should say the sink shape is incompatible with striped
     multi-volume streaming
5. For unknown-size input sets:
   - pre-scan, spool to a bounded temp area, choose conservative metadata FEC
     maxima, or reject
   - do not claim true streaming while silently buffering unbounded output
6. Add a "streaming close" path:
   - if final IndexRoot or dictionary object cannot fit the authenticated class
     maxima, return a finalization error
   - do not emit a success trailer/footer after that failure

Tests:

- Fake append-only sink records every write and fails if the writer seeks,
  overwrites, or reopens.
- Append-only single sink with `stripe_width > 1` rejects before first write.
- Append-only single sink with `volume_loss_tolerance > 0` rejects before first
  write.
- Dictionary-compressed append-only single sink without sidecar rejects before
  first write.
- Dictionary-compressed append-only single sink with sidecar writes a sidecar
  containing ManifestFooter, IndexRoot records, and dictionary records.
- Unknown-size streaming input either chooses conservative maxima or rejects
  before first write.
- A final IndexRoot overflow in streaming mode fails finalization and does not
  produce a clean archive.
- In-memory writer and streaming writer produce archives that the same reader
  validates for a shared deterministic fixture.

Done criteria:

- Either the repo has a tested sink-based writer, or every public API/CLI/doc
  avoids true streaming claims.
- No code path advertises append-only streaming while buffering unbounded data
  behind the caller's back.

## G04 - Sequential Non-seekable Reader and Provisional Output

Spec anchors:

- non-seekable sequential extraction
- reader obligations 4 and 20
- terminal authentication and provisional-output rules

Current gap:

`sequential_extract_tar_stream` returns a `Vec<u8>`. That is safe because bytes
are not released incrementally, but it is not a live streaming/provisional API.
The CLI also uses archive paths rather than an archive-stdin mode.

If a future CLI/API streams archive bytes to stdout or to the filesystem before
terminal authentication, the implementation must mark those bytes as
provisional and must stage filesystem writes until the terminal
ManifestFooter/VolumeTrailer authenticates.

Implementation work:

1. Decide the product/API stance:
   - Option A: keep only whole-buffer sequential extraction and document that no
     live non-seekable extraction API is exposed.
   - Option B: add a live sequential API with provisional output semantics.
2. If Option B:
   - expose `SequentialEvent::ProvisionalBytes`
   - expose a terminal authenticated success event
   - expose terminal authentication failure as a hard failure
   - require callers to opt into retaining provisional bytes after failure
3. For filesystem extraction:
   - write to a staging/quarantine directory
   - commit atomically only after terminal authentication succeeds
   - clean up staged data on failure unless unsafe/debug mode says otherwise
4. For stdout:
   - default should avoid live streaming unless the user opts in to provisional
     output
   - document that already-written stdout bytes cannot be recalled after failure
5. For dictionary archives:
   - without a bootstrap sidecar, reject non-seekable sequential extraction with
     the stable "dictionary bootstrap required" diagnostic
   - with a sidecar, load the dictionary before payload decompression or buffer
     until bootstrap is complete

Tests:

- Valid dictionary-free non-seekable stream emits bytes only as provisional
  before terminal auth, then reports clean success.
- Mutated terminal footer after valid payload envelopes causes:
  - stdout-style API: terminal failure is reported after provisional bytes
  - filesystem API: staged files are not committed
- Dictionary archive without sidecar rejects before payload decompression.
- Payload block after metadata BlockRecord in sequential mode rejects.
- CRC failure before envelope authentication aborts correctly.
- Sequential extraction does not append synthetic tar EOF until terminal auth.

Done criteria:

- The API stance is explicit.
- Any live stream path has tests proving provisional behavior.
- The default filesystem extractor cannot leave unauthenticated files in the
  final destination.

## G05 - Bootstrap Sidecar Authority and Sparse Sections

Spec anchors:

- bootstrap sidecar format
- sparse sidecar section rules
- bootstrap source precedence
- reader obligation 16
- writer obligation 35

Current gap:

The sidecar parser currently behaves like a full non-seekable bootstrap parser:
it requires both ManifestFooter and IndexRoot sections. The v0.36 spec permits
sparse sidecar combinations when another authenticated authority supplies the
missing metadata.

The CLI also rejects bootstrap sidecars with multi-volume input sets. That may
remain a product boundary, but it must be documented and tested. If implemented,
the sidecar authority graph must be precise.

Implementation work:

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
   - if still unsupported, keep a stable unsupported diagnostic and docs example
   - if supported, use sidecar data only after the authority checks above
5. Revisit writer sidecar emission:
   - keep CLI single-volume only if that remains the boundary
   - if multi-volume sidecar emission is added, emit packed sidecars with
     sidecar ManifestFooter volume index zero and matching shared bootstrap
     fields

Tests:

- Sidecar with ManifestFooter and IndexRoot records bootstraps a non-seekable
  dictionary-free archive.
- Dictionary sidecar includes and authenticates dictionary records before
  payload decompression.
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
- Sidecar cap tests cover near-u64 arithmetic and count only present sections.

Done criteria:

- Sidecar parsing is separated from sidecar authority decisions.
- Sparse sidecar combinations match the v0.36 rules.
- CLI unsupported behavior, if any, is explicit and tested.

## G06 - IndexRoot and Dictionary Object Sizing

Spec anchors:

- IndexRoot bounded root object
- metadata object zstd exactness
- GF16 per-object limit
- writer obligations 24, 26, 28, and 38
- reader obligations 11, 21, and 25

Current gap:

Payload, IndexShard, and directory-hint objects now split before object caps.
IndexRoot remains a single non-splittable object. The writer must choose
`index_root_fec_data_shards` and `index_root_fec_parity_shards` before the
CryptoHeader HMAC. If the serialized IndexRoot or dictionary object cannot fit,
the writer must reject with a specific "IndexRoot too large" or dictionary-size
diagnostic instead of relying on a late generic encrypted-object error.

Implementation work:

1. Add metadata sizing planning before CryptoHeader serialization:
   - estimate IndexRoot size from file/shard/hint/dictionary tables
   - estimate dictionary object size if present
   - select metadata data/parity class maxima that can contain both objects
   - ensure actual `data_block_count + parity_block_count <= 65535`
2. For in-memory writer:
   - allow an internal planning/retry loop before bytes are finalized
   - never serialize an authenticated CryptoHeader until the metadata class is
     selected
3. For true streaming writer:
   - choose conservative maxima, pre-scan/spool, or reject before first write
   - if final metadata exceeds the selected class, fail finalization with a
     clear error and no clean trailer/footer
4. Add exact error categories:
   - `IndexRoot too large`
   - `dictionary object too large`
   - `metadata object exceeds GF16 total shard limit`
   - `metadata object exceeds u32 encrypted size limit`
5. Ensure reader validation checks:
   - encrypted size equals data blocks times block size with checked arithmetic
   - class maxima are enforced before FEC repair
   - zero-data metadata objects reject before decrypt/decompress

Tests:

- Writer chooses a larger IndexRoot FEC class when the root is larger than the
  default but within v0.36 limits.
- Writer rejects a root over the maximum with `IndexRoot too large`.
- Dictionary object over class maximum rejects with a dictionary-specific
  diagnostic.
- Actual metadata object where data plus parity exceeds 65,535 rejects even when
  the individual configured maxima fit in u16.
- Mutated ManifestFooter `index_root_encrypted_size` rejects before fetching or
  decrypting IndexRoot.
- Metadata object with trailing zstd bytes, skippable frame, concatenated
  frames, or decompressed-size mismatch rejects.

Done criteria:

- IndexRoot/dictionary sizing is an explicit pre-header decision.
- Late encrypted-object errors are not the only protection against invalid
  metadata class choices.

## G07 - Directory Hints, Directory Entries, and Cloud Mode

Spec anchors:

- directory hint table semantics
- exact file versus directory-prefix lookup
- writer obligation 14
- reader obligations 7, 29, and 31

Current gap:

The writer emits directory hints for large regular-file archives. It does not
currently emit FileEntries for empty directories, and the CLI scanner omits
empty directories. The spec's directory-hint rule includes every ancestor
directory and every FileEntry path whose decoded main tar entry is itself a
directory. That second path only matters if directory FileEntries are supported.

The spec also requires directory hints when the writer claims cloud/object-store
optimized directory-prefix operations. The CLI/API should either expose such a
claim and force hints, or make no such claim.

Implementation work:

1. Decide directory FileEntry support:
   - Option A: support directories as archive entries
   - Option B: continue omitting empty directories and document that directory
     FileEntries are not currently emitted
2. If Option A:
   - extend the tar model to represent regular files and directories
   - scan input directories as entries, including empty directories
   - encode directory tar member groups with canonical one-trailing-slash tar
     names while storing FileEntry paths without trailing slashes
   - validate extracted directory FileEntry path and size bindings
   - make exact lookup of a directory distinct from prefix-descendant lookup
3. Add a directory hint policy:
   - `auto`: hints when `file_count > directory_hint_required_file_count`
   - `always`: hints for cloud/object-store optimized claims
   - `never`: only if spec permits for small archives and no cloud claim
4. Strengthen hint map validation:
   - root hint is canonical
   - every ancestor of every FileEntry path appears
   - directory FileEntry paths appear when directory entries are supported
   - shard list contains sorted unique IndexRoot ShardEntry row indexes, not
     `shard_index` IDs
   - no missing, extra, duplicate, or misordered hints
5. Keep exact file lookup authoritative:
   - a regular file `foo` must not be treated as directory prefix `foo/`
   - misleading directory hints cannot create an exact-file match

Tests:

- Existing exact-file-vs-directory-hint parser tests remain.
- Writer integration test for a directory with:
  - regular file `foo`
  - directory `foo-dir/`
  - child `foo-dir/bar`
  - empty directory, if supported
- Archive over the hint threshold emits root and ancestor hints.
- Forced cloud hint mode emits hints below the threshold.
- Full verify rejects missing root hint, missing ancestor hint, extra hint,
  duplicate hint, misordered hint, and shard indexes that are IDs instead of
  row indexes.
- DirectoryHintShardEntry equal-start ordering uses
  `(first_dir_hash, last_dir_hash, hint_shard_index)`.
- Hint-shard count and entry-count caps reject before allocation.

Done criteria:

- Directory-entry support is either implemented or explicitly outside current
  CLI/API scope.
- Directory hints are exact and verified whenever present.
- No cloud/object-store optimized claim exists without forced hints.

## G08 - Tar Metadata Profile

Spec anchors:

- writer obligation 13
- reader obligations 13 and 23
- metadata warnings corpus cases

Current gap:

The implementation is strongest for regular-file payloads and local path PAX
needed for long/unicode paths. The supported tar metadata profile is not yet
defined as a strict conformance surface. Unsupported PAX/GNU/xattr/ACL/sparse
cases need consistent diagnostics.

Implementation work:

1. Write a supported metadata profile in technical docs:
   - regular files
   - safe relative paths
   - long/unicode path support through local path-specific PAX if needed
   - mode and mtime behavior, if fully supported
   - no global PAX state
   - no global GNU state
   - xattr/ACL/sparse unsupported unless implemented
2. Make reader behavior explicit:
   - reject global PAX/GNU state that affects unrelated entries
   - emit degraded metadata diagnostics for unsupported local profiles
   - best-effort quiet mode may suppress warnings only if documented
3. Make writer behavior explicit:
   - never emit POSIX end-of-archive zero blocks into encrypted tzap tar stream
   - never emit global PAX/GNU state
   - if claiming metadata beyond baseline, emit only path-specific metadata
     inside that member group

Tests:

- Writer emits no global PAX/GNU records for representative inputs.
- Reader rejects global PAX/GNU state rather than carrying mutable tar state
  across FileEntry boundaries.
- Unsupported local PAX/GNU extension, xattr/ACL failure, timestamp precision
  loss, and sparse-file fallback produce diagnostics.
- Quiet/best-effort mode, if present, suppresses only documented warnings.

Done criteria:

- The metadata profile is no longer implicit.
- Unsupported tar metadata does not silently look successful.

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

Spec anchors:

- section 28.1 test corpus additions through v0.36

Current gap:

`crates/tzap-core/tests/v36_corpus.rs` covers many v0.36 cases, but the repo
does not yet have a tracker proving every corpus item is covered, partially
covered, missing, or explicitly deferred.

Implementation work:

1. Add `docs/tzap-v36-corpus-tracker.md`.
2. For each section 28.1 case, record:
   - case name
   - positive fixture/test
   - mutation fixture/test
   - current status
   - deferred reason, if any
3. Add reusable mutation helpers so each test does not hand-patch bytes in a
   bespoke way.
4. Seed fuzzers from the same fixture generator.

Initial corpus triage:

| Corpus case | Current signal | Required action |
| --- | --- | --- |
| Minimal FileEntry frame ranges | tests exist | ensure mutation fixtures cover unrelated trailing frames |
| Exact file versus directory-prefix hints | parser tests exist | add writer/reader test once directory entries are settled |
| Directory hint equal-start ordering | parser test exists | keep as matrix evidence |
| Hash-prefix byte-order vectors | test exists | keep as matrix evidence |
| Argon2id profile vectors | test exists | add malformed parameter negatives if missing |
| AEAD combined-output vectors | test exists | keep as matrix evidence |
| ReedSolomonGF16 wire profile vectors | test exists | add odd block-size and library-default mismatch negatives |
| Directory hint AEAD counter uniqueness | test exists | keep as matrix evidence |
| Shard boundary metadata binding | test exists | ensure decrypted IndexShard and DirectoryHint mutations both covered |
| Sparse local frame offset validation | test exists | add full-verify global gap/overlap mutation if missing |
| Metadata-object zstd exactness | test exists | keep and expand to all metadata object kinds |
| FEC effective object ceiling | test exists | add writer-side split/reject tests |
| Volume format revision freshness | test exists | keep as matrix evidence |
| Sidecar ManifestFooter volume-0 equivalence | missing/partial | add full sidecar authority tests |
| Sequential provisional output | missing | implement or document no live API |
| Zero-data encrypted objects | partial/audit needed | add zero-data mutations for all object kinds |
| Empty archive | partial | add core reader/writer/verify evidence |
| Empty payload envelope rejection | audit needed | add envelope, frame, and file-entry zero-size mutations |
| Reserved FileEntry flags | test exists | keep as matrix evidence |
| Encrypted-size canonicality | audit needed | add checked arithmetic and class-max mutations |
| Exact-fit overflow guard | missing | add writer planning test near u32/FEC boundary |
| Shard and collision caps | partial/audit needed | add max collision and upper-bound landing tests |
| Header/trailer identity binding | audit needed | combine authenticated material from different archives |
| Volume count cross-checks | audit needed | mutate header, crypto header, and footer independently |
| Volume index bounds and duplicates | partial | add duplicate-volume default rejection |
| Magic-field validation | audit needed | mutate every magic field independently |
| CryptoHeader canonical offset | audit needed | reject non-128 offsets even if in bounds |
| CryptoHeader extension TLVs | audit needed | malformed, duplicate, forbidden, critical unknown |
| KDF/HKDF/nonce/AAD vectors | partial | complete literal vectors and negative cases |
| BlockRecord flags and reserved fields | partial | ensure all object kinds covered |
| Per-volume ManifestFooter copies | partial | verify shared fields and per-volume index rules |
| Zero-offset counted tables | audit needed | reject nonzero offset with zero count |
| Archive totals | partial | mutate totals and content hash |
| Bootstrap sidecar sparse/caps | missing/partial | covered by G05 |
| Trailer-from-end and trailing garbage | audit needed | canonical trailer first, bounded recovery scan |
| Metadata warnings | missing/partial | covered by G08 |
| S3/object-store round trip | missing | add optional integration test or documented deferral |

Done criteria:

- Every section 28.1 case has a status.
- Missing cases become work items, not reviewer folklore.
- Corpus tracker and conformance matrix agree.

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
5. G03 and G04: either implement true streaming/provisional APIs or explicitly
   remove those claims from public surfaces.
6. G07 and G08: settle directory entries, cloud hint claims, and tar metadata.
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
