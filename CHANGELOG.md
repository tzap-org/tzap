# Changelog

## Unreleased

- **Changes how pre-epoch timestamps are interpreted, including in archives
  written by 0.2.4.** §16.7.2 encodes a time as a signed decimal in sign-and-
  magnitude form, so `-1.25` means 1.25 seconds before the epoch -- the timespec
  `(-2, 750_000_000)`. 0.2.4 wrote and parsed the two timespec fields out
  literally, which lands a full second early for every pre-epoch time with a
  fractional part: it wrote `(-2, 750_000_000)` as `-2.75`, and read `-2.75` back
  as `(-2, 750_000_000)`. That round-tripped within 0.2.4 while disagreeing with
  the specification and with every other implementation of it.

  Both directions are now correct, and the conversion happens only at the PAX
  boundary (`ArchiveTimestamp::canonical_pax_value` and
  `entry_metadata::parse_timestamp`); `ArchiveTimestamp` is a timespec
  everywhere else, matching libc and every consumer that applies a restored time.

  **What this means for existing archives.** A member written by 0.2.4 whose
  `mtime`, `atime` or creation time falls before 1970 *and* carries a fraction
  will restore 1.5 seconds away from what 0.2.4 intended -- silently, because
  both values are well-formed. Whole-second pre-epoch times, and every time at or
  after the epoch, are unaffected, as are archives written by this release and
  read back by it. The last second before the epoch still has no encoding at all
  (§16.7.2 forbids `-0`), so an optional time in that window is omitted rather
  than approximated, and an `mtime` there fails loudly.

  A regression in either direction is caught in-build by
  `cli_round_trip_restores_pre_epoch_times_exactly`,
  `pre_epoch_times_survive_the_full_encode_parse_round_trip`, and the encoder
  test that pins `-1.5` literally.

- Fixes a sparse input shortened or replaced mid-archive failing the whole run,
  while an ordinary file of the same size was zero-filled and reported. The two
  went down different paths out of `open_source`: the dense reader padded to the
  length the member header already promised and named the file, the sparse reader
  returned `UnexpectedEof` and took the archive with it. Sparse detection is
  automatic on Linux (`SEEK_HOLE`) and Windows, so whether a live backup survived
  came down to whether the file happened to have holes -- a VM disk image or a
  database with a punched hole would kill the run where a dense file did not.
  `tzap-operational-boundaries.md` already documented the padding outcome without
  qualification. The sparse path now pads every byte still owed, across the
  current extent and all later ones, marks the archive incomplete, and names the
  member.

- Fixes two names for one inode failing the whole run when the inode was touched
  between the two stats that saw it. Grouping them into a hardlink alias needs a
  settled observation of both; without one, the entry is now stored in full as an
  ordinary regular file -- larger, always correct -- and reported, rather than
  aborting an archive over ordinary activity on a live tree.

- Hardens the macOS APFS clone post-pass, which addressed already-restored
  members by joining the archive path onto the extraction root and handing the
  result to `File::open`, `clonefile`, `copyfile` and `rename`. Every other
  restore path resolves each component with `open_dir_nofollow` precisely so a
  swapped ancestor cannot redirect a write outside the root, and the post-pass
  gave that up. It now resolves members through the same traversal and does its
  work with `openat`/`clonefileat`/`fcopyfile`/`renameat` against the resolved
  directory handle, opening each leaf `O_NOFOLLOW`. The staging name is also held
  by its `O_EXCL` entry until `clonefileat` replaces it, instead of being unlinked
  immediately and assumed still free. A group that partly succeeded now reports
  how many partners were shared rather than reading as if nothing happened.

- Fixes a Linux birth time in the one second before the epoch being replaced by
  the file's ctime. §16.7.2 cannot encode that second, so the time is meant to be
  omitted; the musl fallback that substitutes ctime where the host exposes no
  birth time at all was firing for it too, recording a different instant instead
  of none.

- Restores exit `16` (`unsupported-feature`) for a streamed Windows auxiliary
  shape the writer refuses. Moving those readers into `tzap-core` put them behind
  an `io::Result`, and flattening that to an I/O error moved the exit code to `3`.

- Fixes `create` telling the operator the archive held everything else when a
  skipped directory had taken its contents with it. The scan never enumerates a
  directory it could not read, so there is no count to report -- and both
  wordings ("the archive contains everything else", then "the archive holds the
  rest") asserted the opposite of what happened. Measured: a directory holding
  five files was skipped and the run still reported `created 2 member(s)` and
  `the archive holds the rest`. The summary now names how many skipped inputs
  were directories and says plainly that everything inside them was skipped too.

- Fixes the same run also claiming it had archived that directory. A directory
  records "archived it and everything inside it without that layer" before it is
  enumerated, and the permission failure that hides its extended metadata is
  usually the one that then fails `read_dir` -- so the run printed that claim
  and, two lines later, that the directory had been skipped entirely. The note
  is now retracted when the scan abandons the input.

- Fixes one file name that is not valid UTF-8 discarding its whole directory.
  The name was decoded inside the directory's child loop and the failure raised
  out of it, so the caller rolled the directory back: every sibling already
  collected, every sibling after it, and the directory itself, reported as a
  single skipped directory. A POSIX file name is a byte string, so this is
  ordinary in a real Linux tree -- measured on ext4, a directory of five
  readable files plus one undecodable name produced `created 1 member(s)` and
  never mentioned the five. The undecodable entry alone is now skipped and
  named. An input named on the command line still fails the run.

- Fixes `create --dry-run` hiding the inputs the real run would leave out. The
  scan already ran by the time the dry-run summary was printed, but it counted
  only what survived and exited `0`: the tree that made `create` exit `4` with a
  named skip made `create --dry-run` print a clean summary. A dry run now
  reports `inputs skipped:`, names each one, and exits `4` as the real run
  would.

- Corrects `public-docs/tzap-operational-boundaries.md`, which still listed APFS
  clone hints as not captured on macOS while the writer records them and the
  reader re-establishes sharing on restore, and still described any source
  object changing during capture as rejected. Adds the section on inputs
  `create` leaves out of an archive it still writes, with worked examples and
  exit labels for the skip, zero-fill, degraded-directory, and dry-run cases.

- Fixes `create` dropping a whole subtree when a directory changed while it was
  being scanned. A directory's mtime, ctime and size move every time one of its
  children is created or removed, and the capture compared all of them against
  the identity the scan had taken, so ordinary activity read as "input changed
  before metadata capture". The retry could not recover: it re-tested the same
  scan-time identity, which could never match again. The directory was then
  skipped, and skipping it discarded every entry already collected beneath it.
  Measured under a churning directory, 10 of 12 runs silently lost five files
  that nothing had touched, while the run reported `created 3 member(s)` and
  `the archive contains everything else`. A directory is now compared as an
  object -- device, inode, mode, ownership, flags, kind -- and every retry
  re-observes the input instead of re-testing a stale expectation. A directory
  whose own extended metadata still cannot be read is archived with portable
  metadata, along with all of its contents, and says so.

- Fixes members with long names being impossible to extract. Restoring writes to
  a temporary sibling built from the member's own name plus a 46-byte suffix, and
  0.2.4 made no room for that suffix: any leaf of 210 bytes or more pushed the
  temporary name past the 255-byte component limit that ext4, XFS, btrfs and NTFS
  enforce, so the create failed before a single payload byte was written. The
  member could not be restored at all, and the error said `corrupt-archive`,
  which points at the archive rather than at the name. A CJK name is three bytes
  per character, so this started at about 70 characters; an ASCII name needed
  210. APFS is not affected, because it measures a component in characters rather
  than bytes -- which is also why it went unnoticed on macOS.

  The temporary name now keeps as much of the real leaf as fits alongside the
  suffix, stopping on a character boundary so a multi-byte character is never
  split (a filesystem that validates UTF-8, APFS among them, rejects a split
  sequence outright with `EILSEQ`). A filesystem that refuses the name for any
  other reason -- eCryptfs caps a component at 143 bytes -- falls back to a
  shorter form, and finally to the suffix alone, instead of failing the restore.
  The temporary name never reaches the restored tree: it is renamed to the
  member's real leaf either way.

- Fixes `extract --restore same-os` and `--restore system` refusing any macOS
  archive that contains an APFS clone pair, writing no files at all. The writer
  records a `TZAP.macos.clone-group` hint, but the reader's conformance table
  had no entry for it and fell through to "unsupported native metadata". §16.11
  classes the hint as optimization only, never applied as authority, so it can
  never make a member unrestorable. Cloned files are the ordinary state of an
  APFS volume, so this affected everyday archives.

- Fixes APFS clone restore overwriting the second partner's metadata with the
  first's. `clonefile` copies the source's mode, times, ACL and extended
  attributes along with its storage, and the restore pass renamed that over a
  destination whose metadata had already been applied correctly: a 0644 file
  stamped 2025 came back 0600 stamped 2020, carrying the other file's xattrs.
  The pass now hands the destination's own metadata back before publishing.
  Two further defects at the same site: it compared partners by reading both
  files fully into memory (586 MB peak for a 150 MB pair, and a cloned disk
  image is routinely tens of GB) and now streams the comparison; and its
  staging name replaced the destination's extension rather than extending it,
  so a restored member named `<stem>.tzap-clone-staging` was silently deleted.

- Fixes the report for a file shortened while it was being archived naming the
  wrong amounts, in the direction that understates the loss. It described the
  size of whichever read first hit end-of-file rather than everything still
  owed, so a 300 MB file truncated to 1 MB was reported as "kept the 299.9 MB
  still there and filled the remaining 8.0 KB with zeros" when 276 MB of the
  member had in fact become zeros. Such a run also exited 0; substituted bytes
  now mark the archive incomplete, as a vanished input already did.

- `create` now exits `4` (`incomplete-archive`) rather than `1` when it writes
  a valid archive that is missing something -- an input it could not read, or
  one replaced by zeros because it vanished or shrank mid-write. Exit `1` is
  documented as an unexpected runtime error, so reusing it left a caller unable
  to tell "archive written, one file skipped" from "the run failed and produced
  nothing". Every affected input is still named on stderr.

- Fixes `create --tar-stdin` rejecting sparse members that GNU tar and
  libarchive actually produce. A GNU sparse 1.0 map ends with a zero-length
  entry at the logical size, and starts with one at offset 0 when the file
  opens with a hole; the ingest path applied revision-45's own output rule
  ("every extent length is greater than zero", §16.7.5) to that input and
  refused the member with "GNU sparse extents overlap, are empty, or are not
  merged". Every sparse file ending in a hole was affected, not just wholly
  sparse ones, so `tar cf - dir | tzap create --tar-stdin -` failed on any
  tree containing one. The zero-length entries are now dropped as part of the
  rewrite to revision-45 canonical framing, which is what
  `public-docs/tzap-operational-boundaries.md` already promised. Maps whose
  remaining extents overlap, are unsorted, are left unmerged, or disagree with
  the stored byte count are still rejected.

## 0.2.4 - 2026-09-12

- Fixes silent sibling-volume discovery failure for bare relative archive
  paths. `Path::parent()` on a bare file name such as `archive.vol000.tzap`
  yields `Some("")` rather than `None`, so the fallback to `.` never fired and
  the empty path reached `read_dir`, whose `NotFound` was read as "zero
  volumes found". Listing, extracting, or verifying a multi-volume archive by
  its first volume's bare name — the most common way to invoke the CLI, from
  inside the archive's own directory — reported the archive as corrupt even
  when every volume was present. The same fix restores `create`'s
  pre-existing-volume collision check, which previously skipped the check for
  bare output paths and could overwrite old volumes without warning.
- Fixes a panic in TZAP volume-name parsing on non-ASCII archive file names.
  Case-insensitive suffix stripping now splits on UTF-8 character boundaries
  instead of raw byte offsets.
- Fixes "streamed tar member metadata flags do not match FileEntry flags" on
  real multi-volume archives written from generic Unix source OSes (FreeBSD,
  NetBSD, OpenBSD, Solaris, other Unix). `LIBARCHIVE.creationtime` is owned by
  the `posix-backup-v1` profile for those source OSes, so the writer now
  declares that profile at the exact call site that attaches the key, and the
  entry-flag prediction agrees with what the reader recomputes from the
  written header. Hardlink aliases keep their `portable-v1`-only invariant.
- Adds `tzap-plugin-signing::x509_chain::verify_root_auth_footer_at_time` —
  chain validation against a caller-supplied time basis instead of the
  verifier's own clock.
- Adds `tzap-core::public_no_key_verify_readers_with` and
  `public_no_key_verify_readers_with_options` — public-no-key verification for
  callers that already hold open readers rather than volume paths.
- Moves the embedded TZAP production and staging root certificates and their
  pinned SHA-256 fingerprints out of `tzap-cli` into
  `tzap-plugin-signing::trust`, so `tzap-cli` and downstream consumers import
  one copy instead of embedding their own and letting the bytes drift.
- Updates `chacha20` to 0.10.2; 0.10.1 was yanked from crates.io.
- Expands test coverage substantially: property-style parser and restore-policy
  tests, Unicode archive end-to-end coverage, platform-aware restore tests,
  and writer-level round-trip coverage for native-metadata flag prediction.
- Runs the fuzzing jobs on nightly Rust.

## 0.2.3 - 2026-08-20

- Extraction is dramatically faster: `tzap extract` no longer fsyncs each
  restored file's data and directory entry by default (pass `--fsync` to
  restore the old durable-by-default behavior), and payload envelopes are
  cached across the members that share one instead of being re-decrypted and
  re-decompressed per file.
- `verify` and `extract --all` decode payload frames in parallel instead of on
  a single thread.
- Upgrades `aes-gcm`, `aes-gcm-siv`, and `chacha20poly1305` to pick up
  hardware-accelerated AES on aarch64, substantially speeding up encrypt,
  decrypt, and verify on Apple Silicon and other 64-bit ARM hosts.
- macOS extraction publishes files with an atomic rename (`renameatx_np`)
  instead of a full-file copy, matching the existing Linux and Windows
  publish paths.
- Reduces allocation and copying on the payload decrypt and repair paths, and
  in the archive writer's chunk buffer.

## 0.2.2 - 2026-08-09

- Adds `tzap-plugin-signing::x509_chain::verify_root_auth_signature` — a
  trustless (no chain, no roots, no time) signature check over the recomputed
  archive root, with the `X509RootAuthSignatureReport` result. Consumers that
  only need to display certificate info can delegate to it instead of
  reimplementing scheme-1-only subset verification.

## 0.2.0 - 2026-08-04

- Updates the tzap format to the v45 specification, incorporating format-level
  improvements and spec refinements.
- Adds cross-platform native metadata capture and restore: Linux sparse files,
  xattrs, project IDs, FIFO/device descriptors, and whiteouts; macOS Darwin
  flags, ACLs, FinderInfo, resource forks, and creation time; Windows reparse
  points, security descriptors, and object IDs.
- Exposes the `list` function in the public API for downstream consumers.
- Fixes PAX column handling and closes metadata column gaps across the reader
  and writer stacks.
- Enhances the reader with indexed entry lookups, frame-based streaming, and
  richer index-only metadata in archive listings.
- Improves the writer with phase-native progress reporting for metadata-heavy
  archives.
- Adds a staging root CA certificate for development and testing workflows.
- Significantly expands CLI smoke test coverage.
- Applies code-review fixes and formatting cleanups.
- Fixes multiple CI pipeline stability issues.

## 0.1.12 - 2026-07-26

- Enables `--allow-absolute-symlinks` extraction toggle for absolute symlink recovery outside the destination directory.
- Fixes validation logic to correctly enforce NFC normalization on absolute symlink targets.
- Verifies implementation of PAX records such as `LIBARCHIVE.creationtime` and `atime` across the reader stack.
- Bumps protocol test coverage by renaming legacy v36 corpus structures to accurately map to v45 expectations.

## 0.1.11 - 2026-07-17

- Closes Linux revision-45 metadata gaps for sparse allocation, auxiliary
  xattrs, no-follow symlink metadata, project IDs, FIFO/device descriptors,
  whiteouts, and authorized native restoration.
- Captures macOS regular-file metadata, including Darwin flags, xattrs, native
  ACLs, FinderInfo, resource forks, creation time, and observed ctime.
- Replaces logical-source-only create progress with phase-native writer progress.
- Reports planning and emission source bytes separately for multi-pass writers.
- Exposes planning-payload, planning-metadata, emitting-payload, and
  emitting-metadata phase transitions for live progress and ETA consumers.

## 0.1.10

- Stores and exposes archive entry modified times in TZAP index metadata.
- Improves streamed list and frame lookup paths by using indexed entries.
- Exposes richer index-only metadata for archive listings.
- Removes legacy v43 parser support and tightens current-format handling.
- Hardens recovery and recipient-wrap paths.
- Updates the embedded TZAP production root.
- Fixes sink-backed create timing labels and CI fixture metadata expectations.
