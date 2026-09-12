# Changelog

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
