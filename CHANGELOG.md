# Changelog

## Unreleased

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
