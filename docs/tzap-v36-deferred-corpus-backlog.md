# tzap v0.36 Deferred Corpus Backlog

Status: post-release evidence backlog
Primary spec: `specs/tzap-format-revisedv36.md`, section 28.1

This backlog is separate from the G13 release gate. G13 decides whether a tag is
safe to publish with supported-surface wording. D01 tracks corpus expansion that
remains visible after the release gate is closed.

Rows in `docs/tzap-v36-corpus-tracker.md` that link to `[D01]` are not hidden
or treated as complete. They block any public "fully v0.36 conformant" or
"complete v0.36 implementation" claim until they are covered, formally
deferred without a public feature claim, or moved to a future release plan.

## D01 - Post-Release Corpus Expansion

Scope:

- Add deterministic fixtures for remaining `partial` and `missing` section
  28.1 corpus rows.
- Add integration fixtures for intentionally unclaimed product modes such as
  true sink writers, CLI archive stdin, S3/range-read workflows, and directory
  FileEntry history views before those modes are advertised.
- Expand mutation matrices for authenticated pointer bounds, table duplicate
  consistency, zero-object rejection, HMAC/CRC boundary bytes, and large stress
  cases.

Representative tracker rows:

- C016 zero-data encrypted objects
- C023 header/trailer identity binding
- C052 cross-shard envelope frame coverage
- C065 directory hint shard-count cap
- C085 hash-sorted index stress
- C096 duplicate local table consistency
- C104 sidecar cap arithmetic
- C109 S3 round-trip

Release rule:

- G13 may close while D01 remains open only because G13 blocks overclaiming and
  keeps those rows out of README marketing language.
- Any future release that wants to claim full v0.36 conformance must close D01
  or split every remaining row into explicit future-release issues with no
  public feature claim.
