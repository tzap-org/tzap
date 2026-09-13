# v45 conformance classes and corpus

This document discharges two publication obligations in
`specs/tzap-format-revisedv45.md`:

- **§16.17**: "An implementation MUST publish its conformance classes and MUST
  NOT advertise an OS backup class when it merely stores primary file bytes."
- **§16.18**: "Before revision 45 is declared stable, the project MUST publish
  deterministic fixtures covering at least: …"

It uses the status terms defined in [README.md](README.md).

## Conformance classes claimed

| §16.17 class | Claimed | Basis |
| --- | --- | --- |
| 16.17.1 Core reader | yes | Validates revision-45 outer structures, parses member groups, verifies auxiliary hashes and metadata canonicality, supports `content` extraction, and reports unsupported profiles without claiming full restoration. |
| 16.17.2 Portable reader/writer | yes | Complete `portable-v1`, safe symlink/hardlink handling, nanosecond mtime, and sparse files in both directions. |
| 16.17.3 POSIX backup reader/writer | yes | `posix-backup-v1` plus POSIX.1e access and default ACLs, which satisfies the class's "at least one declared ACL implementation". NFSv4 ACL syntax is parsed and validated but is **not** claimed as a round-trip implementation — see the gaps below. |
| 16.17.4 Linux backup reader/writer | yes | `linux-backup-v1`, inode flags, project IDs, xattrs, FIFO/device/whiteout descriptors, native sparse allocation, and privileged-namespace diagnostics. |
| 16.17.5 macOS backup reader/writer | yes | `macos-backup-v1`, native ACLs, xattrs, FinderInfo, resource forks, Darwin flags, and APFS clone hints. Clone sharing is recorded at capture and re-established on restore where the destination supports it; per §16.11 failure to clone is storage-layout degradation with a diagnostic, never a content error. |
| 16.17.6 Windows backup reader/writer | yes | `windows-backup-v1`, owner/group/DACL self-relative security descriptors plus SACL where privilege allows, named data streams, EAs, property data, object IDs, reparse data, sparse primary and named streams, native compression, raw EFS, and Windows attributes and 100-ns times. |

None of these classes rests on merely storing primary file bytes. Each OS class
above is backed by capture and restore of that platform's native metadata, with
per-entry authenticated capture reports when a class cannot be captured in full.

## §16.18 corpus coverage

Deterministic fixtures live in the workspace test suite and run under
`cargo test --workspace`. Coverage by corpus section:

| §16.18 section | Clauses | Implemented and tested | Evidence gap | Implementation gap |
| --- | ---: | ---: | ---: | ---: |
| 16.18.1 Portable and Unix | 11 | 11 | 0 | 0 |
| 16.18.2 macOS | 6 | 6 | 0 | 0 |
| 16.18.3 Windows | 8 | 8 | 0 | 0 |
| 16.18.4 Adversarial | 17 | 13 | 4 | 0 |

Every §16.18.3 Windows fixture is `#[cfg(windows)]` and runs only on the
Windows CI job; the macOS and Linux jobs do not exercise it.

### Open gaps

| Item | §16.18 clause | Status | Effect |
| --- | --- | --- | --- |
| Projection rename/mode-override guard | 16.18.4 | Evidence gap | The restore path contains no rename and applies readonly only through the host attribute, never through `TZAP.portable.mode`, so §16.7.1's MUST NOT holds by construction. No regression guard asserts it. |
| Metadata phase-ordering guard | 16.18.4 | Evidence gap | Ordering matches §16.13 steps 8–14: ownership, mode, ACLs, xattrs, timestamps, readonly attributes, then no-change flags last. No regression guard asserts the order. |
| FileEntry flag-summary mismatch | 16.18.4 | Evidence gap | Reserved-bit rejection is asserted. A crafted summary that disagrees with the recomputed group summary is not. |
| Reparse placeholder mis-extraction | 16.18.4 | Evidence gap | Placeholders round-trip correctly. The negative direction — a placeholder extracted as an empty ordinary file, or replaced by a directory for selected descendants — is not separately asserted. |

This list is complete for the four corpus sections, not a selection: 4
evidence gaps and **no implementation gaps** against 42 clauses. Every gap
remaining is a missing regression guard for behaviour that is correct today, not
a defect. They are published
rather than omitted because §16.18 is a completeness obligation. Until they
close, the claim boundary in [README.md](README.md) applies as written:
v45-compliant for documented supported workflows, not for every optional
profile.

An evidence gap means the behavior may well be correct — in several rows above
it is correct by construction — but the corpus does not yet pin it, so a
regression would be silent. None of these rows is a known defect.

## Reproducing

```sh
cargo test --workspace
```

Windows fixtures require a Windows host; macOS fixtures require macOS. The
six-platform CI matrix runs all three families. Privileged fixtures (device
nodes, SACL acquisition, system file flags) skip themselves when the runner
lacks the privilege rather than failing.
