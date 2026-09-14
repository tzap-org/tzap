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
| 16.18.4 Adversarial | 17 | 17 | 0 | 0 |

Every §16.18.3 Windows fixture is `#[cfg(windows)]` and runs only on the
Windows CI job; the macOS and Linux jobs do not exercise it.

### Open gaps

**None.** Every §16.18 row is covered, with no implementation gaps, no missing
fixtures and no missing regression guards.

That is a statement about the corpus, not a claim of total conformance. §16.18
is a floor: it names the cases the project must publish fixtures for. Clearing
it does not substitute for the external conformance program the claim boundary
in [README.md](README.md) calls for, and the wording there still applies —
v45-conformant for documented supported workflows, not for every optional,
future, historical or unsupported profile.

Two rows were closed by withdrawal rather than by new tests, after reading test
bodies instead of names: NFSv4 ACLs already carried positive and negative cases
for both exact syntax IDs, and the reparse-placeholder negative direction was
already asserted against a real Windows junction. Both had been recorded as gaps
by an earlier name-led pass.

### What "no open rows" did not catch

Full §16.18 coverage is a floor, and clearing it is not the same as covering the
combinations the rows describe. Two release-blocking defects sat inside rows
recorded as covered:

- **Long non-ASCII names.** 16.18.1 has a long-name fixture and a unicode-name
  fixture, and neither is a long unicode name. Every member named in more than
  about 70 Chinese characters archived cleanly and could not be extracted at
  all. The differential corpus had the same shape, so neither matrix saw it.
  Both now carry a 240-byte CJK name, and `leaf_prefix_within` is pinned
  directly rather than only through a restore.
- **APFS clone pairs.** 16.18.2 claims macOS clone hints, but nothing in either
  corpus produced two files that actually share storage, so the reader refusing
  to restore the hint the writer had just recorded went unseen. The shared
  corpus now builds a clone pair where the platform supports one.

The lesson is about corpora rather than about these two rows: a row is covered
by a fixture that reaches the code, not by a fixture that shares its name.

## Reproducing

```sh
cargo test --workspace
```

Windows fixtures require a Windows host; macOS fixtures require macOS. The
six-platform CI matrix runs all three families. Privileged fixtures (device
nodes, SACL acquisition, system file flags) skip themselves when the runner
lacks the privilege rather than failing.
