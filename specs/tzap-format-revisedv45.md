# tzap Archive Format Specification (v0.45)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.45 / 2026-07-14.1 (cross-platform metadata profiles) |
| **Status** | Draft implementation target |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Last updated** | 2026-07-14 |
| **Supersedes** | v0.1 ... v0.44 |
| **Superseded by** | None |
| **File extension** | `.tzap` / `.volNNN.tzap` |

## 0. Status, scope, and inherited v0.44 contract

This document defines tzap revision 45. Its primary change is a normative,
cross-platform file-metadata and auxiliary-stream model suitable for high
fidelity file-level backups of Unix, Linux, macOS, and Windows filesystems.

The outer archive machinery defined by v0.44 remains unchanged unless this
document explicitly replaces it. In particular, v0.45 retains the v0.44:

- volume layout, headers, trailers, CMRA, locators, and recovery rules;
- zstd framing, envelope packing, optional AEAD, and object-local FEC;
- IndexRoot, IndexShard, directory-hint, sidecar, and FileEntry byte layouts;
- recipient key wrapping and RootAuth structures;
- safe relative archive-path model; and
- random-access binding between each FileEntry and one tar member group.

The normative text in `tzap-format-revisedv44.md` therefore remains part of
the v0.45 contract except for the following replaced areas:

1. revision identifiers and revision-bound hash/authentication domains;
2. FileEntry flag meanings;
3. tar member-group grammar and verification;
4. file metadata handling; and
5. extraction planning and metadata application order.

If this document conflicts with v0.44 in one of those areas, this document
wins. Implementations and future revisions SHOULD fold the unchanged v0.44
text and this revision into a single self-contained specification before the
format is declared stable.

tzap is a **file-level archive format**, not a block-level filesystem image.
It does not claim to preserve partition tables, filesystem journals, free
space, deleted files, boot sectors, APFS or ZFS snapshots, the NTFS USN
journal, or other volume-internal state. Snapshot-backed capture is addressed
in section 15.

---

## 1. Revision and compatibility rules

### 1.1 Revision identifiers

Conforming v0.45 writers MUST set:

```text
VolumeHeader.volume_format_rev = 45
```

Every other stored revision field MUST also be 45. Revision-bound hash and
authentication domains that ended in `-v44` in v0.44 end in `-v45` in v0.45.
`root_auth_spec_id` is the 20 ASCII bytes `tzap-root-auth-v0.45` followed by
four zero bytes.

The following remain unchanged:

```text
format_version = 1
tzap-v1-* symmetric key-schedule, nonce, AAD, and AEAD domains
```

They identify the cryptographic construction rather than the archive format
revision.

### 1.2 Reader behavior

A reader that does not implement revision 45 MUST fail before interpreting a
v0.45 archive as an earlier revision and SHOULD report:

- observed revision 45;
- its newest supported revision; and
- that a reader upgrade is required.

Because revision 44 has not reached broad deployment, v0.45 conformance does
not require a reader to support v0.44. Implementations MAY support both.
No v0.44-to-v0.45 in-place conversion is defined; conversion is logical
read-and-rewrite.

### 1.3 Revision 45 without rich metadata

All v0.45 archives use revision 45 even when every entry contains only the
portable profile. Writers MUST NOT select a revision per entry.

---

## 2. Design requirements

The v0.45 metadata model has the following requirements:

1. **Self-contained random access.** A FileEntry member group contains all
   portable metadata, native metadata, and auxiliary streams needed for that
   filesystem object.
2. **Portable projection plus native fidelity.** Readers can restore a safe
   portable representation without discarding a richer same-OS
   representation.
3. **No silent success after metadata loss.** Capture and restore omissions
   are explicit and authenticated.
4. **No implicit security translation.** POSIX.1e, NFSv4, macOS, and Windows
   ACLs are not automatically treated as equivalent.
5. **Streamed large metadata.** Resource forks, alternate data streams, EFS
   data, and other large forks are auxiliary members, not unbounded PAX
   values.
6. **Unknown-metadata survivability.** A reader may extract portable data while
   reporting unsupported native metadata, and an archive-to-archive copier can
   retain opaque auxiliary records.
7. **Safe defaults.** Privileged ownership, security labels, device nodes,
   special mode bits, reparse data, and immutable flags are never applied
   accidentally by a quick extractor.

---

## 3. Terminology

**Primary entry**
: The one ustar-compatible regular-file, directory, symlink, hardlink,
  character-device, block-device, or FIFO entry represented by a FileEntry.
  The primary entry is the final tar record in its member group.

**Portable metadata**
: Metadata with specified cross-platform parsing semantics, even when a target
  host cannot apply every field.

**Native metadata**
: Metadata whose exact semantics belong to a named source OS, filesystem, or
  ABI. It may be structured or opaque.

**Auxiliary stream**
: A length-delimited data stream associated with the primary entry but not
  exposed as an independent archive path. Examples include an NTFS named data
  stream, a Windows security descriptor, and a macOS resource fork.

**Selected profile**
: A metadata profile the writer was asked to capture for an entry.

**Required profile**
: A selected profile whose unsupported restoration prevents an operation from
  claiming full-fidelity restoration.

**Capture omission**
: Metadata required by a selected profile that the writer did not capture,
  whether because of policy, privilege, host support, an I/O failure, a limit,
  or concurrent modification.

**Degraded extraction**
: Extraction that restores file content or a portable projection but does not
  restore every required metadata profile.

---

## 4. Revision 45 FileEntry flags

The FileEntry structure and size are unchanged from v0.44. Revision 45 assigns
the following bits in `FileEntry.flags`:

| Bit | Name | Meaning |
|---:|---|---|
| 0 | `EXTENDED_METADATA_V1` | The primary entry carries the v1 metadata declaration from section 6. |
| 1 | `HAS_AUXILIARY_STREAMS` | One or more revision 45 auxiliary members precede the primary entry. |
| 2 | `HAS_NATIVE_METADATA` | A native OS/filesystem profile or native auxiliary stream is present. |
| 3 | `HAS_SPARSE_EXTENTS` | The primary data or an auxiliary stream has a sparse extent map. |
| 4 | `CAPTURE_PARTIAL` | The selected profiles have one or more authenticated capture omissions. |
| 5 | `REQUIRES_SYSTEM_RESTORE` | Full restoration requires the `system` policy from section 13. |
| 6..31 | Reserved | MUST be zero. |

The flags are authenticated lookup and planning hints. Metadata records inside
the member group are authoritative. A reader MUST reject a group when its
decoded contents contradict bits 0 through 5. For example, a group containing
an auxiliary member while bit 1 is clear is malformed.

`HAS_NATIVE_METADATA` is set when the entry selects `linux-backup-v1`,
`macos-backup-v1`, `windows-backup-v1`, another native profile, or carries a
native auxiliary kind. `REQUIRES_SYSTEM_RESTORE` is set when exact restoration
would apply numeric ownership, special executable bits, a privileged/security
xattr, device/FIFO creation, SACL or other privileged security data, arbitrary
reparse data, raw EFS data, or a no-change file flag. `HAS_SPARSE_EXTENTS` is
set when either the primary or any auxiliary stream is sparse.

Every revision 45 FileEntry MUST set bit 0 and declare `portable-v1` as a
required profile. This clean revision boundary avoids two metadata grammars in
new archives. Bits 1 through 5 remain presence/requirement hints and may be
clear for a portable-only entry.

---

## 5. Revision 45 tar member-group grammar

### 5.1 Allowed sequence

A revision 45 FileEntry member group has exactly this sequence:

```text
auxiliary_member*
one primary local PAX header
primary_entry
```

An `auxiliary_member` is:

```text
one local PAX header with TZAP.aux.* keys
one tar header with typeflag 'Z'
auxiliary payload bytes
zero padding to the next 512-byte boundary
```

The primary local PAX header contains the section 6 declaration and every PAX
key applying to the primary entry. Revision 45 writers use the PAX `path` and
`linkpath` keys instead of GNU long-name/long-link records. Multiple primary
local PAX headers, GNU long-name/long-link records, global PAX headers, and
global GNU state are forbidden in revision 45 member groups.

The primary entry MUST be last. A group with no primary entry, more than one
primary entry, an auxiliary member after the primary entry, or unexplained
bytes after the primary entry is malformed.

For deterministic encoding, the tar header for an auxiliary local PAX record
uses `TZAP-PAX/AUX/` plus the same eight-digit ordinal as its auxiliary header.
The primary local PAX record uses `TZAP-PAX/PRIMARY`. These PAX-record header
names are internal labels, never archive paths, and use zero mode, UID, GID,
mtime, uname, gname, and linkname fields.

### 5.2 Auxiliary typeflag

Revision 45 reserves tar typeflag ASCII `Z` (`0x5a`) for a tzap auxiliary
stream. It is meaningful only inside a tzap member group. It MUST NOT produce a
filesystem path during extraction and MUST NOT generate a separate FileEntry.

The auxiliary tar header MUST:

- use the ustar magic and checksum rules;
- use mode, UID, GID, uname, and gname fields of zero/empty;
- use mtime zero;
- set size to the stored auxiliary payload size, or use a local PAX `size`
  override when required;
- use an empty linkname; and
- use the canonical header name `TZAP-AUX/` followed by an eight-digit,
  lowercase hexadecimal ordinal beginning at `00000000` within the group.

Ordinals MUST be contiguous and increasing. They identify ordering only and
are not metadata names.

### 5.3 Required auxiliary PAX keys

The immediately preceding local PAX header MUST contain exactly one value for
each required key:

| Key | Encoding | Meaning |
|---|---|---|
| `TZAP.aux.version` | ASCII decimal | MUST be `1`. |
| `TZAP.aux.kind` | lowercase token | Kind from section 10 or a registered extension kind. |
| `TZAP.aux.name-encoding` | token | `none`, `utf8`, `utf16le-base64`, or `bytes-base64`. |
| `TZAP.aux.name` | profile-defined | Empty when name encoding is `none`; otherwise encoded as declared. |
| `TZAP.aux.flags` | 16 lowercase hex digits | Bit 0 is `AUX_SPARSE_V1`; remaining bits are kind-specific or reserved. Unknown set bits are preserved but not applied. |
| `TZAP.aux.logical-size` | ASCII decimal u64 | Logical size after sparse reconstruction; equals stored size for non-sparse streams. |
| `TZAP.aux.sha256` | 64 lowercase hex digits | SHA-256 of the logical auxiliary byte stream. |

If `AUX_SPARSE_V1` is set, the auxiliary payload begins with the canonical
sparse map from section 8.5. The hash is over the reconstructed logical stream,
including holes as zero bytes. If it is clear, stored and logical size MUST be
equal.

The `(kind, decoded name)` pair MUST be unique within a member group unless a
kind explicitly defines a multi-record sequence. Revision 45 defines no such
multi-record kind.

### 5.4 Streaming and verification

Readers MUST be able to skip or hash an auxiliary payload without allocating
its full size. Full verification recomputes every `TZAP.aux.sha256`, even when
the reader cannot apply that auxiliary kind to the host filesystem.

An extractor MUST finish and verify all auxiliary payloads required for the
selected restore policy before committing the primary object as a successful
full-fidelity restore.

### 5.5 FileEntry binding

`FileEntry.tar_member_group_size` spans from the first auxiliary member's local
PAX header, or the first primary metadata/header when no auxiliary member is
present, through the primary entry's final 512-byte padding. Existing minimal
frame-range rules apply to that entire range.

`FileEntry.path` and `FileEntry.file_data_size` bind only to the decoded primary
entry. Auxiliary header names and auxiliary metadata names do not participate
in path lookup, sorting, directory hints, duplicate-path resolution, or
`file_data_size`. For a sparse regular primary, `file_data_size` is the
reconstructed logical size. It is zero for every non-regular primary type.

Revision 45 primary typeflags are:

| Typeflag | Primary type |
|---|---|
| NUL or ASCII `0` | Regular file |
| ASCII `5` | Directory |
| ASCII `2` | Symlink |
| ASCII `1` | Hardlink |
| ASCII `3` | Character device |
| ASCII `4` | Block device |
| ASCII `6` | FIFO |

All other primary typeflags are malformed unless a later revision defines
them.

---

## 6. Per-entry metadata declaration

Every entry with `EXTENDED_METADATA_V1` set MUST include the following keys in
the local PAX metadata applying to its primary entry:

| Key | Meaning |
|---|---|
| `TZAP.metadata.version=1` | Metadata declaration version. |
| `TZAP.metadata.required-profiles` | Sorted comma-separated required profile IDs. |
| `TZAP.metadata.optional-profiles` | Sorted comma-separated optional profile IDs, or an empty value. |
| `TZAP.metadata.source-os` | `linux`, `freebsd`, `netbsd`, `openbsd`, `solaris`, `macos`, `windows`, `other-unix`, or `other`. |
| `TZAP.metadata.source-filesystem` | Lowercase filesystem token, or `unknown`. |
| `TZAP.metadata.capture-status` | `complete` or `partial`. |

Profile IDs contain only lowercase ASCII letters, digits, hyphen, period, and
underscore, are 1 through 64 bytes, and are compared byte-for-byte. Lists MUST
contain no whitespace, empty items, or duplicates.

`portable-v1` MUST be in the required profile list for every FileEntry. The
source filesystem is informational and MUST NOT be trusted as authority to
perform unsafe restore operations.

If capture status is `partial`:

- `FileEntry.flags.CAPTURE_PARTIAL` MUST be set; and
- exactly one `tzap.capture-report` auxiliary stream MUST be present.

If capture status is `complete`, that auxiliary kind MUST be absent and the
flag MUST be clear.

### 6.1 Unknown profiles

An unknown required profile does not make the archive structurally malformed.
A reader MAY perform content-only or portable degraded extraction after an
explicit caller decision, but MUST NOT report full-fidelity restoration.

An unknown optional profile is skipped with a structured diagnostic. Full
archive verification still verifies its framing, bounds, and auxiliary hashes.

---

## 7. Capture completeness report

The `tzap.capture-report` auxiliary payload uses this canonical UTF-8 format:

```text
tzap-capture-report-v1\n
<metadata-class>\t<reason>\t<percent-encoded-detail>\n
...
```

Rules:

- Lines use LF only and the payload ends with LF.
- `metadata-class` and `reason` are lowercase profile tokens.
- Detail is UTF-8 encoded with every byte outside unreserved ASCII
  `[A-Za-z0-9._~-]` encoded as `%HH` using uppercase hexadecimal.
- Rows are sorted lexicographically by `(metadata-class, reason, encoded
  detail)` and duplicates are forbidden.
- The report MUST contain at least one row.

Defined reasons are:

| Reason | Meaning |
|---|---|
| `excluded-policy` | Caller policy deliberately excluded required metadata. |
| `unsupported-host` | Capture OS has no API for the metadata class. |
| `unsupported-filesystem` | Source filesystem cannot represent the class. |
| `permission-denied` | The writer lacked authority to read it. |
| `changed-during-read` | Relevant identity, size, time, or metadata changed during capture. |
| `limit-exceeded` | A configured resource limit prevented capture. |
| `io-error` | A host I/O or metadata API failed. |
| `invalid-source-metadata` | The host returned metadata that could not be represented safely. |

A strict writer MUST fail archive creation instead of emitting a partial entry
when any selected required profile has an omission. A best-effort writer MAY
emit a partial entry and report every known omission. CLI and GUI creators MUST
make the distinction visible in their final result.

Absence is not an omission. For example, a file with no xattrs can completely
satisfy an xattr-capable profile after the writer successfully enumerates and
finds none.

---

## 8. Canonical portable and POSIX metadata

### 8.1 Baseline fields

The `portable-v1` profile requires:

- normalized path and filesystem object type;
- logical size;
- regular data, directory, symlink target, or hardlink target;
- full mode including file-type and special permission bits;
- numeric UID and GID when the source exposes them;
- user and group names when resolvable without changing numeric ownership;
- modification time with source precision up to nanoseconds;
- sparse extents when the source exposes them; and
- a portable projection of readonly/hidden/system/archive attributes when
  those concepts exist.

The optional portable attribute projection uses
`TZAP.portable.attributes=<8 lowercase hex digits>` with this bit assignment:

| Bit | Meaning |
|---:|---|
| 0 | Readonly |
| 1 | Hidden |
| 2 | System |
| 3 | Archive/needs-backup marker |
| 4..31 | Reserved, MUST be zero |

This field never replaces the exact source-native attribute or flag field.

Every portable declaration also includes:

| Key | Values | Meaning |
|---|---|---|
| `TZAP.portable.owner-kind` | `posix` or `none` | Whether archived UID/GID and names came from a native POSIX ownership model. |
| `TZAP.portable.mode-origin` | `native` or `projected` | Whether mode bits are native or a portable projection synthesized from source attributes. |

When owner kind is `none`, ustar UID/GID fields are zero and uname/gname are
empty placeholders with no ownership meaning. A reader MUST NOT treat them as
a request to restore root ownership.

Standard ustar fields are used when values fit. The standard local PAX keys
`path`, `linkpath`, `size`, `uid`, `gid`, `uname`, `gname`, and `mtime` are used
when the corresponding ustar field is absent, truncated, or lacks required
range or precision. PAX values are authoritative over the ustar fields.

UID/GID and user/group names are archived together. A name never changes the
stored numeric identity. Restoration policy decides whether to apply a numeric
identity, map a name, or leave destination ownership unchanged.

### 8.2 Times

Times use signed decimal seconds with an optional fractional component of one
through nine decimal digits. Writers MUST remove trailing fractional zeroes and
MUST NOT emit a decimal point when the fraction is zero.

Defined keys are:

| Key | Meaning |
|---|---|
| `mtime` | Last data modification time. |
| `atime` | Last access time; optional and normally not restored. |
| `LIBARCHIVE.creationtime` | Birth/creation time, distinct from Unix ctime. |
| `TZAP.unix.ctime-observed` | Unix inode metadata-change time, informational only. |
| `TZAP.windows.change-time` | Windows file change time when available. |

Unix ctime MUST NOT be described or restored as creation time. Writers SHOULD
avoid atime capture when merely reading the file changes it, unless operating
from a snapshot or using a no-atime facility.

### 8.3 Extended attributes

Canonical portable/POSIX xattrs use:

```text
LIBARCHIVE.xattr.<encoded-name>=<base64-value>
```

The name encoding is compatible with libarchive:

- bytes `0x21` through `0x7e` are literal except `%` and `=`;
- all other bytes, `%`, and `=` are encoded as `%HH` with uppercase hex;
- NUL is forbidden in the decoded name.

The value uses the RFC 4648 base64 alphabet without whitespace and without
trailing `=` padding, matching libarchive's PAX convention. Duplicate decoded
xattr names are malformed.

An xattr value that would make the primary PAX header exceed the section 16
limit uses `generic.xattr`; its decoded auxiliary name is the exact xattr name
and its payload is the exact value. Large fork-like xattrs such as
`com.apple.ResourceFork` use their dedicated auxiliary kind when one exists.
An xattr MUST have exactly one canonical representation and must never be
silently truncated.

### 8.4 ACLs

The canonical textual ACL keys are:

| Key | ACL model |
|---|---|
| `SCHILY.acl.access` | POSIX.1e access ACL |
| `SCHILY.acl.default` | POSIX.1e default directory ACL |
| `SCHILY.acl.ace` | NFSv4-style ACL |

When any ACL key is present, `TZAP.acl.projection` is also present with value
`exact` or `lossy`. A native ACL represented only by an auxiliary stream uses
`TZAP.acl.projection=none`.

Named users and groups SHOULD include the numeric qualifier form supported by
the SCHILY/libarchive grammar. Writers use the libarchive compact,
comma-separated text form with extra numeric IDs and no trailing comma or
newline. ACL text is UTF-8. A writer MUST NOT emit POSIX.1e and NFSv4 ACL keys
for the same source ACL unless one is explicitly marked as a lossy projection
and the native representation remains present.

Windows security descriptors and native macOS ACL blobs are not encoded as
these textual fields; they use the native auxiliary kinds in section 10.
Filesystem-internal xattrs that are merely the backing representation of an
ACL already encoded by this section MUST NOT be emitted as duplicate generic
xattrs. An unrecognized ACL-like xattr is preserved as an xattr rather than
discarded.

### 8.5 Sparse files

Revision 45 canonical primary sparse metadata is GNU PAX sparse format 1.0.
Writers MUST emit the local keys `GNU.sparse.major=1`,
`GNU.sparse.minor=0`, `GNU.sparse.name=<real path>`, and
`GNU.sparse.realsize=<logical size>`. The ustar header name uses the GNU sparse
placeholder form and does not replace the FileEntry path binding to
`GNU.sparse.name`. For a sparse primary, `GNU.sparse.name` replaces the ordinary
PAX `path` key; `path` MUST be absent and the decoded `GNU.sparse.name` MUST
equal the FileEntry path. Old GNU sparse headers and GNU sparse PAX versions
0.0 and 0.1 are forbidden.

The stored tar payload begins with a canonical newline-delimited map:

```text
<extent-count>\n
<offset-0>\n
<length-0>\n
...
```

All numbers are minimal unsigned decimal without leading zeroes except the
single value `0`. The map is NUL-padded to a 512-byte boundary and followed by
the extent data in map order. The ustar/PAX stored `size` includes the padded
map plus stored extent bytes; `FileEntry.file_data_size` and
`GNU.sparse.realsize` are the reconstructed logical size.

Extents MUST be sorted, non-overlapping, within logical size, and expressed as
checked u64 offset/length pairs. Adjacent extents SHOULD be merged. A reader
that cannot create sparse output MAY materialize holes as zeroes only with a
degraded-storage diagnostic; logical file bytes remain identical.

An auxiliary stream with `AUX_SPARSE_V1` uses the same newline map, padding,
and extent-data sequence but does not use the `GNU.sparse.*` path keys.
`TZAP.aux.logical-size` supplies its reconstructed size, while the auxiliary
tar header/PAX `size` supplies stored map-plus-data size.

### 8.6 Unix and BSD file flags

`SCHILY.fflags` stores the canonical comma-separated textual projection when
available. Exact native values additionally use one of:

| Key | ABI |
|---|---|
| `TZAP.linux.fsflags` | 16 lowercase hex digits from Linux `FS_IOC_GETFLAGS`. |
| `TZAP.bsd.st-flags` | 16 lowercase hex digits from BSD `st_flags`. |
| `TZAP.macos.st-flags` | 16 lowercase hex digits from Darwin `st_flags`. |

Unknown native bits are retained but never applied by a reader that does not
recognize their source ABI. Immutable, append-only, system-immutable, and
similar no-change flags require the `system` restoration policy and are
applied last.

---

## 9. Metadata profiles

Profiles are composable. A profile makes capture and restoration claims; it
does not imply that every possible metadata item is present on every entry.

### 9.1 `portable-v1`

Mandatory for every FileEntry. It consists of section 8.1,
nanosecond mtime where the source supports it, safe link semantics, and sparse
layout.

### 9.2 `posix-backup-v1`

Adds:

- numeric and named ownership;
- POSIX.1e or NFSv4 ACLs;
- all readable xattrs not moved to an auxiliary stream;
- birth time where available;
- exact native file flags;
- device major/minor descriptors;
- FIFO and device-node types; and
- complete hardlink topology.

Sockets are not archived as recreatable live sockets. A writer MAY record an
omission or a non-restorable inventory entry under an extension profile.

### 9.3 `linux-backup-v1`

Requires `posix-backup-v1` and adds:

- Linux inode flags;
- `user.*`, `security.*`, `system.*`, and `trusted.*` xattrs readable by the
  writer;
- file capabilities and Linux Security Module labels as their exact xattrs;
- optional filesystem project ID using `TZAP.linux.project-id`; and
- optional whiteout representation using `TZAP.linux.whiteout=1` for
  container/overlay workflows.

Privileged xattr namespaces and capabilities require the `system` policy for
restoration.

### 9.4 `macos-backup-v1`

Requires `posix-backup-v1` and adds:

- exact Darwin flags;
- macOS ACL native form plus a portable projection when possible;
- all readable xattrs;
- Finder information;
- resource fork as `macos.resource-fork`;
- creation time and other supported high-resolution times;
- type and creator codes when exposed; and
- optional APFS clone-group hints.

Logical primary and resource-fork bytes are authoritative. Clone-group hints
are optimization metadata; failure to recreate clone sharing does not change
file contents but produces a degraded-storage diagnostic.

### 9.5 `windows-backup-v1`

Adds:

- Windows creation, last-access, last-write, and change times;
- the exact `FILE_ATTRIBUTE_*` mask in `TZAP.windows.file-attributes` as eight
  lowercase hex digits;
- self-relative security descriptor and its captured SECURITY_INFORMATION
  mask;
- NTFS/ReFS named data streams;
- Windows extended-attribute data;
- reparse tag and reparse payload without following the reparse point;
- sparse ranges for primary and named streams;
- object ID, property data, and hardlink identity when exposed;
- case-sensitive-directory state when exposed; and
- optional raw EFS backup data.

The portable time mapping is Windows last-write to `mtime`, last-access to
`atime`, and creation to `LIBARCHIVE.creationtime`; Windows change time remains
the separate `TZAP.windows.change-time` value. No Windows time is mapped to
Unix inode ctime.

The profile is modeled on the Win32 backup stream classes, but excludes
undocumented filesystem-internal streams unless a future profile defines them.
Offline/cloud placeholders MUST NOT be hydrated merely because a writer scans
them unless capture policy explicitly requests hydration.

If `FILE_ATTRIBUTE_ENCRYPTED` is set and exact EFS preservation was selected,
`windows.efs-raw` is required; failure to obtain it makes capture partial or
fails strict capture. A caller may instead select a logical-decrypted-content
backup policy, but that archive does not claim preservation of EFS encryption
state. Failure to recreate NTFS/ReFS physical compression is degraded storage,
not a logical byte mismatch, and must still be reported for same-OS fidelity.

### 9.6 Profile-specific scalar keys

Profile scalar values use these canonical encodings:

| Key | Encoding and meaning |
|---|---|
| `TZAP.linux.project-id` | Minimal unsigned decimal u32 project ID. |
| `TZAP.linux.whiteout` | `1`; primary type is character device with major/minor zero. |
| `TZAP.macos.clone-group` | 32 lowercase hex digits identifying a writer-local logical clone group. |
| `TZAP.windows.file-attributes` | Eight lowercase hex digits containing the exact source `FILE_ATTRIBUTE_*` mask. |
| `TZAP.windows.directory-case-sensitive` | `0` or `1` for the source directory's case-sensitive lookup flag. |

Clone-group values have meaning only within one archive and are hints, not
filesystem object IDs. Unknown Windows attribute bits are retained but not
applied by readers that do not recognize them.

---

## 10. Registered auxiliary kinds

The following kinds are defined in revision 45:

| Kind | Name encoding | Payload |
|---|---|---|
| `tzap.capture-report` | `none` | Canonical report from section 7. |
| `windows.security-descriptor` | `none` | Self-relative Windows security descriptor. |
| `windows.alternate-data` | `utf16le-base64` | Exact named data-stream bytes. |
| `windows.ea-data` | `none` | Opaque Windows backup EA stream. |
| `windows.reparse-data` | `none` | Exact `REPARSE_DATA_BUFFER` bytes returned by the source API. |
| `windows.object-id` | `none` | Opaque object-ID data. |
| `windows.property-data` | `bytes-base64` | Opaque named property stream. |
| `windows.efs-raw` | `none` | Raw EFS backup representation. |
| `macos.resource-fork` | `none` | Exact resource-fork bytes. |
| `macos.acl-native` | `none` | Native macOS ACL external form. |
| `macos.finder-info` | `none` | Exact FinderInfo bytes when not stored canonically as an xattr. |
| `generic.xattr` | `bytes-base64` | Exact xattr value whose name is the decoded auxiliary name. |
| `generic.named-fork` | `bytes-base64` | Source-platform named fork under an extension profile. |

### 10.1 Kind-specific metadata

Kind-specific fields use `TZAP.aux.meta.<name>` keys in the auxiliary PAX
header. Names follow profile-token syntax. Values MUST define their encoding in
the profile that introduces them.

Revision 45 defines:

| Kind | Required field |
|---|---|
| `windows.security-descriptor` | `TZAP.aux.meta.security-information`, eight lowercase hex digits. |
| `windows.reparse-data` | `TZAP.aux.meta.reparse-tag`, eight lowercase hex digits. |
| `windows.alternate-data` | `TZAP.aux.meta.stream-type`, eight lowercase hex digits. |
| `windows.efs-raw` | `TZAP.aux.meta.efs-version`, ASCII decimal. |
| `macos.acl-native` | `TZAP.aux.meta.acl-format=darwin-acl-external-v1`. |

For `windows.reparse-data`, `TZAP.aux.meta.reparse-tag` MUST equal the tag in
the decoded `REPARSE_DATA_BUFFER`. A mismatch is malformed.

`darwin-acl-external-v1` is the opaque external representation produced by the
Darwin ACL externalization API. It is retained for same-OS fidelity. The
`SCHILY.acl.ace` projection remains the portable, inspectable representation;
a reader MUST NOT claim that the opaque representation is portable to a
different ACL ABI.

Readers MUST preserve unknown kind-specific fields during archive-to-archive
copy. Filesystem extraction ignores unknown fields with a diagnostic unless
the containing profile is required, in which case full-fidelity restoration
is unavailable.

### 10.2 Native names

UTF-16LE names are encoded as unpadded RFC 4648 base64 over the exact code-unit
bytes. They MUST contain an even number of decoded bytes and MUST NOT contain a
NUL code unit. Readers MUST validate Windows stream-name rules before applying
them and MUST never concatenate an untrusted stream name into an extraction
path used for an ordinary file.

Byte-string names use unpadded base64 and are never interpreted as archive
paths.

---

## 11. Hardlinks, aliases, and special objects

Hardlink identity is topology, not ownership. Writers MUST choose one primary
regular-file entry containing the data and represent other names as hardlink
entries targeting that canonical archive path. Writers SHOULD order the data
entry before its hardlinks. Readers MAY use a two-pass plan but MUST validate
that every target resolves to an in-archive regular object and never through a
symlink or host reparse point.

Directory hardlinks are forbidden. Symlinks and Windows reparse points are
distinct:

- a normal symlink uses the portable tar symlink entry;
- a reparse point not losslessly representable as a safe symlink uses a
  primary placeholder plus `windows.reparse-data` and requires same-OS restore;
- readers MUST open and capture reparse points without following them.

Device nodes and FIFOs may be represented by `posix-backup-v1`, but creation
requires the `system` restore policy. Live Unix sockets are not recreated.

Mount points, bind mounts, junctions, and other traversal boundaries are not
followed unless capture policy explicitly selects traversal. The writer records
that policy at archive-operation level when such a manifest is available.

---

## 12. Portable projection and native authority

An entry may carry both a portable projection and native metadata. The native
record is authoritative for same-OS restoration; the portable projection is
authoritative only for portable extraction.

Readers MUST NOT automatically perform semantic translations that can grant
additional access or change object behavior, including:

- Windows security descriptor to POSIX or NFSv4 ACL;
- NFSv4 ACL to POSIX.1e ACL;
- POSIX ACL to Windows security descriptor;
- Linux security labels or capabilities to another OS security mechanism;
- arbitrary reparse data to a Unix symlink; or
- Linux/BSD immutable flags to unrelated Windows attributes.

A tool MAY offer an explicit lossy conversion operation. It MUST describe the
conversion, retain the source-native record when producing another tzap
archive, and report that the result is not an exact metadata restoration.

Unknown native metadata may be listed, verified, copied, or exported to a
sidecar. Successfully extracting only the primary data does not erase the fact
that native metadata was skipped.

---

## 13. Restore policies

Conforming extraction APIs expose behavior equivalent to these four policies.
Names in a product UI may differ, but the security boundaries must not.

### 13.1 `content`

Restores regular primary bytes and safe directories only. Links, ownership,
ACLs, xattrs, native streams, and special objects are skipped with diagnostics.

### 13.2 `portable`

This is the default for quick extraction. It restores:

- primary data and directories;
- validated symlinks and hardlinks;
- ordinary user/group/other permission bits;
- sticky bit on directories where supported;
- mtime;
- sparse layout where supported; and
- harmless readonly/hidden projections where the target has a direct meaning.

It does not change ownership, restore setuid/setgid, create device nodes, apply
privileged xattrs, apply native ACLs, create arbitrary reparse points, restore
alternate streams, or set immutable flags.

### 13.3 `same-os`

Adds compatible ordinary ACLs, ordinary xattrs, creation time, native named
streams/forks, and platform attributes. It still excludes operations requiring
system privilege or capable of creating privileged executable state unless the
caller explicitly authorizes them.

### 13.4 `system`

May additionally restore:

- numeric ownership;
- setuid/setgid bits;
- privileged/security xattrs and file capabilities;
- complete Windows security descriptors including requested SACL data;
- arbitrary supported reparse points;
- devices and FIFOs;
- raw EFS data; and
- immutable, append-only, and other no-change flags.

The API MUST require an explicit selection of this policy. Failure to obtain
needed privilege is a restoration failure or an explicitly accepted degraded
result, never silent success.

### 13.5 Unsupported required profiles

When the selected policy requests full restoration and a required profile is
unsupported, the extractor MUST stop before claiming success. It MAY offer:

- cancel;
- portable/degraded extraction with a durable report; or
- extraction of supported entries only with a durable report.

Non-interactive CLI use MUST require an explicit degraded/best-effort option.

---

## 14. Normative extraction order

Metadata is order-sensitive. A conforming full restore performs these phases:

1. Parse and validate every selected FileEntry and member group without
   following destination symlinks or reparse points.
2. Create directories with temporary restrictive permissions.
3. Create primary regular files and write primary data and sparse extents.
4. Create and verify auxiliary streams/forks that are safe for the policy.
5. Create validated symlinks, hardlinks, and supported reparse objects.
6. Apply ownership where authorized.
7. Apply ACLs and xattrs, including security descriptors where authorized.
8. Apply ordinary mode bits and platform attributes.
9. Apply file timestamps.
10. Apply directory ownership, ACLs, mode, and timestamps after their children.
11. Apply immutable, append-only, system-immutable, and other no-change flags
    last.

If a later phase fails, the extractor MUST report the affected path, metadata
class, profile, host error, and whether primary bytes were committed. A
transactional extractor SHOULD stage output and commit only after requested
verification succeeds.

Archive path safety, no-follow ancestry checks, hardlink validation, symlink
escape rules, and the host-independent rejection set from v0.44 remain in
force. Auxiliary names are metadata and never bypass those rules.

---

## 15. Consistent capture

The format can prove what bytes were archived but cannot make a changing live
filesystem consistent. Writers claiming backup-grade capture SHOULD read from
a stable snapshot, including where available:

- VSS on Windows;
- APFS snapshots on macOS;
- ZFS, Btrfs, LVM, or equivalent Unix/Linux snapshots.

Without a snapshot, the writer MUST detect concurrent change at least by
comparing available identity, type, size, modification/change time, link count,
and metadata generation information before and after data/metadata capture.
A detected relevant change is `changed-during-read` and makes a strict selected
profile fail.

Writers MUST capture symlinks and reparse points without following them. They
MUST define whether filesystem boundaries are crossed. Opening a cloud/offline
placeholder, automount, or recall point solely for enumeration MUST NOT trigger
hydration or recall unless capture policy explicitly permits it.

Capture tools SHOULD display and durably log the selected profiles,
strict/best-effort mode, snapshot status, filesystem-boundary and placeholder
policy, creator privilege summary, and aggregate omissions. Revision 45 does
not define a separate archive-level operation-manifest object; per-entry
metadata declarations and capture reports are the authenticated authority.

---

## 16. Resource limits and malformed metadata

Readers must apply resource limits before allocation while distinguishing a
local resource-limit refusal from malformed archive data.

Revision 45 format limits are:

| Item | Limit |
|---|---:|
| Profile count per entry | 64 required + 64 optional |
| Profile ID length | 64 bytes |
| Auxiliary count per member group | 65,535 |
| Decoded auxiliary name | 65,535 bytes |
| Local PAX payload per header | 64 MiB |
| Decoded individual xattr value | 64 MiB |
| Decoded xattr name | 65,535 bytes |
| Capture report payload | 64 MiB |
| Primary or auxiliary logical size | u64 |

Auxiliary payloads are streamed and are not subject to the 64 MiB metadata
value limit. Implementations MAY use lower configurable limits, but MUST report
which limit refused the operation. A writer hitting a configured capture limit
either fails strict capture or records `limit-exceeded` in a partial entry.

Readers MUST reject:

- duplicate PAX keys whose semantics would be ambiguous;
- duplicate decoded xattr names;
- duplicate auxiliary `(kind, name)` pairs;
- invalid base64, percent encoding, UTF-8, or UTF-16LE;
- non-canonical hex or decimal encodings;
- sparse extent overflow, overlap, or out-of-range extents;
- mismatched FileEntry flags and group contents;
- auxiliary hashes or logical sizes that do not verify;
- a complete capture status accompanied by an omission report;
- a partial status without a non-empty canonical omission report; and
- unknown reserved FileEntry flag bits.

---

## 17. Verification and diagnostics

Structural verification does not require the ability to apply every metadata
profile. It does require parsing all revision 45 framing, validating canonical
metadata encodings, checking bounds, and hashing every auxiliary stream.

Full verification reports separately:

1. archive structural/integrity result;
2. capture completeness result;
3. profiles present;
4. profiles the current reader can restore under each policy; and
5. metadata that would be degraded on the current host.

CLI diagnostics are written to stderr and structured library diagnostics
include at least:

```text
path
profile
metadata class or auxiliary kind
operation: capture | parse | verify | restore
status/reason
native host error when available
```

An archive can be structurally valid while capture-partial. A capture-complete
archive can be structurally valid but not fully restorable on the current OS.
Tools MUST not conflate these states.

---

## 18. Conformance classes

### 18.1 Core reader

A core reader:

- validates revision 45 outer structures;
- parses revision 45 member groups;
- verifies auxiliary hashes and metadata canonicality;
- supports `content` extraction; and
- reports unsupported profiles without claiming full restoration.

### 18.2 Portable reader/writer

Adds complete `portable-v1`, safe links, nanosecond mtime, and sparse files.

### 18.3 POSIX backup reader/writer

Adds `posix-backup-v1` and at least one declared ACL implementation.

### 18.4 Linux backup reader/writer

Adds `linux-backup-v1`, including privileged namespace diagnostics.

### 18.5 macOS backup reader/writer

Adds `macos-backup-v1`, native ACLs, xattrs, Finder metadata, resource forks,
and Darwin flags.

### 18.6 Windows backup reader/writer

Adds `windows-backup-v1`, Windows security descriptors, named streams, EAs,
reparse data, sparse streams, and Windows attributes/times.

An implementation MUST publish its conformance classes and MUST NOT advertise
an OS backup class when it merely stores primary file bytes.

---

## 19. Required conformance corpus

Before revision 45 is declared stable, the project MUST publish deterministic
fixtures covering at least:

### Portable and Unix

- executable and non-executable files;
- setuid, setgid, and sticky modes;
- UID/GID plus non-ASCII user/group names;
- directories whose mtimes would otherwise change during extraction;
- symlinks, hardlinks, FIFO, and device descriptors;
- sparse files with leading, middle, and trailing holes;
- nanosecond and pre-epoch timestamps;
- POSIX.1e access/default and NFSv4 ACLs;
- binary, empty, privileged, and non-UTF-8-named xattrs;
- Linux and BSD immutable/append flags; and
- strict capture failure and partial capture reports.

### macOS

- FinderInfo and tags;
- a non-empty resource fork larger than the PAX metadata limit;
- macOS ACL and Darwin flags;
- quarantine/provenance xattrs;
- creation time; and
- APFS clone hints with logical fallback.

### Windows

- DACL, owner/group, and optional SACL security descriptor data;
- multiple named data streams including non-ASCII names;
- sparse primary and named streams;
- readonly, hidden, system, archive, compressed, and encrypted attributes;
- symlink, junction, mount-point, and unknown reparse tags;
- EAs, object ID, hardlink topology, and case-sensitive directory state;
- EFS raw capture where supported; and
- offline/cloud placeholder non-hydration behavior.

### Adversarial

- path traversal and link escape attempts;
- auxiliary-name path confusion;
- malformed PAX lengths and duplicate keys;
- invalid base64/percent/UTF-16 encodings;
- oversized counts and allocation attacks;
- sparse extent overflow/overlap;
- auxiliary hash mismatch;
- required unknown profiles; and
- immutable flags attempting to block later restoration phases.

Round-trip tests compare logical bytes and every metadata item promised by the
selected profile. Tests MUST separately assert capture completeness and restore
completeness.

---

## 20. Implementation guidance (non-normative)

The preferred implementation shape is one common metadata model shared by the
tzap core, CLI, desktop application, and foreign-format adapters. Capture,
archive representation, and restoration should be separate layers.

On Unix-like systems, libarchive already exposes UID/GID, uname/gname,
nanosecond and birth times, ACLs, xattrs, file flags, sparse extents, and macOS
metadata. Direct platform APIs are still needed for Linux-specific flags and
some macOS fidelity.

On Windows, the BackupRead/BackupWrite stream model provides a useful capture
and restoration baseline for security data, alternate streams, EAs, reparse
data, object IDs, and sparse blocks. Direct APIs are still needed for careful
policy, privilege, placeholder, and EFS handling.

Archive tools should expose at least:

```text
create --profile portable|posix-backup|linux-backup|macos-backup|windows-backup
create --strict-metadata | --best-effort-metadata
extract --restore content|portable|same-os|system
verify --metadata
list --metadata --omissions
```

Quick extraction should select `portable`. Backup workflows should normally
select the matching OS profile with strict capture and snapshot-backed input.

---

## 21. Primary references

The revision 45 profiles intentionally align with established platform models:

- [POSIX pax extended headers and ustar](https://pubs.opengroup.org/onlinepubs/9699919799/utilities/pax.html);
- [libarchive PAX conventions](https://github.com/libarchive/libarchive/blob/master/libarchive/tar.5)
  for `SCHILY.acl.*`, `SCHILY.fflags`, `LIBARCHIVE.creationtime`, and
  `LIBARCHIVE.xattr.*`;
- [GNU PAX sparse format 1.0](https://www.gnu.org/software/tar/manual/html_node/PAX-1.html);
- [Linux xattr namespaces](https://man7.org/linux/man-pages/man7/xattr.7.html)
  and `FS_IOC_GETFLAGS`;
- [Apple `copyfile` metadata and AppleDouble model](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/copyfile_state_set.3.html);
- [Win32 `WIN32_STREAM_ID`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-win32_stream_id),
  BackupRead/BackupWrite, security descriptors, reparse points, sparse files,
  and EFS raw backup APIs.

Where a platform ABI and this specification differ, this specification governs
the archive encoding; the platform ABI governs whether and how the metadata can
be applied on that host.
