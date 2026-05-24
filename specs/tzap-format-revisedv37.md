# tzap Archive Format Specification (v0.37 Draft)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.37 / 2026-05-24.1 |
| **Status** | Draft implementation target |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Base document** | `specs/tzap-format-revisedv36.md` |
| **Integrated proposal** | `plugin-specs/tzap-root-auth/tzap-root-auth-v0.17-proposed-v37.md` |
| **Supersedes** | v0.36 draft for new public implementation targets |
| **Superseded by** | None |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |

## Draft Status

This document is the v37 core-format draft. It is intended to become the single
normative implementation target before v37 work starts.

Until this draft is expanded into a fully inlined replacement for v36, all v36
rules continue to apply except where this document explicitly replaces them.
The v37-specific sections below are normative for the changed terminal layout,
critical metadata recovery, optional root-auth footer, and verification result
model.

v37 is not wire-compatible with v36. v37 archives MUST set
`VolumeHeader.volume_format_rev = 37`. v36 readers are expected to reject v37
archives.

## Core Decisions

1. **Encryption remains mandatory.** v37 keeps the v36 payload pipeline:
   `tar member groups -> zstd frames -> pack -> pad -> AEAD ->
   object-local FEC -> stripe -> split`. There is no plaintext archive mode.
2. **Volume splitting remains optional.** `stripe_width = 1` is a valid
   single-volume archive. `stripe_width > 1` is a multi-volume archive.
3. **Critical metadata recovery is mandatory for v37.** Every closed v37 volume
   carries a Critical Metadata Recovery Area (CMRA), a locator mirror, and a
   final locator after the `VolumeTrailer`.
4. **Root authentication is optional.** A v37 archive MAY omit
   `RootAuthFooterV1`. If omitted, all v37 root-auth trailer fields are zero
   and public no-key verification is unavailable.
5. **Signing algorithms are plugin-owned.** Core defines `RootAuthFooterV1`,
   `archive_root`, descriptor serialization, equality checks, and verifier
   result semantics. Core does not define Ed25519, X.509, timestamping, or a
   signing key registry.
6. **Unsigned `archive_root` is not authentication.** Writers that do not have
   an authenticator SHOULD omit `RootAuthFooterV1`; merely computing an
   `archive_root` without a trusted authenticator is not a root-auth result.

## Relationship To v36

v37 carries forward the v36 archive object model unless replaced here:

- `VolumeHeader` and `CryptoHeader` keep the v36 field layout, validation
  model, HMAC binding, KDF handling, AEAD registry, FEC registry, and resource
  cap rules, with `volume_format_rev = 37`.
- `BlockRecord` streams, object-local FEC, payload envelopes, IndexRoot,
  IndexShard, DirectoryHintTable, dictionary objects, safe-path rules, tar
  metadata profile, and full-archive verification rules carry forward from v36.
- v37 replaces the physical terminal layout and EOF/trailer authority rules.
- v37 adds CMRA recovery before critical metadata is trusted.
- v37 optionally adds `RootAuthFooterV1` and `archive_root` verification.

## Physical Layout

v36 layout:

```text
VolumeHeader | CryptoHeader | BlockRecords... | ManifestFooter | VolumeTrailer
```

v37 layout:

```text
VolumeHeader
CryptoHeader
BlockRecords...
ManifestFooter
RootAuthFooterV1?              // optional core carriage
VolumeTrailer
CriticalMetadataRecoveryArea
CriticalRecoveryLocatorMirror  // 128 bytes
CriticalRecoveryLocator        // final 128 bytes
```

Consequences:

- v37 readers MUST NOT apply v36 physical EOF rules to v37 archives.
- `VolumeTrailer` is no longer the final bytes of a v37 volume.
- CMRA and locator bytes are recovery helpers. They are not archive content and
  are not part of `archive_root`.
- v37 writers still write forward-only and MUST NOT require seek-back.

## v37 VolumeTrailer Fields

The v37 `VolumeTrailer` remains 128 bytes and keeps the v36 field order. The
20 bytes reserved by v36 are assigned in v37:

```rust
root_auth_footer_offset:     u64,  // 0 when absent
root_auth_footer_length:     u32,  // 0 when absent, max 64 KiB
root_auth_flags:             u32,  // bit 0: RootAuthFooter present
_reserved_v37:               u32,  // MUST be zero
```

The existing `trailer_hmac` covers these bytes because it covers the first
96 trailer bytes.

If root auth is enabled for a completed archive, every closed v37 volume MUST:

- set `root_auth_flags` bit 0;
- set non-zero `root_auth_footer_offset`;
- set non-zero `root_auth_footer_length`;
- carry the byte-identical `RootAuthFooterV1` required by this spec.

If root auth is absent, all four v37 root-auth trailer fields MUST be zero.
Bits 1 through 31 of `root_auth_flags` are reserved and MUST be zero.

v37 redefines `VolumeTrailer.bytes_written`:

```text
bytes_written = absolute offset of this VolumeTrailer
```

It is the file size up to, but not including, `VolumeTrailer`. It is not
`physical_file_size - 128` because CMRA and two locators follow the trailer.

For an unsigned v37 volume:

```text
block_records_offset      = crypto_header_offset + crypto_header_length
manifest_footer_offset    = block_records_offset
                           + block_count * sizeof(BlockRecord)
manifest_footer_end       = manifest_footer_offset + 136
volume_trailer_offset     = manifest_footer_end
VolumeTrailer.bytes_written == volume_trailer_offset
CMRA_offset               = volume_trailer_offset + 128
physical_file_size        = CMRA_offset + CMRA_length + 256
```

For a root-authenticated v37 volume:

```text
manifest_footer_end       = root_auth_footer_offset
root_auth_footer_end      = root_auth_footer_offset + root_auth_footer_length
volume_trailer_offset     = root_auth_footer_end
VolumeTrailer.bytes_written == volume_trailer_offset
CMRA_offset               = volume_trailer_offset + 128
physical_file_size        = CMRA_offset + CMRA_length + 256
```

Readers MUST verify these equations with checked 64-bit-or-wider arithmetic
after CMRA recovery and trailer HMAC verification.

## v37 Structure Rejection Rules

For every new v37 structure, readers MUST reject before using any offsets,
lengths, flags, digest inputs, CRC/FEC bytes, or root-auth bytes unless:

- every fixed magic field matches;
- every `version` field equals `1`;
- every `format_version` field equals `1`;
- every `volume_format_rev` field equals `37`;
- every reserved byte, reserved integer, and unknown flag bit is zero;
- every enum-like field is assigned by this spec, except for opaque
  root-auth plugin selectors;
- every CRC validates over exactly the specified byte range.

`RootAuthFooterV1.authenticator_id` and
`RootAuthFooterV1.signer_identity_type` are opaque plugin-authentication
selectors. Unknown or unsupported selector values MUST NOT make the footer
malformed by themselves. Instead, root-auth verification is unavailable unless
an external verifier supports the selector values and signer identity bytes.

## Critical Metadata Recovery Area

CMRA is a small per-volume FEC object outside the BlockRecord stream. It
protects the critical bytes needed to bootstrap the same volume:

- `VolumeHeader`;
- `CryptoHeader`;
- `ManifestFooter`;
- optional `RootAuthFooterV1`;
- `VolumeTrailer`;
- enough layout facts to cross-check offsets, lengths, and terminal authority.

CMRA repairs availability failures only. CMRA CRCs, SHA-256 digests, and FEC
do not authenticate an archive. After CMRA recovery, HMAC, AEAD, and optional
root-auth verification decide trust.

### CriticalMetadataImageV1

```rust
struct CriticalMetadataImageV1 {
    magic:                         [u8; 4],   // b"TZMI"
    version:                       u16,       // 1
    volume_format_rev:             u16,       // 37

    archive_uuid:                  [u8; 16],
    session_id:                    [u8; 16],
    volume_index:                  u32,
    stripe_width:                  u32,

    layout_flags:                  u32,       // bit 0: RootAuthFooter present

    volume_header_offset:          u64,       // MUST be 0
    volume_header_length:          u32,       // MUST be 128

    crypto_header_offset:          u64,
    crypto_header_length:          u32,

    block_records_offset:          u64,
    block_records_length:          u64,
    block_count:                   u64,

    manifest_footer_offset:        u64,
    manifest_footer_length:        u32,       // MUST be 136

    root_auth_footer_offset:       u64,       // 0 when absent
    root_auth_footer_length:       u32,       // 0 when absent

    volume_trailer_offset:         u64,
    volume_trailer_length:         u32,       // MUST be 128

    body_bytes_before_cmra:        u64,       // volume_trailer_offset + 128

    volume_header_sha256:          [u8; 32],
    crypto_header_sha256:          [u8; 32],
    manifest_footer_sha256:        [u8; 32],
    root_auth_footer_sha256:       [u8; 32],  // zero when absent
    volume_trailer_sha256:         [u8; 32],

    serialized_region_count:       u16,
    _reserved:                     [u8; 14],

    // SerializedRegion[serialized_region_count]
    // image_crc32c: u32 over all preceding image bytes
}
```

The fixed fields are exactly 320 bytes before the first `SerializedRegion`.

Each `SerializedRegion` is:

```rust
struct SerializedRegion {
    region_type:                  u16,
    _reserved:                    u16,
    offset:                       u64,
    length:                       u32,
    bytes:                        [u8; length],
}
```

Required region types:

| Type | Bytes |
|---:|---|
| 1 | exact `VolumeHeader` bytes |
| 2 | exact `CryptoHeader` bytes |
| 3 | exact `ManifestFooter` bytes |
| 4 | exact `RootAuthFooterV1` bytes, only when present |
| 5 | exact `VolumeTrailer` bytes |

If root auth is absent, `serialized_region_count` MUST equal 4 and region
types MUST be exactly `1, 2, 3, 5`. If root auth is present,
`serialized_region_count` MUST equal 5 and region types MUST be exactly
`1, 2, 3, 4, 5`.

Readers MUST reject duplicate regions, unknown regions, out-of-order regions,
non-canonical offsets, non-canonical lengths, digest mismatches, non-zero
reserved fields, invalid CRC, or a type-4 region that disagrees with
`layout_flags` bit 0.

Before any recovered image field drives BlockRecord reads, root-auth inputs,
object repair, or public observation windows, key-holding readers MUST
cross-check it against HMAC-verified terminal authority. Public no-key readers
MUST enforce the public structural subset defined by this spec before using the
field as an observation boundary.

### CMRA Encoding

```rust
struct CriticalMetadataRecoveryHeader {
    magic:                    [u8; 4],   // b"TZCR"
    version:                  u16,       // 1
    fec_algo:                 u16,       // ReedSolomonGF16 = 1

    shard_size:               u32,       // even, 512..4096
    data_shard_count:         u16,
    parity_shard_count:       u16,
    image_length:             u32,

    archive_uuid_hint:        [u8; 16],
    session_id_hint:          [u8; 16],
    volume_index_hint:        u32,

    image_sha256:             [u8; 32],
    _reserved:                [u8; 24],
    header_crc32c:            u32,
}

struct CriticalMetadataRecoveryShard {
    magic:                    [u8; 4],   // b"TZCS"
    shard_index:              u16,
    shard_role:               u8,        // 0=data, 1=parity
    _reserved:                u8,
    shard_payload_length:     u32,
    shard_crc32c:             u32,
    payload:                  [u8; shard_size],
}
```

`CriticalMetadataRecoveryHeader` is exactly 116 bytes.
`CriticalMetadataRecoveryShard` has a 16-byte header followed by exactly
`shard_size` payload bytes.

Data shards use `shard_role = 0` and indexes
`0 .. data_shard_count - 1`. Parity shards use `shard_role = 1` and indexes
`data_shard_count .. data_shard_count + parity_shard_count - 1`.

Serialized CMRA shard order is canonical:

```text
CriticalMetadataRecoveryHeader
data shard 0
...
data shard data_shard_count - 1
parity shard data_shard_count
...
parity shard data_shard_count + parity_shard_count - 1
```

Readers MUST reject duplicate shard indexes, out-of-order serialized shards,
wrong roles for an index range, non-canonical shard payload lengths, non-zero
final data-shard padding, or a missing data row that cannot be repaired from
available rows.

### CriticalRecoveryLocator

The final 256 bytes of every v37 volume are two locator copies:

```rust
struct CriticalRecoveryLocator {
    magic:                    [u8; 4],   // b"TZCL"
    version:                  u16,       // 1
    volume_format_rev:        u16,       // 37

    cmra_offset:              u64,
    cmra_length:              u32,
    cmra_header_length:       u16,       // 116
    cmra_fec_algo:            u16,       // ReedSolomonGF16 = 1

    volume_trailer_offset:    u64,
    body_bytes_before_cmra:   u64,

    archive_uuid_hint:        [u8; 16],
    session_id_hint:          [u8; 16],
    volume_index_hint:        u32,

    locator_sequence:         u32,       // 0=final, 1=mirror
    cmra_shard_size:          u32,
    cmra_data_shard_count:    u16,
    cmra_parity_shard_count:  u16,
    cmra_image_length:        u32,
    cmra_image_sha256:        [u8; 32],
    locator_crc32c:           u32,
}
```

`CriticalRecoveryLocator` is exactly 128 bytes. Readers first try the final
locator, then the mirror immediately before it, then MAY scan backward within
the derived v37 critical recovery scan cap.

Before a locator-based candidate is accepted, the locator, derived CMRA length,
and recovered image MUST agree on CMRA offset, CMRA length, trailer offset,
body bytes before CMRA, decoder tuple, and identity hints.

## CMRA Caps

Definitions:

```text
VH_LEN                     = 128
MF_LEN                     = 136
VT_LEN                     = 128
MIN_CRYPTO_HEADER_LEN      = 116
CM_IMAGE_FIXED_LEN         = 320
CMRA_HEADER_LEN            = 116
CMRA_SHARD_HEADER_LEN      = 16
MAX_REGION_COUNT           = 5
REGION_HEADER_LEN          = 16
IMAGE_CRC_LEN              = 4
LOCATOR_PAIR_LEN           = 256
active_crypto_header_cap   = reader active cap, default 64 KiB
active_root_auth_cap       = reader active cap, default 64 KiB
active_cmra_parity_pct_cap = reader active cap, default 100
```

The minimum accepted image length for decoder-tuple validation is:

```text
critical_image_min =
    CM_IMAGE_FIXED_LEN
  + 4 * REGION_HEADER_LEN
  + VH_LEN
  + MIN_CRYPTO_HEADER_LEN
  + MF_LEN
  + VT_LEN
  + IMAGE_CRC_LEN
```

The maximum accepted image length is:

```text
critical_image_cap =
    CM_IMAGE_FIXED_LEN
  + MAX_REGION_COUNT * REGION_HEADER_LEN
  + VH_LEN
  + active_crypto_header_cap
  + MF_LEN
  + active_root_auth_cap
  + VT_LEN
  + IMAGE_CRC_LEN
```

Readers MUST compute CMRA caps with checked 64-bit-or-wider arithmetic before
allocation, scan-bound computation, final-shard calculations, or FEC input
construction.

After successful `CryptoHeader.header_hmac` verification, readers MUST enforce:

```text
cmra_min_parity_shard_count =
    max(2, ceil(data_shard_count * bit_rot_buffer_pct / 100))

parity_shard_count >= cmra_min_parity_shard_count
```

Writers MUST emit at least this many CMRA parity shards for every closed v37
volume.

## RootAuthFooterV1

Core owns the minimal footer container so `archive_root` and descriptor
serialization are interoperable. Core does not define the authenticator
algorithm. It carries opaque authenticator bytes.

The optional footer is placed between `ManifestFooter` and `VolumeTrailer`.

```rust
struct RootAuthFooterV1 {
    magic:                         [u8; 4],   // b"TZRA"
    version:                       u16,       // 1
    root_auth_spec_id:             [u8; 24],  // "tzap-root-auth-v0.17\0" padded

    footer_length:                 u32,       // entire footer including CRC
    flags:                         u32,       // reserved, MUST be zero

    archive_uuid:                  [u8; 16],
    session_id:                    [u8; 16],
    format_version:                u16,       // 1
    volume_format_rev:             u16,       // 37

    authenticator_id:              u16,
    signer_identity_type:          u16,
    signer_identity_length:        u32,
    authenticator_value_length:    u32,

    total_data_block_count:        u64,

    critical_metadata_digest:      [u8; 32],
    index_digest:                  [u8; 32],
    fec_layout_digest:             [u8; 32],
    data_block_merkle_root:        [u8; 32],
    signer_identity_digest:        [u8; 32],

    archive_root:                  [u8; 32],

    _reserved:                     [u8; 32],

    // signer_identity_bytes:       [u8; signer_identity_length]
    // authenticator_value:         [u8; authenticator_value_length]
    // footer_crc32c:               u32 over all preceding RootAuthFooter bytes
}
```

`RootAuthFooterV1` fixed fields are exactly 318 bytes before
`signer_identity_bytes`.

Length rules:

- `footer_length <= 65536`;
- `signer_identity_length <= 4096`;
- `authenticator_value_length <= 8192` unless a later core registry raises it;
- `footer_length` MUST equal fixed fields plus identity bytes plus
  authenticator bytes plus `footer_crc32c`;
- the parser-supplied footer byte count MUST equal `footer_length`;
- when root auth is present, `RootAuthFooterV1.footer_length`,
  `VolumeTrailer.root_auth_footer_length`,
  `CriticalMetadataImageV1.root_auth_footer_length`, and
  `SerializedRegion(type 4).length` MUST all be equal before footer use.

When root auth is enabled for a completed v37 archive, every closed volume MUST
carry a byte-identical `RootAuthFooterV1`. A completed archive that carries
root auth on only a subset of closed volumes is malformed.

Footer wire validation is mode-independent and does not require a key,
`CryptoHeader.header_hmac`, `ManifestFooter.manifest_hmac`, or
`VolumeTrailer.trailer_hmac`. Wire validation does not prove the footer belongs
to an authenticated archive.

## RootAuth Descriptor Digest

```text
root_auth_descriptor_digest = SHA-256(
    "tzap-root-auth-descriptor-v1\0"
    || root_auth_spec_id
    || LE16(authenticator_id)
    || LE16(signer_identity_type)
    || LE32(signer_identity_length)
    || SHA-256(signer_identity_bytes)
    || LE32(authenticator_value_length)
    || LE32(RootAuthFooterV1.footer_length)
)
```

It MUST NOT include `archive_root`, `authenticator_value`, `footer_crc32c`, or
any byte whose value depends on `archive_root`. It also MUST NOT include the
per-volume `root_auth_footer_offset`.

If no `RootAuthFooterV1` exists, `root_auth_descriptor_digest` is 32 zero
bytes.

## Archive Root

v37 signs a canonical archive root, not raw volume bytes.

```text
archive_root = SHA-256(
    "tzap-archive-root-v37\0"
    || "tzap-root-auth-v0.17\0"
    || archive_uuid
    || session_id
    || LE16(format_version)
    || LE16(volume_format_rev)
    || LE16(compression_algo)
    || LE16(aead_algo)
    || LE16(fec_algo)
    || LE16(kdf_algo)
    || critical_metadata_digest
    || index_digest
    || fec_layout_digest
    || LE64(total_data_block_count)
    || data_block_merkle_root
    || root_auth_descriptor_digest
    || signer_identity_digest
)
```

Key-holding root-auth verification MUST treat `RootAuthFooterV1` commitment
fields as stored expectations, not substitutes for recomputation. A reader
MUST recompute all component digests from authenticated sources, require them
to equal the footer fields, recompute `archive_root`, require it to equal the
footer field, and only then dispatch to the authenticator plugin.

## Authenticator Plugin Boundary

Core authenticator dispatch is intentionally narrow:

- Core validates `RootAuthFooterV1` wire structure and equality bindings.
- Core recomputes `archive_root`.
- Core passes the exact selector fields, signer identity bytes,
  authenticator bytes, and recomputed `archive_root` to an external verifier.
- Core MUST NOT treat unknown selector values as malformed footer bytes.
- Core MUST report root auth as unavailable when no verifier supports the
  selector values.

The Ed25519 signing profile is plugin-owned. A draft plugin profile is expected
to register one `authenticator_id`, define `authenticator_value` bytes, define
the signing input over `archive_root`, and define strict verification rules.

## Key-holding Verification

`root_auth_content_verified` is a full-archive result. It is available only
after both gates complete:

1. The archive passes the v37 full-archive content-conformance operation. This
   imports the v36 full-archive checks after v37 terminal authorities replace
   the v36 EOF/trailer placement rules.
2. The reader recomputes every root-auth component needed by `archive_root`,
   including IndexRoot plaintext, every referenced IndexShard table, dictionary
   metadata when present, directory-hint metadata when present, FEC layout rows,
   and every signed data-kind BlockRecord after object FEC and AEAD/HMAC
   validation as needed.

Partial operations MAY report v36 HMAC/AEAD results for checked metadata and
objects, but MUST NOT report `root_auth_content_verified`.

## Public No-key Verification

Public no-key verification is available only when `RootAuthFooterV1` is
present and a supported authenticator plugin plus trusted public key are
available.

Public no-key verification can prove only this outcome:

```text
Trusted key signed a commitment to this observed CRC-valid public encrypted
data-block set and to opaque component digests. Plaintext, IndexRoot,
HMAC-authenticated metadata, physical completeness, and recovery margin were
not inspected.
```

Public no-key verification MUST NOT claim plaintext authenticity, file-list
authenticity, IndexRoot authenticity, HMAC-authenticated metadata validity, or
FEC recovery of missing data.

## Writer Flow

1. Choose v37 options, all FEC class maxima, and CMRA parity policy before
   writing `CryptoHeader`.
2. Write `VolumeHeader`, `CryptoHeader`, and BlockRecords in v36 order.
3. Maintain `data_block_merkle_root` state when root auth is enabled.
4. Build and HMAC `ManifestFooter`.
5. If root auth is enabled, choose root-auth descriptor fields and exact
   authenticator output length.
6. Build and HMAC `VolumeTrailer` with v37 root-auth pointer fields.
7. If root auth is enabled, compute all root-auth component digests and
   `archive_root`, obtain authenticator bytes over `archive_root`, and
   serialize byte-identical `RootAuthFooterV1` bytes for every closed volume.
8. Write `ManifestFooter`, optional `RootAuthFooterV1`, and `VolumeTrailer` on
   every volume.
9. Build `CriticalMetadataImageV1` from exact terminal bytes.
10. Encode and write CMRA.
11. Write locator mirror and final locator.

No step requires rewriting bytes already emitted to a volume.

## Reader Bootstrap Order

Seekable v37 open order:

1. Try the final `CriticalRecoveryLocator`, then its mirror, then optional
   bounded scan.
2. Read bounded CMRA.
3. Validate at least one CMRA decoder envelope.
4. FEC-repair `CriticalMetadataImageV1`.
5. Validate image CRC, image SHA-256, region digests, offsets, and lengths.
6. Parse recovered `VolumeHeader`, `CryptoHeader`, `ManifestFooter`, optional
   `RootAuthFooterV1`, and `VolumeTrailer`.
7. Treat recovered bytes as untrusted until `VolumeHeader` CRC,
   `CryptoHeader.header_hmac`, `VolumeTrailer.trailer_hmac`,
   `ManifestFooter.manifest_hmac`, and all identity, offset, length,
   block-count, and adjacency checks pass.
8. Use recovered metadata to locate BlockRecords and IndexRoot.
9. If root auth is present and requested, run full-archive content-conformance,
   recompute `archive_root`, and dispatch to the authenticator plugin.

## Non-seekable Sequential v37

v37 keeps v36's provisional-output rule. A non-seekable sequential reader that
emits live output before terminal authentication MUST treat that output as
provisional. Default filesystem extractors MUST NOT commit filesystem-visible
results as clean until terminal verification succeeds.

Without an external trusted bootstrap source:

1. Read `VolumeHeader` and `CryptoHeader` at stream start.
2. Stream BlockRecords and authenticate payload envelopes as in v36.
3. Buffer the terminal tail up to the derived terminal cap.
4. At EOF, parse `ManifestFooter | RootAuthFooterV1? | VolumeTrailer | CMRA |
   LocatorMirror | Locator`.
5. Apply CMRA recovery and terminal HMAC/root-auth checks.
6. Commit filesystem output only after terminal verification succeeds.

Root auth is available in non-seekable sequential mode only when the reader
retains enough metadata, object extent, FEC, and data-leaf state to run the
same recomputation a seekable reader would run. Otherwise root auth is
unavailable for that operation.

## Minimum v37 Conformance Tests

The v37 test suite MUST include at least:

1. CMRA repair of one-byte corruption in `VolumeHeader`, `CryptoHeader`,
   `ManifestFooter`, and `VolumeTrailer`.
2. Final-locator corruption with mirror-locator recovery.
3. Locatorless bounded scan success and beyond-bound failure.
4. CMRA shard corruption within and beyond parity budget.
5. CMRA CRC recomputation attacks rejected by HMAC/root-auth checks.
6. v37 `VolumeTrailer.bytes_written` physical-EOF mutation rejected.
7. Max-size `CryptoHeader` and max-size `RootAuthFooterV1` cap tests.
8. CRC coverage tests for every new v37 structure.
9. Root-auth absent archive with all root-auth trailer fields zero.
10. Root-auth present archive with byte-identical footer on every closed
    volume.
11. Missing or divergent `RootAuthFooterV1` copies rejected for completed
    root-auth archives.
12. Root-auth content verification after tolerated volume loss and object FEC
    reconstruction.
13. Public no-key success on a complete observed encrypted data-block set with
    required limited-scope diagnostics.
14. Public no-key incomplete/failure for missing, duplicate, gapped,
    incongruent, or CRC-invalid observed BlockRecords.
15. Non-seekable sequential extraction commits output only after terminal tail,
    CMRA, HMACs, and optional root auth verify.
16. Unknown authenticator selector values produce root-auth unavailable, not
    malformed footer, when all footer wire checks otherwise pass.

## Implementation Note

The existing v36 conformance matrix and corpus tracker should be replaced or
forked for v37 before implementation starts. v37 release claims MUST distinguish
these surfaces:

- v37 encrypted archive layout;
- v37 CMRA critical metadata recovery;
- v37 key-holding full-archive verification;
- optional root-auth verification;
- optional public no-key verification;
- optional authenticator plugins.
