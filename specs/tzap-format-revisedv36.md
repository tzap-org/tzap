# tzap Archive Format Specification (v0.36)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.36 / 2026-05-22.6 (v0.36 bootstrap precedence clarifications) |
| **Status** | Draft for review, no implementation yet |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Last updated** | 2026-05-22 |
| **Supersedes** | v0.1, v0.2, v0.3, v0.4, v0.5, v0.6, v0.7, v0.8, v0.9, v0.10, v0.11, v0.12, v0.13, v0.14, v0.15, v0.16, v0.17, v0.18, v0.19, v0.20, v0.21, v0.22, v0.23, v0.24, v0.25, v0.26, v0.27, v0.28, v0.29, v0.30, v0.31, v0.32, v0.33, v0.35 |
| **Superseded by** | None |
| **Conflict rule** | This document supersedes earlier tzap format drafts. If it conflicts with v0.1-v0.35 text, this v0.36 draft wins unless a later dated spec explicitly supersedes it. |
| **File extension** | `.tzap` (single-volume) / `.tzap.NNN` (multi-volume) |

## Changelog from v0.35

This revision resolves random-access correctness and directory extraction
findings in v0.35: non-minimal FileEntry frame ranges could force readers
to fetch/decode unrelated trailing frames for a file, and directory-prefix
hints could be misapplied as though they were an exact regular-file index.

1. **Draft visibility is bumped.** `volume_format_rev = 36` for this
   draft. (§8, §17.1, §23, §28.1, §29)
2. **FileEntry frame ranges are canonical and minimal.** The final byte of
   a FileEntry tar member group must fall inside the final referenced
   FrameEntry; readers reject frame ranges that include unused trailing
   frames. (§15.6, §15.9, §17.2, §28.1, §29)
3. **Directory-prefix extraction is separated from exact-file lookup.**
   User path extraction first resolves the exact final-view FileEntry;
   directory hints are used for a subtree only when the requested path is
   a directory or when the caller explicitly requested directory-prefix
   semantics. (§15.8, §17.2, §28.1, §29)
4. **Bootstrap source precedence is explicit.** Seekable bootstrap uses
   terminal trailer/ManifestFooter authority; non-seekable random-access
   bootstrap uses only trusted sidecar data with the section rules in
   §12.3 and dictionary requirements in §12.4. (§12.4, §17.1, §17.3)

---

## Abstract

tzap is a multi-volume archive format combining POSIX tar bundling, zstd
compression, authenticated encryption (AEAD), and Reed-Solomon forward
error correction (FEC). It targets long-term archival storage where
confidentiality, integrity, bit-rot resilience, volume-loss resilience,
and random access matter together.

The pipeline is `tar member groups → zstd frames → pack → pad → AEAD →
object-local FEC → stripe → split`.

---

## 1. Design Goals

1. **Confidentiality.** File contents, names, per-file metadata, and the
   random-access index are unreadable without the key. The outer
   container still reveals unavoidable traffic-analysis metadata: number
   of volumes, total bytes per volume, block size, padded encrypted
   object sizes, and IndexRoot location/size.
2. **Integrity.** Modification, reorder, or substitution of an
   authenticated object is detected before that object's plaintext is
   exposed. Archive truncation or missing terminal material is detected
   before a clean extraction is reported. Non-seekable sequential readers
   that emit live output before terminal authentication MUST treat that
   output as provisional; default filesystem extractors MUST NOT commit
   filesystem-visible results as clean until terminal authentication
   succeeds.
3. **Bit-rot resilience.** Random bit flips within a configurable
   tolerance are repaired transparently.
4. **Volume-loss resilience.** Loss of any N volumes is recoverable when
   parity satisfies `G_parity ≥ N × ceil(G_total / V)`. The CLI
   auto-scales parity from the user's tolerance.
5. **Random access.** Any single file is extractable by reading the
   minimum ordered zstd frame extent(s) that contain that file's
   self-contained tar member group. Typical small files require one
   envelope decrypt and one frame decompress; large files may span
   multiple frames and envelopes.
6. **True single-pass append-only streaming.** No seek-back is required
   at any point in the write path. Writers stream from start to close,
   compatible with POSIX and S3 multipart. Fully non-reopenable
   single-sink streams (pipes/tape) are supported for single-volume
   archives; striped multi-volume archives require concurrent named
   volume streams, append-reopenable sinks, an external multiplexing
   wrapper, or local spooling. The core tzap format does not define a
   single-pipe multi-volume wrapper. Live stdout-to-stdin decompression
   without a sidecar requires `has_dictionary = 0`;
   dictionary-compressed streams require a bootstrap sidecar or buffering
   until the dictionary object is available.
7. **Splittable.** Volume size is configurable; volumes are independent
   files sharing an archive UUID.
8. **Implementable with standard libraries.** Metadata application is
   delegated to off-the-shelf tar libraries.
9. **Localized failure.** After bootstrap metadata is recovered, sharded
   index corruption affects only the files whose IndexShard or
   directory-hint shard is unrecoverable.

## 2. Non-Goals

- Highest possible compression ratio.
- Append or in-place edit.
- Multi-recipient key wrapping; public-key mode.
- Network protocol or chunked transfer.
- Cross-archive deduplication.

## 3. Threat Model

**In scope:** passive observation; active modification, truncation,
reorder, substitution; bit-rot; volume loss (any subset); wrong-passphrase
detection; replay attacks; loss of CryptoHeader or ManifestFooter copies;
mid-stream writer crashes.

Active modification is in scope for integrity detection and plaintext
non-release for any object that fails AEAD/HMAC authentication, not for
guaranteed repair. The unkeyed per-block CRC identifies accidental
corruption and missing/erased shards for FEC, but an active attacker who
can rewrite a BlockRecord and recompute its CRC can still cause object
AEAD failure and deny availability even when parity would have repaired
an accidental error at the same location. Whole-archive truncation in
non-seekable sequential mode is detected at terminal authentication;
any live output emitted before that point is provisional and must not be
reported or committed as a clean extraction until the terminal
ManifestFooter and VolumeTrailer authenticate.

**Out of scope:** host side channels; quantum adversaries beyond AES-256
Grover resistance; chosen-plaintext attacks against the compression layer
(CRIME/BREACH); DoS via crafted parameters (mitigated by reader caps).

---

## 4. Conventions

- Little-endian integers.
- `u8`, `u16`, `u32`, `u64`, `i64`.
- Tightly packed structs; explicit padding shown. Multi-byte integer
  fields are not guaranteed to be naturally aligned, even when shown in
  Rust-like `#[repr(C, packed)]` notation. Implementations MUST decode
  integer fields with unaligned-safe loads or by copying bytes into
  aligned scratch storage before interpretation.
- UTF-8, NFC-normalized strings; no BOM, no NUL terminator.
- SHA-256; CRC-32C; HMAC-SHA-256.
- Time: nanoseconds since Unix epoch (signed 64-bit).
- The `||` operator denotes raw byte concatenation with no length
  prefix, separator, or terminator. Operands are encoded according to
  their declared type: for example `[u8; 16]` UUIDs and session IDs are
  the 16 raw bytes on the wire, not hex strings.
- Whenever an 8-byte SHA-256 prefix field (`[u8; 8]`) is used as a sort
  key, interval bound, or lookup key, comparisons are lexicographic over
  the raw digest bytes in stored order: compare byte 0 first, then byte
  1, and so on through byte 7. Implementations MUST NOT reinterpret
  these prefixes as little-endian, big-endian, host-endian, or aligned
  integer values for ordering. Equality is byte-for-byte equality.
- Every field named `_reserved`, `_reserved1`, `_reserved2`,
  `_reserved_a`, `_reserved_b`,
  `_padding_*`, or otherwise explicitly reserved MUST be zero on the
  wire. Readers MUST reject any parsed structure whose reserved bytes or
  reserved integer fields are non-zero unless a later format version
  explicitly assigns that field.

---

## 5. Algorithm Registry

```rust
#[repr(u16)]
enum CompressionAlgo { None = 0, ZstdFramed = 1 }

#[repr(u16)]
enum AeadAlgo { AesGcmSiv256 = 1, XChaCha20Poly1305 = 2, AesGcm256 = 3 }

#[repr(u16)]
enum FecAlgo { None = 0, ReedSolomonGF16 = 1, Wirehair = 2 }

#[repr(u16)]
enum KdfAlgo { Raw = 0, Argon2id = 1 }
```

Unknown algorithm IDs are hard errors. Range `0xFF00..0xFFFF` is reserved
for experimental use.
`CompressionAlgo::None` is a reserved registry value in this draft, not
a usable archive mode. Conformant v0.36 writers MUST set
`compression_algo = ZstdFramed`; Conformant v0.36 readers MUST reject
`compression_algo = None`. All normative references to frames in this
document therefore mean complete zstd frames.
`FecAlgo::None` and `FecAlgo::Wirehair` are reserved registry values in
this draft, not usable archive modes. Conformant v0.36 writers MUST set
`fec_algo = ReedSolomonGF16`; Conformant v0.36 readers MUST reject any
other `fec_algo` value.

AEAD parameter constants are determined by `aead_algo`:

| `aead_algo` | Algorithm | `AEAD_NONCE_LEN` | `AEAD_TAG_LEN` |
|---|---|---:|---:|
| 1 | AES-256-GCM-SIV | 12 bytes | 16 bytes |
| 2 | XChaCha20-Poly1305 | 24 bytes | 16 bytes |
| 3 | AES-256-GCM | 12 bytes | 16 bytes |

Writers and readers MUST use the nonce and tag lengths from this table
when applying §14. Every AEAD-protected object serializes the combined
AEAD output as `ciphertext || tag`: ciphertext bytes first, followed
immediately by the final `AEAD_TAG_LEN` authentication-tag bytes. The
ciphertext length is exactly the padded plaintext length, and the
combined length is the object's recorded `encrypted_size`. Detached tags,
tag prefixes, implementation-native alternate layouts, or omitted tag
bytes are non-conforming; readers MUST reject an object whose recorded
encrypted size is smaller than `AEAD_TAG_LEN` or whose combined output
does not split exactly into ciphertext plus final tag under the selected
algorithm. AES-256-GCM-SIV is the default AEAD and refers to the
nonce-misuse-resistant AES-GCM-SIV construction from RFC 8452.
AES-256-GCM remains registered for environments that can enforce unique
nonces; nonce derivation in §14 binds nonce uniqueness to
`(archive_uuid, session_id, domain, counter)`.

---

## 6. Logical Pipeline

### Write path

```
files
  │ build tar member groups (PAX/ustar records for one logical path)
  ▼
tar member group stream
  │ split into independently-decodable zstd frames
  │ frame boundaries prefer tar member group boundaries
  │ uses pre-trained dictionary if one is located by IndexRoot
  ▼
zstd frames f₁, f₂, …, fₙ
  │ pack complete frames into envelopes; a frame MUST NOT be split
  │ across envelopes
  ▼
envelopes E_j
  │ in-envelope pad (SUFFIX-MARKER SCHEME, §6.1)
  │ envelope_total_size = next multiple of BLOCK_SIZE such that
  │   |E_j| + pad_len + AEAD_TAG_LEN = envelope_total_size
  ▼
padded plaintexts
  │ AEAD-encrypt
  ▼
encrypted envelopes EE_j
  │ split into BLOCK_SIZE-sized blocks
  ▼
data blocks
  │ object-local FEC for this envelope
  ▼
all blocks (data + parity)
  │ stripe across V volumes: volume = block_index mod V
  ▼
archive.tzap.001 … archive.tzap.V
```

### 6.1 In-envelope padding (suffix-marker scheme)

The padding is appended to the end of the envelope plaintext such that
**the very last byte of the plaintext** carries the marker:

```
For pad_len ∈ [1, 254]   (byte form):
    padding = [0×(pad_len − 1) ‖ pad_len: u8]
    Total padding length = pad_len bytes.

For pad_len ∈ [5, …]     (wide form):
    padding = [0×(pad_len − 5) ‖ pad_len: u32 LE ‖ 0xFF]
    Total padding length = pad_len bytes.
```

The writer chooses byte form for `pad_len ≤ 254` and wide form for
`pad_len ≥ 255`. (Wide form is also legal for `pad_len ∈ [5, 254]`, but
writers SHOULD NOT use it below 255; byte form is the canonical efficient
choice for `pad_len ≤ 254`.) Byte form with `pad_len = 255` is not
defined. A final marker byte of `0xFF` always selects wide-form parsing;
readers MUST NOT fall back to byte form for that plaintext.

**Reader algorithm:**

```
1. Decrypt envelope; let plaintext have length
   `N = envelope_total_size - AEAD_TAG_LEN`, where
   `envelope_total_size` is a multiple of `BLOCK_SIZE`.
2. If N = 0, reject as malformed.
3. Inspect plaintext[N − 1]:
     - if < 0xFF:  byte form. marker_size = 1;
                    pad_len = plaintext[N − 1].
     - if = 0xFF:  if N < 5, reject immediately; otherwise wide form.
                    marker_size = 5;
                    pad_len = u32 LE from the four bytes at offsets
                    N−5, N−4, N−3, and N−2.
4. Verify pad_len ≥ marker_size and pad_len ≤ N. Reject if not. This is
   equivalent to `pad_len ≥ 1` for byte form and `pad_len ≥ 5` for wide
   form. `pad_len = 0` is always malformed. Compute payload_len =
   checked_sub(N, pad_len); any underflow is malformed.
5. Verify all bytes from offset `payload_len` up to but not including
   offset `N - marker_size` are zero. This is canonical-format
   validation. Tampering would already have failed AEAD, but a valid
   archive must still use zero padding.
6. zstd payload = plaintext[0 .. payload_len].
```

When an object has an authenticated out-of-band plaintext length field,
the depadded `payload_len` MUST exactly equal that field before any
consumer slices the buffer. For payload envelopes, this means
`payload_len == EnvelopeEntry.plaintext_size`; readers MUST reject before
using any FrameEntry offset if the values differ. Metadata objects use
the same suffix-marker depadding before zstd decompression, but their
post-decompression size is validated against their recorded
`decompressed_size`.

Edge cases:

- The minimum `pad_len` is 1, so the very last byte is always a padding
  marker, never zstd data. Writers must always include at least 1 byte
  of padding, even if the data fits exactly — in that case, an extra
  `BLOCK_SIZE` is added to the envelope.
- `pad_len = 0` is not valid in v0.36. The extra block in the exact-fit
  case is an accepted canonical-format cost; it keeps padding parsing
  suffix-only and avoids algorithm-specific length exceptions.
- Byte form is defined only for `pad_len ≤ 254`. A final byte of `0xFF`
  is always wide form; readers MUST NOT fall back to interpreting it as
  a byte-form `pad_len = 255`.
- The exact-fit extra block is still subject to every u32 and FEC object
  limit. Writers MUST split or shrink the envelope before
  `packed_frames.len() + AEAD_TAG_LEN + BLOCK_SIZE` would exceed
  `u32::MAX`, the selected object-class data-shard cap, or the
  ReedSolomonGF16 total-shard cap.
- Because `BLOCK_SIZE ≥ 4096`, an exact-fit envelope that adds a full
  block of padding always serializes that padding with wide form.
- Because padding always occupies at least the final byte, zstd payload
  data never extends into the final byte of the envelope plaintext.
  The marker is therefore parsed from padding bytes, not from zstd data.
- In wide form, `N ≥ 5` is necessary but not sufficient: readers still
  must enforce `pad_len ≥ 5` and `pad_len ≤ N` before subtraction. This
  rejects malformed tiny or hostile wide-form markers whose 4-byte length
  field would otherwise be partly exposed as zstd payload bytes.

### 6.2 Four nested units

- **Tar member group** = one logical path's complete tar records: any
  path-specific PAX/GNU metadata records followed by the main tar header,
  data bytes, and tar padding.
- **tzap tar stream** = concatenation of tar member groups only. It
  excludes the POSIX end-of-archive marker (two 512-byte zero blocks).
  That marker is synthetic at reader/export boundaries, not encrypted
  archive content.
- **Frame** = one independent zstd frame; unit of random decompression.
  A frame contains bytes from the tar member group stream.
- **Envelope** = packed group of frames; unit of AEAD encryption + padding.
- **Block** = fixed-size storage chunk; unit of striping, CRC, and
  object-local FEC.

`tar member group bytes ⊆ decompressed zstd frame plaintexts ⊆ envelope
plaintexts ⊆ blocks ⊆ volumes`.

`IndexRoot.tar_total_size` and `IndexRoot.content_sha256` cover exactly
the tzap tar stream bytes, excluding any synthetic POSIX
end-of-archive marker. Readers that feed decoded bytes to a strict tar
library or export a complete tar file MUST append two 512-byte zero
blocks after the selected decoded tar member groups. Those synthetic
blocks are never included in `tar_total_size`, `content_sha256`,
FrameEntry coverage, or FileEntry `tar_member_group_size`.

Writers SHOULD start a new zstd frame at the beginning of every tar
member group. They MAY split a very large tar member group across
multiple frames, but FileEntry MUST record the exact ordered frame range
and decompressed offset needed to reconstruct that member group (§15.6).
`CryptoHeader.chunk_size` is the writer's target maximum uncompressed
zstd-frame payload when splitting large tar member groups. It is a
writer framing target, not a reader parsing boundary: readers MUST use
FrameEntry and EnvelopeEntry metadata to locate bytes.

---

## 7. Archive Layout

### 7.1 Per-volume structure

```
Volume_i =
    VolumeHeader            (fixed 128 B, at offset 0)
    CryptoHeader            (replicated; identical across volumes)
    BlockRecord_…           (this volume's striped blocks)
    ManifestFooter          (per-volume authoritative copy; same index-root fields,
                             volume_index matches this volume)
    VolumeTrailer           (fixed 128 B, at end-of-file; holds ManifestFooter pointer)
```

### 7.2 Block-to-volume striping

```
volume_index_zero_based = block_index mod V
position_in_volume      = block_index div V
```

### 7.3 Volume-loss recoverability rule

```
G_parity ≥ N × ceil(G_total / V)         for N-volume tolerance.
```

Writers MUST enforce `0 ≤ N < V`. A single-volume archive (`V = 1`) can
protect against bit-rot within that volume, but it cannot tolerate loss
of that only volume; it therefore requires `N = 0`. The CLI auto-scales
parity from `--volume-loss-tolerance N` (§27).

### 7.4 Default write mode: parallel volumes

The writer opens V volume sinks concurrently, or uses sinks that can be
reopened for append without rewriting earlier bytes. Each sink receives
blocks based on the modulo mapping. The write path is strictly forward
within each sink: no seek-back or overwrite is required.

### 7.5 Single-stream streaming mode

For a fully non-reopenable single sink (for example a pipe or a tape
stream), conforming v0.36 writers MUST use `stripe_width = 1`,
`volume_loss_tolerance = 0`, and either `has_dictionary = 0` or a
bootstrap sidecar containing authenticated encrypted IndexRoot and
dictionary-object copies (§12.2, §17.3). A live reader cannot decompress
dictionary-compressed payload frames until that sidecar is available.

A writer asked to produce `V > 1` striped volumes with only one
non-reopenable sink MUST either:

- reject the request as incompatible with striped multi-volume streaming;
- spool locally until it can write each target volume forward-only; or
- use append-reopenable sinks and follow §7.4.

It MUST NOT claim true streaming while silently buffering an unbounded
amount of future volume data in memory.

---

## 8. Volume Header

Fixed 128 bytes, at offset 0 of every volume.

```rust
#[repr(C, packed)]
struct VolumeHeader {
    magic:                    [u8; 4],   // b"TZAP"
    format_version:           u16,       // 1
    volume_format_rev:        u16,       // 36 for this draft
    volume_index:             u32,       // 0-based
    stripe_width:             u32,       // V
    archive_uuid:             [u8; 16],
    session_id:               [u8; 16],
    crypto_header_offset:     u32,       // MUST equal sizeof(VolumeHeader) = 128
    crypto_header_length:     u32,
    _reserved:                [u8; 68],
    header_crc32c:            u32,       // CRC32C over first 124 bytes
                                             // (offsets 0..123; excludes this field)
}
```

**Historical note:** `manifest_footer_offset` and `manifest_footer_length`
are removed. Those pointers now live in the VolumeTrailer (§12). The
removal frees 12 bytes that are reclaimed into `_reserved`. The
VolumeHeader is now fully write-once: no field requires backfill at
archive close.

`header_crc32c` is an unkeyed corruption detector only. Readers MUST NOT
treat VolumeHeader identity fields or offsets as authenticated until they
are matched against authenticated CryptoHeader, VolumeTrailer, and
ManifestFooter fields after HMAC verification (§17.1). Readers MUST
verify `magic = b"TZAP"` and range-check `crypto_header_length` against
the actual volume or stream bounds and reader caps before allocating or
reading the CryptoHeader. Writers MUST set `crypto_header_offset =
sizeof(VolumeHeader) = 128`; readers MUST reject any other value. This
draft permits no padding, extension bytes, or unclaimed gap between
VolumeHeader and CryptoHeader. Writers MUST set `stripe_width ≥ 1` and
MUST set `volume_index < stripe_width`; readers MUST reject a
VolumeHeader whose `stripe_width = 0` or whose
`volume_index >= stripe_width`.
Before CryptoHeader HMAC verification succeeds, readers MUST treat the
length, `archive_uuid`, and `session_id` as untrusted input used only to
locate and verify a bounded candidate CryptoHeader at the canonical
offset.

---

## 9. CryptoHeader

Replicated identically in every volume. Contains static parameters needed
to derive keys and parse the archive. "Replicated identically" refers to
the CryptoHeader bytes themselves; each volume's VolumeHeader points to
that identical byte sequence at the canonical offset
`sizeof(VolumeHeader)`.

```rust
#[repr(C, packed)]
struct CryptoHeaderFixed {
    magic:                    [u8; 4],   // b"TZCH"
    length:                   u32,

    compression_algo:         u16,
    aead_algo:                u16,
    fec_algo:                 u16,
    kdf_algo:                 u16,

    chunk_size:               u32,
    envelope_target_size:     u32,
    block_size:               u32,
    fec_data_shards:          u16,
    fec_parity_shards:        u16,
    index_fec_data_shards:    u16,
    index_fec_parity_shards:  u16,
    index_root_fec_data_shards:    u16,    // may be raised if IndexRoot/dictionary is large
    index_root_fec_parity_shards:  u16,
    stripe_width:             u32,

    volume_loss_tolerance:    u8,
    bit_rot_buffer_pct:       u8,
    has_dictionary:           u8,         // 1 if IndexRoot locates a zstd dict object
    _padding_a:               u8,

    max_path_length:          u32,
    expected_volume_size:     u64,

    _reserved:                [u8; 16],
}
// Followed by:
//   KdfParams       (variable)
//   Extension[]     (TLV list; each value ≤ 256 bytes)
//   Terminator TLV  (tag = 0, length = 0)
//   header_hmac     [u8; 32]
```

`length` is the total CryptoHeader byte length, including
`CryptoHeaderFixed`, `KdfParams`, all Extension TLVs, the terminator TLV,
and `header_hmac`. `CryptoHeaderFixed.length` MUST exactly equal
`VolumeHeader.crypto_header_length`; readers MUST reject any mismatch
before parsing extension bytes beyond the shorter length.
Readers MUST reject a CryptoHeader whose `magic != b"TZCH"` before
interpreting any other CryptoHeader field.
Writers SHOULD keep CryptoHeader small and MUST NOT rely on readers
accepting unbounded replicated header data. Readers MUST reject a
CryptoHeader whose `length` or containing `VolumeHeader.crypto_header_length`
exceeds the active `CryptoHeader byte length` cap (§13.3) before
allocating a buffer, reading extension payloads, or running the KDF.
`header_hmac = HMAC-SHA-256(mac_key, b"tzap-v1-crypto-header" ||
VolumeHeader.archive_uuid || VolumeHeader.session_id || all CryptoHeader
bytes before the header_hmac field)`. Readers MUST reject a CryptoHeader
whose length is smaller than the fixed header, the selected KdfParams
payload, the required Extension TLV terminator, and the HMAC. At
minimum, a candidate header must contain
`sizeof(CryptoHeaderFixed) + 2 + 6 + 32` bytes: the fixed header, the
shortest raw KdfParams payload, a terminator TLV (`tag = 0`, `length =
0`), and `header_hmac`. This minimum lets the KdfParams `algo_tag` be
read safely and leaves room for the mandatory terminator before the HMAC.
After `kdf_algo` is known, readers MUST prove the complete KdfParams
payload indicated by §13.1 fits before `length - 32`, and only then
perform a structural Extension TLV scan. This pre-HMAC scan treats
Extension bytes as untrusted and may validate only framing:
1. Every TLV header must fit before `length - 32`.
2. Every Extension payload length must be `≤ 256`, even for unknown tags.
3. `tag = 0` is valid only as the terminator with `length = 0`.
4. The terminator TLV must be present and must end exactly at
   `length - 32`, immediately before `header_hmac`.
Readers MUST reject a CryptoHeader whose TLV list does not satisfy those
framing rules, or whose reserved bytes are non-zero.
Readers MUST NOT make semantic decisions from Extension tags or values
until after CryptoHeader HMAC verification succeeds.
After HMAC verification, readers interpret each non-terminator extension
by defining `ext_tag = tag & 0x7FFF` and
`is_critical = (tag & 0x8000) != 0`. The high bit is the critical bit and
is masked from `ext_tag` when validating known tags. Readers MUST:
1. Reject forbidden `ext_tag` values `0x0004` and `0x0006` regardless of
   the critical bit.
2. Reject unknown `ext_tag` values when `is_critical = true` (critical
   extension; hard error).
3. Ignore unknown non-critical `ext_tag` values when `is_critical = false`
   unless a future version reserves that tag.
4. Reject duplicate known `ext_tag` values.
5. Reject any known extension whose payload length or payload encoding is
   invalid for its type in this draft.
Readers MUST reject any `compression_algo`, `aead_algo`, `fec_algo`, or
`kdf_algo` value not defined in §5 before interpreting algorithm-specific
parameters.
Readers MUST reject `compression_algo = None` in v0.36; payload and
metadata compression in this draft is always `ZstdFramed`. Readers MUST
reject `fec_algo != ReedSolomonGF16`; object-local FEC in this draft is
always Reed-Solomon over GF(2^16). Readers MUST reject
`has_dictionary` values other than 0 or 1, `volume_loss_tolerance >=
stripe_width`, `bit_rot_buffer_pct > 100`, or any class data-shard
maximum (`fec_data_shards`, `index_fec_data_shards`, or
`index_root_fec_data_shards`) equal to zero.

Binding the VolumeHeader UUID/session into the CryptoHeader HMAC makes a
mismatched header pair fail immediately after KDF/HMAC verification,
before any object AEAD attempt. The VolumeHeader is still not trusted as
a security boundary; the same identity fields are later checked against
the authenticated VolumeTrailer and ManifestFooter.

`chunk_size` records the writer's target maximum uncompressed zstd-frame
payload for large tar member groups (§6.2). Writers MUST set
`1 ≤ chunk_size ≤ envelope_target_size`; readers MUST reject
`chunk_size = 0`, `envelope_target_size = 0`, `stripe_width = 0`, or
`block_size < 4096`. Because `ReedSolomonGF16` operates on 16-bit
symbols in this draft, writers MUST set `block_size` to an even byte
count and readers MUST reject odd `block_size` values. Readers MUST
reject `chunk_size >
envelope_target_size`; this condition is malformed, not advisory.
Readers MUST also reject `chunk_size`, `envelope_target_size`, or
`block_size` values above their configured reader-side caps (§13.3)
before allocating buffers or planning work. After these value checks
succeed, readers MUST NOT allocate memory or infer frame boundaries from
`chunk_size` alone; actual frame sizes are described by FrameEntry.
The writer-side `chunk_size` constraint exists to keep this metadata
meaningful for progress estimates, diagnostics, and planning heuristics;
it is not a parsing authority.
`expected_volume_size` is authenticated advisory metadata for planning
and progress reporting. Writers set it to the intended maximum volume
size in bytes, or zero when unknown/unbounded. Readers MUST NOT allocate,
seek, or validate object extents from `expected_volume_size`; observed
authenticated offsets and trailer byte counts are authoritative. Readers
MAY warn when a non-zero expected size differs from observed volume
sizes.

### 9.1 Extension TLVs

```rust
#[repr(C, packed)]
struct Extension {
    tag:    u16,        // high bit = critical-must-understand
    length: u32,        // MUST be ≤ 256 in CryptoHeader
    value:  [u8; length],
}
// Terminator: tag = 0x0000, length = 0
```

**Historical note:** Extension payloads in CryptoHeader are capped
at 256 bytes. This prevents replication bloat (every volume holds an
identical copy of CryptoHeader; a 100 KiB extension × 1000 volumes = 100
MB of dead weight). Bulky data (e.g. zstd dictionary) must live in
encrypted metadata objects located by IndexRoot instead.

The table lists `ext_tag` values after masking off the critical bit. All
known extensions are single-valued in v0.36; writers MUST NOT emit the
same known `ext_tag` more than once. Writers SHOULD clear the critical
bit on these informational extensions.

Reserved tags (all under the 256-byte cap):

| Tag | Type | Purpose |
|---|---|---|
| `0x0001` | UTF-8 | User comment |
| `0x0002` | UTF-8 | Creator tool identifier |
| `0x0003` | `i64` | Creation timestamp (ns) |
| ~~`0x0004`~~ | ~~`[u8; 32]`~~ | **Forbidden in v0.36.** The tar-stream content hash is encrypted inside IndexRoot. Writers MUST NOT emit this extension; readers MUST reject it if present. |
| `0x0005` | UTF-8 | Locale tag for filenames |
| ~~`0x0006`~~ | ~~bytes~~ | **Forbidden in v0.36; moved to encrypted metadata.** A writer setting `has_dictionary = 1` declares that IndexRoot locates a dictionary-object extent (§15.2). Writers MUST NOT emit this extension; readers MUST reject it if present. |

### 9.2 Replication

Every volume contains an identical CryptoHeader. Readers can open any
volume to bootstrap; if one copy fails HMAC, try another.

---

## 10. Block Record

Every on-disk block carries exactly `BLOCK_SIZE` bytes of ciphertext or
parity, wrapped in 20 bytes of framing.

```rust
#[repr(C, packed)]
struct BlockRecord {
    magic:         [u8; 4],          // b"TZBK"
    block_index:   u64,
    kind:          u8,               // 0 = payload-data
                                     // 1 = payload-parity
                                     // 2 = index-root-data
                                     // 3 = index-root-parity
                                     // 4 = index-shard-data
                                     // 5 = index-shard-parity
                                     // 6 = dictionary-data
                                     // 7 = dictionary-parity
                                     // 8 = directory-hint-data
                                     // 9 = directory-hint-parity
    flags:         u8,               // bit 0: last data block of encrypted object
                                     // bits 1..7: reserved; MUST be zero in v0.36
    _reserved:     [u8; 2],
    payload:       [u8; BLOCK_SIZE],
    record_crc32c: u32,
}
```

On-disk size: `BLOCK_SIZE + 20` bytes per block.

`record_crc32c` is computed over the `magic`, `block_index`, `kind`,
`flags`, `_reserved`, and `payload` fields: total length
`16 + BLOCK_SIZE` bytes, at offsets `0 .. 16 + BLOCK_SIZE - 1`. The CRC
field itself is excluded.

BlockRecord kind values 0 through 9 are defined above. Values 10 through
255 are reserved for future use. Writers MUST NOT emit reserved kind
values; readers MUST reject any BlockRecord with a `kind` outside
0 through 9. Writers MUST set `magic = b"TZBK"`; readers MUST reject any
BlockRecord whose magic field differs before using its kind, flags,
block index, payload, or CRC result for object assembly.

Writers MUST set all reserved `BlockRecord.flags` bits to zero. Readers
MUST reject a BlockRecord with any reserved flag bit set; in v0.36 this
means any flag bit other than bit 0 is invalid. Bit 0 MUST be set on the
last data block of every encrypted object, including payload envelopes
(kind 0), IndexRoot (kind 2), IndexShards (kind 4), dictionary objects
(kind 6), and directory-hint shards (kind 8). Bit 0 MUST be zero on all
other data blocks and on all parity blocks (kinds 1, 3, 5, 7, and 9).
Readers MUST reject parity blocks with bit 0 set. Within the data-block
run of any encrypted object, exactly one data BlockRecord MUST have bit 0
set, and it MUST be the final data block of that object's declared or
inferred data range. Readers MUST reject missing, duplicate, or early
last-data flags before object decryption.

For a volume whose authenticated header/trailer identity establishes
`volume_index = v` and `stripe_width = V`, every BlockRecord in that
volume MUST satisfy `block_index mod V = v`. Consecutive BlockRecords in
the same volume MUST differ by exactly `V`; this is stronger than merely
being sorted and lets a reader detect per-volume omissions even when it
does not have every other volume available.

A "complete input set" means all `V` volumes named by `stripe_width` are
available to the reader and have passed header/trailer identity checks.
For a complete input set, no two BlockRecords may share the same
`block_index`, and the observed global block indices MUST cover every
value from 0 through the final emitted block index. Object extents
declared by ManifestFooter, ShardEntry, DirectoryHintShardEntry, or
EnvelopeEntry MUST refer to contiguous global block-index ranges. Readers
MUST reject duplicates, decreasing order, gaps in a complete input set,
or any missing block required by an operation when no recovery mode can
repair it.

For a supplied volume set, authenticated `volume_index` values MUST be
within `[0, stripe_width)`. A reader given more than one volume with the
same authenticated `volume_index` MUST reject the set by default rather
than choosing one copy arbitrarily. An explicit duplicate-copy recovery
mode MAY accept multiple files for the same `volume_index` only after
their authenticated terminal material matches and their complete byte
contents, or all BlockRecords needed by the requested operation, are
byte-for-byte identical. A complete input set contains exactly one
accepted volume for every index `0 .. stripe_width - 1`.

Declared encrypted-object block ranges MUST NOT overlap across distinct
objects in a completed archive. When a reader has loaded enough metadata
to compare two object extents, it MUST reject any overlap unless the two
records are duplicate descriptions of the same object with the same
object class, identity counter, block range, data/parity counts, and
encrypted size. Full-archive `verify` MUST check this globally across
ManifestFooter, IndexRoot, every ShardEntry, every
DirectoryHintShardEntry, every distinct EnvelopeEntry, and the optional
dictionary object.

When reading a declared object extent from fewer than all volumes,
readers MUST still validate the extent they can observe before object
assembly. Every available block used for that object MUST have a
`block_index` inside the declared contiguous range and the expected kind;
missing data or parity positions MUST be tracked by their object-local
shard index. If the available data blocks plus available parity blocks
cannot repair every missing required data block under that object's FEC
parameters, the reader MUST abort that object with a clear missing-block
error before AEAD decryption. A reader MUST NOT silently splice a
shorter or shifted block sequence into an encrypted object.

---

## 11. ManifestFooter

Written to every volume in default parallel-volume mode and located via
the VolumeTrailer (§12). ManifestFooter copies are semantically
replicated but not byte-identical: `archive_uuid`, `session_id`,
`total_volumes`, and IndexRoot location/size fields are the same across
all volume footers, while `volume_index` MUST match the containing
volume. The ManifestFooter is intentionally small and contains only
bootstrap metadata; archive content hashes, tar size, envelope count,
and frame count are encrypted inside IndexRoot.

```rust
#[repr(C, packed)]
struct ManifestFooter {
    magic:                       [u8; 4],   // b"TZMF"
    archive_uuid:                [u8; 16],
    session_id:                  [u8; 16],
    volume_index:                u32,
    is_authoritative:            u8,
    _reserved_a:                 [u8; 3],

    total_volumes:               u32,

    index_root_first_block:      u64,
    index_root_data_block_count: u32,
    index_root_parity_block_count: u32,
    index_root_encrypted_size:   u32,
    index_root_decompressed_size: u32,

    _reserved_b:                 [u8; 32],

    manifest_hmac:               [u8; 32],
}
```

Packed on-disk size: `sizeof(ManifestFooter) = 136` bytes. This constant
is normative for `manifest_footer_length` in VolumeTrailer and bootstrap
sidecar records.
Writers MUST set `magic = b"TZMF"`; readers MUST reject any
ManifestFooter whose magic field differs, even if its HMAC would
otherwise verify.

`manifest_hmac = HMAC-SHA-256(mac_key, b"tzap-v1-manifest-footer" ||
archive_uuid || session_id || all ManifestFooter bytes before the
manifest_hmac field)`. Reserved bytes MUST be zero. Writers MUST set
`is_authoritative` to either 0 or 1; readers MUST reject any other value.
Completed v0.36 writers MUST set `is_authoritative = 1` in every closed
volume footer they emit. Readers MUST treat `is_authoritative = 0` as a
partial, recovery-only, or future extension footer and must not use it
for random-access bootstrap.

In this version, `is_authoritative = 1` means "this footer was emitted
after the final IndexRoot was written and can bootstrap the completed
archive." Because every closed volume is intended to be a valid
bootstrap point, normal completed writers set the flag on every volume.
`is_authoritative = 0` is reserved for partial checkpoints, crash
recovery artifacts, or future append/checkpoint extensions; such footers
are never random-access authorities.

The ManifestFooter is the bootstrap authority for locating and sizing
IndexRoot. IndexRoot is still FEC-protected as an object, but that repair
is possible only after the reader has obtained an authenticated
ManifestFooter or authenticated bootstrap sidecar that identifies the
IndexRoot block extent. Replication of ManifestFooter across volumes and
the optional sidecar are therefore part of the bootstrap resilience
model.
Readers MUST reject a ManifestFooter whose
`index_root_data_block_count * block_size`, computed with checked
unsigned 64-bit arithmetic or wider, overflows u32 or does not equal
`index_root_encrypted_size` before fetching or decrypting IndexRoot. This
is the IndexRoot instance of the encrypted-object size canonicality rule
used throughout §15.9.
Readers MUST reject `index_root_data_block_count = 0` or
`index_root_encrypted_size = 0` for every present IndexRoot. Even an empty
archive has a non-empty encrypted IndexRoot object containing the empty
archive totals.

---

## 12. Volume Trailer

Fixed 128 bytes. The absolute last bytes of every volume file. **Holds
the ManifestFooter pointer** so the reader can locate it without
relying on any field in the VolumeHeader.

```rust
#[repr(C, packed)]
struct VolumeTrailer {
    magic:                    [u8; 4],   // b"TZVT"
    archive_uuid:             [u8; 16],
    session_id:               [u8; 16],
    volume_index:             u32,
    block_count:              u64,
    bytes_written:            u64,       // file size up to (not including) trailer

    // Pointer to ManifestFooter within this volume
    manifest_footer_offset:   u64,
    manifest_footer_length:   u32,

    closed_at_ns:             i64,

    _reserved:                [u8; 20],
    trailer_hmac:             [u8; 32],  // HMAC-SHA-256(mac_key,
                                             // b"tzap-v1-volume-trailer" ||
                                             // archive_uuid || session_id ||
                                             // first 96 bytes)
                                             // (offsets 0..95; excludes this field)
}
```

`block_count` is the number of BlockRecords physically written in this
volume, not the highest global `block_index`. For a completed conforming
volume, the BlockRecord byte region starts immediately after the
CryptoHeader bytes and ends immediately before the ManifestFooter bytes.
The ManifestFooter bytes then end immediately before the VolumeTrailer;
there is no authenticated or unauthenticated padding region between the
ManifestFooter and VolumeTrailer in v0.36.
Readers MUST verify `block_count` against that observed region when
opening a seekable volume or authenticating the terminal material of a
non-seekable sequential stream.

**Historical note:** Trailer size grew from 96 to 128 bytes to
accommodate the manifest pointer and reach a round size. Conforming
writers place the trailer as the final bytes of the volume and MUST NOT
emit trailing padding or garbage after it. Seekable readers normally use
`file_size − 128` to locate the trailer; bounded trailing-garbage
recovery is an optional reader tolerance (§17.1), not writer permission.
Non-seekable readers use a bootstrap sidecar or sequential extraction
(§12.2, §17.3).

`trailer_hmac = HMAC-SHA-256(mac_key, b"tzap-v1-volume-trailer" ||
archive_uuid || session_id || first 96 trailer bytes)`.
Writers MUST set `magic = b"TZVT"`; readers MUST reject any
VolumeTrailer whose magic field differs before using its pointer or byte
count fields.
For seekable inputs with no trailing-garbage recovery, authenticated
`bytes_written` MUST equal `file_size - sizeof(VolumeTrailer)`. If a
reader uses bounded trailing-garbage recovery (§17.1), authenticated
`bytes_written` MUST instead equal the candidate trailer offset that was
found by the recovery scan. Readers MUST reject a seekable volume whose
trailer HMAC is valid but whose `bytes_written` does not match the
selected trailer offset.

### 12.1 Reader diagnostic logic

| Trailer state | Diagnosis |
|---|---|
| Present, valid HMAC, authoritative ManifestFooter, matching identity, `bytes_written`, and `block_count` | Clean close |
| Present, invalid HMAC | Tampered or wrong key |
| Present, valid HMAC, mismatched identity | Mixed volumes from different archives |
| Absent (no valid trailer at EOF, or within the optional trailing-garbage scan window) | Writer crashed, truncated, or garbage beyond recovery cap |
| Volume file entirely missing | Sibling lost |

### 12.2 Compatibility with non-seekable read

For environments where the reader cannot seek to the end of the file, the
writer may additionally emit a bootstrap sidecar file
(`<base>.tzap.bootstrap`) or a separate sidecar stream/file descriptor.
The sidecar may contain:

- a sidecar ManifestFooter instance containing the shared bootstrap
  fields and its own HMAC;
- BlockRecord copies for the encrypted IndexRoot data/parity blocks
  (§12.3);
- for dictionary archives, BlockRecord copies for the encrypted
  dictionary object.

Sidecar bytes are not trusted merely because they are adjacent to the
archive. Readers MUST verify the same HMAC/AEAD authentication that would
be verified when reading the bytes from a volume before using sidecar
BlockRecords to locate, repair, decrypt, or decompress any object. A
dictionary archive
uses the sidecar's authenticated encrypted IndexRoot copy to locate the
dictionary object and the sidecar's authenticated encrypted dictionary
copy to recover dictionary bytes before payload decompression. If a
reader starts from a live non-seekable stream before the sidecar is
complete, it MUST either buffer encrypted payload bytes until the
dictionary is recovered or reject with "dictionary bootstrap required."
The core tzap payload stream does not define an in-band sidecar
multiplexing format; a live pipe workflow that needs dictionary
decompression must deliver the sidecar out of band and make it available
to the reader before payload frame decompression begins.

A sidecar can provide bootstrap metadata without seeking. It does not by
itself make a non-seekable payload stream randomly accessible: random
extraction still requires range-capable volume storage, reopened volume
files, or local buffering of the needed blocks. If no sidecar is
available, a conforming reader MUST either use sequential extraction
(§17.3) or reject operations that require the ManifestFooter or
IndexRoot.

### 12.3 Bootstrap sidecar layout

The bootstrap sidecar is a forward-written helper file. It is not part
of the core volume set, does not change `archive_uuid`, and does not
change `stripe_width` or `ManifestFooter.total_volumes`.

```rust
#[repr(C, packed)]
struct BootstrapSidecarHeader {
    magic:                       [u8; 4],   // b"TZBS"
    version:                     u32,       // 1
    archive_uuid:                [u8; 16],
    session_id:                  [u8; 16],
    flags:                       u32,       // bit 0: ManifestFooter present
                                             // bit 1: IndexRoot BlockRecords present
                                             // bit 2: Dictionary BlockRecords present
                                             // bits 3..31: reserved; MUST be zero in v0.36

    manifest_footer_offset:      u64,       // 0 if absent
    manifest_footer_length:      u32,       // 0 if absent

    index_root_records_offset:   u64,       // 0 if absent
    index_root_records_length:   u64,       // 0 if absent

    dictionary_records_offset:   u64,       // 0 if absent
    dictionary_records_length:   u64,       // 0 if absent

    _reserved:                   [u8; 4],
    sidecar_hmac:                [u8; 32],  // HMAC-SHA-256(mac_key,
                                               // b"tzap-v1-sidecar" ||
                                               // archive_uuid || session_id ||
                                               // first 92 bytes)
                                               // (offsets 0..91; excludes this field and CRC)
    header_crc32c:               u32,       // CRC32C over first 124 bytes
                                                // (offsets 0..123; excludes this field)
}
```

On-disk size: 128 bytes.
Writers MUST set `magic = b"TZBS"`; readers MUST reject any
BootstrapSidecarHeader whose magic field differs before trusting its
flags, offsets, lengths, CRC, or HMAC result.

If a presence flag is set, the corresponding offset and length fields
MUST be non-zero; `manifest_footer_length` MUST equal
`sizeof(ManifestFooter)` (136 bytes). If a presence flag is clear, the
corresponding offset and length fields MUST be zero.
BootstrapSidecarHeader `_reserved` bytes and flag bits 3 through 31 MUST
be zero in v0.36; readers MUST reject the sidecar before trusting any
offset if they are non-zero.

When a ManifestFooter is placed in a bootstrap sidecar, it is a sidecar
ManifestFooter instance. It MAY be byte-identical to the volume-0
per-volume ManifestFooter when every serialized field and HMAC input is
identical. Writers MUST NOT copy a nonzero-volume ManifestFooter and
then mutate `volume_index` after HMAC. Writers MUST serialize the
sidecar ManifestFooter instance with
`ManifestFooter.volume_index = 0` and `is_authoritative = 1`, then
compute that instance's `manifest_hmac` over those sidecar bytes. The
zero volume index is informational for sidecar bootstrapping because the
sidecar is not itself a volume. Readers MUST verify the sidecar
ManifestFooter HMAC and `archive_uuid`/`session_id`, MUST reject a v0.36
bootstrap sidecar whose sidecar ManifestFooter has `volume_index != 0`
or `is_authoritative != 1`, and MUST NOT require that zero value to
match the currently opened VolumeHeader. Seekable per-volume
ManifestFooter copies still MUST match their containing volume (§17.1).

When present, the sidecar layout is a packed sequence:

```
BootstrapSidecarHeader
ManifestFooter bytes, if flag bit 0 is set
BlockRecord[] for IndexRoot data/parity blocks, if flag bit 1 is set
BlockRecord[] for dictionary data/parity blocks, if flag bit 2 is set
```

No padding, extension bytes, or unclaimed gaps are permitted in a v0.36
bootstrap sidecar. Offsets are validated by a canonical cursor:

1. Initialize `cursor = 128`.
2. If flag bit 0 is set, `manifest_footer_offset` MUST equal `cursor`,
   then advance by `manifest_footer_length`; otherwise both
   ManifestFooter fields MUST be zero.
3. If flag bit 1 is set, `index_root_records_offset` MUST equal
   `cursor`, then advance by `index_root_records_length`; otherwise both
   IndexRoot record fields MUST be zero.
4. If flag bit 2 is set, `dictionary_records_offset` MUST equal
   `cursor`, then advance by `dictionary_records_length`; otherwise both
   dictionary record fields MUST be zero.
5. The sidecar file size MUST equal the final cursor.

This cursor rule is authoritative for sparse flag combinations: a
present later section follows the last present earlier section in the
canonical order, not an absent section's zero offset.

Sparse sidecar sections are valid only when another authenticated
authority supplies the metadata needed to verify them. A sidecar with
IndexRoot BlockRecords but no sidecar ManifestFooter is usable only if
the reader already has an authenticated ManifestFooter for the same
`archive_uuid`/`session_id` from a volume or another trusted sidecar. A
sidecar with dictionary BlockRecords is usable only after the reader has
an authenticated IndexRoot for the same archive/session, from this
sidecar or another authenticated source, that declares the dictionary
object extent. A sidecar MUST NOT be treated as a non-seekable bootstrap
source unless it carries at least flag bits 0 and 1 and those sections
verify. For dictionary-compressed non-seekable bootstrap, flag bits 0, 1,
and 2 MUST all be set and all three declared byte ranges MUST be present.

`index_root_records_length` MUST be an integer multiple of
`sizeof(BlockRecord)`, and every copied BlockRecord MUST have kind 2
(`index-root-data`) or kind 3 (`index-root-parity`). The copied
BlockRecord payload bytes are the same authenticated encrypted/parity
bytes that would be read from the volume set.
After obtaining an authenticated ManifestFooter from the sidecar or
another source, readers MUST verify that the IndexRoot record section
contains exactly the BlockRecords in the
half-open global block-index range
`[index_root_first_block, index_root_first_block +
index_root_data_block_count + index_root_parity_block_count)`, sorted by
`block_index`, with no duplicates or extras, with data kinds before
parity kinds, and with exactly one last-data flag on the final IndexRoot
data block.
`dictionary_records_length`, when present, follows the same rule and may
contain only kind 6 (`dictionary-data`) or kind 7 (`dictionary-parity`)
BlockRecords.
After decrypting and validating IndexRoot, readers MUST verify that the
dictionary record section, when present, contains exactly the dictionary
object's declared block-index range under the same ordering, duplicate,
kind, and last-data-flag rules. If `has_dictionary = 0`, flag bit 2
MUST be clear and all dictionary record fields MUST be zero.
Before reading copied BlockRecord arrays into memory, readers MUST bound
each present record section by the corresponding FEC class maxima from
the authenticated CryptoHeader:
`index_root_records_length / sizeof(BlockRecord) ≤
index_root_fec_data_shards + index_root_fec_parity_shards`, and
`dictionary_records_length / sizeof(BlockRecord) ≤
index_root_fec_data_shards + index_root_fec_parity_shards`. Readers MUST
also enforce the bootstrap sidecar file-size cap in §13.3. These caps are
checked in addition to the packed cursor rule and HMAC/AEAD
authentication.

The sidecar header CRC is only an unkeyed corruption check over the raw
received header bytes. Readers MAY compute it before KDF/HMAC work to
reject obvious corruption early, even though the covered bytes include
the as-received `sidecar_hmac` field. `sidecar_hmac` verification is
mandatory before trusting flags, offsets, or lengths. The CRC covers the
`sidecar_hmac` bytes because it covers the first 124 header bytes; this
is intentional and does not make the CRC an authentication mechanism.
Authority for copied archive objects still comes from the ManifestFooter
HMAC plus AEAD verification of IndexRoot and any copied dictionary
object.
Readers MUST verify that the sidecar `archive_uuid` and `session_id`
match the VolumeHeader/CryptoHeader pair before using any sidecar bytes.
Readers implementing this draft MUST reject `version != 1`.
Readers MUST range-check every non-zero offset/length pair against the
sidecar file size before reading and MUST reject overlapping declared
ranges unless a future version explicitly defines such overlap.
Readers MUST ignore unknown flag bits only if they are explicitly marked
non-critical by a future version; for v0.36, unknown flag bits are a hard
error.

---

### 12.4 Bootstrap precedence and trust requirements

Bootstrap selection is deterministic:

- Seekable random-access bootstrap is terminal-authority based:
  `VolumeTrailer` authentication then `ManifestFooter` identity and
  `ManifestFooter.is_authoritative = 1` form the primary source.
- For seekable input when the terminal bootstrap is not authoritative for
  the requested operation, readers may try additional accepted volumes
  or a trusted sidecar only if the same authority graph is established.
- Non-seekable random-access bootstrap is sidecar-based only.
  For `has_dictionary = 0`, sidecar flag bits 0 and 1 are required.
  For `has_dictionary = 1`, bit 2 is also required and sidecar
  dictionary records must be validated against the authenticated IndexRoot
  dictionary extent before payload decompression.
- If sidecar bits or validations are missing while random access is
  required, readers MUST reject (or, for streams that can buffer, defer
  payload decompression until bootstrap is complete).
- Conflicting bootstrap authorities (different `archive_uuid`/`session_id`
  or mismatched bootstrap fields) are treated as corrupted or mixed
  archives; operations that rely on bootstrap MUST reject.

## 13. Key Derivation

### 13.1 Argon2id parameters

For `KdfAlgo::Argon2id`, the CryptoHeader KdfParams payload is exactly
the following byte sequence:

| Offset | Size | Field | Required value / meaning |
|---:|---:|---|---|
| 0 | 2 | `algo_tag` | `1` |
| 2 | 4 | `t_cost` | Argon2id iterations; default `3` |
| 6 | 4 | `m_cost_kib` | Argon2id memory in KiB; default `262_144` |
| 10 | 4 | `parallelism` | Argon2 lanes/threads; default `4` |
| 14 | 2 | `salt_length` | byte length of following salt |
| 16 | `salt_length` | `salt` | raw salt bytes |

There is no second salt field and no implicit alignment padding. Writers
MUST use `t_cost ≥ 1`, `8 ≤ salt_length ≤ 64`, `parallelism ≥ 1`, and
`m_cost_kib ≥ 8 × parallelism`. Readers MUST reject salts or Argon2id
parameter sets outside those bounds, including `t_cost = 0`, or KDF
parameter buffers that do not fit inside CryptoHeader, before invoking
Argon2id.
Readers MUST first verify that at least 16 KdfParams bytes are available
before reading `salt_length`, then verify that `16 + salt_length` bytes
fit before the CryptoHeader HMAC and Extension TLV region.

Argon2id uses the Argon2 version 0x13 (decimal 19) profile. The output
length is exactly 32 bytes. Argon2 `secret` and associated-data inputs
are empty byte strings. `parallelism` is both the Argon2 lane count and
the requested thread count; implementations that execute with fewer
host threads for scheduling reasons MUST still compute the same
lane-count result. Implementations MUST NOT use PHC string encodings,
library-default output lengths, library-default versions, or non-empty
secret/associated-data inputs as implicit archive parameters.

The Argon2id password input named `passphrase_utf8_nfc` in §13.2 is the
exact byte string produced by UTF-8 encoding the caller-supplied Unicode
passphrase after NFC normalization. The archive format does not
implicitly trim newlines, strip NUL bytes, remove or add a BOM, apply
locale-dependent transcoding, or use a platform-native character set.
CLI front ends MAY define user-interface conveniences before invoking
the KDF, but they MUST document them and MUST apply the same transform
for create, extract, verify, and recovery. Test vectors MUST state the
literal Unicode string and expected UTF-8 byte sequence used as
Argon2id input.

For `KdfAlgo::Raw`, the CryptoHeader KdfParams payload is exactly
two bytes: `algo_tag: u16 = 0`. The user supplies the 32-byte
`master_key` via keyfile. No KDF salt is stored for raw mode because
HKDF-Extract already uses the archive UUID and session ID as public
per-archive/session salt (§13.2). Readers MUST reject a KdfParams
`algo_tag` that does not match `CryptoHeader.kdf_algo`. The Extension
TLV list begins immediately after those two bytes; there is no raw-mode
padding or alignment field.
Readers MUST verify those two KdfParams bytes are present before reading
`algo_tag`.

### 13.2 Master key and subkeys

```
master_key       = Argon2id(passphrase_utf8_nfc, salt, params, len=32)

prk              = HKDF-Extract-SHA-256(
                       salt = b"tzap-v1-subkeys" ||
                              archive_uuid ||
                              session_id,
                       IKM  = master_key)

enc_key          = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-enc",      L=32)
mac_key          = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-mac",      L=32)
nonce_seed       = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-nonce",    L=32)
index_root_key   = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-idxroot",  L=32)
index_shard_key  = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-idxshard", L=32)
dictionary_key   = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-dict",     L=32)
dir_hint_key     = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-dirhint",  L=32)
index_nonce_seed = HKDF-Expand-SHA-256(prk, info=b"tzap-v1-idxnonce", L=32)
```

This HKDF construction is normative. Writers and readers MUST use
HKDF-SHA-256 Extract followed by Expand exactly as shown. The HKDF salt
binds the public archive identity to the subkey schedule, giving raw-key
mode the same per-archive/session key separation that Argon2id mode gets
from its random KDF salt. The Argon2id salt remains the per-archive
password-hardening salt in §13.1. Raw-key mode uses the supplied 32-byte
value as `master_key` and still runs the same HKDF subkey schedule.

### 13.3 Reader-side caps

| Cap | Default |
|---|---|
| `m_cost_kib` | 4 GiB |
| `t_cost` | 100 |
| `parallelism` | 64; also requires `m_cost_kib ≥ 8 × parallelism` |
| `argon2id_salt_length` | 8..64 bytes |
| `CryptoHeader byte length` | 64 KiB |
| `chunk_size` | 64 MiB |
| `envelope_target_size` | 64 MiB |
| `block_size` | 1 MiB |
| `stripe_width V` | 1..4096 |
| `fec_data_shards + fec_parity_shards` | 4096 local default, or 131,070 for full class-maximum interoperability |
| `index_fec_data_shards + index_fec_parity_shards` | 4096 local default, or 131,070 for full class-maximum interoperability |
| `index_root_fec_data_shards + index_root_fec_parity_shards` | 131,070 or lower local cap |
| `max_path_length` | 4096 |
| `max_shard_count` | 1,000,000 |
| `max_files_per_index_shard` | 1,000,000 |
| `max_directory_hint_shards` | 1,000,000 |
| `max_entries_per_directory_hint_shard` | 1,000,000 |
| `max_hash_collision_shard_scan` | 16 adjacent shards per direction |
| `max_trailing_garbage_scan` | 1 MiB |
| Bootstrap sidecar file size | derived cap below |
| Total extraction size | `min(100 GiB, 10 × observed archive byte size)` unless explicitly raised |

The three FEC class-total caps above are reader resource caps on
CryptoHeader maxima, not wire-format validity rules. A reader that uses
a lower local cap may reject an otherwise valid archive with a
resource-limit diagnostic. They are separate from the hard
ReedSolomonGF16 per-object total-shard limit of 65,535 and from each
actual object's class-max and u32-size checks.

The `CryptoHeader byte length` cap applies to both
`VolumeHeader.crypto_header_length` and `CryptoHeaderFixed.length` before
the reader allocates a header buffer, parses KDF parameters, scans
Extension TLVs, or runs the KDF. Readers MAY expose a lower local cap,
but MUST reject any header over the active cap with a resource-limit
diagnostic rather than truncating, streaming semantic TLV interpretation,
or allocating from the unauthenticated u32 length.

The bootstrap sidecar cap is:

```
128
+ (flag bit 0 ? sizeof(ManifestFooter) : 0)
+ record_section_count
  × (index_root_fec_data_shards + index_root_fec_parity_shards)
  × sizeof(BlockRecord)
```

where `record_section_count` is `(flag bit 1 set ? 1 : 0) + (flag bit 2
set ? 1 : 0)`. The dictionary BlockRecord term is included only when the
sidecar actually carries dictionary records. Readers MAY expose a lower
local cap, but MUST reject a sidecar whose declared packed size or
observed file size exceeds the active cap before buffering untrusted
sidecar bytes.
The cap calculation MUST use checked unsigned 64-bit arithmetic or wider;
all intermediate additions and multiplications are checked. Overflow
while computing the cap is a hard rejection before allocation. If the
computed cap exceeds `SIZE_MAX`, the platform's maximum representable
file size/offset, or any host API length type needed to stat or read the
sidecar, the reader MUST treat the sidecar as exceeding caps and reject
it rather than truncate or wrap the size.

"Total extraction size" means the sum of logical regular-file payload
bytes that would be written for the selected extraction set after tar/PAX
interpretation, including sparse-file expanded logical size when sparse
restoration is supported. It excludes tar headers, tar padding,
directories, symlinks, hardlink metadata entries, and other non-regular
metadata records. Readers MUST enforce this cap from validated tar
header/PAX sizes before writing file payload bytes, and MUST count actual
bytes written as a backstop during streaming extraction.
For this cap, "observed archive byte size" means the sum of file sizes
for all supplied volume files that have passed identity checks when the
input set is seekable. For non-seekable or partial/recovery inputs, it
means the cumulative bytes consumed from supplied archive streams that
have passed their available CRC/HMAC/AEAD checks, plus authenticated
sidecar bytes if a sidecar is used. Readers MAY choose a lower local cap
or require all volumes before extracting, but MUST NOT use the size of a
single opened volume as the whole multi-volume archive size when more
authenticated volumes are available.

---

## 14. AEAD Construction

### 14.1 Nonces and AAD

```rust
fn derive_nonce(
    seed: &[u8; 32],
    domain: &[u8],
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    counter: u64,
    len: usize,
) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(b"tzap-v1-nonce");
    info.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    info.extend_from_slice(domain);
    info.extend_from_slice(archive_uuid);
    info.extend_from_slice(session_id);
    info.extend_from_slice(&counter.to_le_bytes());
    hkdf_expand_sha256(seed, &info, len)
}

fn aad(domain: &[u8], archive_uuid: &[u8; 16], session_id: &[u8; 16], counter: u64) -> Vec<u8> {
    let mut a = Vec::new();
    a.extend_from_slice(b"tzap-v1-aad");
    a.extend_from_slice(&(domain.len() as u16).to_le_bytes());
    a.extend_from_slice(domain);
    a.extend_from_slice(archive_uuid);
    a.extend_from_slice(session_id);
    a.extend_from_slice(&counter.to_le_bytes());
    a
}
```

`session_id` is part of both nonce derivation and AAD. This binds every
AEAD object to the write session that produced it and prevents
same-key/same-archive counter replay across sessions, including raw
keyfile mode.

`hkdf_expand_sha256` in nonce derivation is HKDF-Expand-SHA-256 using
the 32-byte nonce seed as the PRK and the constructed `info` bytes above.
It is used here as an HMAC-SHA-256-based deterministic PRF with variable
output length, not as a password-hardening step. The domain string is
length-prefixed, and archive UUID, session ID, and counter are fixed
length, so the nonce derivation has unambiguous domain separation. The
requested output length is the AEAD nonce length from §5. No nonce
randomness is required after `session_id` is generated.

### 14.2 Envelope encryption

```rust
fn encrypt_envelope(j: u64, packed_frames: &[u8]) -> Vec<u8> {
    let tag_len = AEAD_TAG_LEN;
    let mut total_blocks = max(1,
        (packed_frames.len() + tag_len + BLOCK_SIZE - 1) / BLOCK_SIZE);
    let mut envelope_total = total_blocks * BLOCK_SIZE;
    let mut pad_len = envelope_total - packed_frames.len() - tag_len;
    if pad_len == 0 {
        total_blocks += 1;
        envelope_total = total_blocks * BLOCK_SIZE;
        pad_len = BLOCK_SIZE;
    }
    // pad_len is now always ≥ 1.

    let mut plaintext = Vec::with_capacity(envelope_total - tag_len);
    plaintext.extend_from_slice(packed_frames);
    append_suffix_padding(&mut plaintext, pad_len);   // §6.1

    let nonce = derive_nonce(
        &nonce_seed, b"envelope", &archive_uuid, &session_id, j, AEAD_NONCE_LEN);
    aead_encrypt(
        &enc_key, &nonce, &aad(b"envelope", &archive_uuid, &session_id, j), &plaintext)
}
```

The value returned by this construction is an encrypted object whose
bytes are the §5 combined `ciphertext || tag` serialization and whose
length is recorded in `EnvelopeEntry.encrypted_size` as u32. Writers MUST
perform the arithmetic above with checked integer operations and MUST
split the envelope before the exact-fit extra block, AEAD tag, or
`data_block_count * block_size` product would exceed `u32::MAX` or the
selected FEC object limits. Truncating or wrapping `encrypted_size` is
non-conforming.

### 14.3 Index encryption

```rust
fn encrypt_index_root(plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let counter = 0; // IndexRoot is a singleton within the archive.
    let nonce = derive_nonce(
        &index_nonce_seed, b"idxroot", &archive_uuid, &session_id, counter, AEAD_NONCE_LEN);
    aead_encrypt(
        &index_root_key, &nonce,
        &aad(b"idxroot", &archive_uuid, &session_id, counter), &padded)
}

fn encrypt_index_shard(s: u64, plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let nonce = derive_nonce(
        &index_nonce_seed, b"idxshard", &archive_uuid, &session_id, s, AEAD_NONCE_LEN);
    aead_encrypt(
        &index_shard_key, &nonce,
        &aad(b"idxshard", &archive_uuid, &session_id, s), &padded)
}

fn encrypt_dictionary(plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let counter = 0; // one dictionary object per archive.
    let nonce = derive_nonce(
        &index_nonce_seed, b"dict", &archive_uuid, &session_id, counter, AEAD_NONCE_LEN);
    aead_encrypt(
        &dictionary_key, &nonce,
        &aad(b"dict", &archive_uuid, &session_id, counter), &padded)
}

fn encrypt_directory_hint_shard(h: u64, plaintext: &[u8]) -> Vec<u8> {
    let padded = suffix_pad_for_aead(plaintext, AEAD_TAG_LEN, BLOCK_SIZE);
    let nonce = derive_nonce(
        &index_nonce_seed, b"dirhint", &archive_uuid, &session_id, h, AEAD_NONCE_LEN);
    aead_encrypt(
        &dir_hint_key, &nonce,
        &aad(b"dirhint", &archive_uuid, &session_id, h), &padded)
}
```

The same suffix-marker padding scheme is used for index encryption.
`suffix_pad_for_aead` is the §6.1 construction with the exact-fit extra
block rule from §14.2; it MUST NOT produce `pad_len = 0`. Readers trim
ciphertext to the recorded `encrypted_size`, AEAD-decrypt, and then strip
suffix padding with the §6.1 algorithm before zstd-decompressing any
IndexRoot, IndexShard, dictionary, or directory-hint object.

Each metadata object compressed payload (IndexRoot, IndexShard, dictionary
object, and DirectoryHintTable) MUST be exactly one complete non-skippable
zstd frame. Writers MUST NOT encode metadata objects as concatenated zstd
frames, zstd skippable frames, or a valid frame followed by trailing bytes.
Readers MUST reject unless the metadata zstd decoder consumes the entire
depadded plaintext as one frame and produces exactly the recorded
`decompressed_size`.

For every AEAD object, the counter used in nonce derivation MUST match
the counter encoded in AAD. The IndexRoot is a singleton and uses
counter 0; IndexShard uses its shard index.
The dictionary object uses `dictionary_key`, domain `dict`, and counter
0. Directory hint shards use `dir_hint_key`, domain `dirhint`, and their
directory-hint shard index.
`DirectoryHintShardEntry.hint_shard_index` values MUST be unique within an
archive because they are AEAD counters for the `dirhint` domain under
`dir_hint_key`. Readers MUST reject duplicate hint shard indexes from
IndexRoot before decrypting any directory-hint shard.

---

## 15. Index Format

### 15.1 Layout

```
Index Root          (small, high-parity FEC root with shard/object tables)
Index Shard 0       (file table + local frame/envelope tables)
Index Shard 1
…
Index Shard S−1
Dictionary object   (optional encrypted metadata object)
Directory Hint Shards (optional encrypted metadata objects)
```

**Files in the index are globally sorted by
`(SHA-256(normalized path)[0..8], normalized path bytes,
tar_member_group_start)`,** not alphabetically by path string alone. The
8-byte hash prefix is the primary sort key using the bytewise ordering
defined in §4; the normalized UTF-8 path string is the collision
tie-breaker; and `tar_member_group_start` is the tar-stream byte offset
of the FileEntry's tar member group. This keeps shard hash bounds
monotonic, makes equal-prefix ordering deterministic without storing the
full 32-byte hash, and gives duplicate tar paths a defined order.

### 15.2 Index Root

```rust
#[repr(C, packed)]
struct IndexRoot {
    magic:                   [u8; 4],   // b"TZIR"
    version:                 u32,       // 1
    shard_count:             u32,
    directory_hint_shard_count: u32,
    frame_count:             u64,
    envelope_count:          u64,
    file_count:              u64,
    payload_block_count:     u64,       // sum of data blocks for distinct payload envelopes (kind 0)
    tar_total_size:          u64,       // encrypted; tzap tar stream bytes, excluding POSIX EOA marker
    content_sha256:          [u8; 32],  // SHA-256 of tzap tar stream pre-encryption

    shard_table_offset:      u64,
    directory_hint_shard_table_offset: u64, // 0 if omitted

    // Optional pre-trained zstd dictionary metadata object.
    dictionary_first_block:  u64,       // ignored if has_dictionary = 0
    dictionary_data_block_count: u32,   // 0 if no dictionary
    dictionary_parity_block_count: u32, // 0 if no dictionary
    dictionary_encrypted_size: u32,     // 0 if no dictionary
    dictionary_decompressed_size: u32,  // raw dictionary byte length, 0 if none

    _reserved:               [u8; 32],
}
// Plaintext layout (concatenated after IndexRoot header):
//   ShardEntry[shard_count]
//   if directory_hint_shard_count > 0:
//       DirectoryHintShardEntry[directory_hint_shard_count]
```

**Important:** the IndexRoot itself is compressed with zstd **without
using the user's dictionary**. The dictionary is a separate encrypted
metadata object located by the dictionary fields above, so it cannot be a
prerequisite for decompressing IndexRoot. After the reader decrypts and
decompresses the dictionary object, it loads those bytes into a zstd
decompression context for use on payload envelopes only.

When `has_dictionary = 1`, every payload-envelope zstd frame MUST be
compressed using the loaded dictionary. Metadata objects (IndexRoot,
IndexShard, dictionary object, and directory-hint shards) MUST NOT use
the dictionary. Readers MUST initialize metadata zstd contexts without a
dictionary and payload zstd contexts with the dictionary after it is
authenticated and decompressed.

Whenever `CryptoHeader.has_dictionary = 0`,
`dictionary_first_block`, `dictionary_data_block_count`,
`dictionary_parity_block_count`, `dictionary_encrypted_size`, and
`dictionary_decompressed_size` MUST all be zero. Readers MUST reject an
archive with `has_dictionary = 0` and any non-zero dictionary field.
Equivalently, `dictionary_data_block_count = 0` means no dictionary
object is present and requires all dictionary fields, including
`dictionary_first_block`, to be zero.
Whenever `CryptoHeader.has_dictionary = 1`, `dictionary_first_block`,
`dictionary_data_block_count`, `dictionary_encrypted_size`, and
`dictionary_decompressed_size` MUST all be non-zero.
`dictionary_parity_block_count` MAY be zero only when the computed
per-object parity requirement is zero. Readers MUST reject invalid
dictionary fields before attempting dictionary-object load.
`payload_block_count` is an authenticated archive total and MUST equal
the sum of data blocks for all distinct payload envelopes. Because
EnvelopeEntry rows are shard-local, random extraction may not observe
the whole sum; full-archive `verify` MUST check it (§15.9).
The same full-archive rule applies to `frame_count`, `envelope_count`,
`file_count`, `tar_total_size`, and `content_sha256`: these fields are
authenticated metadata, but they provide verification value only when
`verify` cross-checks them against distinct shard-local rows and the
reconstructed tzap tar stream (§15.9).

IndexRoot MUST remain a bounded root object. It contains shard metadata
and encrypted archive totals, but not global FrameEntry or EnvelopeEntry
tables and not raw dictionary bytes. Those tables live in IndexShard
objects (§15.5), and dictionary bytes live in the dictionary metadata
object. This keeps random access proportional to the target shard set
and keeps IndexRoot within the selected FEC object's shard limit.

Empty archives are valid. For an archive with zero input files, writers
set `file_count = 0`, `shard_count = 0`, `frame_count = 0`,
`envelope_count = 0`, `payload_block_count = 0`, `tar_total_size = 0`,
and `directory_hint_shard_count = 0`. `payload_block_count` counts only
payload-data BlockRecords (kind 0); IndexRoot blocks (kinds 2/3) are not
payload blocks. `has_dictionary` in CryptoHeader MUST be 0, all
dictionary fields in IndexRoot MUST be zero, `shard_table_offset = 0`,
`directory_hint_shard_table_offset = 0`, and `content_sha256 =
SHA-256(b"")`, whose hex digest is
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
Writers MUST NOT emit tar end-of-archive zero blocks for empty archives,
and `tar_total_size = 0`. This is the same rule used for non-empty
archives: the POSIX end-of-archive marker is not encrypted archive
content. No payload envelopes, IndexShard objects, directory hint shards,
or dictionary object are written, but the archive still contains a valid
IndexRoot, ManifestFooter, and VolumeTrailer.

For IndexRoot counted tables, a zero count means the corresponding table
is absent and its offset MUST be zero. Specifically,
`shard_table_offset = 0` when `shard_count = 0`, and
`directory_hint_shard_table_offset = 0` when
`directory_hint_shard_count = 0`. Readers MUST NOT apply fixed-header
range validation to an absent zero-count table.

### 15.3 Envelope and Frame tables

```rust
#[repr(C, packed)]
struct EnvelopeEntry {
    envelope_index:        u64,
    first_block_index:     u64,
    data_block_count:      u32,       // encrypted envelope data blocks
    parity_block_count:    u32,       // object-local FEC parity blocks
    encrypted_size:        u32,       // total ciphertext bytes including AEAD tag
    plaintext_size:        u32,       // packed frame bytes before suffix padding
    first_frame_index:     u64,
    frame_count:           u32,
    _reserved:             u32,
}

#[repr(C, packed)]
struct FrameEntry {
    frame_index:           u64,
    envelope_index:        u64,
    offset_in_envelope:    u32,       // compressed frame offset in envelope plaintext
    compressed_size:       u32,
    decompressed_size:     u32,
    flags:                 u32,
    tar_stream_offset:     u64,       // decompressed tar-stream offset of frame start
    _reserved:             u32,
}
```

`offset_in_envelope` is an offset in the decrypted, depadded envelope
plaintext. It points to the start of a complete zstd frame, not to a tar
header. A zstd frame MUST be wholly contained in one envelope.

Payload envelopes are assigned `envelope_index` values in write order,
starting at 0 and increasing by 1 for every payload envelope. The global
payload envelope sequence has no gaps. Because v0.36 stores only
shard-local EnvelopeEntry rows, an individual IndexShard's EnvelopeEntry
table is a sorted unique subset of that global sequence and MAY be
sparse. Local EnvelopeEntry tables MUST be sorted by `envelope_index`,
MUST NOT contain duplicate `envelope_index` values, and MUST contain
every envelope needed by that shard's local FileEntry/FrameEntry ranges.
They MUST NOT be padded with unrelated global EnvelopeEntry rows merely
to make the local table contiguous. Full-archive `verify` reconstructs
the distinct global EnvelopeEntry set and checks that it covers
`[0, IndexRoot.envelope_count)` exactly once (§15.9). The envelope AEAD
counter `j` is exactly `envelope_index`; a sequential reader without
IndexRoot can therefore maintain a local `next_envelope_index` counter.

An IndexShard-local FrameEntry table is likewise an exact shard-local
subset: it MUST be sorted by `frame_index`, MUST NOT contain duplicate
`frame_index` values, and MUST contain exactly every frame referenced by
that shard's FileEntry ranges. It MUST NOT contain unrelated frame rows
from the global frame sequence. The shard-local EnvelopeEntry table is
then the exact sorted unique set of envelopes referenced by those local
FrameEntry rows. This exactness keeps random extraction deterministic and
prevents conforming readers from diverging about whether unrelated local
rows are warnings, ignored data, or hard errors.

`EnvelopeEntry.first_frame_index` and `EnvelopeEntry.frame_count` describe
the full global frame range packed into that envelope. They do not imply
that every frame in that range is present in every shard-local
FrameEntry table that references the envelope. A local shard that needs
only one frame from a multi-frame envelope records that local FrameEntry
and the corresponding EnvelopeEntry, but does not add unrelated frames
solely to make the envelope range locally complete. Full-archive
`verify` reconstructs the distinct global FrameEntry set across all
IndexShards before checking whole-envelope frame coverage (§15.9).

Payload EnvelopeEntry records MUST describe at least one complete zstd
frame: `frame_count ≥ 1` and `plaintext_size > 0`. Empty archives use no
payload EnvelopeEntry records; writers MUST NOT emit empty payload
envelopes, and readers MUST reject them.
After AEAD decryption and suffix depadding, the depadded envelope
plaintext length MUST exactly equal `EnvelopeEntry.plaintext_size` before
any `FrameEntry.offset_in_envelope` or `compressed_size` is used.

`FrameEntry.flags` bit 0 means the frame starts at a tar member group
boundary; bit 1 means the frame ends at a tar member group boundary.
Bits 2..31 are reserved and MUST be zero. These flags are hints for
validation and diagnostics; FileEntry remains the authority for
extraction extents.
Every FrameEntry MUST describe a non-empty complete zstd frame:
`compressed_size > 0` and `decompressed_size > 0`.
The byte slice described by each FrameEntry MUST parse and decode as
exactly one complete zstd frame and consume exactly `compressed_size`
bytes. Decompression failure, trailing bytes after one frame, or output
whose length differs from `decompressed_size` is a hard archive error.

For every encrypted object in v0.36, `encrypted_size` is the total
ciphertext length including the AEAD tag after suffix padding. It MUST
equal `data_block_count * block_size`. Writers MUST ensure this product
fits in `u32`; readers MUST compute the product with checked unsigned
64-bit arithmetic or wider, and MUST reject any encrypted object whose
recorded `encrypted_size` is not exactly that product or whose product
would overflow `u32`.
Every present encrypted object MUST have `data_block_count ≥ 1` and
`encrypted_size ≥ block_size`. `parity_block_count` MAY be zero when the
per-object parity calculation permits it, but a zero-data-block
IndexRoot, IndexShard, dictionary object, directory-hint shard, or
payload envelope is malformed and MUST be rejected before FEC repair,
AEAD decryption, or decompression.

All u32 plaintext size fields are hard wire-format caps. Writers MUST
reject any payload envelope whose packed-frame `plaintext_size` exceeds
`u32::MAX`; any FrameEntry whose `compressed_size` or `decompressed_size`
exceeds `u32::MAX`; and any IndexRoot, IndexShard, dictionary object, or
DirectoryHintTable whose recorded decompressed size would exceed
`u32::MAX`. Readers MUST reject decompression output that exceeds the
recorded u32 size or any configured resource cap.

### 15.4 ShardEntry

```rust
#[repr(C, packed)]
struct ShardEntry {
    shard_index:           u64,
    first_block_index:     u64,       // first block of this shard's encrypted bytes
    data_block_count:      u32,
    parity_block_count:    u32,
    encrypted_size:        u32,
    decompressed_size:     u32,
    file_count:            u32,
    first_path_hash:       [u8; 8],   // first 8 bytes of SHA-256(first normalized path)
    last_path_hash:        [u8; 8],   // first 8 bytes of SHA-256(last normalized path)
}
```

Because the global file table is sorted by
`(SHA-256(normalized path)[0..8], normalized path bytes,
tar_member_group_start)`, shards are contiguous ranges in file-table
order. Hash-prefix comparisons use the bytewise ordering defined in §4:
`first_path_hash ≤ last_path_hash` for every shard, and shard ranges are
monotonic under that ordering. ShardEntry records in IndexRoot MUST be
sorted by `(first_path_hash, last_path_hash, shard_index)` ascending,
where the hash-prefix fields are compared bytewise and `shard_index` is
compared as an unsigned integer. Adjacent entries MAY share boundary
hashes, which is why readers apply the candidate-block scan below.
`shard_index` values MUST be unique across the IndexRoot ShardEntry
table. They are stable object identifiers, not row positions; readers
MUST reject duplicate `shard_index` values before building any
`shard_index → ShardEntry` lookup map.

Writers SHOULD avoid splitting identical
`SHA-256(normalized path)[0..8]` prefixes
across shard boundaries while a prefix run remains below
`max_hash_prefix_run_files` (§24). If continuing the run would exceed
that ceiling, the writer MUST split the run across adjacent shards rather
than creating an unbounded shard. This gives normal archives a compact
candidate set while bounding malicious or pathological collision-heavy
inputs.
Writers MUST also size shards so `file_count ≤ max_files_per_index_shard`
(default 1,000,000 in §13.3).

Readers MUST use deterministic point-lookup semantics for these closed
hash intervals. To locate `target_hash`, perform an upper-bound search
for the first ShardEntry whose `first_path_hash > target_hash`. If such
a row exists, step back one row to the landing candidate; if no row is
strictly greater and the table is non-empty, the landing candidate is the
final row in the table. If the table is empty, if the upper-bound result
is the first row and there is no previous row, or if the landing
candidate's `last_path_hash < target_hash`, no shard contains the hash.
Otherwise, collect the contiguous candidate block including the landing
row by scanning left and right while
`first_path_hash ≤ target_hash ≤ last_path_hash`. Readers MUST cap this
scan at `max_hash_collision_shard_scan` adjacent shards per direction
(§13.3). If the cap is reached before the containing block ends, the
reader MUST fail with "hash-prefix collision run exceeds resource caps"
rather than returning a partial lookup result. This rule covers both
ordinary boundary equality, such as `[A, H] [H, B]`, and split identical
prefix runs such as `[H, H] [H, H]`.

This is an intentional availability trade-off: adversarial archives may
be rejected if they require unbounded equal-prefix scanning, but
conforming readers do not perform unlimited random-access lookups.

### 15.5 Index Shard plaintext

```rust
#[repr(C, packed)]
struct IndexShardHeader {
    magic:                 [u8; 4],   // b"TZIS"
    version:               u32,       // 1
    shard_index:           u64,
    file_count:            u32,
    frame_count:           u32,
    envelope_count:        u32,
    file_table_offset:     u32,
    frame_table_offset:    u32,
    envelope_table_offset: u32,
    string_pool_offset:    u32,
    string_pool_size:      u32,
    _reserved:             [u8; 16],
}
// Then:
//   FileEntry[file_count]   sorted by (SHA-256(normalized path)[0..8],
//                                      path bytes, tar_member_group_start)
//   FrameEntry[frame_count] sorted by frame_index
//   EnvelopeEntry[envelope_count] sorted by envelope_index
//   string_pool: [u8; string_pool_size]
```

Each IndexShard carries the FileEntry records for its path-hash range and
the local FrameEntry/EnvelopeEntry rows needed to extract those files.
For each counted table in `IndexShardHeader`, a zero count means the
corresponding table is absent and its offset MUST be zero; readers MUST
NOT range-validate absent zero-count tables against the fixed header.
If `string_pool_size = 0`, `string_pool_offset` MUST also be zero.
An IndexShard in a non-empty archive MUST have `file_count ≥ 1`, and its
`shard_index` MUST equal the `ShardEntry.shard_index` used to locate and
decrypt it.
The locating ShardEntry's `file_count` MUST equal
`IndexShardHeader.file_count`. The FileEntry table in each IndexShard
MUST be sorted by
`(path_hash, normalized path bytes, tar_member_group_start)`, using the
bytewise hash-prefix ordering from §4 and bytewise comparison of the
validated string-pool path bytes. If the table is non-empty, the locating
ShardEntry's `first_path_hash` MUST equal the first FileEntry's
`path_hash`, and its `last_path_hash` MUST equal the last FileEntry's
`path_hash`. Readers MUST reject a loaded IndexShard if these count,
ordering, or boundary bindings do not match.
Frame and envelope rows MAY be duplicated across shards when a compressed
frame or envelope is referenced by files whose paths hash into different
shards. Writers SHOULD minimize duplication by starting zstd frames at
tar member group boundaries, but correctness does not depend on that
optimization.
Archives with very large shared frame/envelope ranges across many hash
shards can grow a larger index because of this self-contained-shard
design. Writers SHOULD close frames and envelopes at tar member group
boundaries where practical to keep shard-local duplication low.

### 15.6 FileEntry

```rust
#[repr(C, packed)]
struct FileEntry {
    path_hash:             [u8; 8],   // SHA-256(normalized path)[0..8] — sort key
    path_offset:           u32,       // into this shard's string_pool
    path_length:           u32,
    first_frame_index:     u64,
    frame_count:           u32,
    offset_in_first_frame_plaintext: u32,
    tar_member_group_size: u64,       // metadata records + main tar entry + padding
    file_data_size:        u64,       // logical file payload size, 0 for non-regular entries
    flags:                 u32,
    _reserved:             u32,
}
```

`FileEntry` addresses decompressed frame plaintext, not envelope
plaintext. The target file's tar member group begins at
`offset_in_first_frame_plaintext` within `first_frame_index` and spans
`tar_member_group_size` bytes across `frame_count` ordered zstd frames.
The group includes any path-specific PAX/GNU metadata records needed to
restore the main tar entry.
`offset_in_first_frame_plaintext` MUST be strictly less than the
decompressed size of the first referenced frame; otherwise that frame
does not contain any byte of the tar member group and the FileEntry is
not minimally encoded.
The referenced frame range MUST also be minimal at the end: the final
byte of the tar member group MUST fall inside the final referenced
FrameEntry. Readers validate this using checked unsigned 64-bit
arithmetic over the referenced FrameEntry decompressed sizes. For
`frame_count = 1`, `tar_member_group_size` MUST be no greater than
`first_frame.decompressed_size - offset_in_first_frame_plaintext`. For
`frame_count > 1`, let `bytes_before_last` be the bytes available from
the first referenced frame after `offset_in_first_frame_plaintext` plus
the full decompressed sizes of all referenced middle frames before the
last frame. Then `tar_member_group_size` MUST be greater than
`bytes_before_last` and no greater than
`bytes_before_last + last_frame.decompressed_size`. A FileEntry that
includes a trailing frame whose bytes are not needed for the tar member
group is malformed. This keeps random extraction bounded to the minimum
ordered frame extent for that file.

`FileEntry.flags` is reserved in v0.36. Writers MUST set it to zero, and
readers MUST reject a FileEntry with any non-zero flag bit.
FileEntry paths are NFC-normalized UTF-8 archive paths using `/` as the
only component separator. Writers MUST convert platform-native directory
separators to `/` before normalization and MUST NOT emit backslash as a
directory separator. Readers MUST validate path safety against `/`
components and MUST reject platform-specific escape forms before writing
to the host filesystem.
Readers MUST recompute `SHA-256(path bytes)[0..8]` from the normalized
string-pool bytes for every FileEntry they load and MUST reject if it
does not exactly equal `FileEntry.path_hash`. Writers MUST compute
`path_hash` from exactly the bytes stored for that FileEntry path after
UTF-8 validation and NFC normalization. Lookup, sorting, and duplicate
path handling MUST use this verified `(path_hash, path bytes)` binding;
readers MUST NOT trust a stored hash that is inconsistent with the
stored path string.
`path_length` MUST be at least 1 and no greater than
`CryptoHeader.max_path_length`; the empty string is reserved only for the
root directory encoding in DirectoryHintTable (§15.8), never for a file
path.
Every FileEntry MUST reference at least one zstd frame
(`frame_count ≥ 1`) and at least one tar record
(`tar_member_group_size ≥ 512`). Even an empty regular file, directory,
symlink, or metadata-only entry has a 512-byte tar header.
`file_data_size` MUST equal the logical payload size declared by the
main tar entry after applying the supported PAX/GNU size metadata for
that tar member group; it MUST be zero for non-regular entries. Readers
that decode the tar member group during extraction or full-archive
verification MUST compare the main tar entry's normalized archive path
with the FileEntry path string and MUST compare the tar-declared logical
payload size with `FileEntry.file_data_size`. Readers MUST reject on
mismatch before writing file payload bytes, applying metadata, or
reporting the path or size as content-verified. Index-only listing tools
MAY display `path` and `file_data_size` as authenticated index metadata,
but MUST NOT label them as verified against the tar stream unless these
checks have run.

Multiple FileEntry rows MAY have the same normalized path, because a tar
stream can contain later entries that replace earlier entries for the
same path. For ordering and lookup, a FileEntry's
`tar_member_group_start` is computed as the first referenced
FrameEntry's `tar_stream_offset + offset_in_first_frame_plaintext`, using
checked unsigned 64-bit arithmetic. For identical normalized paths,
writers MUST order FileEntry rows by increasing `tar_member_group_start`.
A default random-access lookup for a path MUST return the FileEntry with
the greatest `tar_member_group_start`, matching normal tar "last entry
wins" extraction behavior. Tools MAY expose all occurrences through an
explicit history/listing mode, but MUST NOT choose first occurrence by
default.

### 15.7 Lookup path

```
1. Normalize `target_path` under the FileEntry path rules in §15.6 and
   §16, then compute `target_hash = SHA-256(normalized_target_path)[0..8]`.
2. Open IndexRoot: locate its data/parity block extent via
   ManifestFooter, FEC-repair if needed, decrypt with index_root_key,
   and decompress (without dictionary).
3. Binary search ShardEntry[] with the §15.4 upper-bound rule: find the
   first row whose `first_path_hash > target_hash`; if no row is greater,
   use the final row as the landing candidate; reject if the table is
   empty, if no previous/final landing candidate exists, or if that
   candidate's `last_path_hash < target_hash`; otherwise collect the
   contiguous candidate block including the landing row while
   `first_path_hash ≤ target_hash ≤ last_path_hash`, subject to reader
   caps.
4. Read candidate shard data/parity block extent(s) from ShardEntry;
   FEC-repair if needed, decrypt with index_shard_key, and decompress
   (without dictionary).
5. Binary search FileEntry[] by `(path_hash, normalized path bytes)`
   within every shard in the candidate-shard block. On hash match,
   verify by reading the actual path from string_pool and comparing
   strings. Repeat for collisions and duplicate paths by scanning around
   each landing position while the `(path_hash, normalized path bytes)`
   key is equal. If more than one FileEntry has the exact normalized path
   across all candidate shards, select the row with the greatest computed
   `tar_member_group_start`.
6. Extract (first_frame_index, frame_count,
   offset_in_first_frame_plaintext, tar_member_group_size).
7. Look up each FrameEntry in the shard-local FrameEntry table. For each
   unique envelope_index, look up the corresponding EnvelopeEntry in the
   shard-local EnvelopeEntry table, read its blocks, FEC-repair using its
   object-local data/parity counts, AEAD-decrypt, and strip suffix
   padding (§6.1).
8. For each FrameEntry, slice
   envelope_plaintext[offset_in_envelope ..
   offset_in_envelope + compressed_size] and zstd-decode that complete
   frame using the dictionary if has_dictionary = 1.
9. Concatenate decoded frame plaintexts in frame order, discard
   offset_in_first_frame_plaintext bytes from the first frame, and stream
   exactly tar_member_group_size bytes into a tar library. Compare the
   main tar entry's normalized archive path with the FileEntry path string
   and compare the main tar entry's logical payload size with
   `FileEntry.file_data_size` before writing file payload bytes, applying
   metadata, or reporting the path/size as content-verified.
```

The candidate-block scan is deliberately resource-bounded. A malicious
archive producer or malicious path set can force up to
`2 × max_hash_collision_shard_scan` extra candidate-shard reads per
lookup before a compliant reader fails. Implementations for hostile
archives MAY lower that cap, require `verify` first, or disable random
single-file extraction after repeated collision-run failures.

### 15.8 Directory and path-order operations

Because the primary index is sorted by hash, listing files alphabetically
requires either (a) reading all shards, building a full file table in
memory, and sorting by path, or (b) using a path-locality structure.

For typical archives (≤1M files × 56-byte FileEntry records + path
strings), option (a) uses roughly 75-120 MiB of RAM depending on average
path length — acceptable for many offline operations.

Writers MUST include Directory Hint Shard metadata when
`file_count > directory_hint_required_file_count` (§24) or when the
archive claims cloud/object-store optimized directory-prefix operations.
Writers MAY include it for smaller archives. Directory hints are stored
as one or more encrypted/FEC-protected directory-hint shard objects
listed by IndexRoot. They map normalized directory paths to ShardEntry
row indexes for shards that contain the directory entry itself, direct
children, or descendants of that directory. For a conforming archive, the
hint set is exact: writers MUST include one DirectoryHintEntry for the
root directory, for every normalized ancestor directory of every
FileEntry path, and for every FileEntry path whose decoded main tar entry
is itself a directory. Each entry's shard-row-index list MUST contain
exactly every IndexRoot ShardEntry row whose IndexShard contains at least
one FileEntry whose normalized path equals that directory path or has
that directory path as an ancestor. No shard row may be omitted or added.
Directory hints are acceleration structures only: readers MUST verify
actual paths from each shard's string pool before extracting or listing,
and full-archive `verify` MUST recompute and compare the exact hint map
before reporting directory hints as completeness-verified (§15.9).

Directory paths in this table are NFC-normalized UTF-8 with `/` as the
separator. The empty string is the canonical encoding of the root
directory and is the only directory path with `path_length = 0`. All
other directory paths MUST have at least one non-empty component, no
leading `/`, no `..` component, no empty inter-segment component, and no
trailing slash.
For directory-hint and directory-prefix matching, directory path `d` is
an ancestor of FileEntry path `p` exactly when either `d` is the empty
root directory string, or `p` starts with `d || "/"`. A plain byte prefix
without the separator is not enough: `foo` is not an ancestor of
`foobar`. A request for the archive root is normalized to the empty
directory string before hashing and lookup.

For a DirectoryHintEntry, `path_length = 0` is canonical only for the
root directory entry. Such an entry MUST set `path_offset = 0` and
`dir_hash = SHA-256(b"")[0..8]`; readers MUST reject any other
zero-length directory path encoding. For non-root directory entries,
`path_length > 0` and `path_offset + path_length` MUST select an
in-bounds byte range in the DirectoryHintTable string pool using checked
unsigned 64-bit arithmetic or wider.

```rust
#[repr(C, packed)]
struct DirectoryHintTable {
    magic:                  [u8; 4],    // b"TZDH"
    version:                u32,        // 1
    hint_shard_index:       u64,
    entry_count:            u64,
    entry_table_offset:     u64,
    shard_list_offset:      u64,
    string_pool_offset:     u64,
    string_pool_size:       u64,
    _reserved:              [u8; 16],
}

#[repr(C, packed)]
struct DirectoryHintEntry {
    dir_hash:               [u8; 8],    // SHA-256(normalized directory_path)[0..8]
    path_offset:            u64,        // into hint string pool
    path_length:            u32,
    _reserved:              u32,
    shard_list_start_index: u32,        // u32 index into shard-row-index array
    shard_count:            u32,
    _reserved2:             u64,
}

#[repr(C, packed)]
struct DirectoryHintShardEntry {
    hint_shard_index:       u64,
    first_dir_hash:         [u8; 8],
    last_dir_hash:          [u8; 8],
    first_block_index:      u64,
    data_block_count:       u32,
    parity_block_count:     u32,
    encrypted_size:         u32,
    decompressed_size:      u32,
    entry_count:            u64,
}
```

DirectoryHintShardEntry records live in IndexRoot and are sorted by
`(first_dir_hash, hint_shard_index)`, where `first_dir_hash` uses the
bytewise hash-prefix ordering defined in §4 and `hint_shard_index` is
compared as an unsigned integer. `hint_shard_index` values are stable
AEAD identity counters for directory-hint shard objects; they need not
equal IndexRoot row positions, but they MUST be unique across the
DirectoryHintShardEntry table. Their hash ranges MUST be monotonic under
the same bytewise ordering: for adjacent entries,
`last_dir_hash ≤ next.first_dir_hash`; if the boundary hashes are equal,
readers use the same upper-bound candidate-block lookup and scan cap as
§15.4, and `last_dir_hash > next.first_dir_hash` is malformed. Each
DirectoryHintTable is the
plaintext of one directory-hint shard object encrypted with
`dir_hint_key`, AEAD domain `dirhint`, and counter
`hint_shard_index`. Its `hint_shard_index` field MUST equal the
`DirectoryHintShardEntry.hint_shard_index` used to locate and decrypt
the object. A DirectoryHintShardEntry listed by IndexRoot MUST describe a
non-empty DirectoryHintTable: `entry_count` MUST be at least 1 and MUST
equal `DirectoryHintTable.entry_count`. Its `first_dir_hash` MUST equal
the first DirectoryHintEntry's `dir_hash`, and its `last_dir_hash` MUST
equal the last DirectoryHintEntry's `dir_hash`.
DirectoryHintEntry records inside a shard are sorted by
`(dir_hash, directory_path)` using bytewise comparison of normalized
UTF-8 directory paths as the collision tie-breaker. Duplicate exact
directory paths are malformed. If multiple directory paths share the same
`dir_hash`, readers MUST compare the actual string from the hint string
pool.
Readers MUST recompute `SHA-256(directory_path bytes)[0..8]` from the
normalized hint string-pool bytes for every DirectoryHintEntry they load
and MUST reject if it does not exactly equal `DirectoryHintEntry.dir_hash`.
Writers MUST compute `dir_hash` from exactly the bytes stored for that
DirectoryHintEntry path after UTF-8 validation and NFC normalization.
`DirectoryHintTable.shard_list_offset` points to the start of a
contiguous u32 shard-row-index array in the DirectoryHintTable plaintext
and MUST be 4-byte aligned. `DirectoryHintEntry.shard_list_start_index`
is a u32 element index into that shard-row-index array, not a byte
offset. The `shard_count` row indexes for an entry start at
`DirectoryHintTable.shard_list_offset + shard_list_start_index * 4` and
MUST fit within the shard-list array, be sorted ascending, and be unique.
Every shard-row index MUST be `< IndexRoot.shard_count`; it selects that
zero-based row in the canonical IndexRoot ShardEntry table. It is not a
`ShardEntry.shard_index` value. Readers MUST perform the multiplication
and addition with checked unsigned 64-bit arithmetic or wider before
indexing.

If `DirectoryHintTable.entry_count = 0`, then `entry_table_offset`,
`shard_list_offset`, `string_pool_offset`, and `string_pool_size` MUST
all be zero and the table contains no usable hint entries. Readers MUST
NOT range-validate absent zero-count tables against the fixed header.
This zero-entry layout is defined only for structural rejection and future
extension safety; a v0.36 DirectoryHintShardEntry in IndexRoot MUST NOT
point at a zero-entry DirectoryHintTable.

Writers MUST split directory hints into multiple DirectoryHintTable
objects before any single directory-hint shard would exceed the FEC
object shard limits in §18, `max_entries_per_directory_hint_shard`, or
reader resource caps. The 64-bit offsets inside DirectoryHintTable are
wire-format fields used to avoid silent overflow in checked arithmetic
and to leave room for future layouts; they do not permit a single FEC
object to exceed §18 or the recorded u32 `decompressed_size`. Values
above the actual plaintext length, above `u32::MAX`, or above reader caps
are malformed even though the fields are u64.
Each DirectoryHintTable object is bounded by the
`index_fec_data_shards` / `index_fec_parity_shards` class maxima and by
the ReedSolomonGF16 65,535-total-shard limit. Writers MUST size and
split directory-hint shards before encryption/FEC so each object fits
those limits.

Directory hints are a directory-subtree accelerator, not a replacement
for the exact path lookup in §15.7. A reader extracting user-supplied
paths MUST first resolve the exact final-view FileEntry for the requested
normalized path. If that exact entry exists and its decoded main tar entry
is not a directory, the request extracts that entry as a file and MUST NOT
use the directory-hint table as though it were an exact-file index for the
same string. If the exact final-view entry is a directory, the reader uses
directory-prefix extraction to find that directory's descendants and
includes the directory entry itself in the default final view. If no exact
entry exists but the caller explicitly requested directory-prefix
semantics, directory hints MAY be used to find descendants of that
directory path; if the required hint is absent or corrupt, the fallback
rules below apply. In the prefix filtering rules below, equality with the
requested directory path means the decoded directory entry itself; regular
files with the same normalized string are found by exact lookup.

Directory-prefix extraction resolves hints with this normative
procedure:

1. Normalize the requested directory path using the rules above, then
   compute `dir_hash = SHA-256(normalized_dir_path)[0..8]`.
2. Binary-search `DirectoryHintShardEntry[]` in IndexRoot with the §15.4
   upper-bound rule applied to `first_dir_hash`: find the first row whose
   `first_dir_hash > dir_hash`; if no row is greater, use the final row
   as the landing candidate; reject if the table is empty, if no
   previous/final landing candidate exists, or if that candidate's
   `last_dir_hash < dir_hash`; otherwise collect the contiguous candidate
   block including the landing row while
   `first_dir_hash ≤ dir_hash ≤ last_dir_hash`, subject to reader caps.
3. For each matching hint shard, read its object-local block extent,
   first verifying `encrypted_size = data_block_count * block_size` with
   checked unsigned 64-bit arithmetic or wider and verifying the counts
   fit the index FEC class limits. Then FEC-repair if needed,
   AEAD-decrypt with `dir_hint_key`, and zstd-decompress without a
   dictionary.
4. Validate the DirectoryHintTable (§15.9), then binary-search
   DirectoryHintEntry records by `(dir_hash, directory_path)`. Resolve
   hash collisions by comparing the actual normalized directory string
   from the hint string pool. If more than one DirectoryHintEntry across
   the candidate hint shards has the exact requested normalized directory
   path, the archive is malformed and the reader MUST reject rather than
   choosing one entry arbitrarily.
5. Use the associated sorted u32 shard-row-index list as the candidate
   IndexShard row set.
6. For each shard-row index, read that zero-based row from the IndexRoot
   ShardEntry table, then use that ShardEntry's stable `shard_index` and
   object-local block extent to read, repair, decrypt, depad, decompress,
   and validate the IndexShard.
7. Verify actual FileEntry paths from each candidate shard before
   extracting or listing.

By default, directory-prefix extraction presents the same final-view
semantics as single-path lookup: after filtering verified FileEntry paths
to rows whose normalized path equals the requested directory path and
whose decoded main tar entry is a directory, or whose normalized path has
that directory path as an ancestor, group rows by normalized path and
select the row with the greatest computed `tar_member_group_start` for
each path.
Tools MAY expose all occurrences in increasing `tar_member_group_start`
order through an explicit history/listing mode, but MUST NOT emit earlier
occurrences as the default view of an overwritten path.

The IndexRoot ShardEntry table is sorted for path-hash lookup, not for
`shard_index` lookup. Readers MAY build an auxiliary `shard_index →
ShardEntry` map after validating IndexRoot; otherwise a linear scan of
the ShardEntry table is conforming.

For ordinary directory-prefix extraction, if required hint shards are
absent, corrupt, or incomplete in an archive that requires them, readers
SHOULD warn and fall back to scanning all shards when resource caps
permit. If caps do not permit a full scan, readers MUST fail clearly
with "directory index unavailable." Full-archive `verify` is stricter:
when `IndexRoot.file_count > directory_hint_required_file_count`, it
MUST reject `directory_hint_shard_count = 0` and MUST reject any missing,
extra, incomplete, duplicate, or misordered hint map (§15.9).

Alphabetical listing still requires sorting verified paths after reading
the candidate shard(s). Directory hints are not a full
path-sorted index and do not by themselves define listing order.

### 15.9 Structural validation

After decrypting and decompressing IndexRoot, an IndexShard, or a
DirectoryHintTable object, readers MUST validate all counts, offsets,
lengths, and table sizes against the actual plaintext buffer before
allocating heap storage or indexing into the buffer. For validation, a
"counted table" means a specific `(count, offset)` or `(size, offset)`
pair such as `file_count/file_table_offset` or
`string_pool_size/string_pool_offset`; the zero-offset exception is
applied per pair, not to the whole structure. A reader MUST reject a
structure if:

- a present table offset points before the fixed header or beyond the
  plaintext;
- a counted table has count/size zero but a non-zero offset, or has a
  non-zero count/size but a zero offset;
- `count × sizeof(entry)` overflows or exceeds the plaintext length;
- any present counted table overlaps another present table, appears out
  of canonical order, leaves an unclaimed gap, or extends past the final
  canonical cursor for that structure;
- any fixed magic field does not exactly match the value defined for its
  structure (`TZIR`, `TZIS`, or `TZDH` for decrypted index objects, and
  the corresponding outer magic values in §§8-12.3 before those outer
  structures are trusted);
- an IndexRoot does not satisfy the IndexRoot cursor rule below;
- an IndexShard does not satisfy the IndexShard cursor rule below;
- a DirectoryHintTable plaintext is not packed exactly as
  `DirectoryHintTable`, present DirectoryHintEntry table, the referenced
  contiguous u32 shard-row-index array, then present string pool, with
  no gaps or overlap;
- `IndexRoot.version != 1`, `IndexShardHeader.version != 1`, or
  `DirectoryHintTable.version != 1`;
- any reserved field or reserved byte range is non-zero;
- `dictionary_data_block_count = 0` while any IndexRoot dictionary field
  is non-zero;
- `CryptoHeader.has_dictionary = 0` while any IndexRoot dictionary field
  is non-zero;
- `CryptoHeader.has_dictionary = 1` while `dictionary_first_block`,
  `dictionary_data_block_count`, `dictionary_encrypted_size`, or
  `dictionary_decompressed_size` is zero;
- dictionary-object fields, directory-hint shard entries, string-pool, or
  shard-list ranges overflow or overlap invalidly;
- any DirectoryHintTable `shard_list_offset` is not 4-byte aligned;
- any DirectoryHintEntry shard list range overflows, or
  `shard_list_start_index + shard_count` exceeds the number of u32 row
  indexes available in the DirectoryHintTable shard-list array;
- any shard-row index referenced by a DirectoryHintEntry is greater than
  or equal to `IndexRoot.shard_count`;
- any DirectoryHintEntry has `shard_count = 0`;
- any `FileEntry.path_length` is zero or exceeds
  `CryptoHeader.max_path_length`;
- `path_offset + path_length` exceeds the owning string pool;
- any FileEntry path string is not valid UTF-8, is not NFC-normalized,
  is unsafe under §16, or has a `path_hash` that does not equal
  `SHA-256(path bytes)[0..8]`;
- any DirectoryHintEntry path string is not valid UTF-8, is not
  NFC-normalized, is unsafe under the directory path rules in §15.8/§16,
  or has a `dir_hash` that does not equal
  `SHA-256(directory_path bytes)[0..8]`;
- any DirectoryHintEntry has `path_length = 0` with non-zero
  `path_offset` or a `dir_hash` other than `SHA-256(b"")[0..8]`, or has
  `path_length > 0` with a string-pool range that does not fit;
- `shard_count`, `directory_hint_shard_count`, `envelope_count`,
  `frame_count`, or `file_count` exceed reader resource caps, including
  `max_shard_count` for IndexShards and
  `max_directory_hint_shards` for directory-hint shards;
- any DirectoryHintTable `entry_count` exceeds
  `max_entries_per_directory_hint_shard`;
- any ShardEntry has `file_count = 0`;
- any DirectoryHintShardEntry has `entry_count = 0`;
- any parsed IndexShard has `file_count = 0`;
- any payload EnvelopeEntry has `frame_count = 0`;
- any FileEntry has `frame_count = 0` or `tar_member_group_size < 512`;
- any object `data_block_count`, `parity_block_count`, or
  `encrypted_size` exceeds the class limits declared in CryptoHeader or
  reader caps;
- any present encrypted object has `data_block_count = 0` or
  `encrypted_size = 0`;
- any payload EnvelopeEntry has `data_block_count >
  CryptoHeader.fec_data_shards` or `parity_block_count >
  CryptoHeader.fec_parity_shards`;
- any ShardEntry or DirectoryHintShardEntry has `data_block_count >
  CryptoHeader.index_fec_data_shards` or `parity_block_count >
  CryptoHeader.index_fec_parity_shards`;
- the IndexRoot object described by ManifestFooter, or the dictionary
  object described by IndexRoot, has `data_block_count >
  CryptoHeader.index_root_fec_data_shards` or `parity_block_count >
  CryptoHeader.index_root_fec_parity_shards`;
- any ReedSolomonGF16 object's actual
  `data_block_count + parity_block_count` exceeds 65,535;
- any IndexShard `file_count` exceeds `max_files_per_index_shard`;
- any encrypted object's `data_block_count * block_size`, computed with
  checked unsigned 64-bit arithmetic or wider, overflows `u32` or does
  not equal its recorded `encrypted_size`;
- any recorded `decompressed_size`, payload `plaintext_size`, frame
  `compressed_size`, or frame `decompressed_size` is inconsistent with
  the actual decompressed/decrypted size or would require more than
  `u32::MAX` bytes;
- any metadata-object zstd payload (IndexRoot, IndexShard, dictionary
  object, or DirectoryHintTable) is not exactly one complete
  non-skippable zstd frame consuming the whole depadded plaintext, or its
  decompressed size differs from the recorded `decompressed_size`;
- any FrameEntry has `compressed_size = 0` or `decompressed_size = 0`;
- any FrameEntry slice fails to parse and decode as exactly one complete
  zstd frame, consumes fewer or more than `compressed_size` bytes, or
  produces a byte count different from `decompressed_size`;
- any FrameEntry has flag bits other than 0 or 1 set.

The IndexRoot cursor rule is:

```
cursor = sizeof(IndexRoot)
if shard_count > 0:
    shard_table_offset MUST equal cursor
    cursor += shard_count * sizeof(ShardEntry)
else:
    shard_table_offset MUST equal 0

if directory_hint_shard_count > 0:
    shard_count MUST be > 0
    directory_hint_shard_table_offset MUST equal cursor
    cursor += directory_hint_shard_count * sizeof(DirectoryHintShardEntry)
else:
    directory_hint_shard_table_offset MUST equal 0

IndexRoot plaintext length MUST equal cursor
```

All additions and multiplications in this rule use checked arithmetic.
The `directory_hint_shard_count > 0 ⇒ shard_count > 0` invariant reflects
that directory hints point to rows in the IndexRoot ShardEntry table;
hint shards without any IndexShards are malformed.

The IndexShard cursor rule is:

```
cursor = sizeof(IndexShardHeader)
if file_count > 0:
    file_table_offset MUST equal cursor
    cursor += file_count * sizeof(FileEntry)
else:
    file_table_offset MUST equal 0

if frame_count > 0:
    frame_table_offset MUST equal cursor
    cursor += frame_count * sizeof(FrameEntry)
else:
    frame_table_offset MUST equal 0

if envelope_count > 0:
    envelope_table_offset MUST equal cursor
    cursor += envelope_count * sizeof(EnvelopeEntry)
else:
    envelope_table_offset MUST equal 0

if string_pool_size > 0:
    string_pool_offset MUST equal cursor
    cursor += string_pool_size
else:
    string_pool_offset MUST equal 0

IndexShard plaintext length MUST equal cursor
```

All additions and multiplications in this rule use checked arithmetic.

For the DirectoryHintTable packed-layout rule, if `entry_count = 0`, the
offset fields and `string_pool_size` MUST be zero and the plaintext
length MUST equal `sizeof(DirectoryHintTable)`. If `entry_count > 0`, the
referenced u32 shard-row-index array length is the smallest byte length
that covers every `DirectoryHintEntry.shard_list_start_index +
shard_count` range. Readers compute each range end and the resulting
byte length with checked unsigned 64-bit arithmetic or wider, including
the multiplication by 4, and MUST reject if the result exceeds the
plaintext length or host indexing limits. In that case
`entry_table_offset` MUST equal `sizeof(DirectoryHintTable)` and
`shard_list_offset` MUST equal the end of the entry table. If
`string_pool_size > 0`, `string_pool_offset` MUST equal the end of that
computed shard-row-index array; otherwise `string_pool_offset` MUST be
zero and the final cursor is the end of the shard-row-index array.
DirectoryHintTable plaintext length MUST equal the applicable final
cursor.

Readers MUST also validate cross-table references before decoding:

- ShardEntry records are sorted as required by §15.4, with
  `last_path_hash ≤ next.first_path_hash` for adjacent entries; if the
  boundary hashes are equal, readers use the §15.4 candidate-block rule,
  but `last_path_hash > next.first_path_hash` is malformed;
- ShardEntry `shard_index` values are unique across the IndexRoot
  ShardEntry table;
- every loaded IndexShardHeader `file_count` equals the locating
  ShardEntry `file_count`;
- every loaded IndexShard FileEntry table is sorted by
  `(path_hash, normalized path bytes, tar_member_group_start)`, contains
  no duplicate full sort key, and has no row whose `path_hash` falls
  outside the locating ShardEntry's closed
  `first_path_hash .. last_path_hash` interval;
- every loaded IndexShard's first and last FileEntry `path_hash` values
  equal the locating ShardEntry's `first_path_hash` and `last_path_hash`
  respectively;
- DirectoryHintShardEntry records are sorted as required by §15.8, with
  `last_dir_hash ≤ next.first_dir_hash` for adjacent entries; if the
  boundary hashes are equal, readers use the §15.8 candidate-block rule,
  but `last_dir_hash > next.first_dir_hash` is malformed;
- DirectoryHintShardEntry `hint_shard_index` values are unique across the
  IndexRoot DirectoryHintShardEntry table;
- every ShardEntry, EnvelopeEntry, FrameEntry, and FileEntry referenced
  by another table exists;
- every IndexShard-local EnvelopeEntry table is sorted by
  `envelope_index`, contains no duplicate `envelope_index` values, and
  contains exactly the envelope rows required by its local FrameEntry
  references; local EnvelopeEntry tables may be sparse subsets of the
  global payload envelope sequence;
- an IndexShardHeader's `shard_index` does not match the ShardEntry used
  to locate that shard object;
- a DirectoryHintTable's `hint_shard_index` does not match the
  DirectoryHintShardEntry used to locate that directory-hint object;
- a DirectoryHintShardEntry's `entry_count` does not match the decoded
  DirectoryHintTable's `entry_count`, or the decoded table is empty;
- a decoded DirectoryHintTable's DirectoryHintEntry rows are not sorted by
  `(dir_hash, normalized directory path bytes)`, contain duplicate exact
  directory paths, or have first/last `dir_hash` values that do not match
  the locating DirectoryHintShardEntry's `first_dir_hash` and
  `last_dir_hash`;
- the same normalized directory path appears in more than one loaded
  DirectoryHintEntry row. Full-archive `verify` MUST reject any duplicate
  DirectoryHintEntry path globally.
- each IndexShard's local FrameEntry table is not sorted by
  `frame_index`, contains duplicate `frame_index` values, contains any
  frame not referenced by that shard's FileEntry ranges, or omits any
  frame referenced by those ranges;
- each IndexShard's local EnvelopeEntry table is not the exact sorted
  unique set of envelopes referenced by that shard's local FrameEntry
  table;
- every local FrameEntry references an EnvelopeEntry in the owning
  IndexShard's local EnvelopeEntry table, has the same `envelope_index`
  as that row, and has a `frame_index` inside the EnvelopeEntry's global
  range `first_frame_index .. first_frame_index + frame_count`, with the
  range end computed using checked unsigned 64-bit arithmetic or wider;
- `FrameEntry.offset_in_envelope + compressed_size` is within
  `EnvelopeEntry.plaintext_size`, computed with checked unsigned
  arithmetic;
- local FrameEntry slices belonging to the same EnvelopeEntry, ordered by
  `offset_in_envelope`, do not overlap each other. Gaps are valid during
  shard-local validation because unrelated frames in the same envelope
  may belong only to other IndexShards. Readers MUST NOT require a
  shard-local FrameEntry table to cover the whole
  `[0, EnvelopeEntry.plaintext_size)` range unless that local table
  actually contains every global frame in the EnvelopeEntry's declared
  frame range;
- if an IndexShard-local FrameEntry table does contain every global frame
  in a payload EnvelopeEntry's declared frame range, the sum of
  `compressed_size` for those rows must equal
  `EnvelopeEntry.plaintext_size`, and those slices ordered by
  `offset_in_envelope` must cover `[0, EnvelopeEntry.plaintext_size)`
  exactly once without gaps or overlap;
- `EnvelopeEntry.encrypted_size = data_block_count × block_size`;
- after AEAD decryption and suffix depadding, the depadded envelope
  plaintext length equals `EnvelopeEntry.plaintext_size`;
- every payload `EnvelopeEntry.frame_count` is at least 1 and
  `plaintext_size` is greater than 0;
- every payload envelope contains complete FrameEntry records only; no
  zero-length, padding-only, or frame-less payload envelope is valid;
- every global frame index in
  `FileEntry.first_frame_index .. first_frame_index + frame_count`
  exists in the owning IndexShard's local FrameEntry table, with the
  range end computed using checked unsigned 64-bit arithmetic or wider;
- every FileEntry's computed `tar_member_group_start` fits in u64, and
  FileEntry rows with identical `(path_hash, normalized path bytes)` are
  ordered by strictly increasing `tar_member_group_start`;
- `offset_in_first_frame_plaintext` is strictly less than the first
  frame's `decompressed_size`;
- `tar_member_group_size` fits within the concatenated decoded bytes
  from the FileEntry frame range after applying
  `offset_in_first_frame_plaintext`;
- the FileEntry frame range is minimal: for `frame_count = 1`, the tar
  member group fits in the first referenced frame after
  `offset_in_first_frame_plaintext`; for `frame_count > 1`, the tar
  member group's final byte falls inside the final referenced FrameEntry
  and not before it. Readers MUST reject ranges that include unused
  trailing FrameEntry rows for that FileEntry;
- whenever a FileEntry tar member group is decoded, the main tar entry's
  normalized archive path matches the FileEntry path string,
  `file_data_size` matches the logical payload size declared by the main
  tar entry after supported PAX/GNU size metadata is applied, and
  `file_data_size` is zero for non-regular entries;
- local frame `tar_stream_offset` values increase with `frame_index`;
  when two adjacent local FrameEntry rows have consecutive `frame_index`
  values, the latter offset equals the previous row's
  `tar_stream_offset + decompressed_size`; when there is a frame-index
  gap, the latter offset must be greater than the previous row's end, and
  full-archive `verify` checks exact global tar-stream coverage;
- when the same `frame_index` or `envelope_index` appears in more than
  one loaded IndexShard local table, every defined field in the
  duplicated FrameEntry or EnvelopeEntry row MUST match. Because all
  reserved fields are separately required to be zero in this format
  version, this is equivalent to byte-identical row encoding in v0.36.
  Readers MUST reject on mismatch. A full-archive `verify` operation
  MUST check this globally across all IndexShards.
- in full-archive `verify`, `IndexRoot.payload_block_count` MUST equal
  the sum of `EnvelopeEntry.data_block_count` over all distinct payload
  envelopes observed across shard-local EnvelopeEntry tables;
- in full-archive `verify`, `IndexRoot.file_count` MUST equal both the
  sum of `ShardEntry.file_count` values and the total FileEntry rows
  decoded from all IndexShards;
- in full-archive `verify`, `IndexRoot.frame_count` MUST equal the count
  of distinct global FrameEntry rows, and the distinct `frame_index`
  values MUST cover `[0, frame_count)` with no gaps;
- in full-archive `verify`, `IndexRoot.envelope_count` MUST equal the
  count of distinct global EnvelopeEntry rows, and the distinct
  `envelope_index` values MUST cover `[0, envelope_count)` with no gaps;
- in full-archive `verify`, for every distinct payload EnvelopeEntry, all
  global frame indexes in
  `EnvelopeEntry.first_frame_index .. first_frame_index + frame_count`
  MUST exist in the distinct global FrameEntry set, MUST have matching
  `envelope_index`, and their slices ordered by `offset_in_envelope` MUST
  cover `[0, EnvelopeEntry.plaintext_size)` exactly once without gaps or
  overlap;
- in full-archive `verify`, all encrypted-object extents described by
  ManifestFooter, IndexRoot dictionary fields, ShardEntry rows,
  DirectoryHintShardEntry rows, and distinct EnvelopeEntry rows MUST be
  non-overlapping unless duplicate records describe the same object with
  identical object class, identity counter, block range, data/parity
  counts, and encrypted size;
- in full-archive `verify`, distinct FrameEntry rows sorted by
  `tar_stream_offset` MUST cover the half-open range
  `[0, IndexRoot.tar_total_size)` exactly once, with no gap or overlap;
  equivalently, each frame starts at the previous frame's end and the
  final end equals `IndexRoot.tar_total_size`. Empty archives have no
  payload frames and MUST use `tar_total_size = 0`;
- in full-archive `verify`, readers MUST reconstruct the exact tar
  stream bytes by zstd-decompressing each distinct payload frame and
  ordering the decoded bytes by `tar_stream_offset`; the SHA-256 of that
  reconstructed byte stream MUST equal `IndexRoot.content_sha256`.
- in full-archive `verify`, readers MUST parse the reconstructed tzap
  tar stream into tar member groups according to §6.2 and the supported
  metadata profiles in §16. Distinct FileEntry rows sorted by computed
  `tar_member_group_start` MUST match that parsed tar member group
  sequence exactly: each FileEntry start and `tar_member_group_size` MUST
  equal the parsed group's half-open byte range, the FileEntry path MUST
  equal the normalized main tar entry path, and `file_data_size` MUST
  equal the parsed main entry's logical payload size (or zero for
  non-regular entries). Missing FileEntries, extra FileEntries, duplicate
  FileEntry extents, gaps, overlaps, or path/size mismatches are
  malformed.
- in full-archive `verify`, if `directory_hint_shard_count > 0`, readers
  MUST recompute the complete directory-hint map from all validated
  FileEntry rows and IndexRoot ShardEntry row positions. The recomputed
  map contains the root directory, every normalized ancestor directory of
  every FileEntry path, and every FileEntry path whose decoded main tar
  entry is itself a directory. Each value is the exact sorted unique set
  of ShardEntry row indexes whose shard contains at least one FileEntry
  whose normalized path equals that directory path or has that directory
  path as an ancestor. Readers MUST reject missing
  DirectoryHintEntry rows, extra DirectoryHintEntry rows, omitted shard
  rows, added shard rows, duplicate shard rows, or ordering mismatches.
- in full-archive `verify`, if
  `IndexRoot.file_count > directory_hint_required_file_count`, readers
  MUST reject `directory_hint_shard_count = 0` before reporting the
  archive as writer-conformant. If ordinary extraction falls back to a
  full shard scan for such an archive, that fallback does not make the
  archive pass `verify`.
- in full-archive `verify`, if identical normalized FileEntry paths
  appear in more than one IndexShard, their combined rows sorted by
  `(path_hash, normalized path bytes, tar_member_group_start)` MUST be in
  the same order as the global file table, with strictly increasing
  `tar_member_group_start` for that exact path.

---

## 16. File Metadata Handling

Metadata preservation is profile-based, not magic. The baseline archive
profile is POSIX ustar: path, type, mode, uid/gid, size, mtime, symlink
targets, and hardlink targets that fit ustar limits. A writer that
claims xattrs, ACLs, sparse files, long paths, non-ASCII names, or
nanosecond timestamps MUST emit the corresponding PAX or GNU tar
extension records inside the same tar member group as the main entry.

The tzap format does not duplicate per-file metadata outside the
encrypted zstd/tar stream. Readers delegate metadata application to a tar
library, but conformance claims MUST name the tar extension profile they
support. A reader that does not support an extension profile may still
extract file contents but MUST report that metadata fidelity is degraded.
CLI readers MUST write this warning to stderr. Library readers MUST
surface it through their diagnostics/error channel; library diagnostics
SHOULD be structured and include unsupported extension/profile
identifiers when available. Unsupported PAX/GNU extension records, failed
xattr/ACL application, timestamp precision loss, sparse-file fallback,
and ownership/mode application failures MUST be reported unless the user
explicitly requested best-effort quiet mode.

Recommended profile identifiers for diagnostics and conformance strings
are: `ustar-baseline`, `pax-posix-2001`, `gnu-longname`,
`pax-xattrs-acls`, and `gnu-sparse`. Implementations MAY expose more
specific local profile names, but they SHOULD map them to these baseline
identifiers when reporting unsupported metadata.

The encrypted tzap tar stream contains only path-specific tar member
groups. Writers MUST NOT emit global PAX headers, global GNU state, or
any other non-path-specific tar metadata record whose semantics affect
later unrelated entries. Readers MUST reject such records during
extraction or full-archive verification rather than carrying mutable
global tar state across FileEntry boundaries. Path-specific PAX extended
headers, GNU long name/link records, sparse metadata records, and other
supported extension records are valid only when they are immediately
associated with the following main tar entry in the same tar member
group and do not define state for later groups.

Path validation (no `..`, no leading `/`, no escape via symlinks) is
performed by the extractor at write and read time. Writers MUST NOT emit
archive paths with absolute paths, `..` components, empty components, NUL
bytes, platform-specific escape forms, or platform-native directory
separators standing in for `/`. The archive path separator is always the
literal `/` byte. Readers MUST still validate and reject unsafe paths
because archives may be malicious or non-conforming.

FileEntry path strings are canonical archive paths and MUST NOT contain
a trailing slash. When decoding a tar main entry for FileEntry binding,
directory-hint derivation, or extraction planning, readers first apply
the supported PAX/GNU path metadata for that tar member group. If the
main entry is a directory and the resulting tar path has exactly one
trailing `/`, that single trailing slash is treated as the conventional
tar directory marker and is removed before UTF-8/NFC validation,
FileEntry path comparison, and directory-hint map construction. Writers
SHOULD emit directory main-entry names without the trailing marker, but
MAY rely on a tar library that writes this one conventional directory
slash. Any other trailing slash, doubled slash, interior empty component,
or slash on a non-directory main entry remains an empty component and is
malformed under the normal path-safety rules.

The platform-escape rejection set is host-independent in this draft so
that readers do not diverge by operating system. Writers MUST NOT emit,
and default conforming readers MUST reject before filesystem creation,
any FileEntry path or hardlink target that:

- contains a backslash byte (`0x5C`) anywhere;
- contains a colon byte (`0x3A`) anywhere;
- begins with `/`, `//`, `\\`, `\\?\`, or `\\.\`;
- has a first component matching an ASCII drive designator such as
  `C:` or `z:`;
- has any component that is empty, `.`, or `..`;
- has any component whose Windows device-name stem is `CON`, `PRN`,
  `AUX`, `NUL`, `CLOCK$`, `COM1` through `COM9`, `COM¹` through
  `COM³`, `LPT1` through `LPT9`, or `LPT¹` through `LPT³`, compared
  ASCII-case-insensitively after stripping any suffix beginning at `.`
  and after stripping trailing spaces and dots.

The colon ban intentionally rejects NTFS alternate data streams and
drive-relative paths even on non-Windows hosts. Implementations MAY offer
an explicit unsafe/expert extraction mode that preserves such names on a
host that can represent them safely, but that mode is outside default
conformance and MUST be opt-in with diagnostics.

Safe extraction is part of conformance, not a tar-library accident.
Before creating or replacing any host filesystem object, readers MUST
resolve the destination relative to the selected extraction root using
no-follow ancestry checks: every existing parent component must be a
directory that is still inside the extraction root and must not be a
symlink or other reparse/alias object that would redirect later writes
outside that root. The final path component may be a symlink only when
the current tar member being restored is itself a symlink; readers MUST
NOT follow an existing final symlink when writing a regular file,
directory, hardlink, device, FIFO, or metadata update.

Hardlink targets are archive-internal path references. Writers MUST emit
hardlink target names using the same normalized relative path rules as
FileEntry paths, and readers MUST reject hardlink targets that are
absolute, empty, contain `..` or empty components, contain NUL bytes, use
platform-native separators as directory separators, violate the
platform-escape rejection set above, or resolve outside the extraction
root. If a hardlink target has not already been restored or cannot be
resolved safely inside the extraction root, readers MUST reject the
hardlink or materialize it only in an explicitly requested best-effort
mode that reports degraded metadata fidelity.

Default conforming readers MUST resolve hardlink targets with the same
no-follow ancestry checks used for extraction destinations. They MUST
NOT follow symlinks, reparse points, bind mounts, or other aliasing
objects while validating the target. In default mode, a hardlink target
MUST name an already-restored non-directory regular-file object inside
the extraction root; hardlinks to directories, symlinks, devices, FIFOs,
sockets, missing paths, or targets whose type cannot be verified safely
MUST be rejected or materialized only in an explicitly requested
best-effort/unsafe mode with diagnostics. This rule is intentionally more
restrictive than some tar implementations so conforming extractors do not
diverge on host-specific hardlink-to-symlink behavior.

Symlink target bytes are preserved as tar metadata, but readers MUST NOT
use a symlink target to authorize later path traversal. Creating an
absolute symlink or a relative symlink whose normalized resolution from
its containing directory escapes the extraction root is allowed only
under an explicit unsafe/expert extraction option; the default
conforming extractor MUST skip or reject that symlink with a diagnostic.
Regardless of whether such a symlink is created, later archive members
MUST still pass the no-follow ancestry checks above.

---

## 17. Read Algorithm

### 17.1 Open

```
1. Read VolumeHeader at offset 0; verify CRC.
   Reject if `magic != b"TZAP"`, `format_version != 1`, or
   `volume_format_rev` is greater than the newest revision implemented
   by the reader. A reader claiming only v0.36 conformance rejects
   `volume_format_rev != 36`. Reject if `VolumeHeader.stripe_width = 0`
   or `VolumeHeader.volume_index >= VolumeHeader.stripe_width`, or if
   `crypto_header_offset != sizeof(VolumeHeader)`.
2. Validate `crypto_header_length` against the volume/stream bounds and
   reader caps; reject if the canonical CryptoHeader byte range
   `sizeof(VolumeHeader) .. sizeof(VolumeHeader) + crypto_header_length`
   exceeds available bytes on seekable input or requires an allocation
   over caps. Then read CryptoHeader. Reject this CryptoHeader copy
   before KDF if `CryptoHeaderFixed.magic != b"TZCH"`, if
   `CryptoHeaderFixed.length != VolumeHeader.crypto_header_length`, if
   `CryptoHeader.stripe_width = 0`, or if `CryptoHeader.stripe_width !=
   VolumeHeader.stripe_width`; try another volume's CryptoHeader copy if
   one is available.
3. Reject unknown `compression_algo`, `aead_algo`, `fec_algo`, or
   `kdf_algo` values before selecting any algorithm-specific parser.
   Reject `compression_algo != ZstdFramed`,
   `fec_algo != ReedSolomonGF16`, invalid boolean `has_dictionary`,
   `volume_loss_tolerance >= stripe_width`, `bit_rot_buffer_pct > 100`,
   zero data-shard class maxima, `chunk_size = 0`,
   `envelope_target_size = 0`, `chunk_size > envelope_target_size`,
   `block_size < 4096`, odd `block_size`, or any header parameter above
   its active reader-side cap in v0.36. Parse KdfParams only after `kdf_algo` is
   known and supported; prompt for passphrase or load keyfile. If
   `kdf_algo == Raw`, first verify that the two-byte raw KdfParams
   payload fits before `length - 32` and reject unless its `algo_tag` is
   exactly `0`. If `kdf_algo == Argon2id`, first verify that the 16-byte
   fixed Argon2id KdfParams prefix fits, reject unless its `algo_tag` is
   exactly `1`, then reject if `t_cost`, `m_cost_kib`, `parallelism`, or
   `salt_length` exceed reader caps or if `salt_length` is outside
   8..64 bytes, `t_cost = 0`, `parallelism = 0`,
   `m_cost_kib < 8 × parallelism`, or the full `16 + salt_length`
   KdfParams payload does not fit before
   `length - 32`. Structurally scan Extension TLVs for bounded headers,
   `length ≤ 256`, valid terminator encoding, and no bytes between the
   terminator and `header_hmac`.
4. Run KDF → master_key. Derive mac_key using the archive UUID and
   session ID from VolumeHeader (§13.2). Verify CryptoHeader HMAC,
   including the VolumeHeader UUID/session binding (§9).
   On failure: try another volume's CryptoHeader copy. If all fail under
   the same key: abort "wrong key or all CryptoHeader copies corrupt."
   After HMAC succeeds, interpret Extension semantics. Reject forbidden
   tags `0x0004` and `0x0006`, duplicate known tags, malformed known
   extension values, and unknown critical extensions. Ignore unknown
   non-critical extensions.
5. Derive enc_key, nonce_seed, index_root_key, index_shard_key,
   dictionary_key, dir_hint_key, and index_nonce_seed.
6. If the input is seekable:
     a. Determine file size of an available volume (OS stat / Content-Length).
     b. If file_size < sizeof(VolumeHeader) + sizeof(VolumeTrailer),
        reject the volume as malformed before seeking. Otherwise seek to
        file_size − 128; read VolumeTrailer. This early check is a
        seek-underflow guard only; later CryptoHeader, ManifestFooter,
        and block range checks reject volumes that are physically large
        enough to hold a trailer but too small to hold a valid archive.
     c. Verify trailer magic and trailer HMAC. If the candidate at
        `file_size - sizeof(VolumeTrailer)` fails and the reader supports
        trailing-garbage recovery, it MAY scan backward from that offset
        for at most `max_trailing_garbage_scan` bytes (§13.3), checking
        only candidate `TZVT` positions by verifying the full trailer
        HMAC. The nearest authenticated candidate to end-of-file wins. If
        no authenticated candidate is found, this volume is tampered or
        truncated; try another volume. Verify that the authenticated
        trailer `archive_uuid`, `session_id`, and `volume_index` match
        the VolumeHeader, and that `bytes_written` equals the selected
        trailer offset, not necessarily `file_size -
        sizeof(VolumeTrailer)` when trailing garbage was tolerated. On
        mismatch, reject this volume without attempting object
        decryption. Bytes after the selected trailer are ignored only for
        this recovery path and SHOULD produce a diagnostic.
     d. Range-check `manifest_footer_offset` and
        `manifest_footer_length` against the volume size and reader caps
        before seeking or allocating. `manifest_footer_length` MUST equal
        `sizeof(ManifestFooter)`. Verify that
        `manifest_footer_offset` equals
        `crypto_header_offset + crypto_header_length +
        block_count * sizeof(BlockRecord)` using checked unsigned
        64-bit arithmetic or wider, and that this product does not
        exceed the selected trailer offset. This is the required
        `block_count` consistency check even when trailing-garbage
        recovery selected a trailer before physical EOF: the physically
        present BlockRecord region for the selected archive image is
        exactly the byte range from `crypto_header_offset +
        crypto_header_length` up to, but not including,
        `manifest_footer_offset`. Verify that
        `manifest_footer_offset + manifest_footer_length` equals the
        selected trailer offset, also with checked unsigned
        64-bit-or-wider arithmetic. Then read ManifestFooter and verify
        HMAC. Verify that ManifestFooter `archive_uuid`,
        `session_id`, and `volume_index` match both the authenticated
        trailer and the VolumeHeader. Verify
        `ManifestFooter.total_volumes == CryptoHeader.stripe_width ==
        VolumeHeader.stripe_width` and that the value is non-zero; reject
        on mismatch. Verify
        `ManifestFooter.index_root_encrypted_size =
        ManifestFooter.index_root_data_block_count * block_size` with
        checked unsigned 64-bit arithmetic or wider, and verify both
        fields are non-zero, before using the IndexRoot extent.
     e. If ManifestFooter.is_authoritative = 0, this volume is not a
        random-access bootstrap source. Try another volume, use a
        trusted bootstrap sidecar under the sidecar rules in step 7a, or
        enter sequential recovery mode.
     f. When opening multiple supplied volumes, reject the set if two
        accepted volumes have the same authenticated `volume_index`, or
        if any authenticated `volume_index >= stripe_width`, unless an
        explicit duplicate-copy recovery mode validates the duplicate
        copies as byte-for-byte identical for the requested operation.
7. If the input is non-seekable:
     a. If a trusted bootstrap sidecar is supplied, use it for
        ManifestFooter and IndexRoot bootstrap only when sidecar flag
        bits 0 and 1 are set and both sections verify. First verify the
        sidecar HMAC and the sidecar ManifestFooter HMAC. For a
        ManifestFooter obtained from a sidecar, verify `archive_uuid`,
        `session_id`, and `total_volumes == CryptoHeader.stripe_width`;
        require `volume_index = 0` and `is_authoritative = 1` for the
        sidecar copy, but do not compare that zero volume index with the
        current VolumeHeader because the sidecar is not a volume. Also
        verify `index_root_encrypted_size =
        index_root_data_block_count * block_size` with checked unsigned
        64-bit arithmetic or wider, and verify both fields are non-zero,
        before using the IndexRoot extent.
        Then verify the IndexRoot BlockRecord section exactly matches
        that extent, repair if needed, decrypt, depad, decompress, and
        validate IndexRoot. If `has_dictionary = 1`, the sidecar MUST
        also set flag bit 2 and the dictionary BlockRecord section MUST
        verify against the authenticated IndexRoot dictionary extent
        before payload decompression.
     b. Otherwise enter sequential extraction mode (§17.3). Random access,
        listing, and directory-prefix extraction are unavailable.
8. If has_dictionary = 1 in CryptoHeader: defer loading until step 11.
```

### 17.2 Random extract

```
9. Read IndexRoot data and parity blocks using
   ManifestFooter.index_root_first_block,
   index_root_data_block_count, and index_root_parity_block_count.
   Before fetching or repairing, verify again that
   `index_root_encrypted_size = index_root_data_block_count *
   block_size` with checked unsigned 64-bit arithmetic or wider and that
   both fields are non-zero.
   FEC-repair, trim to index_root_encrypted_size, AEAD-decrypt with
   index_root_key, strip suffix padding, and zstd-decompress
   (no dictionary).
10. Validate IndexRoot structure (§15.9); extract the shard table,
    optional directory-hint shard table, and optional dictionary object
    extent.
11. If has_dictionary = 1: read the dictionary object blocks from the
    IndexRoot dictionary extent. Before fetching or repairing, verify
    `dictionary_encrypted_size = dictionary_data_block_count *
    block_size` with checked unsigned 64-bit arithmetic or wider and
    verify dictionary data/parity counts fit the IndexRoot FEC class
    limits. Then repair, trim, AEAD-decrypt with `dictionary_key` using
    domain `dict`, strip suffix padding, and zstd-decompress
    (no dictionary). Initialize the payload zstd decompression context
    with those bytes.
12. Normalize target_path under §15.6/§16, then compute
    `target_hash = SHA-256(normalized_target_path)[0..8]`.
13. Binary search ShardEntry with the §15.4 upper-bound rule to produce
    the complete bounded candidate-shard block.
14. Read candidate shard data/parity blocks using each ShardEntry's
    object-local FEC counts. Before fetching or repairing each shard,
    verify `encrypted_size = data_block_count * block_size` with checked
    unsigned 64-bit arithmetic or wider and verify the counts fit the
    index-shard FEC class limits. Then repair, trim to encrypted_size,
    AEAD-decrypt with index_shard_key, strip suffix padding, and
    zstd-decompress (no dictionary).
15. Validate each IndexShard structure (§15.9), including that
    `IndexShardHeader.shard_index` matches the locating ShardEntry.
16. Binary search FileEntry by `(path_hash, normalized path bytes)`;
    resolve hash collisions via string compare and duplicate exact paths
    by selecting the greatest computed `tar_member_group_start`; get
    (first_frame_index, frame_count, offset_in_first_frame_plaintext,
    tar_member_group_size).
17. Read the FrameEntry range from the same IndexShard's local frame
    table, validate that the range is the minimal ordered frame extent
    containing the FileEntry tar member group under §15.6, and collect the
    unique EnvelopeEntry records from that shard's local envelope table.
18. For each needed envelope, read its data and parity blocks using the
    EnvelopeEntry object-local FEC counts. Before fetching or repairing,
    verify `encrypted_size = data_block_count * block_size` with checked
    unsigned 64-bit arithmetic or wider and verify the counts fit the
    payload-envelope FEC class limits. Then repair if needed, trim to
    encrypted_size, AEAD-decrypt with enc_key, and strip suffix padding.
    Verify the depadded plaintext length equals
    `EnvelopeEntry.plaintext_size`; reject before slicing if it differs.
19. Slice and zstd-decode each complete compressed frame from its
    containing envelope. Each slice MUST decode as exactly one zstd frame
    consuming the full `FrameEntry.compressed_size` and producing exactly
    `FrameEntry.decompressed_size` bytes; otherwise reject before using
    decoded bytes. Concatenate decoded frame plaintexts in order, skip
    offset_in_first_frame_plaintext bytes from the first frame, and
    stream exactly tar_member_group_size bytes to a tar library. Compare
    the main tar entry's normalized archive path with the FileEntry path
    string and compare the main tar entry's logical payload size with
    `FileEntry.file_data_size` before writing file payload bytes, applying
    metadata, or reporting the path/size as content-verified. If the tar
    consumer requires a POSIX end-of-archive marker, append two synthetic
    512-byte zero blocks after the selected tar member group bytes; do not
    count those bytes in any IndexRoot or FileEntry size/hash field.
```

### 17.3 Sequential extract

Sequential extraction does not use IndexRoot to locate payload
envelopes. Starting from a VolumeHeader and CryptoHeader, the reader
streams payload BlockRecords in global block order. For each payload
envelope, it collects consecutive kind-0 data BlockRecords until the one
with the last-data flag set. It then collects the immediately following
consecutive kind-1 parity BlockRecords, if any, until the next kind-0
payload-data block, a metadata BlockRecord kind (2 through 9), or a
non-`TZBK` boundary. That observed kind-1 run is the inferred parity set
for the current envelope. The inferred parity count MUST be ≤
`CryptoHeader.fec_parity_shards`; otherwise the stream is malformed. If
repair is requested or a data block was missing/CRC-failed, the reader
uses the collected data/parity set for FEC repair before AEAD
verification. If no repair is needed, the reader MAY skip parity payload
bytes after validating BlockRecord framing, CRC, kind, flags, and block
ordering.
When the archive parameters do not guarantee at least one payload parity
BlockRecord for every payload envelope, any CRC failure in a payload-data
BlockRecord before the current envelope has authenticated is immediately
unrecoverable in pure sequential mode. This includes
`CryptoHeader.fec_parity_shards = 0` and any `volume_loss_tolerance = 0`
/ `bit_rot_buffer_pct = 0` archive where per-object payload parity may
be absent. The failed block might have carried the last-data flag, and
the reader has no authenticated EnvelopeEntry extent to re-establish the
boundary. In that case the reader MUST abort sequential extraction before
consuming later payload blocks as part of the current envelope.
In v0.36, archive parameters guarantee at least one payload parity
BlockRecord for every non-empty payload envelope only when
`volume_loss_tolerance > 0` or `bit_rot_buffer_pct > 0`, and
`fec_parity_shards > 0`; under §27, conforming writers then compute a
per-envelope `parity_block_count ≥ 1`.

Sequential output is provisional until the terminal ManifestFooter and
VolumeTrailer authenticate. A reader that writes to a filesystem in
default conforming mode MUST stage output in a temporary/quarantine
location, or otherwise make it non-final, until the terminal material
has verified. It MUST NOT replace existing files, report success, or
present the result as a clean extraction before that point. A live
stdout or library streaming API MAY deliver bytes after each payload
envelope AEAD verifies, but it MUST document and signal that those bytes
are provisional until terminal authentication succeeds; an explicit
best-effort/unsafe mode is required to keep or treat them as final after
terminal authentication fails.

The reader verifies each complete envelope with the current
`next_envelope_index` counter and strips suffix padding. Because
sequential mode has no FrameEntry table, the depadded envelope plaintext
itself is parsed as a concatenated zstd-frame stream: starting at offset
0, the reader MUST decode exactly one complete zstd frame, advance by
the compressed byte count consumed by that frame, emit that frame's
decompressed bytes to the tar stream, and repeat until the envelope
plaintext is fully consumed. A zstd failure, a truncated frame, a frame
decoder that consumes zero bytes, or any trailing non-frame bytes before
the end of the depadded envelope plaintext is a hard archive error.
Sequential readers MUST NOT infer tar member boundaries from zstd frame
boundaries; the tar library consumes the resulting byte stream.
In a single-volume stream, the reader continues the BlockRecord scan
while the next 4 bytes are `TZBK`. A truncated partial BlockRecord is
malformed unless an explicit recovery mode can repair the affected
object. BlockRecords of kinds 2 through 9 may appear after all payload
blocks in the same stream; the first metadata BlockRecord closes the
payload phase for sequential extraction. A sequential extractor that is
not bootstrapping metadata MUST validate metadata BlockRecord
framing/CRC and skip them, not treat their presence as an
envelope-counter event or as an abort condition. If a kind-0 or kind-1
payload BlockRecord appears after a metadata BlockRecord has been
observed, the stream is malformed.
`next_envelope_index` starts at 0 and increments exactly once after each
complete payload envelope authenticates. Payload-parity BlockRecords do
not increment this counter. Metadata objects (kinds 2 through 9) use
their own AEAD domains/counters and do not affect the payload envelope
counter.
If any BlockRecord at a position where the reader expects a
payload-data block for the current envelope fails CRC, the reader MUST
treat that block as an erasure. Because a CRC-failed block's `kind` and
`flags` are not trustworthy, the reader MUST NOT identify envelope-end
position by inspecting that block. A pure sequential reader MAY continue
past that erasure only when the archive parameters guarantee at least one
payload parity BlockRecord for every payload envelope. In that case,
encountering a valid kind-1 block before another kind-0 block starts the
tentative parity run for the current envelope; encountering another
kind-0 block before any kind-1 block means the boundary is still
ambiguous and the reader MUST abort rather than absorb a possible next
envelope. While collecting a tentative parity run, the reader MUST NOT
release bytes, advance `next_envelope_index`, or begin a later envelope
until the current envelope has been reconstructed and authenticated. If
FEC parity cannot reconstruct enough data blocks for the current envelope
to authenticate, the reader MUST abort sequential extraction at that
envelope. It MUST NOT guess the envelope boundary.
After any irrecoverable envelope boundary, CRC, FEC, AEAD, depadding, or
zstd failure, the reader MUST NOT attempt to decrypt later payload
envelopes by guessing a replacement counter or boundary; the sequential
stream is unrecoverable from that point except under an explicit recovery
mode that reconstructs the failed envelope first.

A non-`TZBK` boundary or end-of-stream is not proof of a clean archive
end. For a clean v0.36 core volume, after the reader has skipped any
post-payload metadata BlockRecords, the terminal bytes MUST parse as a
ManifestFooter followed by a VolumeTrailer and both HMACs MUST verify
against the current VolumeHeader/CryptoHeader identity. The
ManifestFooter and VolumeTrailer MUST also cross-check as in §17.1:
matching UUID/session/volume identity, `manifest_footer_offset` equal to
the observed ManifestFooter offset, `manifest_footer_length =
sizeof(ManifestFooter)`, and `bytes_written` equal to the observed
VolumeTrailer offset. `manifest_footer_offset + manifest_footer_length`
MUST equal that VolumeTrailer offset. `block_count` MUST equal the number
of complete BlockRecords observed in that volume before the
ManifestFooter. The terminal ManifestFooter MUST have
`is_authoritative = 1`; `is_authoritative = 0` is not a clean archive
completion signal. If the non-`TZBK` bytes do not form authenticated
terminal material, if the terminal ManifestFooter is not authoritative,
or if the stream ends before authenticated terminal material, the reader
MUST report unexpected EOF/tamper and MUST NOT
append synthetic POSIX end-of-archive blocks or report a clean
extraction. An explicit best-effort recovery mode MAY expose already
authenticated file bytes with a diagnostic, but it still MUST NOT use a
synthetic marker to hide the unauthenticated end.

Only after authenticated terminal material has verified may readers that
feed the decoded stream to a strict tar consumer append two synthetic
512-byte zero blocks. These bytes are not archive content and are not
included in `tar_total_size` or `content_sha256`.

For non-seekable single-volume input, this is the required fallback when
no bootstrap sidecar is available and `has_dictionary = 0`. If
`has_dictionary = 1`, the reader needs authenticated dictionary material
before decompressing payload frames. Without a bootstrap sidecar that
provides an authenticated encrypted IndexRoot copy that locates the
dictionary object and an authenticated encrypted dictionary-object copy
that supplies the dictionary bytes, the reader MUST reject with
"dictionary bootstrap required." If the payload stream is already flowing
before the sidecar is available, the reader MUST buffer encrypted
envelope bytes until the dictionary is recovered or reject; it MUST NOT
attempt dictionary-less decompression.

For multi-volume striped archives, a non-seekable sequential reader must
receive all required volume streams in a way that allows global block
order to be reconstructed; otherwise it must reject with "global block
ordering required for striped multi-volume sequential extract."
One conforming implementation strategy is to read each supplied volume
stream sequentially, inspect each BlockRecord header, and merge records
by ascending `block_index` before envelope assembly. This is an
implementation note; the wire format requirement is only that global
payload-data block order be reconstructable. This is not a single raw
pipe mode: the core tzap format does not define a multiplexed
multi-volume pipe container, concatenation delimiter, or volume-stream
wrapper. A reader presented with a pure concatenation of striped volumes
without external framing MUST reject because volume identity, concurrent
ordering, and terminal authentication are not reconstructable from that
pipe alone. Any tool that concatenates, delimits, or multiplexes volumes
is outside this archive wire format and must present the original
BlockRecord `volume_index`/`block_index` semantics and each volume's
authenticated terminal ManifestFooter/VolumeTrailer to the reader.

### 17.4 Recovery mode

Sequentially read surviving blocks, FEC-repair object by object when the
needed parity blocks are available, decrypt envelopes in order, and hand
the concatenated tar bytes to a tar library. Files in unrecoverable
envelopes manifest as gaps that the tar library reports. A recovery
reader appends the synthetic POSIX end-of-archive marker only after the
recovered stream has reached a known complete end; it MUST NOT use the
synthetic marker to hide unrecoverable missing member data. For V=1
non-reopenable streaming, loss of the only volume is unrecoverable unless
a separate copy exists.

---

## 18. Forward Error Correction

Default `ReedSolomonGF16` is the systematic Cauchy Reed-Solomon profile
defined below. FEC is object-local: every encrypted object is encoded
independently before its blocks are assigned global block indices and
striped with `block_index mod V`.
For IndexRoot, object-local repair still requires bootstrap metadata
from ManifestFooter or a bootstrap sidecar to locate the IndexRoot block
extent (§11).
For each FEC object, all data and parity BlockRecords occupy one
contiguous global `block_index` range:
`first_block_index .. first_block_index + data_block_count +
parity_block_count`. Data blocks appear first, followed by parity blocks.
Every present FEC object MUST have at least one data block; zero-data
objects have no last-data BlockRecord, no valid AEAD tag-bearing
ciphertext extent, and are malformed. Parity blocks remain optional when
the per-object parity calculation yields zero.
Distinct encrypted objects in a completed archive MUST use
non-overlapping global block-index ranges. Reusing a range for two
different object identities is malformed even if the underlying
BlockRecords are byte-identical; duplicate descriptions are valid only
when they describe the same object class and same AEAD identity counter
with identical counts, range, and encrypted size.

Object classes:

- payload envelope: bounded by `fec_data_shards` / `fec_parity_shards`;
- index shard: bounded by `index_fec_data_shards` /
  `index_fec_parity_shards`;
- IndexRoot: bounded by `index_root_fec_data_shards` /
  `index_root_fec_parity_shards`;
- dictionary object: bounded by `index_root_fec_data_shards` /
  `index_root_fec_parity_shards`;
- directory hint shard: bounded by `index_fec_data_shards` /
  `index_fec_parity_shards`.

`ReedSolomonGF16` is a systematic object-local Cauchy Reed-Solomon shard
codec over GF(2^16). Field elements are represented as 16-bit
polynomials over GF(2), reduced by the primitive polynomial
`x^16 + x^12 + x^3 + x + 1` (hex `0x1100B`, with the implicit `x^16`
bit included). Addition is bitwise XOR. Multiplication is polynomial
multiplication reduced by that polynomial; inversion is multiplicative
inversion in the same field.

Each data or parity shard is exactly `BLOCK_SIZE` bytes, and
`BLOCK_SIZE` MUST be even so every shard contains an integral number of
16-bit field symbols. Within a shard, symbol `k` is serialized as the
two bytes at offsets `2*k` and `2*k + 1`, interpreted as a little-endian
u16 field element. Parity shards are serialized with the same symbol
byte order.

For an object with `D = data_block_count` and `P = parity_block_count`,
object-local row identities are fixed as follows:

- data shard `i` for `0 ≤ i < D` is systematic row `e_i`;
- parity shard `j` for `0 ≤ j < P` has object-local shard index `D + j`
  and Cauchy coefficients
  `C[j][i] = inverse(x_i XOR y_j)`, where `x_i = u16(i)` and
  `y_j = u16(D + j)`.

The hard `D + P ≤ 65,535` rule guarantees the `x_i` and `y_j` sets are
disjoint u16 field elements, so every denominator is non-zero. For each
symbol position `k`, the serialized parity symbol is:

```
parity[j][k] = Σ_{i=0}^{D-1} data[i][k] * C[j][i]
```

where multiplication and summation are in GF(2^16). The on-disk
BlockRecord order remains all data blocks first, then all parity blocks.
To repair erasures, readers form a `D × D` matrix from any `D` available
rows: identity row `e_i` for available data shard `i`, or Cauchy row
`C[j]` for available parity shard `j`; they invert that matrix over the
same field and solve for the original data symbols. Implementations MAY
use any equivalent encoder/decoder internally, but the emitted parity
bytes and repaired data bytes MUST match this profile and the reference
vectors. A codec that uses GF(2^8), a different GF(2^16) polynomial, a
different Cauchy matrix, a Vandermonde matrix, a different symbol byte
order, a non-systematic code, or a different parity-shard ordering under
`FecAlgo::ReedSolomonGF16` is not wire-compatible with this draft and
needs a different FEC algorithm ID.

For `ReedSolomonGF16`, a single FEC object MUST NOT use more than
65,535 total shards (`data_block_count + parity_block_count`). Writers
MUST reject parameters or split metadata before exceeding this field
limit; readers MUST reject an object whose recorded total exceeds it.
At the default 64 KiB block size, this caps any one Reed-Solomon object
at just under 4 GiB of encoded shard payload, so large metadata must be
sharded rather than placed in IndexRoot.

`record_crc32c` on data and parity BlockRecords is an unkeyed bit-rot
detector, not a cryptographic authenticator. Undetected corruption in a
parity block can cause repair to fail or produce candidate ciphertext
that later fails AEAD verification, but readers MUST NOT release
plaintext from any repaired object until that object's AEAD tag verifies.
An active attacker who can modify a BlockRecord can also recompute its
CRC32C, causing the reader to treat a poisoned shard as apparently
intact rather than as an erasure. In that case FEC repair is not
guaranteed to recover availability; the affected object is expected to
fail AEAD/HMAC verification before plaintext release. tzap's FEC is an
availability feature for loss and accidental corruption, not a
cryptographic tamper locator.

For each object, the writer splits encrypted bytes into
`data_block_count` data blocks, derives that object's actual
`parity_block_count` from §27 using `data_block_count`, computes parity,
and writes data followed by parity. The object's table entry records
`first_block_index`, `data_block_count`, `parity_block_count`, and
`encrypted_size`; readers use those fields to fetch exactly the blocks
required to repair and decrypt that object.

Because a contiguous range striped by `block_index mod V` is balanced
across volumes, loss of any N volumes removes at most
`N × ceil(G_total / V)` shards from that object. Writers do not need to
pad each object to a multiple of V for the volume-loss guarantee.

`*_data_shards` and `*_parity_shards` in CryptoHeader are class maxima,
not the parity count that must be written for every object. The actual
per-object `parity_block_count` MUST be ≤ the relevant class maximum.

For a proposed encrypted object with `D = data_block_count`, writers MUST
compute `P = compute_parity(D, V, N, bit_rot_pct)` before emitting that
object. That data-block count is valid only if `D ≤ class_data_shards`,
`P ≤ class_parity_shards`, `D + P ≤ 65,535`, and `D * block_size` equals
the recorded `encrypted_size` without exceeding `u32::MAX`. If any of
those checks fails, the writer MUST split the object earlier, choose
different class maxima before CryptoHeader emission, or reject; it MUST
NOT emit an object that depends on truncating parity, overflowing the
GF16 shard limit, or wrapping the u32 size field. Readers MUST enforce the
same checks from the authenticated object metadata before FEC repair.

Writers MUST size objects so `data_block_count` does not exceed the data
shard limit for that object class. The effective data-shard limit for
any class is also bounded by `floor(u32::MAX / block_size)`, because
`encrypted_size` is a u32 and must equal `data_block_count * block_size`.
There is no global 64 KiB block-size requirement: larger block sizes are
valid only when class maxima and actual object sizes are small enough
for this product to fit in `u32`. If an envelope, index shard,
IndexRoot, dictionary object, or directory hint shard would exceed its
limit, the writer must split earlier or choose larger FEC parameters
before writing. IndexRoot itself MUST NOT be used as the split target for
unbounded metadata; shard-local frame/envelope tables and directory hint
shards are the scaling mechanism. IndexRoot is not splittable in this
format version. Writers MUST keep it below the selected
`index_root_fec_data_shards` limit, the effective u32-size limit, and
the ReedSolomonGF16 total-shard limit by increasing files per shard,
reducing root-table cardinality where possible, or otherwise reject with
"IndexRoot too large."

Writers MUST also ensure `data_block_count * block_size` fits in `u32`
for every encrypted object, because `encrypted_size` is a u32 field.

Recoverability for each object: `parity_block_count ≥ N ×
ceil(G_total / V)` for N-volume tolerance, where `G_total =
data_block_count + parity_block_count` for that object.

Synthetic zero shards used internally by a Reed-Solomon implementation to
fill an encoder matrix are virtual. They MUST NOT be written as
BlockRecords, assigned block indices, or counted in `data_block_count`.
`BlockRecord.flags` bit 1 is reserved for future compatibility and MUST
be zero in v0.36 archives. Readers MUST reject blocks with reserved flag
bits set.

---

## 19. Write Algorithm

### 19.1 Default: parallel-volume forward-only write

```
1. Generate `archive_uuid` and `session_id` from a CSPRNG. Each is 16
   bytes with at least 128 bits of entropy; timestamp-derived or
   deterministic session IDs are forbidden.
2. Derive keys.
3. Determine V and N. Auto-scale G_parity via §27.
4. Optionally load a pre-trained zstd dictionary. Set has_dictionary
   accordingly.
5. Choose all CryptoHeader class maxima, including
   `index_root_fec_data_shards` and `index_root_fec_parity_shards`,
   before writing any bytes. A writer with a known file list SHOULD size
   these from the planned IndexRoot/dictionary upper bound. A true
   streaming writer with unknown final metadata size MAY choose the
   maximum acceptable class values upfront and accept the parameter
   overhead, or reject/spool until it can choose bounded values. It MUST
   NOT raise these CryptoHeader fields after the header HMAC is emitted.
6. Build CryptoHeader; compute HMAC.
7. Open V sinks (file handles, S3 multipart streams, etc.).
8. For each sink: write VolumeHeader, then CryptoHeader bytes.
   (Both are now fully write-once. No fields to backfill.)
9. Stream files into tar member groups. For each group:
     - emit any path-specific PAX/GNU metadata records first;
     - emit the main tar header, data, and tar padding;
     - record exactly one FileEntry as a decompressed frame extent whose
       normalized path and `file_data_size` match the main tar entry.
   Do not emit the POSIX two-zero-block end-of-archive marker into the
   encrypted tzap tar stream.
10. Compress tar bytes into independent zstd frames. Prefer one frame per
   tar member group; split very large groups into ordered frame ranges
   whose uncompressed frame payloads target chunk_size. Record
   FrameEntry.tar_stream_offset and decompressed_size for each frame.
11. Pack complete frames into envelopes. A frame MUST NOT be split across
    envelopes. Assign envelope_index sequentially from 0 in closure
    order. When closing an envelope:
     - suffix-pad and AEAD-encrypt it;
     - if the exact-fit padding rule or AEAD tag would make
       `encrypted_size`, `data_block_count`, or the FEC object exceed
       u32/class limits, split the envelope earlier and retry;
     - split encrypted bytes into data blocks; `data_block_count` is the
       number of ciphertext blocks including the AEAD tag and suffix
       padding;
     - compute object-local parity blocks;
     - write data+parity blocks through the stripe mapper;
     - record EnvelopeEntry with data/parity counts and frame range;
     - record FrameEntry.envelope_index and offset_in_envelope in memory.
12. Build index (compute SHA-256(normalized path) for every FileEntry,
    sort by hash):
     a. Partition into shards of ~10,000 files each (default)
        while applying the bounded hash-prefix run rule (§15.4).
    b. For each shard: serialize FileEntry records plus the local
        FrameEntry and EnvelopeEntry rows needed by those files,
        zstd-compress as one complete metadata zstd frame (no dict), AEAD-encrypt, object-local FEC-encode,
        write blocks (continuing block_index, kind 4/5), and record
        ShardEntry data/parity counts.
     c. If has_dictionary = 1: zstd-compress the raw dictionary bytes as one complete metadata zstd frame
        without using the dictionary itself, AEAD-encrypt with
        dictionary_key using domain `dict`, object-local FEC-encode, and
        write dictionary blocks (kind 6/7).
     d. If directory hints are required or requested: build one or more
        DirectoryHintTable objects, zstd-compress (no dict),
        AEAD-encrypt with dir_hint_key using domain `dirhint`,
        object-local FEC-encode, write blocks (kind 8/9), and record
        DirectoryHintShardEntry data/parity counts.
     e. Build Index Root: encrypted archive totals + ShardEntry table +
        dictionary object extent (if any) + DirectoryHintShardEntry table
        (if any). IndexRoot MUST NOT contain global FrameEntry or
        EnvelopeEntry tables or raw dictionary bytes.
     f. zstd-compress IndexRoot as one complete metadata zstd frame (no dictionary even if has_dictionary = 1),
        AEAD-encrypt with index_root_key, object-local FEC-encode using
        `compute_parity(D = data_block_count, V, N, bit_rot_pct)` from
        §27 bounded by `index_root_fec_data_shards` /
        `index_root_fec_parity_shards`, write blocks (kind 2/3), and
        record IndexRoot data/parity counts for the ManifestFooter.
13. Build the shared ManifestFooter bootstrap fields (authoritative).
14. For each sink, in any order (no inter-sink dependencies):
     - Build this volume's ManifestFooter copy by setting
       volume_index to the sink's zero-based volume index and computing
       manifest_hmac over that copy.
     - Write that ManifestFooter at current sink position
     - Write VolumeTrailer with:
         block_count = blocks written to this sink
         bytes_written = sink's current cursor
         manifest_footer_offset = position where footer was written above
         manifest_footer_length = sizeof(ManifestFooter)
         trailer_hmac = HMAC using the §12 domain-separated trailer
         input over the first 96 trailer bytes
     - Close the sink. No seek-back ever required.
15. If emitting a bootstrap sidecar, build its ManifestFooter instance
    from the same shared authoritative bootstrap fields, set
    `volume_index = 0` and `is_authoritative = 1`, and compute
    `manifest_hmac` over that sidecar instance. This instance may be
    byte-identical to the volume-0 ManifestFooter when all fields match,
    but do not byte-copy a nonzero-volume footer and mutate
    `volume_index` after HMAC.
```

### 19.2 Cloud / S3 compatibility

The above write algorithm is fully compatible with S3 multipart uploads
(or any append-only object storage):

- Each volume is an S3 multipart upload.
- Each "block" or batch of blocks is written as a multipart part (5 MiB+
  per part is the S3 minimum).
- VolumeHeader, CryptoHeader, payload blocks, ManifestFooter, and
  VolumeTrailer are all appended sequentially.
- The CompleteMultipartUpload API finalizes the object.

No part of the v0.36 write path needs to revisit a closed S3 part or to
write at an arbitrary byte offset.

### 19.3 Single-stream streaming mode

Single-sink, fully non-reopenable streaming is supported only with
`stripe_width = 1` and `volume_loss_tolerance = 0`. The writer emits one
volume forward-only: VolumeHeader, CryptoHeader, payload/index blocks,
ManifestFooter, and VolumeTrailer. If the writer uses a payload zstd
dictionary (`has_dictionary = 1`), it MUST also emit a bootstrap sidecar
containing authenticated encrypted IndexRoot and dictionary-object copies
(§12.2), otherwise non-seekable sequential extraction would be
impossible.
Because CryptoHeader is authenticated before payload metadata exists,
single-stream writers with unknown file counts MUST either choose
conservative IndexRoot/dictionary FEC class maxima before emitting the
CryptoHeader, pre-scan/spool until the metadata bound is known, or reject
the stream. They MUST NOT emit a header that assumes a later in-place
raise of `index_root_fec_data_shards`.
If a forward-only writer discovers at close time that the serialized
IndexRoot cannot fit within the already-authenticated
`index_root_fec_*` class limits, it MUST reject finalization rather than
emit a non-conforming archive. On non-rewriteable sinks this can strand
previously written payload bytes as an unusable incomplete archive, so
tools that accept unknown-size streams SHOULD pre-scan, spool, or choose
conservative maxima before committing remote or long-running writes.
Because the IndexRoot is finalized after payload envelopes, this mode is
not live-decompressible with a dictionary unless the reader can obtain an
already-complete sidecar or buffer encrypted payload bytes until the
sidecar is complete.
That buffer can be as large as the encrypted payload stream. A writer
MUST NOT advertise live stdout-to-stdin decompression for a
dictionary-compressed single stream unless the required bootstrap sidecar
is complete and available to the reader before payload decompression
starts.
The bootstrap sidecar may be written to a separate path, file
descriptor, or stream. It is not interleaved into the core tzap payload
stream unless an external wrapper outside this format defines such
multiplexing.

For `stripe_width > 1`, the writer must use §7.4 behavior. If only one
non-reopenable sink is available, it must reject or spool locally before
writing final volumes. There is no conforming v0.36 mode that round-robins
striped blocks into multiple non-reopenable volume streams without
either concurrent sinks or spooling.

---

## 20. Performance

### 20.1 Padding overhead (v0.36 unchanged from v0.15)

| Envelope size | Block size | Avg overhead |
|---|---|---|
| 1 MiB | 64 KiB | ~3% |
| 4 MiB | 64 KiB | ~0.8% |
| 16 MiB | 64 KiB | ~0.2% |

These are average estimates. Worst-case overhead can be higher for very
small envelopes or exact-fit envelopes, because the canonical padding
rule adds an entire `BLOCK_SIZE` when plaintext plus AEAD tag would
otherwise exactly fill the final block.

### 20.2 Dictionary

When `has_dictionary = 1`, the dictionary is loaded once per archive
(after IndexRoot decode) and reused across all payload envelope
decompressions. For small-file corpora, compression ratio improvements
of 30–50% are typical.

### 20.3 Parallelism

Same as v0.15. Envelope-level AEAD, object-local FEC encoding, zstd frame
compression, and per-sink writes are all independent.

---

## 21. Failure Modes

| Failure | Detection | Recovery |
|---|---|---|
| Bit-rot in block payload | record_crc32c | FEC repair |
| Active block tamper with recomputed CRC | AEAD/HMAC failure | Detected before plaintext release; FEC availability is not guaranteed |
| Any single volume lost (default mode) | block_index gap | FEC (if parity sized correctly) |
| CryptoHeader corrupt in 1 volume | HMAC fails | Use another volume's copy |
| ManifestFooter corrupt in 1 volume | HMAC fails | Use another volume's copy |
| All ManifestFooter copies corrupt/missing | HMAC/trailer lookup fails | Use trusted bootstrap sidecar or sequential recovery |
| VolumeTrailer corrupt | HMAC fails | Try another volume; if all corrupt, optionally scan from end for authenticated magic within cap |
| Bounded trailing garbage after trailer | EOF trailer candidate fails; earlier authenticated TZVT found | Ignore trailing bytes with diagnostic if within `max_trailing_garbage_scan` |
| V=1 streaming volume lost | Volume file missing | Unrecoverable unless another copy exists |
| Mid-stream writer crash | VolumeTrailer absent or HMAC fails | Reader reports clearly |
| Sequential output before terminal authentication | Terminal ManifestFooter/VolumeTrailer not yet authenticated | Output is provisional; default filesystem extractors stage/quarantine and commit only after terminal authentication |
| Streaming writer cannot fit final IndexRoot | Writer detects FEC/u32 class-limit overflow at close | Reject finalization; avoid by pre-scan, spool, or conservative maxima |
| Adversarial volume splice | session_id mismatch | Detected; rejected |
| IndexRoot block extent known but unrecoverable | High parity usually saves it | If exhausted, recovery mode |
| Index Shard S unrecoverable | Shard FEC exhausted | Files in shard S lose random-access; sequential extract still works |

---

## 22. Security Analysis

- File data, paths, per-file metadata, archive content hash, file count,
  frame count, envelope count, tar size, and directory hints are inside
  AEAD-protected encrypted objects.
- The outer container necessarily leaks volume count, total volume sizes,
  block size, CryptoHeader parameters, IndexRoot location/size, and
  padded encrypted object sizes. The authenticated plaintext
  VolumeTrailer also leaks `closed_at_ns`, the write-completion timestamp
  recorded by the writer.
- Per-envelope padding masks exact packed-frame length within the chosen
  block-size granularity; it does not hide total archive size or object
  count from an observer who can see all volume bytes.
- All plaintext-deriving bytes are authenticated by AEAD and/or HMAC.
- Non-seekable sequential readers may expose per-envelope-authenticated
  bytes before whole-archive terminal authentication only as provisional
  output. Default filesystem extractors preserve the truncation
  non-release guarantee by staging or quarantining writes until terminal
  ManifestFooter/VolumeTrailer authentication succeeds.
- VolumeHeader and BlockRecord CRC32C fields are corruption detectors,
  not authentication. Readers only trust archive identity and repaired
  object bytes after authenticated header/trailer/footer checks and
  AEAD/HMAC verification succeed.
- Because BlockRecord CRC32C is unkeyed, an active attacker can modify a
  data or parity shard and recompute the CRC so the reader does not mark
  that shard as an erasure. This can force the enclosing AEAD/HMAC object
  to fail authentication even when enough original parity would have
  repaired an accidentally corrupted shard. This is an availability
  denial, not a plaintext integrity bypass: readers MUST NOT release
  plaintext until object authentication succeeds.
- `session_id` is bound into AEAD nonce derivation and AAD, preventing
  same-key/same-archive envelope or index replay across write sessions.
- Directory-hint shard indexes are unique because they are AEAD counters
  for the `dirhint` domain under `dir_hint_key`; duplicate hint shard
  indexes would reuse a nonce for distinct directory-hint objects and are
  malformed.
- `archive_uuid` and `session_id` are also bound into HKDF subkey
  derivation and CryptoHeader HMAC input, so raw-key mode does not reuse
  the same `mac_key` or AEAD keys across write sessions.
- Padding is authenticated by AEAD; zero padding is additionally checked
  as canonical-format validation.
- Reader caps and structural validation are mandatory before allocation.
- The 64-bit path-hash prefix is an indexing compactness trade-off, not
  collision-resistant identity. A malicious archive producer or
  path-supplying adversary may force hash-prefix collision runs; readers
  bound the work with `max_hash_collision_shard_scan` and fail clearly
  rather than performing unbounded random-access scans. Administrators
  handling trusted but collision-heavy archives MAY raise the cap or run
  full-archive `verify` before relying on random single-file lookup.
- Duplicated FrameEntry/EnvelopeEntry rows across IndexShards are checked
  for consistency when multiple relevant shards are loaded and by
  full-archive `verify`. Random extraction of a single file normally
  loads only the file's owning shard, so it cannot prove that another
  shard's duplicate row agrees. Users who do not control the archive
  producer SHOULD run `verify` before trusting random-extract output.
- The registered AEADs are not specified as formally key-committing
  AEADs. tzap provides early wrong-key detection through archive-bound
  HMACs and authenticated metadata before plaintext release, but formal
  key-commitment is left to a future committed-AEAD mode or detached
  signature profile (§30).

---

## 23. Versioning

`format_version` bumps on breaking changes; `volume_format_rev` identifies
the draft-level wire revision while the format is pre-implementation. This
document uses `format_version = 1` and `volume_format_rev = 36`. Readers
MUST reject archives with `format_version != 1` or with
`volume_format_rev` greater than the newest revision they implement.
Readers claiming conformance only to this draft MUST require
`volume_format_rev = 36`; accepting earlier draft revisions requires an
explicit compatibility mode.
Unknown algorithm IDs and critical extensions are hard errors.

The v0.x documents are pre-implementation drafts. A later v0.x draft may
still refine wire details while retaining `format_version = 1`; once any
implementation claims conformance to this v0.36 draft, incompatible
changes require a `format_version` bump.

Readers MUST reject IndexRoot, IndexShard, DirectoryHintTable, and
BootstrapSidecarHeader structures whose `version` field is not `1` in
this format version.
Per-structure `version` fields are independent of `volume_format_rev`.
A future draft may change one structure's version without changing the
others; `volume_format_rev` identifies the overall draft-level wire
revision, while each structure version gates that structure's plaintext
layout.

---

## 24. Sizing Defaults

| Parameter | Default | Notes |
|---|---|---|
| `chunk_size` | 256 KiB | writer target for uncompressed zstd-frame chunks; not a parsing boundary; MUST be non-zero and ≤ `envelope_target_size` |
| `envelope_target_size` | 1 MiB | MUST be non-zero |
| `block_size` | 64 KiB | MUST be at least 4096 bytes and even |
| `fec_data_shards` | 224 | maximum payload-envelope data blocks |
| `fec_parity_shards` | derived from V and N | maximum payload-envelope parity blocks; actual count is per-object (§27) |
| `index_fec_data_shards` | 16 | maximum index-shard and directory-hint-shard data blocks |
| `index_fec_parity_shards` | derived from V and N | maximum index-shard/directory-hint-shard parity blocks; actual count is per-object (§27) |
| `index_root_fec_data_shards` | dynamic before CryptoHeader emission, minimum 16 | maximum IndexRoot and dictionary-object data blocks; writer MUST choose a value large enough for serialized IndexRoot before writing CryptoHeader, but actual object `data_block_count + parity_block_count` and `data_block_count * block_size` must fit §18 limits |
| `index_root_fec_parity_shards` | derived from V and N | maximum IndexRoot/dictionary parity blocks; actual count is per-object (§27) |
| Files per shard | 10_000 | |
| `max_hash_prefix_run_files` | 50_000 | shard split ceiling for identical 8-byte hash prefixes |
| `directory_hint_required_file_count` | 100_000 | directory hint shards required above this count |
| `stripe_width V` | 8 | MUST be at least 1 |
| AEAD | AES-256-GCM-SIV | |
| KDF | Argon2id t=3 m=256 MiB p=4 | |
| `volume_loss_tolerance N` | 1 | |
| `bit_rot_buffer_pct` | 5 | MUST be ≤ 100 |

The u32-size data-shard ceiling for every object class is
`min(class_data_shards, floor(u32::MAX / block_size))`. Writers MUST
choose class maxima and actual object sizes so `encrypted_size` remains
representable as u32. Larger `block_size` values are therefore usable
only with smaller data-shard counts. This u32-size ceiling is not the
complete effective object ceiling: after §27 parity is computed for a
proposed `D = data_block_count`, the object is valid only if the computed
`P` also fits the class parity maximum and `D + P ≤ 65,535` for
ReedSolomonGF16.

The dynamic IndexRoot data-shard value has no unbounded escape hatch.
The class maxima are u16 fields and MAY have a sum greater than the
ReedSolomonGF16 per-object total-shard limit, but every actual IndexRoot
and dictionary object MUST still satisfy the §18 rule:
`data_block_count + parity_block_count ≤ 65,535`, and each actual count
MUST be ≤ its corresponding class maximum. If the serialized IndexRoot
cannot fit after root-table cardinality has been reduced as far as this
format allows, the writer MUST reject rather than emit a non-conforming
root object. A two-level or continuation IndexRoot is future work (§30).
The minimum value 16 is only a floor for small archives, not a
recommendation for large file sets; writers must choose a value large
enough before CryptoHeader emission.
The value is "dynamic" only before CryptoHeader serialization. Once the
CryptoHeader HMAC has been emitted, `index_root_fec_data_shards` and
`index_root_fec_parity_shards` are fixed archive parameters.

`max_hash_prefix_run_files` is a writer-side planning default: it is the
maximum number of files with the same 8-byte path-hash prefix that the
writer places in one IndexShard before splitting the prefix run across
adjacent shards. It is not itself a reader validation cap. Readers bound
lookup work with `max_hash_collision_shard_scan` (§13.3) or by requiring
full-archive verification for hostile inputs.

---

## 25. Magic Numbers

| ASCII | Hex | Purpose |
|---|---|---|
| `TZAP` | `54 5A 41 50` | Volume header |
| `TZCH` | `54 5A 43 48` | CryptoHeader |
| `TZBK` | `54 5A 42 4B` | Block record |
| `TZIR` | `54 5A 49 52` | Index Root |
| `TZIS` | `54 5A 49 53` | Index Shard |
| `TZDH` | `54 5A 44 48` | Directory Hint Table |
| `TZMF` | `54 5A 4D 46` | ManifestFooter |
| `TZVT` | `54 5A 56 54` | VolumeTrailer |
| `TZBS` | `54 5A 42 53` | Bootstrap sidecar |

---

## 26. CLI Sketch (non-normative)

```
tzap create  [--volumes V | --volume-size 100M]
             [--volume-loss-tolerance N]
             [--unsafe-parity DATA:PARITY]
             [--password-stdin] [--keyfile FILE]
             [--compression-level 3]
             [--chunk-size 256K] [--envelope-size 1M] [--block-size 64K]
             [--files-per-shard 10000]
             [--dictionary FILE]
             [--exclude PATTERN] -o BASENAME INPUT...

tzap extract [--password-stdin] [--keyfile FILE] [--bootstrap FILE]
             [--strip-components N] [-C DIR] ARCHIVE [PATH...]

tzap list    [--password-stdin] [--keyfile FILE] [--bootstrap FILE] [--long]
             [--sort path|hash] ARCHIVE        # sort=hash is faster

tzap verify  [--password-stdin] [--keyfile FILE] [--bootstrap FILE]
             [--repair-to DIR] ARCHIVE

tzap info    ARCHIVE

tzap recover [--password-stdin] [--keyfile FILE]
             [--bootstrap FILE] ARCHIVE...
```

---

## 27. Parity Auto-Scaling (Required CLI Behavior)

```
fn compute_parity(D, V, N, bit_rot_pct):
    min_parity       = 1 if (N > 0 || bit_rot_pct > 0) else 0
    G_parity         = 0

    iterate until G_parity stabilizes:
        G_total          = D + G_parity
        G_parity_volume  = N * ((G_total + V - 1) / V)
        G_parity_bitrot  = (G_total * bit_rot_pct + 99) / 100
        G_parity         = max(G_parity_volume + G_parity_bitrot, min_parity)

class maximum:
    class_parity_shards = compute_parity(D = class_data_shards, V, N, bit_rot_pct)

per object:
    parity_block_count = compute_parity(D = data_block_count, V, N, bit_rot_pct)
```

The iteration MUST stop after convergence or after 100 iterations,
whichever comes first. If it has not converged within 100 iterations, the
writer MUST reject the parameter set. Normal parameter sets converge in a
small number of iterations.

All arithmetic in `compute_parity` MUST use checked unsigned 64-bit
integer operations. Writers MUST reject the parameter set if any
intermediate addition, multiplication, or ceiling calculation overflows.
The two divisions above are integer ceiling divisions. Implementations
MUST NOT use ordinary truncating division for those terms.
Writers MUST reject `bit_rot_pct > 100` as nonsensical even though the
field is a u8. The computed class-maximum parity value MUST be ≤ 65,535
because it is stored in u16 class fields; if it exceeds that limit, the
writer MUST reject the configuration.

A simple sufficient condition for the unrounded recurrence to converge
is `N / V + bit_rot_pct / 100 < 1`. The required `N < V` rule and the
default 5% bit-rot buffer satisfy this for normal configurations. The
100-iteration cap remains normative because integer ceilings and unsafe
override parameters still need a deterministic rejection path. Parameter
sets outside the sufficient condition may be rejected by the 100-iteration
cap even if a different recurrence analysis would eventually converge.

The class-maximum invocation chooses each class maximum
(`*_parity_shards`) from that class's maximum data shards
(`*_data_shards`). The per-object invocation stores the resulting
`parity_block_count` in EnvelopeEntry, ShardEntry, or ManifestFooter and
MUST NOT exceed the class maximum.

For payload defaults (D_max=224, V=8, N=1, bit_rot=5%): the class maximum
stabilizes at `G_parity = 48`. That is 272 encoded shards total, a
17.6% parity fraction of encoded blocks and ~21.4% storage overhead over
data at the maximum object size. A smaller object uses fewer parity
blocks. For example, a 17-data-block payload envelope with the same V/N
and bit-rot settings stabilizes at `parity_block_count = 5`.

The bit-rot term is deliberately conservative extra margin after
volume-loss sizing. It is not a separate guarantee independent of volume
loss; rather, the stated guarantee is recovery from the configured
volume loss plus additional scattered block corruption up to the chosen
buffer, subject to Reed-Solomon erasure/error handling and successful
identification of corrupt blocks by CRC/AEAD.

Writers MUST reject `N ≥ V`. For `V = 1`, writers MUST set `N = 0`;
bit-rot parity may still be emitted, but no amount of parity can recover
the loss of the only volume.

The CLI emits the chosen parity and the resilience guarantee in plain
English at archive creation. Power users may override with
`--unsafe-parity D:P` combined with an explicit acknowledgment flag.

---

## 28. Reference Implementation Notes

Crate selection unchanged from v0.16. Reference implementations should
model IndexRoot, IndexShard, dictionary object, and directory hint shard
as distinct encrypted metadata object types.

### 28.1 Test corpus additions through v0.36

Additional v0.36 cases:

- **Minimal FileEntry frame ranges**: create a FileEntry whose
  `tar_member_group_size` ends before the final referenced frame begins,
  while all referenced FrameEntry rows otherwise decode correctly. Verify
  readers reject the non-minimal range rather than fetching/decompressing
  unrelated trailing frames. Include valid cases where the tar member group
  ends inside a single shared frame and where it spans into the final frame
  without consuming that whole final frame.
- **Exact file versus directory-prefix hints**: create an archive with a
  regular file `foo`, with no directory `foo/`, and unrelated descendants
  whose hashes populate other directory hints. Verify extracting path
  `foo` uses exact FileEntry lookup and does not require or consult a
  DirectoryHintEntry for `foo`. Repeat with `foo` as a directory and
  `foo/bar` as a child, verifying the exact directory entry is included
  and hints are used only for descendants. Mutate hints so a regular-file
  exact path is present only as a misleading directory hint and verify
  readers do not treat that hint as an exact-file authority.

Additional v0.35 cases retained from the previous draft:

- **Hash-prefix byte-order vectors**: construct FileEntry and
  DirectoryHintEntry prefixes whose bytewise order differs from
  little-endian and host-endian integer order, for example prefixes that
  differ in byte 0 and byte 7. Verify writers sort by raw digest byte
  order and readers use the same order for ShardEntry and
  DirectoryHintShardEntry upper-bound lookup.
- **Argon2id profile vectors**: fixed passphrase bytes, salt, `t_cost`,
  `m_cost_kib`, and `parallelism` with expected 32-byte `master_key`
  output. Verify Argon2 version 0x13, empty secret, empty
  associated-data, and exact 32-byte output; verify implementations do
  not accept PHC-string defaults, `t_cost = 0`, or alternate Argon2
  versions as equivalent.
- **AEAD combined-output vectors**: for each registered AEAD, verify the
  on-wire encrypted object is `ciphertext || tag` with the tag occupying
  the final `AEAD_TAG_LEN` bytes. Mutate vectors to prefix the tag,
  detach it, truncate it, or append extra tag bytes; verify readers reject
  before depadding or decompression.
- **ReedSolomonGF16 wire profile vectors**: fixed even `block_size`,
  ordered data shards, `D`, and `P` with expected parity BlockRecord
  payload bytes under the §18 GF(2^16) polynomial and Cauchy coefficient
  matrix. Include vectors that distinguish little-endian 16-bit symbol
  serialization, data-first then parity ordering, the selected primitive
  polynomial, Cauchy coefficients, and the registered GF(2^16) profile
  from GF(2^8), Vandermonde, or library-default Reed-Solomon codecs. Also
  set an odd `block_size` and verify readers reject before FEC repair.
- **Directory hint AEAD counter uniqueness**: create an IndexRoot with two
  DirectoryHintShardEntry rows that use the same `hint_shard_index` but
  different extents; verify readers reject the IndexRoot before decrypting
  either directory-hint shard. Also verify unique non-row-position values
  remain valid when all ordering and lookup rules hold.
- **Shard boundary metadata binding**: mutate ShardEntry `file_count`,
  `first_path_hash`, and `last_path_hash` so they no longer match the
  decrypted IndexShard FileEntry table; verify readers reject the loaded
  shard rather than silently missing lookup candidates. Repeat for
  DirectoryHintShardEntry `entry_count`, `first_dir_hash`, and
  `last_dir_hash`, and verify zero-entry directory-hint shards are
  rejected.
- **Sparse local frame offset validation**: create shard-local FrameEntry
  tables with intentional frame-index gaps for unrelated files. Verify
  random extraction accepts increasing `tar_stream_offset` values across
  gaps, requires exact adjacency only for consecutive frame indexes, and
  full-archive `verify` still rejects global tar-stream gaps or overlaps.
- **Metadata-object zstd exactness**: mutate IndexRoot, IndexShard,
  dictionary, and DirectoryHintTable encrypted objects so their depadded
  plaintext is a valid zstd frame followed by trailing bytes, a skippable
  frame, concatenated frames, or a frame whose decompressed size differs
  from the recorded `decompressed_size`; verify readers reject before
  structural validation trusts the decompressed object.
- **FEC effective object ceiling**: choose class data/parity maxima whose
  sum exceeds 65,535, then attempt objects near the class data maximum.
  Verify writers split or reject when the computed per-object parity count
  would make `data_block_count + parity_block_count > 65,535`, even if
  each individual count fits its u16 class maximum and the u32 size product
  fits.
- **Volume format revision freshness**: create archives with
  `volume_format_rev` below, equal to, and above 36; verify v0.36-only
  readers accept only 36 and reject older or newer revisions.

Previously required regression cases retained from earlier drafts:

- **Sidecar ManifestFooter volume-0 equivalence**: emit a sidecar
  ManifestFooter whose bytes are identical to the volume-0
  ManifestFooter and verify readers accept it. Copy a nonzero-volume
  ManifestFooter, mutate `volume_index` to zero without recomputing
  HMAC, and verify rejection. Recompute the HMAC over the sidecar
  instance and verify acceptance only when all other sidecar rules hold.
- **Sequential provisional output**: stream a valid dictionary-free
  archive to a stdout-style API and verify emitted bytes are marked
  provisional until terminal authentication succeeds. Repeat with a
  filesystem extractor and verify writes are staged/quarantined and not
  committed when terminal ManifestFooter/VolumeTrailer authentication
  fails after otherwise valid payload envelopes.
- **Zero-data encrypted objects**: mutate IndexRoot, IndexShard,
  dictionary, directory-hint, and payload EnvelopeEntry metadata so
  `data_block_count = 0` and `encrypted_size = 0`; verify readers reject
  before FEC repair, AEAD decryption, decompression, or plaintext
  release.

- **Empty archive**: archive with zero files; verify `file_count = 0`,
  `shard_count = 0`, `directory_hint_shard_count = 0`, no dictionary,
  no payload envelopes, `payload_block_count = 0`, and valid IndexRoot,
  ManifestFooter, and trailer. Verify `tar_total_size = 0` and
  `content_sha256 =
  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **Empty payload envelope rejection**: mutate an archive to contain a
  payload EnvelopeEntry with `frame_count = 0` or `plaintext_size = 0`;
  verify readers reject it rather than invoking a zstd decoder on empty
  payload bytes. Also mutate FrameEntry records to
  `compressed_size = 0` or `decompressed_size = 0`, and FileEntry records
  to `frame_count = 0` or `tar_member_group_size < 512`; verify readers
  reject before extraction.
- **Reserved FileEntry flags**: set one FileEntry flag bit; verify reader
  rejects before extraction.
- **Encrypted-size canonicality**: mutate `encrypted_size` to be smaller
  or larger than `data_block_count * block_size`; verify rejection.
  Include products that overflow 32-bit arithmetic but fit in 64-bit
  arithmetic, and verify readers use checked unsigned 64-bit-or-wider
  arithmetic before comparison.
  Mutate payload, index-shard, directory-hint, IndexRoot, and dictionary
  data/parity counts above their CryptoHeader class maxima and above the
  ReedSolomonGF16 total-shard limit; verify rejection before FEC repair.
- **Exact-fit overflow guard**: synthesize an envelope plan whose
  packed-frame bytes plus AEAD tag exactly fill the final block near the
  u32 limit. Verify the writer splits before the mandatory extra padding
  block would overflow `encrypted_size` or FEC limits, and verify readers
  reject any wrapped/truncated encoding.
- **Shard and collision caps**: create a shard over
  `max_files_per_index_shard` and a hash-prefix collision run over
  `max_hash_collision_shard_scan`; verify both fail clearly. Construct
  adjacent ShardEntry rows whose intervals are all `[H, H]` and verify
  lookup uses the §15.4 upper-bound landing rule, includes the landing
  shard, and returns the complete bounded candidate block. Also look up a
  target hash greater than or equal to every `first_path_hash` and verify
  the upper-bound end position lands on the final row rather than
  crashing or falsely rejecting.
- **Header/trailer identity binding**: combine a VolumeHeader from one
  archive with an authenticated trailer/footer from another archive under
  the same key; verify the reader rejects before object decryption.
- **Volume count cross-checks**: mutate `VolumeHeader.stripe_width`,
  `CryptoHeader.stripe_width`, and `ManifestFooter.total_volumes`
  independently; verify readers reject any mismatch.
- **Volume index bounds and duplicates**: mutate VolumeHeader,
  VolumeTrailer, and ManifestFooter copies so an authenticated
  `volume_index` is equal to or greater than `stripe_width`; verify
  readers reject even for volumes with zero BlockRecords. Supply two
  different volume files with the same authenticated `volume_index` and
  verify default readers reject instead of choosing one arbitrarily.
  Repeat with an explicit duplicate-copy recovery mode and verify it
  accepts only byte-for-byte identical duplicate inputs for the requested
  operation.
- **Magic-field validation**: mutate each fixed magic field independently
  (`TZAP`, `TZCH`, `TZBK`, `TZMF`, `TZVT`, `TZBS`, `TZIR`, `TZIS`, and
  `TZDH`) while preserving any applicable CRC/HMAC/AEAD envelope for the
  malformed bytes where possible; verify readers reject before trusting
  the containing structure.
- **CryptoHeader canonical offset**: set `crypto_header_offset` to values
  other than `sizeof(VolumeHeader)`, including a valid in-bounds offset
  with padding bytes before the CryptoHeader; verify v0.36 readers reject
  instead of accepting an unclaimed gap.
- **Volume format revision**: create archives with `volume_format_rev`
  below, equal to, and above 36; verify v0.36-only readers accept only 36
  and reject older or newer revisions.
- **CryptoHeader length consistency**: mutate
  `VolumeHeader.crypto_header_length` and `CryptoHeaderFixed.length`
  independently; verify readers reject mismatches before parsing trailing
  extension bytes. Also set both lengths consistently above the active
  `CryptoHeader byte length` cap and verify readers reject before
  allocation, KDF work, or Extension TLV scanning.
- **KDF parameter dispatch**: mutate `kdf_algo` to an unknown value and
  verify readers reject before attempting to parse KdfParams. Mutate
  raw-mode KdfParams to carry `algo_tag = 1` and Argon2id KdfParams to
  carry `algo_tag = 0`; verify readers reject the mismatch before KDF
  execution. Mutate Argon2id fixed-prefix length, salt length,
  `t_cost = 0`, and `m_cost_kib < 8 × parallelism`; verify rejection
  before invoking Argon2id.
- **Argon2id passphrase canonicalization**: include vectors whose
  passphrase contains composed and decomposed Unicode forms, a trailing
  newline, an embedded NUL, and a leading U+FEFF character. Verify the
  KDF input is exactly the UTF-8 encoding of the NFC-normalized caller
  string and that the archive format itself does not trim, strip, or
  transcode those bytes.
- **CryptoHeader parameter validity**: mutate `fec_algo` to `None` and
  `Wirehair`, mutate `has_dictionary` to values other than 0 or 1,
  mutate `volume_loss_tolerance >= stripe_width`, mutate
  `bit_rot_buffer_pct > 100`, set `chunk_size >
  envelope_target_size`, and set each data-shard class maximum to zero
  or each FEC class-total maximum above configured reader caps; verify
  readers reject before object planning or FEC repair. Mutate
  `expected_volume_size` and verify readers treat it as advisory only.
- **CryptoHeader Extension TLVs**: with a valid HMAC, inject an unknown
  non-critical extension tag `0x0009` with valid length and payload;
  verify v0.36 readers ignore it and continue parsing. Repeat with the
  same unknown extension as critical `0x8009`; verify readers reject with
  a hard error after CryptoHeader HMAC verification. Also mutate `tag = 0`
  with non-zero length, an extension length above 256 bytes, bytes between
  the terminator and HMAC, duplicate known tags, forbidden tag `0x0004`,
  and forbidden tag `0x0006`; verify readers reject each case.
- **CryptoHeader identity binding**: combine a VolumeHeader from one
  archive with a CryptoHeader from another archive under the same raw key
  and verify CryptoHeader HMAC fails because UUID/session are bound.
- **Per-volume ManifestFooter copies**: create a multi-volume archive and
  verify each footer HMAC authenticates with that volume's own
  `volume_index` while all shared IndexRoot/bootstrap fields are equal.
- **HMAC domain vectors**: fixed `mac_key`, UUID/session, and serialized
  CryptoHeader, ManifestFooter, VolumeTrailer, and BootstrapSidecarHeader
  bytes. Verify all HMACs use their `tzap-v1-*` domain strings and raw
  byte concatenation exactly.
- **Unsafe paths**: include absolute paths, `..` components, empty
  components, NUL-containing names, and host-native separator escape
  forms such as backslash-as-directory-separator; verify conformant
  writers reject and readers reject non-conforming archives.
- **Safe extraction through links**: create archives containing a symlink
  `dir -> ../outside` followed by `dir/file`, a symlink `dir -> /tmp`
  followed by `dir/file`, a pre-existing extraction-root symlink parent,
  a hardlink with an absolute target, and a hardlink whose target
  contains `..`. Verify default readers do not follow the symlink or
  hardlink target outside the extraction root, reject or skip unsafe link
  entries with diagnostics, and do not write later file payload bytes via
  symlink ancestry.
- **Parity convergence cap**: use pathological parity parameters that do
  not converge within 100 iterations; verify writer rejects. Also verify
  checked arithmetic rejects overflow, `bit_rot_pct > 100`, and class
  parity results above 65,535.
- **AEAD constants**: for every registered AEAD algorithm, verify the
  nonce length and tag length match §5 and that archives using another
  length are rejected. Mutate `aead_algo` and `kdf_algo` to unregistered
  values and verify readers reject before algorithm-specific parsing.
- **Integrity byte ranges**: corrupt the byte immediately before and at
  each CRC/HMAC field boundary for VolumeHeader, ManifestFooter,
  VolumeTrailer, and BootstrapSidecarHeader; verify only covered bytes
  affect that checksum/MAC and authenticated structures still reject
  tampering.
- **Sequential envelope counters**: pipe a dictionary-free archive with
  multiple envelopes and parity blocks through sequential extraction.
  Verify AEAD counters start at 0, increment once per payload envelope,
  and do not increment for parity BlockRecords. Verify the reader infers
  each envelope's parity set from consecutive kind-1 records immediately
  after the last flagged data block, stops the parity run at the next
  kind-0 or metadata block, and rejects parity runs above
  `CryptoHeader.fec_parity_shards`.
- **Reserved BlockRecord flags**: set bit 1 and a high flag bit on data
  and parity BlockRecords; verify readers reject before using payload
  bytes. Also set bit 0 on two data blocks in one object and verify the
  reader rejects duplicate last-data flags before decryption.
- **Parity recurrence seed**: verify class-max and per-object parity
  calculations start from `G_parity = 0` and converge to the expected
  values in §27.
- **HKDF vectors**: fixed passphrase, Argon2id salt/params, raw-key
  cases, archive UUID, and session ID with expected `enc_key`, `mac_key`,
  nonce seeds, index keys, dictionary key, and directory-hint key. Verify
  independent implementations derive identical subkeys and that changing
  UUID/session changes all subkeys. The reference corpus MUST contain
  literal input byte strings and expected hex outputs, not only
  property-style tests.
- **KDF parameter caps**: Argon2id salt lengths below 8 and above 64,
  `t_cost = 0`, `t_cost`, `m_cost_kib`, and `parallelism` over reader
  caps, `m_cost_kib < 8 × parallelism`, and raw mode with exactly two
  KdfParams bytes `algo_tag = 0`. Verify all invalid cases reject before
  expensive allocation or KDF execution. Also truncate CryptoHeader so it contains
  only the fixed header plus HMAC, a one-byte raw KdfParams payload, a
  fixed header plus raw KdfParams plus HMAC but no TLV terminator, a
  malformed/non-terminating TLV list, a short Argon2id prefix, or an
  Argon2id salt shorter than `salt_length`; verify readers reject before
  semantic extension handling or KDF execution.
- **Nonce info vectors**: verify nonce derivation uses
  `b"tzap-v1-nonce" || u16(domain_len) || domain || uuid || session ||
  counter_le64`; changing only the domain length encoding changes the
  derived nonce and old non-length-prefixed derivations fail to decrypt.
- **IndexRoot AEAD counter**: archive whose IndexRoot uses counter 0 for
  both nonce and AAD; verify decryption succeeds. Archive using the old
  mismatched AAD counter must fail authentication.
- **Chunk-size semantics**: archives with `chunk_size` smaller than,
  equal to, and larger than typical file sizes. Verify writers reject
  `chunk_size > envelope_target_size`, readers ignore valid non-zero
  values for parsing, readers reject `chunk_size = 0` and `chunk_size >
  envelope_target_size`, and FrameEntry extents remain the only
  random-access authority. Also verify readers reject `chunk_size`,
  `envelope_target_size`, and `block_size` values above configured caps
  before allocation.
- **Sparse shard-local EnvelopeEntry tables**: create an archive whose
  IndexShard references envelopes with non-contiguous global
  `envelope_index` values. Verify random extraction succeeds when the
  local EnvelopeEntry table contains exactly the sorted sparse subset
  needed by that shard, and verify full-archive `verify` still rejects a
  distinct global envelope set with gaps or duplicates.
- **Exact shard-local FrameEntry tables**: add an unrelated FrameEntry to
  an otherwise valid IndexShard, omit a referenced FrameEntry, duplicate
  a local `frame_index`, and add an unrelated EnvelopeEntry not
  referenced by any local FrameEntry. Verify readers reject the shard
  before lookup or extraction.
- **Cross-shard envelope frame coverage**: create an envelope containing
  frames for files whose paths land in different IndexShards. Verify each
  shard-local FrameEntry table contains only the frames referenced by
  that shard's FileEntries, while each local EnvelopeEntry still records
  the full global envelope frame range. Verify random extraction accepts
  the sparse local frame coverage, and full-archive `verify` rejects only
  when the union of distinct global FrameEntry rows fails to cover the
  envelope plaintext exactly once.
- **Path-hash binding**: mutate a FileEntry `path_hash` without changing
  the string-pool path, and mutate a DirectoryHintEntry `dir_hash`
  without changing its hint string-pool path. Verify readers reject the
  loaded shard or hint table before lookup/extraction can silently miss
  or misroute the entry.
- **Platform escape paths**: include FileEntry paths and hardlink targets
  containing backslash, colon/alternate-stream syntax, drive-designator
  first components, UNC/device namespace prefixes, Windows device-name
  components, empty components, and `..`. Verify default extraction
  rejects each case before filesystem creation.
- **Hardlink no-follow targets**: create hardlinks whose target is an
  already-restored symlink, directory, device-like entry, missing path,
  or path reachable only by following a symlink/reparse ancestor. Verify
  default readers reject or skip with diagnostics and never follow the
  target outside the extraction root.
- **Compression registry enforcement**: mutate CryptoHeader to
  `compression_algo = None`; verify v0.36 readers reject it before
  payload or metadata decompression. Mutate `fec_algo` away from
  `ReedSolomonGF16` and verify readers reject before FEC planning.
- **Zstd frame validity**: mutate a FrameEntry slice to arbitrary bytes,
  to a truncated zstd frame, and to a valid zstd frame followed by
  trailing bytes inside `compressed_size`; verify readers reject before
  using decompressed payload.
- **BlockRecord CRC and kind validation**: corrupt every byte range
  covered by `record_crc32c`, set unknown `kind` values, set reserved
  bytes, set bit 0 on parity blocks, clear bit 0 on the last data block
  of an encrypted object, and set bit 0 on a non-final data block; verify
  readers reject.
- **Block index ordering**: duplicate, decreasing, and missing
  `block_index` values inside required object extents and across
  multi-volume reconstruction; verify readers reject unless explicit
  recovery mode repairs the gap.
- **Object extent overlap**: mutate two EnvelopeEntry rows, two
  ShardEntry rows, an IndexRoot dictionary extent, and a directory-hint
  extent so their global block-index ranges overlap. Verify random reads
  reject overlaps among loaded metadata and full-archive `verify`
  rejects every cross-object overlap unless the duplicate rows describe
  the exact same object identity and extent.
- **Striped block congruence**: for multi-volume archives, mutate one
  volume so a BlockRecord has `block_index mod stripe_width !=
  volume_index`, and mutate another so consecutive block indices differ
  by more than `stripe_width`; verify readers reject the volume even when
  other volumes are unavailable.
- **ManifestFooter bootstrap dependency**: corrupt all ManifestFooter
  copies while leaving IndexRoot blocks intact; verify random-access
  bootstrap fails unless a valid bootstrap sidecar is supplied.
- **Large-index root bound**: synthesize an archive plan with enough
  files that global FrameEntry/EnvelopeEntry tables would exceed one
  GF(2^16) FEC object. Verify IndexRoot contains only ShardEntry and
  metadata-object extent tables, while each IndexShard carries its local
  frame/envelope rows. Also synthesize a root table that still exceeds
  the IndexRoot FEC/u32 limits and verify the writer rejects "IndexRoot
  too large."
- **Directory hint sharding**: build directory hints whose entry table
  and string pool exceed 4 GiB in aggregate. Verify writers emit multiple
  DirectoryHintTable objects with 64-bit internal offsets and readers
  reject any single hint shard exceeding §18 object limits. Verify
  `DirectoryHintTable.shard_list_offset` and
  `DirectoryHintEntry.shard_list_start_index` point to an in-bounds u32
  shard-row-index range and reject ranges whose checked
  `start_index + shard_count` exceeds the array length, whose
  multiplication by 4 overflows, or whose row index is
  `>= IndexRoot.shard_count`. Also verify
  `max_directory_hint_shards` and
  `max_entries_per_directory_hint_shard` caps are enforced before large
  allocations.
- **Directory hint shard-count cap**: set
  `directory_hint_shard_count` above `max_directory_hint_shards` while
  keeping `shard_count` under `max_shard_count`; verify readers reject
  using the directory-hint cap rather than accepting because the generic
  IndexShard cap was not exceeded.
- **Directory hint lookup**: directory paths at root and nested levels,
  hash collisions, and boundary equality across hint shards. Verify the
  §15.8 lookup algorithm returns only verified candidate ShardEntry row
  indexes, then uses each row's stable `shard_index` only after reading
  that row from the IndexRoot ShardEntry table.
- **Required directory hints in verify**: create an archive with
  `file_count > directory_hint_required_file_count` but
  `directory_hint_shard_count = 0`. Verify ordinary directory-prefix
  extraction may fall back to scanning all IndexShards with a diagnostic
  when caps permit, but full-archive `verify` rejects the archive as
  writer-nonconformant.
- **Decompressed-size caps**: create metadata objects that decompress to
  more than their recorded u32 `decompressed_size` or more than
  `u32::MAX`; verify readers reject before allocation.
- **Block-size/product cap**: use a large `block_size` with class data
  shard maxima whose product would overflow u32; verify writers reject
  or reduce the effective data-shard limit and readers reject overflow.
- **GF16 object limit**: attempt to encode an object whose
  `data_block_count + parity_block_count` exceeds 65,535 under
  `ReedSolomonGF16`; verify writer and reader reject it.
- **Padding boundaries**: envelopes whose ciphertext length, including
  AEAD tag, would otherwise be exactly a multiple of BLOCK_SIZE (force
  the writer to add an extra BLOCK_SIZE of padding); verify reader
  correctly truncates.
- **Padding marker boundary**: fuzz payloads whose last compressed byte
  is 0xFF and verify the marker remains unambiguous because mandatory
  suffix padding occupies the envelope plaintext's final byte(s).
- **Wide-form padding**: envelopes where pad_len ≥ 255 (common when
  envelope is large and last frame is small); include malformed
  plaintexts with final byte 0xFF, N < 5, `pad_len < 5`, `pad_len > N`,
  and `pad_len = 0`. Verify all are rejected before subtraction or
  slicing.
- **Depadded payload length binding**: mutate a valid envelope so AEAD
  still authenticates but the suffix padding marker yields a depadded
  length different from `EnvelopeEntry.plaintext_size`; verify the reader
  rejects before applying any FrameEntry slice.
- **Envelope frame coverage**: mutate FrameEntry `compressed_size` or
  `offset_in_envelope` so an envelope's frame range no longer sums to or
  exactly covers `EnvelopeEntry.plaintext_size`; verify readers reject
  before decompression.
- **Session-bound AEAD**: two archives with the same raw key,
  archive_uuid, and envelope counter but different session_id; verify
  envelope and index splicing fails authentication.
- **Frame-addressed random access**: files whose tar member group starts
  at frame offset 0, starts mid-frame after another file, and spans
  multiple frames/envelopes. Verify extraction decodes frame ranges and
  slices decompressed frame plaintext, never envelope plaintext.
- **Object-local FEC repair**: corrupt one data block in a payload
  envelope, an index shard, and IndexRoot. Verify each object repairs
  using only its recorded data/parity block extent. Verify actual
  per-object parity counts are smaller for small objects than the class
  maximum.
- **Parity-block corruption**: corrupt parity BlockRecord payloads and
  CRCs independently. Verify CRC-detected corruption is treated as an
  erasure and any unrepaired or incorrectly repaired ciphertext still
  fails AEAD before plaintext release. Also tamper with a data
  BlockRecord and recompute its unkeyed CRC; verify the reader does not
  mis-release plaintext and reports AEAD/HMAC failure rather than
  claiming FEC availability.
- **Large tar member group**: one regular file larger than
  `envelope_target_size`; verify FileEntry.frame_count > 1 and random
  extraction streams the reconstructed tar member group correctly.
- **FileEntry tar binding**: mutate `FileEntry.file_data_size` so it no
  longer matches the main tar entry's logical size for a regular file,
  mutate a non-regular entry to a non-zero value, mutate a FileEntry path
  so it no longer matches the main tar entry path, shift a FileEntry
  start/size so it overlaps only part of a tar member group, omit a
  FileEntry for a tar member group, and add an extra FileEntry pointing
  into already-covered tar bytes. Verify extraction rejects path/size
  mismatch before writing and full-archive `verify` rejects any
  FileEntry/tar-member-group coverage mismatch.
- **Tar directory trailing slash canonicalization**: create directory
  main entries encoded both as `dir` and as the conventional tar
  directory name `dir/`, with FileEntry path `dir`. Verify both compare
  to the same normalized directory path, while non-directory `dir/`,
  `dir//`, and directory names with additional empty components are
  rejected.
- **Global tar metadata rejection**: create tar streams containing global
  PAX headers or other non-path-specific tar metadata records before
  otherwise valid member groups. Verify writers do not emit them and
  readers reject them rather than carrying global tar state across
  FileEntry boundaries.
- **Metadata profiles**: ustar-only entry, PAX long path, xattr/ACL
  profile entry, and sparse-file profile entry. Verify unsupported
  profiles report degraded metadata fidelity.
- **Hash-sorted index**: 1M files with various path distributions; verify
  binary search by hash succeeds for every file and rejects non-existent
  paths.
- **Hash collisions**: synthetically construct two paths whose 8-byte
  SHA-256 prefixes match; verify lookup correctly disambiguates by
  string compare. Also force a would-be shard-boundary collision and
  verify the writer extends the shard below `max_hash_prefix_run_files`
  and splits the run above that ceiling. Verify readers scan adjacent
  containing shards from the deterministic upper-bound landing point only
  up to `max_hash_collision_shard_scan` and fail clearly when the cap is
  exceeded.
- **Duplicate tar paths**: create a tar stream with multiple entries for
  the same normalized path. Verify FileEntry rows are ordered by
  increasing computed `tar_member_group_start`, default random-access
  extraction returns the final occurrence, and an explicit listing/history
  mode can expose earlier occurrences without changing default lookup
  semantics. Repeat through directory-prefix extraction and verify the
  default prefix view returns only the final occurrence for each
  normalized path.
- **Directory hints**: archive with many directories whose files hash
  into distant shards; verify prefix extraction uses hinted ShardEntry
  row indexes and still validates string-pool paths. Verify archives with
  more than `directory_hint_required_file_count` files include directory
  hint shards, and readers warn/fall back or fail clearly when required
  hints are absent or corrupt. Include an explicit empty directory entry
  and verify its own directory hint maps to the shard containing that
  directory FileEntry. Verify root lookup uses the empty directory string,
  `foo` matches `foo/bar`, and `foo` does not match `foobar`. Mutate the
  root DirectoryHintEntry to use `path_length = 0` with non-zero
  `path_offset` or a non-empty-string `dir_hash`, and mutate a non-root
  DirectoryHintEntry so its path range is outside the string pool; verify
  readers reject. Mutate a hint to omit one shard-row index, add an
  unrelated shard-row index, omit a required ancestor directory entry,
  add an extra directory entry, duplicate a directory entry, or
  duplicate/reorder shard-row indexes; verify full-archive `verify`
  rejects by recomputing the exact hint map from all FileEntries.
- **Structural validation**: malformed IndexRoot and IndexShard buffers
  with overflowing counts, invalid versions, non-zero reserved fields,
  invalid offsets, overlapping or out-of-order table ranges, unclaimed
  gaps, non-canonical IndexRoot and IndexShard cursor offsets,
  `directory_hint_shard_count > 0` with `shard_count = 0`, and
  out-of-range string-pool paths; verify rejection before allocation.
  Include an IndexShard whose
  `IndexShardHeader.shard_index` does not match the locating ShardEntry
  and an IndexShard with `file_count = 0`, plus duplicate ShardEntry
  `shard_index` values.
- **Counted zero tables**: IndexRoot with `shard_count = 0`,
  IndexShardHeader with zero local table counts, and DirectoryHintTable
  with `entry_count = 0`; verify corresponding offsets must be zero and
  are not rejected merely for pointing before the fixed header.
- **Directory hint shard ranges**: mutate DirectoryHintShardEntry ranges
  so `last_dir_hash > next.first_dir_hash`; verify lookup and verify
  reject before binary search.
- **Directory hint shard identity**: decrypt a valid DirectoryHintTable
  under one locating DirectoryHintShardEntry and mutate the table
  `hint_shard_index`; verify readers reject the structural mismatch even
  though AEAD identity is separately enforced by the counter/AAD.
- **Directory hint empty shard lists**: mutate a DirectoryHintEntry to
  `shard_count = 0`; verify readers reject rather than treating the hint
  as a successful empty candidate set.
- **Archive totals**: mutate `IndexRoot.payload_block_count` so it no
  longer equals the sum of distinct payload EnvelopeEntry
  `data_block_count` values; mutate `file_count`, `frame_count`, and
  `envelope_count`; introduce a global tar-stream gap or overlap across
  shards; mutate `IndexRoot.tar_total_size`; and mutate
  `content_sha256`. Verify full-archive `verify` rejects every mismatch
  after reconstructing the tzap tar stream.
- **Tar end marker policy**: create non-empty and empty archives and
  verify writers do not encrypt the POSIX two-zero-block
  end-of-archive marker, `tar_total_size` and `content_sha256` exclude
  it, and readers append exactly two synthetic zero blocks only when
  exporting or feeding a strict tar consumer.
- **Duplicate local table consistency**: duplicate the same global
  FrameEntry or EnvelopeEntry in multiple IndexShards with one byte
  changed; verify full archive verification and multi-shard reads reject.
- **Single-sink streaming rejection**: attempt `stripe_width > 1` with a
  fully non-reopenable sink; verify the writer rejects or requires local
  spooling instead of silently buffering unbounded data. Present a
  striped multi-volume archive as one unframed concatenated pipe and
  verify the reader rejects unless an external wrapper supplies original
  volume identity, block ordering, and terminal authentication.
- **Streaming IndexRoot FEC preselection**: feed a true streaming writer
  an unknown-size input. Verify it either selects conservative
  `index_root_fec_*` maxima before CryptoHeader HMAC, pre-scans/spools,
  or rejects; it must not emit an archive that requires changing
  CryptoHeader after payload metadata is known. Also force final
  IndexRoot serialization to exceed the selected class/u32 limits on a
  non-rewriteable sink and verify the writer rejects finalization rather
  than emitting a non-conforming archive.
- **Non-seekable sequential extract**: pipe a single-volume archive into
  the reader without a sidecar; verify sequential envelope extraction
  succeeds for `has_dictionary = 0` while listing/random extract fail
  clearly. Verify each depadded payload envelope is parsed as a
  concatenated zstd-frame stream without FrameEntry metadata, rejecting a
  truncated frame, a zero-progress decoder result, and trailing non-frame
  bytes. Repeat with `has_dictionary = 1` and no bootstrap sidecar; verify
  the reader rejects with "dictionary bootstrap required."
- **Sequential scan boundary**: append index, dictionary, and
  directory-hint BlockRecords after payload envelopes, then a valid
  ManifestFooter/trailer. Verify sequential extraction skips metadata
  BlockRecords, authenticates the terminal ManifestFooter/VolumeTrailer
  before reporting clean completion, and does not increment the envelope
  counter for skipped kinds. Change the terminal ManifestFooter to
  `is_authoritative = 0` and recompute its HMAC; verify sequential
  extraction refuses to report clean completion. Corrupt one envelope
  irrecoverably, including a CRC-failed data BlockRecord whose flags
  cannot be trusted, and verify the reader treats it as an erasure and
  does not attempt later envelopes when FEC cannot repair it. Truncate a
  stream after a valid envelope and append unauthenticated `TZMF` bytes;
  verify the reader reports unexpected EOF/tamper and does not append
  synthetic tar end-of-archive blocks.
- **Sequential optional-parity CRC failure**: create a dictionary-free
  archive with `volume_loss_tolerance = 0`, `bit_rot_buffer_pct = 0`,
  and `fec_parity_shards = 0`. Corrupt the CRC-covered bytes of the final
  data block of an envelope immediately followed by another payload
  envelope. Verify a pure sequential reader aborts before consuming the
  next envelope as part of the damaged one. Repeat with parameters that
  guarantee at least one parity block per payload envelope; verify the
  reader may continue only if the next trusted block is kind 1 and
  aborts if another kind-0 block appears before any parity run. Also
  place a payload BlockRecord after a metadata BlockRecord and verify
  sequential extraction rejects it as out-of-order.
- **Bootstrap sidecar**: dictionary archive with a bootstrap sidecar;
  verify `TZBS` header CRC, sidecar HMAC, UUID/session binding,
  ManifestFooter HMAC, IndexRoot AEAD, and dictionary-object AEAD are
  checked; verify IndexRoot and dictionary objects decrypt from sidecar
  BlockRecord copies and the dictionary is available before payload
  frame decompression. Verify the sidecar ManifestFooter uses
  `volume_index = 0`, has a valid HMAC computed over that sidecar
  instance, and can bootstrap while the opened VolumeHeader has another
  `volume_index`; mutate that value to non-zero after HMAC and verify
  rejection. Set sidecar `is_authoritative = 0` with a recomputed HMAC
  and verify rejection. Verify that byte-copying a per-volume
  ManifestFooter and then changing `volume_index` to zero fails HMAC
  unless the HMAC is recomputed for the sidecar instance. Verify sparse
  flag combinations follow the §12.3 cursor and authority rules: a
  sidecar with IndexRoot records but no ManifestFooter is usable only
  when an authenticated ManifestFooter is already available from another
  source, a sidecar with dictionary records is usable only after an
  authenticated IndexRoot declares the dictionary extent, and
  non-seekable bootstrap requires bits 0 and 1 (and bit 2 for dictionary
  archives). Mutate sidecar IndexRoot/dictionary
  BlockRecord sections to omit a required block, add an extra block,
  duplicate a block, mis-sort block indices, use the wrong kind, or set
  the last-data flag on the wrong copied data block; verify readers
  reject before trusting the sidecar object. Set BootstrapSidecarHeader
  `_reserved` bytes or flag bits 3..31 non-zero and verify rejection.
  Verify sidecars with padding, extension bytes, unclaimed gaps, or
  trailing bytes are rejected.
- **Bootstrap sidecar caps**: mutate sidecar record lengths and observed
  file size above the §13.3 derived sidecar cap, including
  near-`u64::MAX` lengths that still satisfy naive offset arithmetic;
  verify readers reject before buffering or allocating the declared
  sections. Verify the cap counts only present IndexRoot and dictionary
  record sections according to the sidecar flags.
- **Sidecar cap arithmetic**: use large `block_size` and large
  `index_root_fec_*` class maxima so the derived sidecar cap exceeds
  32-bit range; verify readers compute the cap with checked 64-bit or
  wider arithmetic and reject on overflow or when the cap exceeds the
  platform file-size/offset representation.
- **ManifestFooter pointer bounds**: mutate `manifest_footer_offset` and
  `manifest_footer_length` in VolumeTrailer to point outside the volume,
  before valid data, or to the wrong length; verify readers reject before
  seeking, allocating, or attempting ManifestFooter HMAC. Mutate
  authenticated `VolumeTrailer.block_count` so it no longer matches the
  BlockRecord byte region between CryptoHeader and ManifestFooter; verify
  readers reject after trailer HMAC verification and before object use.
  Insert bytes between ManifestFooter and VolumeTrailer while keeping
  HMACs internally valid; verify readers reject because the ManifestFooter
  no longer ends exactly at the selected trailer offset.
- **Trailer byte count and trailing garbage**: mutate authenticated
  `VolumeTrailer.bytes_written` so it no longer equals the selected
  trailer offset; verify seekable readers reject after trailer HMAC
  verification. Append trailing garbage within and beyond
  `max_trailing_garbage_scan`; verify bounded recovery accepts only an
  earlier authenticated trailer whose `bytes_written` equals its offset,
  warns, and rejects beyond the cap.
- **Volume tolerance constraints**: verify writers reject `N ≥ V` and
  force `N = 0` for fully non-reopenable `V = 1` streaming.
- **Forbidden CryptoHeader hash**: archive containing extension `0x0004`
  is rejected.
- **S3 round-trip**: write to actual S3 (or minio) via multipart upload;
  read back via Range requests; no seek-back used.
- **Dictionary**: archives created with and without dictionary; verify
  dictionary correctly bootstraps via IndexRoot's dictionary-object
  extent. Mutate `has_dictionary = 1` with zero required dictionary
  fields and verify readers reject before payload decompression.
- **IndexRoot manifest size canonicality**: mutate
  `ManifestFooter.index_root_encrypted_size` so it no longer equals
  `index_root_data_block_count * block_size`; verify readers reject
  before fetching or decrypting IndexRoot.
- **Trailer-from-end**: verify seekable readers first try the trailer at
  `file_size - 128`, then reject cleanly if the required VolumeHeader or
  CryptoHeader bytes are unavailable or if the volume is smaller than
  `sizeof(VolumeHeader) + sizeof(VolumeTrailer)`. Verify the optional
  trailing-garbage scan is bounded and only accepts an authenticated
  trailer candidate.
- **Metadata warnings**: unsupported PAX/GNU extension record, failed
  xattr/ACL application, timestamp precision loss, and sparse-file
  fallback all produce diagnostics unless best-effort quiet mode is
  explicitly enabled.

---

## 29. Conformance

A conformant writer:

1. Produces archives whose write sequence is strictly forward
   (no seek-back, no overwrite-in-place) and sets
   `format_version = 1`, `volume_format_rev = 36`, every fixed magic
   field to the value specified for its structure, and
   `crypto_header_offset = sizeof(VolumeHeader) = 128`.
2. Sorts the file table globally by
   `(SHA-256(normalized path)[0..8], normalized path bytes,
   tar_member_group_start)`, with duplicate normalized paths ordered by
   increasing tar-stream occurrence. For each IndexShard, emits a
   FileEntry table sorted by the same key and sets the locating
   ShardEntry `file_count`, `first_path_hash`, and `last_path_hash` to
   match the shard's actual FileEntry table.
3. Avoids splitting identical 8-byte path-hash prefixes below
   `max_hash_prefix_run_files`, and splits rather than creating
   unbounded shards above that ceiling.
4. Records FileEntry as the minimal decompressed zstd frame extent that
   contains that file's tar member group, never as a tar offset inside
   envelope plaintext and never with unrelated trailing frames.
5. Keeps every zstd frame wholly inside one envelope.
6. Records object-local FEC data/parity counts for every encrypted
   object.
7. Stores the ManifestFooter pointer in the VolumeTrailer and emits a
   per-volume ManifestFooter whose authenticated `volume_index` matches
   the containing volume and whose `is_authoritative = 1` for every
   closed completed volume. Sets `VolumeTrailer.block_count` to the
   number of BlockRecords physically written in that volume and writes no
   bytes after the VolumeTrailer.
8. Caps CryptoHeader extension payloads at 256 bytes each.
9. Stores any pre-trained zstd dictionary as an encrypted dictionary
   object located by IndexRoot, not in CryptoHeader or raw IndexRoot
   plaintext.
10. Applies suffix-marker padding (§6.1).
11. Binds AEAD nonce derivation and AAD to both `archive_uuid` and
   `session_id`.
12. Uses `stripe_width = 1` for fully non-reopenable single-sink
   streaming, sets `volume_loss_tolerance = 0` in that mode, and emits a
   §12.3 bootstrap sidecar if `has_dictionary = 1`.
13. Emits PAX/GNU tar extension records when claiming metadata beyond
   ustar baseline, and does not emit POSIX end-of-archive zero blocks
   into the encrypted tzap tar stream. Emits only path-specific tar
   metadata records inside the member group for the main entry they
   modify; never emits global PAX headers, global GNU state, or other
   non-path-specific tar metadata records that affect later unrelated
   groups.
14. Includes directory hint shards when
    `file_count > directory_hint_required_file_count` or when claiming
    cloud/object-store optimized directory-prefix operations (§15.8), and
    encodes directory hint shard lists as ShardEntry row indexes, not
    `shard_index` IDs. Directory hints include the root and every
    normalized ancestor directory of every FileEntry path, plus every
    FileEntry path whose decoded main tar entry is itself a directory.
    Each hint row's shard-row-index list is the exact sorted unique set
    of IndexRoot ShardEntry rows containing the directory entry itself,
    direct children, or descendants of that directory.
    DirectoryHintShardEntry `hint_shard_index` values are unique AEAD
    counters for directory-hint shard objects. Each
    DirectoryHintShardEntry describes a non-empty sorted
    DirectoryHintEntry table and records `entry_count`, `first_dir_hash`,
    and `last_dir_hash` values that match that table exactly.
15. Chooses per-object parity counts that satisfy the volume-loss and
    bit-rot recoverability rules in §7.3 and §18. A tzap CLI also
    auto-scales `G_parity` per §27 by default unless its documented
    unsafe override is used. Encodes `ReedSolomonGF16` parity with the
    exact §18 GF(2^16) Cauchy wire profile.
16. Rejects `volume_loss_tolerance N` values where `N ≥ V`, rejects
    `bit_rot_buffer_pct > 100`, and emits only data-shard class maxima
    greater than zero. Writers MUST set `stripe_width V ≥ 1` and every
    per-volume `volume_index` in `[0, V)`.
17. Never emits CryptoHeader extension tags `0x0004` or `0x0006`.
18. Derives subkeys with the §13.2 HKDF-SHA-256 schedule, including
    archive UUID and session ID in HKDF-Extract salt.
19. Uses the same AEAD counter value in nonce derivation and AAD,
    including counter 0 for IndexRoot, and serializes every AEAD object as
    `ciphertext || tag`.
20. Sets `compression_algo = ZstdFramed`, sets
   `fec_algo = ReedSolomonGF16`, sets `has_dictionary` to 0 or 1, and
   sets `chunk_size` to a non-zero writer target no larger than
   `envelope_target_size` and does not rely on it as an on-disk parsing
   boundary. Emits KDF parameter payloads exactly as §13.1 specifies,
    including
    `t_cost ≥ 1` and `m_cost_kib ≥ 8 × parallelism` for Argon2id, and
    feeds Argon2id the exact UTF-8 bytes of the NFC-normalized caller
    passphrase without
    archive-format newline trimming, BOM insertion/removal, NUL stripping,
    locale conversion, or platform-charset conversion.
21. Assigns payload envelope indices contiguously from 0 in write order.
22. Sets all reserved BlockRecord flag bits to zero, sets bit 0 on and
    only on the last data block of each encrypted object, emits exactly
    one bit-0 data block per encrypted object, and never sets bit 0 on
    parity blocks.
23. Keeps global FrameEntry and EnvelopeEntry tables out of IndexRoot;
    each IndexShard carries the exact sorted unique local FrameEntry rows
    needed by its FileEntry records and the exact sorted unique local
    EnvelopeEntry rows referenced by those frames. IndexShard-local
    EnvelopeEntry tables may be sparse subsets of the global contiguous
    envelope sequence, but they contain no unrelated or duplicate
    envelope indices. A local EnvelopeEntry may describe a global
    envelope frame range that includes frames stored only in other
    IndexShards; the writer does not add those unrelated FrameEntry rows
    to the local shard.
24. Splits metadata before any ReedSolomonGF16 FEC object would exceed
    65,535 total shards, and rejects if the non-splittable IndexRoot
    itself would exceed that limit. May choose IndexRoot/dictionary
    class maxima whose sum exceeds 65,535, but never emits an actual
    object whose `data_block_count + parity_block_count` exceeds 65,535.
25. Sets `FileEntry.flags = 0` and emits only NFC UTF-8 archive paths
    using `/` as the component separator; emits no unsafe archive paths
    (absolute paths, `.`, `..`, empty components, NUL bytes, backslash,
    colon, drive/UNC/device namespace forms, Windows device-name
    components, or other platform escape forms defined in §16), and emits
    hardlink targets that obey the same safe relative path rules.
    FileEntry path strings never contain trailing slashes. Directory main
    tar entries are compared after applying the §16 conventional
    one-trailing-slash directory canonicalization rule.
    Computes every FileEntry `path_hash` and DirectoryHintEntry
    `dir_hash` from the exact normalized string-pool bytes stored for
    that row; encodes the directory-hint root as `path_length = 0`,
    `path_offset = 0`, and `dir_hash = SHA-256(b"")[0..8]`. Every
    FileEntry path length is at least 1 and no greater than
    `CryptoHeader.max_path_length`; every FileEntry has
    `frame_count ≥ 1`, `tar_member_group_size ≥ 512`, and a
    decoded main tar entry whose normalized archive path equals the
    FileEntry path and whose logical payload size equals
    `file_data_size`. Distinct FileEntry extents cover the parsed tzap tar
    member group sequence exactly once.
26. Ensures every encrypted object's `encrypted_size` equals
    `data_block_count * block_size` and fits in `u32`; also ensures
    every recorded u32 plaintext/decompressed size field fits in `u32`.
    Splits a payload envelope before exact-fit padding would force an
    extra block that violates the u32 or FEC object limits.
    Chooses every encrypted object's data-block count only when the computed
    per-object parity count fits the class maximum and the data/parity
    total fits the ReedSolomonGF16 limit.
27. Emits valid empty archives when `file_count = 0` rather than inventing
    placeholder files or shards.
28. Never emits a payload envelope with `frame_count = 0`,
    `plaintext_size = 0`, or no complete zstd frames, and never emits a
    FrameEntry with zero compressed or decompressed size. Every FrameEntry
    slice encodes exactly one complete zstd frame. Never emits any
    present encrypted object with `data_block_count = 0` or
    `encrypted_size = 0`.
    Encodes each metadata object as exactly one complete non-skippable zstd
    frame and emits no metadata-object trailing bytes, skippable frames, or
    concatenated frames.
29. Sizes IndexShards so `file_count ≤ max_files_per_index_shard`
    (1,000,000 in this draft).
30. Emits only BlockRecord kinds 0 through 9, never reserved kind values,
    emits `BlockRecord.magic = b"TZBK"`, and zeroes every `_reserved*`
    field.
31. Generates `archive_uuid` and `session_id` from a CSPRNG with at least
    128 bits of entropy each.
32. Writes BlockRecords for each volume in strictly increasing
    `block_index` order, with each `block_index ≡ volume_index (mod
    stripe_width)` and consecutive records in that volume spaced exactly
    by `stripe_width`; never emits duplicate global block indices and
    never emits duplicate volume indexes in the same volume set.
33. Emits `IndexShardHeader.version = 1` and uses domain-separated HMAC
    inputs for CryptoHeader, ManifestFooter, VolumeTrailer, and
    BootstrapSidecarHeader.
34. Sets all IndexRoot dictionary fields to zero whenever
    `has_dictionary = 0`; when `has_dictionary = 1`, emits a non-empty
    dictionary object with non-zero `dictionary_first_block`,
    `dictionary_data_block_count`, `dictionary_encrypted_size`, and
    `dictionary_decompressed_size`.
35. Emits v0.36 bootstrap sidecars as packed sequences with no padding,
   extension bytes, unclaimed gaps, or trailing bytes. If a
   ManifestFooter is present in a sidecar, freshly serializes that
   sidecar ManifestFooter with `volume_index = 0` and
   `is_authoritative = 1`, and computes its `manifest_hmac` over the
   sidecar bytes; does not mutate a per-volume ManifestFooter after
   HMAC. Emits non-seekable bootstrap sidecars with ManifestFooter and
   IndexRoot BlockRecord sections present, and includes dictionary
   BlockRecord sections whenever `has_dictionary = 1`.
36. Emits zero offsets for absent counted tables and no non-zero
    zero-count table pointers.
37. Sets `IndexRoot.file_count`, `frame_count`, `envelope_count`,
    `payload_block_count`, `tar_total_size`, and `content_sha256` to the
    values obtained from the distinct global file/frame/envelope rows and
    the exact reconstructed tzap tar stream, excluding any synthetic
    POSIX end-of-archive marker. Assigns non-overlapping global
    block-index ranges to all distinct encrypted objects.
38. Chooses `index_root_fec_data_shards` and
    `index_root_fec_parity_shards` before emitting the CryptoHeader HMAC;
    unknown-size streaming writers either choose conservative maxima,
    pre-scan/spool, or reject rather than depending on a later header
    change.

A conformant reader:

1. On seekable input, locates the VolumeTrailer by seeking to
   `file_size - 128`; performs the bounded trailing-garbage recovery
   scan in §17.1 only if the canonical trailer candidate fails
   authentication. Rejects any VolumeHeader whose magic is not `TZAP` or
   whose `crypto_header_offset` is not `sizeof(VolumeHeader)`, and
   rejects any authenticated volume whose `volume_index >= stripe_width`.
2. Locates the ManifestFooter from the trailer or from a trusted
   bootstrap sidecar, not from VolumeHeader.
3. Rejects non-authoritative ManifestFooter copies for random-access
   bootstrap.
4. On non-seekable input without a sidecar, either performs sequential
   extraction (§17.3) for non-dictionary archives or rejects operations
   that require random access or dictionary bootstrap clearly.
5. Strips padding by reading the final byte (and possibly 4 more for
   wide form), not by scanning from the start.
6. Rejects wide-form padding with `N < 5`, `pad_len < 5`,
   `pad_len > N`, or `pad_len = 0` before indexing, subtracting, or
   slicing.
7. Searches the file table by
   `(SHA-256(normalized path)[0..8], normalized path bytes)`, not by
   string compare on partial path bounds. If multiple FileEntries have
   the exact same normalized path, returns the one with the greatest
   computed `tar_member_group_start` unless the caller explicitly asks
   for all occurrences. For user path extraction, performs this exact
   lookup before using directory-prefix hints; a regular-file exact match
   is extracted as that file and is not looked up through the directory
   hint table as if hints were an exact-file index. Directory-prefix
   extraction applies the same final-view rule per normalized path by
   default.
8. Uses the §15.4 upper-bound-on-`first_path_hash` lookup rule, includes
   the final row as the landing candidate when no first hash is greater
   than the target, includes the landing shard in the candidate block,
   and scans adjacent containing shards subject to
   `max_hash_collision_shard_scan`.
9. Validates IndexRoot, IndexShard, and DirectoryHintTable magic fields,
   structural counts, offsets, canonical table order, exact shard-local
   FrameEntry and sparse EnvelopeEntry semantics, ShardEntry/IndexShard
   and DirectoryHintShardEntry/DirectoryHintTable count and hash-bound
   bindings, stored path/hash bindings, and non-overlap before allocation
   or indexing. For local
   EnvelopeEntry validation, it checks referenced FrameEntry slices
   without requiring unrelated frames from the same global envelope to be
   present in that shard.
10. Reconstructs random-access file bytes by decoding the minimal
   FileEntry frame range and slicing decompressed frame plaintext; rejects
   FileEntry ranges that include unrelated trailing frames.
11. Uses object-local FEC counts from ManifestFooter, EnvelopeEntry,
   ShardEntry, DirectoryHintShardEntry, or IndexRoot dictionary fields to
   repair encrypted objects only after checking `encrypted_size =
   data_block_count * block_size` with checked unsigned 64-bit-or-wider
   arithmetic and checking class limits.
12. Loads the zstd dictionary (if `has_dictionary = 1`) from the
   dictionary object located by IndexRoot before decompressing any
   payload envelope.
13. Reports degraded metadata fidelity when the relevant tar extension
   profile is unsupported or metadata application fails.
14. Enforces all resource caps from §13.3, including bootstrap sidecar
    size, directory-hint shard count, directory-hint entry count, and
    total extraction size.
15. Structurally validates CryptoHeader Extension TLVs before KDF/HMAC
   using only bounded framing rules; after CryptoHeader HMAC succeeds,
   rejects forbidden extension tags `0x0004` and `0x0006`, duplicate
   known tags, malformed known extension values, and unknown critical
   extension tags, while ignoring unknown non-critical extensions.
16. Validates §12.3 sidecar HMAC, UUID/session binding,
    known flag bits, zero reserved bytes, ManifestFooter HMAC, IndexRoot AEAD, and
    dictionary-object AEAD when present before trusting bootstrap sidecar
    bytes. It MAY use sidecar CRC as an early corruption check. For a
    sidecar ManifestFooter, requires `volume_index = 0` and
    `is_authoritative = 1`, and does not compare that zero volume index
    with the current VolumeHeader. Uses sidecar BlockRecord sections only
    with an authenticated ManifestFooter and, for dictionary records, an
    authenticated IndexRoot from the sidecar or another source; requires
    ManifestFooter and IndexRoot sections for non-seekable sidecar
    bootstrap.
17. Derives subkeys with the §13.2 HKDF-SHA-256 schedule and verifies
    CryptoHeader HMAC with the VolumeHeader UUID/session binding.
18. Rejects unknown algorithm IDs, `compression_algo != ZstdFramed`,
    `fec_algo != ReedSolomonGF16`, `has_dictionary` values other than 0
    or 1, `volume_loss_tolerance >= stripe_width`,
    `bit_rot_buffer_pct > 100`, zero data-shard class maxima,
    `chunk_size = 0`, `envelope_target_size = 0`, `chunk_size >
    envelope_target_size`, `block_size < 4096`, odd `block_size`, and
    `chunk_size`, `envelope_target_size`, `block_size`, or CryptoHeader
    byte lengths above configured reader caps, and rejects
    non-canonical CryptoHeader offsets. Before running
    the KDF, rejects unknown `kdf_algo`, verifies
    that the selected KdfParams payload fits inside CryptoHeader, verifies
    the KdfParams `algo_tag` matches `CryptoHeader.kdf_algo`, rejects
    Argon2id `t_cost = 0`, and
    structurally scans Extension TLVs only for bounded framing, payload
    length caps, valid terminator encoding, and exact terminator
    placement before the HMAC. It then treats the validated `chunk_size`
    and `expected_volume_size` as advisory metadata only; FrameEntry,
    EnvelopeEntry, and authenticated trailer/footer offsets remain
    authoritative.
19. Rejects BlockRecords with magic other than `TZBK`, reserved flag bits
    set, unknown `kind` values, non-zero reserved bytes, bit 0 set on
    parity blocks, bit 0 missing from an encrypted object's last data
    block, or bit 0 set on a non-final data block; within each encrypted
    object's data-block run, requires exactly one bit-0 flag and requires
    it on the final data block.
20. For sequential extraction, derives each payload envelope AEAD counter
    from a local contiguous counter starting at 0 and incremented only
    after a complete payload envelope authenticates. Infers each
    envelope's parity set from consecutive kind-1 BlockRecords following
    the last data block, bounded by `CryptoHeader.fec_parity_shards`.
    Metadata objects do not affect the payload envelope counter. If a
    payload-data block fails CRC before the envelope authenticates, aborts
    before consuming later kind-0 blocks unless the archive parameters
    guarantee at least one parity BlockRecord for every payload envelope
    and the next trusted block starts the tentative parity run. Rejects a
    payload BlockRecord that appears after any metadata BlockRecord in
    sequential mode. After depadding an authenticated sequential payload
    envelope, parses the envelope plaintext as a concatenated zstd-frame
    stream and rejects zstd failure, truncated frames, zero-progress
    decode, or trailing non-frame bytes.
    Before reporting clean extraction or appending synthetic tar EOF
    blocks, verifies authenticated authoritative terminal
    ManifestFooter/VolumeTrailer material; after an irrecoverable
    envelope, non-authoritative terminal footer, or terminal-authentication
    failure, does not continue or seal the tar stream by guessing a
    counter, boundary, or clean EOF. Treats any live bytes emitted before
    terminal authentication as provisional, and in default filesystem
    extraction stages or quarantines writes until terminal authentication
    succeeds.
21. Rejects any ReedSolomonGF16 object whose
    `data_block_count + parity_block_count` exceeds 65,535, and repairs
    only with the exact §18 GF(2^16) Cauchy wire profile for this
    `FecAlgo`.
22. Uses shard-local FrameEntry and sparse shard-local EnvelopeEntry
    tables for random extraction; IndexRoot is not expected to contain
    global copies.
23. Rejects non-zero `FileEntry.flags`, unsafe archive paths, and
    FileEntry paths with `path_length = 0` or length greater than
    `CryptoHeader.max_path_length`; rejects FileEntry `path_hash` and
    DirectoryHintEntry `dir_hash` values that do not match the SHA-256
    prefix of their normalized string-pool bytes; rejects FileEntries with
    `frame_count = 0` or `tar_member_group_size < 512`, FrameEntries with
    zero compressed/decompressed size or slices that do not decode as
    exactly one complete zstd frame, FileEntry tar member groups whose
    main tar entry path or size does not match the FileEntry path or
    `file_data_size` when decoded, and encrypted objects whose
    `encrypted_size` does not equal `data_block_count * block_size`
    computed with checked unsigned 64-bit-or-wider arithmetic. During
    extraction, prevents writes outside the extraction root by enforcing
    the platform-escape rejection set, no-follow ancestry checks,
    rejecting unsafe hardlink targets, rejecting hardlinks whose targets
    require following symlinks/reparse points or are not already-restored
    regular files, and rejecting or skipping symlinks that would escape
    the extraction root unless an explicit unsafe mode is requested.
    Rejects global PAX headers, global GNU state, and other
    non-path-specific tar metadata records rather than carrying mutable
    tar state across FileEntry boundaries.
24. Verifies authenticated VolumeTrailer and per-volume ManifestFooter
    identity fields match the VolumeHeader before using bootstrap data,
    verifies seekable `bytes_written` equals the selected trailer offset
    (normally `file_size - 128`, or an authenticated recovery-scan
    candidate), verifies `VolumeTrailer.block_count` matches the observed
    BlockRecord region before the ManifestFooter, verifies that the
    ManifestFooter ends exactly at the selected trailer offset, and
    range-checks `manifest_footer_offset` / `manifest_footer_length`
    before reading the ManifestFooter.
25. Rejects empty or zero-data-block payload envelopes; rejects
    zero-data-block IndexRoot, IndexShard, dictionary, and
    DirectoryHintTable objects; and rejects any IndexRoot, IndexShard,
    dictionary object, or DirectoryHintTable object that exceeds its FEC,
    u32 size-field, or reader resource limits.
    Rejects metadata-object compressed payloads that are not exactly one
    complete non-skippable zstd frame consuming the entire depadded
    plaintext.
26. Rejects any parsed structure with non-zero `_reserved*` fields unless
    a later format version explicitly assigns that field.
27. Verifies that BlockRecords within a volume are strictly increasing by
    `block_index`, that each block satisfies
    `block_index mod stripe_width = volume_index`, and that consecutive
    records in the same volume are spaced by exactly `stripe_width`.
    When reconstructing a complete global order across volumes, verifies
    that no two BlockRecords share the same `block_index` and that no
    global block index is missing. Rejects duplicate supplied
    authenticated volume indexes by default unless an explicit
    duplicate-copy recovery mode proves the duplicate data identical for
    the requested operation. Duplicate or decreasing block indices are
    hard errors; gaps inside a declared object extent are hard errors
    unless the reader is in an explicit recovery mode that can repair the
    missing blocks.
28. Rejects unsupported `volume_format_rev`, mismatched
    `VolumeHeader.stripe_width`, `CryptoHeader.stripe_width`, or
    `ManifestFooter.total_volumes`, zero stripe/volume counts,
    `VolumeHeader.crypto_header_offset != sizeof(VolumeHeader)`,
    `CryptoHeaderFixed.length != VolumeHeader.crypto_header_length`, bad
    fixed magic fields, and truncated or excessive KDF parameters before
    attempting expensive work.
29. Rejects `dictionary_data_block_count = 0` with any non-zero IndexRoot
    dictionary field, `has_dictionary = 0` with non-zero IndexRoot
    dictionary fields, `has_dictionary = 1` with missing or zero required
    dictionary object fields, unrecognized IndexShard versions, invalid
    zero-count table offsets, IndexShard `shard_index` mismatches,
    DirectoryHintTable `hint_shard_index` mismatches, DirectoryHintEntry
    rows with `shard_count = 0`, zero-length DirectoryHintEntry paths
    whose `path_offset` or `dir_hash` is not the canonical root encoding,
    duplicate ShardEntry `shard_index` values, duplicate
    DirectoryHintShardEntry `hint_shard_index` values, duplicate
    DirectoryHintEntry paths when observed, invalid DirectoryHintShardEntry
    ordering, shard-row-index values outside the IndexRoot ShardEntry
    table, invalid shard-list ranges, and
    non-matching duplicate FrameEntry/EnvelopeEntry rows when observed.
30. Rejects sidecars that are not packed exactly as §12.3 specifies.
31. During full-archive `verify`, checks that
    `IndexRoot.file_count`, `frame_count`, `envelope_count`,
    `payload_block_count`, `tar_total_size`, and `content_sha256` match
    the distinct shard-local rows and the exact reconstructed tzap tar
    stream, including global envelope frame coverage and global
    tar-stream coverage with no gap or overlap.
    Parses the reconstructed tar stream into tar member groups and
    verifies distinct FileEntry extents match those groups exactly, with
    no missing, extra, duplicate, overlapping, or misbound FileEntries.
    Verifies all distinct encrypted-object block ranges are
    non-overlapping unless duplicate records describe the same object
    identity and extent.
    If directory hints are present, recomputes the exact
    directory-to-ShardEntry-row map from all validated FileEntries and
    rejects missing, extra, incomplete, duplicate, or misordered hint
    entries. If `IndexRoot.file_count` exceeds
    `directory_hint_required_file_count`, rejects missing directory hints
    rather than treating a full-shard-scan fallback as a clean verify.
    Appends a synthetic POSIX end-of-archive marker only when presenting
    bytes to a strict tar consumer or exporting a complete tar file.

---

## 30. Open Questions / Future Work

1. Optional full secondary path-sorted index for fast alphabetical
   listing on huge archives. Directory hints accelerate prefix
   extraction but are not a complete sorted listing index.
2. Append support.
3. Multi-recipient key wrap; public-key (age-style) mode.
4. Detached signatures.
5. Mid-stream readable checkpoints for very large streaming archives.
6. Per-file content_sha256 in FileEntry (optional, for random-access
   verification).
7. Two-level or continuation IndexRoot for archives whose root tables
   exceed the single-object FEC/u32 size limits.
8. Formally key-committing AEAD mode or a mandatory detached signature
   profile for deployments that require key-commitment properties beyond
   archive-bound HMAC wrong-key detection.
9. Optional keyed per-BlockRecord tamper locator/MAC for deployments that
   need FEC availability against active modification, not just accidental
   corruption and missing shards.
10. Optional redundant envelope-length metadata in BlockRecord or an
   envelope table for stronger sequential extraction diagnostics after
   unrecoverable bit errors.

---

## 31. Glossary

- **Block** — fixed-`BLOCK_SIZE` ciphertext/parity; FEC unit.
- **Envelope** — packed group of zstd frames; AEAD unit.
- **Frame** — one zstd frame; compression unit.
- **FEC object** — one encrypted object repaired with its own data/parity
  block extent: payload envelope, index shard, or IndexRoot. IndexRoot
  still needs ManifestFooter or bootstrap sidecar metadata to locate that
  extent.
- **Group** — `G_total = data_block_count + parity_block_count` blocks;
  FEC math unit for one object.
- **Shard** — independent encrypted/FEC-protected segment of the file table.
- **Index Root** — small encrypted root object with archive totals,
  ShardEntry records, and optional metadata-object extents; it does not
  contain global frame/envelope tables or raw dictionary bytes.
- **Tar member group** — all tar records needed to restore one logical
  archive path, including path-specific metadata records and main entry.
- **tzap tar stream** — concatenated tar member groups stored in zstd
  frames, excluding the POSIX two-zero-block end-of-archive marker.
- **Stripe width V** — number of volumes; `volume = block_index mod V`.
- **session_id** — CSPRNG-generated 16-byte per-write-invocation value;
  distinguishes archives even when archive_uuid coincides.
- **Suffix-marker padding** — padding scheme where the last byte of the
  envelope plaintext encodes the padding length (extending to a 5-byte
  wide form for pad_len ≥ 255).

---

## Appendix A: All changes from v0.35 -> v0.36

| Section | Change |
|---|---|
| §8 / §17.1 / §23 / §28.1 / §29 | `volume_format_rev` is bumped to 36 |
| §15.6 / §15.9 / §17.2 / §28.1 / §29 | Requires FileEntry frame ranges to be minimal and rejects unused trailing referenced frames |
| §15.8 / §28.1 / §29 | Separates exact path extraction from directory-prefix hints so regular-file exact matches are not resolved through the directory-hint table |

---

*End of v0.36 specification.*
