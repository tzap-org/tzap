# tzap Archive Format Specification (v0.42)

| Field | Value |
|---|---|
| **Format version** | 1 |
| **Document version** | 0.42 / 2026-05-30.2 (optional encryption: unencrypted protection mode; all open decisions resolved) |
| **Status** | Superseded draft — never released; consolidated into v0.43 |
| **Owner** | Frank Zhu |
| **Maintainers** | Frank Zhu |
| **Last updated** | 2026-05-30 |
| **Supersedes** | v0.1 … v0.40, v0.41 |
| **Superseded by** | **v0.43** (standalone merge of this delta into the full spec, with unified versioning). This v0.42 delta draft was never released. |
| **Base document** | `specs/tzap-format-revisedv41.md` (this draft is a **delta** on v0.41) |
| **Conflict rule** | v0.42 inherits the entire v0.41 specification unchanged **except** where this document explicitly overrides it. Where this document conflicts with v0.41, v0.42 wins. Where this document is silent, v0.41 text is normative. |
| **File extension** | `.tzap` (single-volume) / `.volNNN.tzap` (multi-volume, e.g. `backup.vol000.tzap`, `backup.vol001.tzap`, …) |

> **Editorial note.** This is a deliberately delta-style specification: it
> inherits the entire ~7,300-line v41 base and specifies only the new
> *unencrypted protection mode* and every place the existing keyed pipeline must
> branch on it. All design decisions are resolved (§14); there are no open
> items. An implementer needs this document plus `tzap-format-revisedv41.md`.

---

## 1. Summary of the change

v0.41 always applies authenticated encryption (AEAD) to every payload and
metadata object, and always derives the working keys from a master key. The
"no password" convenience path (`--insecure-zero-key`) still runs the **full**
key schedule and **full** per-byte AEAD with a publicly known all-zero key.
That is wasted computation: it provides no confidentiality yet pays the entire
cryptographic cost.

v0.42 makes encryption **optional**, the same way RootAuth signing is optional.
It introduces an **unencrypted protection mode** selected by a new registry
value `aead_algo = None`. In that mode:

- No key derivation function (KDF) runs.
- No HKDF subkey schedule runs.
- No per-byte AEAD encryption/decryption runs.
- No per-byte authentication tag is computed or stored.
- Payload and metadata objects are stored as plaintext (still zstd-compressed,
  still padded, still FEC-protected, still block-framed).
- Per-block `record_crc32c` (already mandatory in v41) provides corruption
  detection.
- Keyed footer/header HMACs are replaced by unkeyed digests over the same
  bytes (small, fixed-size inputs; negligible cost).
- **Tamper-evidence**, when required, is provided by the existing optional
  RootAuth signature (v41 §30.7), which is asymmetric and does not depend on
  any archive secret.

Encrypted archives are otherwise **unchanged from v41** (see §13). The only
mandatory change for an encrypted archive is the revision bump to 42.

**Primary goal:** eliminate the per-byte and key-schedule computation for the
common no-secret case while preserving tar/zstd bundling, FEC, volume-loss
resilience, critical-metadata recovery, random access, and optional signed
authenticity.

---

## 2. Changelog from v0.41

v0.42 is **not** wire-compatible with v0.41: writers set
`VolumeHeader.volume_format_rev = 42`, and v0.41-only readers reject v0.42
archives (v41 §30.3 already requires readers to reject unexpected revisions).

1. **New protection-mode selector.** `AeadAlgo::None = 0` is promoted from a
   reserved value to the *unencrypted protection mode* (§4, §5).
2. **New KDF selector.** `KdfAlgo::None = 2` denotes "no key material" and is
   the only legal `kdf_algo` when `aead_algo = None` (§4, §6).
3. **Object tag length is mode-dependent.** A new constant `OBJECT_TAG_LEN`
   replaces every textual use of `AEAD_TAG_LEN` in object framing,
   sizing, and padding math. `OBJECT_TAG_LEN = AEAD_TAG_LEN` in encrypted
   mode and `0` in unencrypted mode (§7).
4. **Pipeline branch.** The "AEAD-encrypt" stage becomes a no-op in
   unencrypted mode; the read path skips decryption and depads directly (§8).
5. **Metadata objects may be plaintext.** IndexRoot, IndexShards, dictionary,
   and directory-hint objects are stored unencrypted in unencrypted mode (§9).
6. **Unkeyed integrity for headers/footers.** `header_hmac`, `manifest_hmac`,
   `trailer_hmac`, and `sidecar_hmac` are reinterpreted as unkeyed SHA-256
   digests in unencrypted mode, at the same offset and size (§10).
7. **Integrity model restated.** In unencrypted mode, symmetric integrity is
   downgraded to *corruption detection*; *tamper-evidence* is available only
   through optional RootAuth signing (§11, §12).
8. **Confidentiality goal made conditional** (§3).
9. **Revision gate.** `volume_format_rev = 42`; cross-field consistency rules
   added (§4.3, §13).
10. **Password is optional; `--insecure-zero-key` removed.** Producing a
   no-secret archive no longer means "encrypt under a public all-zero key"; it
   means selecting the unencrypted mode and skipping the cryptography. When no
   passphrase or keyfile is requested, the writer defaults to unencrypted mode
   (§13). The v41 `--insecure-zero-key` path is removed (§13, §14).

---

## 3. Design-goal deltas (overrides v41 §1)

- **Goal 1 — Confidentiality (now conditional).** When an encryption mode is
  selected (`aead_algo ∈ {AesGcmSiv256, XChaCha20Poly1305, AesGcm256}`),
  confidentiality is exactly as in v41 §1.1. When `aead_algo = None`, the
  archive provides **no confidentiality**: file contents, names, per-file
  metadata, and the random-access index are readable by anyone who can read
  the bytes. This is the explicit, opt-in behavior of unencrypted mode.
- **Goal 2 — Integrity (refined).** In encrypted mode, integrity is as in
  v41 §1.2. In unencrypted mode, modification or corruption of a stored object
  is **detected** (per-block CRC32C, structural block-continuity rules, and
  header/footer digests), but detection is not *authenticated*: an actor who
  rewrites the bytes can also recompute the CRCs and digests. Cryptographic
  **tamper-evidence** in unencrypted mode requires the optional RootAuth
  signature (§12). Readers MUST NOT report an unencrypted, unsigned archive as
  cryptographically authenticated.
- **Goals 3–N (recovery, random access, bit-rot/volume-loss resilience,
  bootstrap).** Unchanged. All FEC, CMRA, striping, and bootstrap machinery
  operate identically on plaintext objects.

### 3.1 Unencrypted-mode threat model

This replaces the confidentiality/authenticity assumptions of v41 §3 when
`aead_algo = None`. v41 §3 lists "wrong-passphrase" as an attack surface; that
surface does not exist in unencrypted mode because there is no key.

- **Confidentiality: none.** An unencrypted archive offers no protection of
  contents, names, sizes, or the index against any party who can read the
  bytes. Callers MUST select an encryption mode (passphrase or keyfile) if
  confidentiality is required.
- **Accidental corruption: detected.** Per-block CRC32C, the structural
  block-continuity rules (v41 §10), the unkeyed header/footer digests (§10),
  Reed-Solomon FEC, and CMRA detect and where possible repair bit-rot,
  truncation, and volume loss exactly as in encrypted mode.
- **Intentional tampering by an active adversary:**
  - *Without RootAuth:* **not** resisted. An adversary who rewrites the bytes
    recomputes every CRC and unkeyed digest. Detection of malicious
    modification is not provided. Readers MUST NOT present an unsigned
    unencrypted archive as authenticated.
  - *With RootAuth (recommended for distribution):* resisted. The signed
    `archive_root` (v41 §30.9) binds the metadata and the data-block Merkle
    root; forging it requires the signer's private key, which is independent of
    the archive's (absent) encryption key. `verify --public-no-key` detects any
    modification.
- **Out of scope, unchanged from v41:** unavoidable traffic-analysis metadata
  (volume count, sizes, block geometry) — now joined by full content visibility
  as the explicit consequence of choosing this mode.

---

## 4. Protection mode

### 4.1 Definition

The **protection mode** of an archive is determined solely by
`CryptoHeaderFixed.aead_algo`:

| `aead_algo` | Mode | Confidentiality | Object authenticity |
|---|---|---|---|
| `0` `None` | **Unencrypted** | none | none (CRC + digest only); tamper-evidence via optional RootAuth |
| `1` `AesGcmSiv256` | Encrypted | yes | AEAD |
| `2` `XChaCha20Poly1305` | Encrypted | yes | AEAD |
| `3` `AesGcm256` | Encrypted | yes | AEAD |

The protection mode is a single switch. There is no per-object override: an
archive is either fully encrypted or fully unencrypted.

### 4.2 The `CryptoHeader` in unencrypted mode

The structure formerly described purely as the "crypto header" (v41 §9, magic
`TZCH`) is retained byte-for-byte. In unencrypted mode it carries no
secret-derived material; it still carries the algorithm registry, geometry
fields (`block_size`, `stripe_width`, FEC class counts, …), the KdfParams
selector, the Extension TLV list, and a trailing 32-byte integrity field
(reinterpreted per §10). Its name is kept for layout stability.

### 4.3 Cross-field consistency rules (new; readers MUST enforce)

A v0.42 reader MUST reject a CryptoHeader unless all of the following hold,
checked before any object processing:

1. `aead_algo` is one of `{0,1,2,3}`.
2. If `aead_algo = None` then `kdf_algo = None` (§6) and the KdfParams payload
   is the 2-byte `None` form (§6.2). Any other `kdf_algo` with
   `aead_algo = None` is malformed.
3. If `aead_algo ≠ None` then `kdf_algo ∈ {Raw, Argon2id}` exactly as in v41
   §13; `kdf_algo = None` with an encryption algorithm is malformed.
4. `compression_algo = ZstdFramed` and `fec_algo = ReedSolomonGF16` (unchanged
   from v41 §5; compression and FEC are independent of the protection mode).
5. `volume_format_rev = 42` in every VolumeHeader of a v0.42 archive.

Unknown algorithm IDs remain hard errors. Range `0xFF00..0xFFFF` remains
reserved for experimental use.

---

## 5. Registry change (overrides v41 §5)

```rust
#[repr(u16)]
enum AeadAlgo { None = 0, AesGcmSiv256 = 1, XChaCha20Poly1305 = 2, AesGcm256 = 3 }
```

`AeadAlgo::None` is no longer reserved; it selects the unencrypted protection
mode. The AEAD parameter table gains a row:

| `aead_algo` | Algorithm | `AEAD_NONCE_LEN` | `AEAD_TAG_LEN` |
|---|---|---:|---:|
| 0 | None (unencrypted) | 0 | 0 |
| 1 | AES-256-GCM-SIV | 12 | 16 |
| 2 | XChaCha20-Poly1305 | 24 | 16 |
| 3 | AES-256-GCM | 12 | 16 |

`CompressionAlgo` and `FecAlgo` are unchanged; `ZstdFramed` and
`ReedSolomonGF16` remain mandatory regardless of protection mode.

---

## 6. Key derivation in unencrypted mode (overrides v41 §13)

### 6.1 KdfAlgo

```rust
#[repr(u16)]
enum KdfAlgo { Raw = 0, Argon2id = 1, None = 2 }
```

`KdfAlgo::None = 2` means **no key material exists**. When `kdf_algo = None`:

- No master key is derived.
- The HKDF-Extract/Expand subkey schedule of v41 §13.2 is **not run**. None of
  `enc_key`, `mac_key`, `nonce_seed`, `index_root_key`, `index_shard_key`,
  `dictionary_key`, `dir_hint_key`, or `index_nonce_seed` exist.
- No salt is stored or consumed.

`KdfAlgo::None` is legal **only** with `aead_algo = None` (§4.3).

### 6.2 KdfParams for `None`

For `KdfAlgo::None`, the KdfParams payload is exactly two bytes:
`algo_tag: u16 = 2`. The Extension TLV list begins immediately after those two
bytes. Readers MUST verify the two bytes are present and that `algo_tag`
equals `CryptoHeader.kdf_algo` (= 2) before continuing, mirroring the v41 §13
Raw-mode rule. There is no salt, padding, or alignment field.

### 6.3 Identity fields are retained

`archive_uuid` and `session_id` remain present and remain bound into header,
footer, RootAuth, and BlockRecord identity checks. In unencrypted mode they no
longer serve an anti-replay/nonce-uniqueness purpose; they remain
identity/domain-separation inputs to the unkeyed digests of §10 and to RootAuth
(§12). Writers MUST still populate them per v41 §8.

---

## 7. Object framing in unencrypted mode (overrides v41 §6.1, §14.2, §14.3)

### 7.1 `OBJECT_TAG_LEN`

Introduce the constant `OBJECT_TAG_LEN`:

```
OBJECT_TAG_LEN = (aead_algo == None) ? 0 : AEAD_TAG_LEN
```

Every normative use of `AEAD_TAG_LEN` in object **sizing, padding, and
splitting** math (v41 §6.1 reader algorithm step 1; §14.2 `encrypt_envelope`;
§14.3 index/dictionary/hint encryption; the "encrypted-object size
canonicality" rule of v41 §11 and §15.9) is replaced by `OBJECT_TAG_LEN`.
Nonce-related quantities (`AEAD_NONCE_LEN`) are simply unused when
`aead_algo = None`.

In unencrypted mode therefore `OBJECT_TAG_LEN = 0`, and:

- An object's stored byte length equals its padded plaintext length.
- `data_block_count × block_size == object_size` still holds (the canonicality
  rule loses only the additive tag term).
- The suffix-marker padding scheme (v41 §6.1) is **unchanged**: at least one
  padding byte is always present, the final byte is always a marker, and the
  exact-fit extra-block rule still applies (computed with
  `OBJECT_TAG_LEN = 0`).

In unencrypted mode there is **no per-object integrity field** of any kind: no
AEAD tag and no unkeyed object digest. Per-byte integrity is provided entirely
by per-block `record_crc32c` (corruption detection, v41 §10) and, when present,
the signed RootAuth `data_block_merkle_root` (tamper-evidence, §12). An unkeyed
object digest is deliberately **not** added: against accidental corruption it is
redundant with per-block CRC32C, and against tampering it is forgeable (an actor
who rewrites the bytes recomputes the digest), so it would cost a per-byte hash
pass without adding either property.

### 7.2 Read-path depadding

v41 §6.1 reader step 1 becomes, in unencrypted mode:

```
1. Let plaintext be the object bytes directly (no decryption). Its length is
   N = object_size - OBJECT_TAG_LEN = object_size, a multiple of BLOCK_SIZE.
```

Steps 2–6 (marker inspection, canonical-form checks, zstd payload slice) are
unchanged. The v41 note "tampering would already have failed AEAD" no longer
applies in unencrypted mode; readers MUST still enforce canonical zero-padding
and reject non-canonical padding as malformed.

### 7.3 Minimum object size

The v41 rule "reject an object whose recorded encrypted size is smaller than
`AEAD_TAG_LEN`" becomes "smaller than `OBJECT_TAG_LEN`." In unencrypted mode the
effective minimum is one block (`BLOCK_SIZE`), because every object still
carries at least one padding byte and is block-aligned. The v41 rule that
IndexRoot `object_size ≠ 0` and `data_block_count ≠ 0` is retained: even an
empty archive has a non-empty plaintext IndexRoot object.

### 7.4 Write path (overrides v41 §14.2/§14.3 in unencrypted mode)

`encrypt_envelope`, `encrypt_index_root`, `encrypt_index_shard`,
`encrypt_dictionary`, and `encrypt_directory_hint_shard` are replaced by their
plaintext equivalents:

```rust
fn package_object_plaintext(packed_or_serialized: &[u8]) -> Vec<u8> {
    // Identical padding/sizing math as v41 §14.2 with OBJECT_TAG_LEN = 0.
    // No nonce, no AAD, no AEAD, no tag. Returns the padded plaintext.
    suffix_pad(packed_or_serialized, /*tag_len=*/0, BLOCK_SIZE)   // §6.1 scheme
}
```

The returned bytes are the object bytes split into blocks exactly as in v41
§6/§10. No `ciphertext || tag` concatenation occurs; the object **is** the
padded plaintext.

---

## 8. Logical pipeline delta (overrides v41 §6)

Write path, unencrypted mode:

```
files → tar member groups → zstd frames → pack into envelopes
      → in-envelope pad (§6.1, OBJECT_TAG_LEN = 0)
      → [NO AEAD]  (plaintext object == padded plaintext)
      → object-local FEC → stripe across volumes → split into blocks
```

Read path, unencrypted mode:

```
blocks → verify per-block CRC32C → reassemble object by extent
       → [NO AEAD decrypt] → depad (§6.1) → zstd-decompress → tar member groups
```

The four nested units (v41 §6.2) are retained; the only change is that
"**Envelope** = packed group of frames; unit of AEAD encryption + padding"
becomes "unit of **packaging** + padding" — packaging is AEAD in encrypted mode
and a plaintext no-op in unencrypted mode.

---

## 9. Metadata objects in unencrypted mode (overrides v41 §15)

IndexRoot, IndexShards, the optional dictionary object, and directory-hint
shards are, in encrypted mode, AEAD-encrypted metadata objects (v41 §15,
§14.3). In unencrypted mode they are **plaintext** zstd objects packaged exactly
per §7.4. Consequences:

- The directory structure, file names, sizes, and the tar-stream content hash
  (`content_sha256`, carried inside IndexRoot) are readable without any key.
- All locating, sizing, FEC, and canonicality rules for these objects are
  unchanged (they were never about confidentiality, only framing/size).
- The v41 forbidden Extension tags `0x0004` (tar-stream content hash) and
  `0x0006` (dictionary presence) remain **forbidden** in v0.42 in **both**
  modes: writers MUST NOT emit them; readers MUST reject them. The content hash
  stays inside IndexRoot and dictionary presence stays signalled by
  `has_dictionary` + IndexRoot. **Resolved:** v0.42 does **not** add a cleartext
  content-hash TLV. In unencrypted mode IndexRoot is already plaintext, so
  `content_sha256` is directly readable from it; a duplicate TLV would only add
  a second copy requiring an equality rule and would gain nothing. This keeps
  the metadata layout byte-identical across modes.

---

## 10. Header and footer integrity in unencrypted mode (overrides v41 §9, §11, §12, §12.3)

In encrypted mode, the trailing 32-byte fields `header_hmac` (CryptoHeader),
`manifest_hmac` (ManifestFooter), `trailer_hmac` (VolumeTrailer), and
`sidecar_hmac` (bootstrap sidecar) are keyed HMAC-SHA-256 over `mac_key`. In
unencrypted mode there is no `mac_key`. These fields keep the **same offset and
size** but are reinterpreted as **unkeyed SHA-256 digests** using new v2 domain
strings:

```
header_digest   = SHA-256(b"tzap-v2-crypto-header"    || archive_uuid || session_id || <all CryptoHeader bytes before this field>)
manifest_digest = SHA-256(b"tzap-v2-manifest-footer"  || archive_uuid || session_id || <all ManifestFooter bytes before this field>)
trailer_digest  = SHA-256(b"tzap-v2-volume-trailer"   || archive_uuid || session_id || <all VolumeTrailer bytes before this field>)
sidecar_digest  = SHA-256(b"tzap-v2-bootstrap-sidecar"|| archive_uuid || session_id || <all sidecar bytes before this field>)
```

Rules:

- A v0.42 reader selects keyed-HMAC verification or unkeyed-digest verification
  **by protection mode** (`aead_algo`), determined from the CryptoHeader fixed
  fields, which are themselves covered by `header_digest`/`header_hmac`.
- These digests provide **corruption detection and identity binding only**.
  They are not authentication: a rewriter can recompute them. Readers MUST NOT
  treat a verified unkeyed digest as proof of authenticity, and MUST NOT report
  `*_hmac`-equivalent authenticated states for unencrypted archives.
- The digest input domains are deliberately distinct from the v1 HMAC domains
  so that a digest can never be confused with, or substituted for, an HMAC.
- All structural/identity cross-checks that v41 performs *after* HMAC
  verification (UUID/session/volume_index agreement across CryptoHeader,
  ManifestFooter, VolumeTrailer; magic checks; reserved-byte zero checks) are
  retained and performed after digest verification in unencrypted mode.

The pre-HMAC CryptoHeader framing scan (v41 §9, the bounded TLV-framing scan
that runs before HMAC) is retained verbatim; only the final verification step
switches between HMAC and digest.

---

## 11. BlockRecord wording (overrides v41 §10)

BlockRecord is structurally unchanged: 20 bytes of framing, `record_crc32c`
over `magic|block_index|kind|flags|_reserved|payload`. The only changes are
terminological and semantic:

- The `flags` bit 0 documentation "last data block of **encrypted** object"
  becomes "last data block of **object**." The flag is set on the last data
  block of every object (payload envelope, IndexRoot, IndexShard, dictionary,
  directory-hint) in both modes.
- All block-continuity rules (`block_index mod V == v`, consecutive blocks
  differ by `V`, no duplicates/gaps in a complete input set, contiguous object
  extents) are unchanged and are the primary structural integrity mechanism in
  unencrypted mode.
- `record_crc32c` is the per-byte corruption-detection mechanism for plaintext
  payloads. It is mandatory in both modes (already true in v41) and is the only
  per-byte hashing that touches payload bytes in unencrypted mode.

No new BlockRecord `kind` values are introduced; kinds 0–9 retain their
meaning, now describing plaintext data/parity in unencrypted mode.

---

## 12. RootAuth interaction (refines v41 §30)

RootAuth (v41 §30.7) is the tamper-evidence layer for unencrypted archives and
is **independent of the protection mode**:

- `RootAuthFooterV1` wire validation already requires no key (v41 §30.7) and is
  unchanged.
- `archive_root` and its component digests (`data_block_merkle_root`,
  `index_digest`, `critical_metadata_digest`, `fec_layout_digest`) are computed
  over the **stored object/block bytes**. In unencrypted mode those bytes are
  plaintext; the computation, domains, and merkle construction (v41 §30.9.x) are
  otherwise unchanged.
- The v41 "key-holding" RootAuth verification path (full recomputation,
  v41 §30.9.6) is retained by that name for cross-reference, but in unencrypted
  mode it requires **no archive key**: the reader opens the plaintext objects
  and recomputes the component digests directly. The name refers to the
  *full-recomputation* verification mode, not to possession of an archive
  encryption key. In encrypted mode it runs after HMAC/AEAD metadata
  validation; in unencrypted mode it runs after CRC32C, structural
  block-continuity, and unkeyed-digest validation.
- `verify --public-no-key` (v41 §30.11) works unchanged on unencrypted
  archives: it recomputes the public commitments over the observed blocks and
  verifies the signature with the trusted public key.
- **RootAuth is optional in unencrypted mode** (and in encrypted mode), exactly
  as in v41. v0.42 does not require signing. A signed unencrypted archive
  (`aead_algo = None` + RootAuth present) is the recommended configuration for
  distributing public, tamper-evident archives with no password; an unsigned
  unencrypted archive has corruption detection only.

---

## 13. Encrypted archives in v0.42

An encrypted v0.42 archive (`aead_algo ≠ None`) is **byte-identical to a v0.41
archive except for `volume_format_rev = 42`**. All of v41 §13 (KDF), §14
(AEAD/nonce/AAD), §9–§12 (HMAC headers/footers), and §15 (encrypted metadata)
apply unchanged. v0.42 readers MUST support both modes. v0.42 writers select
the mode from the requested key source:

- **No key source (the default)** → `aead_algo = None`, `kdf_algo = None`
  (unencrypted). This is what a writer produces when the caller requests neither
  a passphrase nor a keyfile. **Encryption is strictly opt-in; a password is
  never required.**
- A passphrase (opt-in) → `aead_algo` = default (`AesGcmSiv256`),
  `kdf_algo = Argon2id`.
- A raw keyfile (opt-in) → `aead_algo` = default, `kdf_algo = Raw`.

The v41 all-zero `--insecure-zero-key` path is **removed** in v0.42. It existed
only to produce a no-secret archive while still running the full key schedule
and full per-byte AEAD under a publicly known key — exactly the wasted
computation this revision eliminates. The unencrypted protection mode replaces
it. v0.42 writers MUST NOT expose an all-zero-key encrypted mode, and there is
no deprecated alias: the no-secret archive **is** the unencrypted mode
(`aead_algo = None`).

---

## 14. Resolved decisions

Every design decision is settled. There are no open items; the specification is
ready for implementation. For the record:

1. **Password is optional; unencrypted is the default.** No passphrase and no
   keyfile → unencrypted archive (`aead_algo = None`, §13). Encryption is opt-in.
2. **`--insecure-zero-key` is removed** (§13). The unencrypted mode replaces it;
   no deprecated alias.
3. **No per-object integrity tag** (§7.1). `OBJECT_TAG_LEN = 0` in unencrypted
   mode. Integrity = per-block CRC32C + optional RootAuth. No unkeyed object
   digest (redundant against accidental corruption, forgeable against tampering).
4. **Signing stays optional** in both modes (§12). v0.42 does not mandate
   RootAuth for unencrypted archives — consistent with v41 and with the design
   intent that password and signing are independent, independently-optional
   capabilities.
5. **Footer/header integrity primitive is SHA-256** (§10). Chosen for
   consistency with every other digest in the format (HMAC-SHA-256,
   `archive_root`, component digests); the inputs are tiny so speed is moot.
6. **No cleartext content-hash TLV** (§9). `content_sha256` stays inside
   IndexRoot, which is already plaintext in unencrypted mode; Extension tags
   `0x0004`/`0x0006` remain forbidden in both modes. Metadata layout is
   byte-identical across modes.
7. **Unencrypted-mode threat model is specified** (§3.1): no confidentiality;
   accidental corruption detected; tampering resisted only with RootAuth.
8. **RootAuth verification terminology** (§12): the v41 "key-holding"
   full-recomputation path keeps its name but requires no archive key in
   unencrypted mode.
9. **CLI safety messaging is non-normative** and out of format scope. Reference
   behavior: creating an unencrypted archive is **silent** (like creating an
   unsigned archive); front ends MAY add a one-line non-confidential notice.
   This has no effect on the wire format.

---

## 15. Conformance delta

### 15.1 Writers

A conforming v0.42 writer:

1. MUST set `volume_format_rev = 42` in every VolumeHeader.
2. MUST, for unencrypted archives, set `aead_algo = None`, `kdf_algo = None`,
   emit the 2-byte `None` KdfParams, run no KDF, derive no subkeys, and apply
   no AEAD.
3. MUST package every payload and metadata object as padded plaintext per §7.4
   in unencrypted mode, with `OBJECT_TAG_LEN = 0`.
4. MUST compute the unkeyed header/footer digests of §10 in unencrypted mode.
5. MUST still compute every `record_crc32c`, FEC parity set, CMRA, locator, and
   (if requested) RootAuth commitment exactly as in v41.
6. MUST NOT mix modes within one archive (single `aead_algo` for the whole
   archive, replicated identically in every volume's CryptoHeader).
7. For encrypted archives, MUST behave exactly as a v41 writer except for the
   revision number.

### 15.2 Readers

A conforming v0.42 reader:

1. MUST reject `volume_format_rev ≠ 42` for v0.42 inputs and continue to reject
   unknown future revisions.
2. MUST determine protection mode from `aead_algo` and enforce the §4.3
   cross-field consistency rules before any object processing.
3. MUST, in unencrypted mode, verify header/footer **digests** (§10), per-block
   CRC32C, and all structural block-continuity rules, and MUST NOT decrypt or
   expect AEAD tags.
4. MUST NOT report any authenticated/HMAC-verified state for unencrypted
   archives; MAY report `corruption-checked` and, if RootAuth verifies,
   `root-auth verified` / `public_data_block_commitment_verified`.
5. MUST support encrypted archives exactly as a v41 reader.
6. MUST apply the v41 resource caps (§13.3) unchanged; the KDF caps are simply
   not exercised in unencrypted mode.

---

## 16. Test vectors to add (delta)

- An empty unencrypted archive: `aead_algo = None`, single plaintext IndexRoot
  object of exactly one block, valid `manifest_digest`/`trailer_digest`.
- A small multi-file unencrypted archive; verify plaintext IndexRoot is
  readable and that depadding/zstd round-trips.
- Cross-field rejection vectors: `aead_algo = None` with `kdf_algo ∈ {Raw,
  Argon2id}`; `aead_algo ≠ None` with `kdf_algo = None`; `None` KdfParams whose
  `algo_tag ≠ 2`.
- Digest-tamper vectors: flip a payload byte and confirm CRC32C rejection;
  flip a CryptoHeader field and confirm `header_digest` rejection.
- Signed unencrypted archive: confirm `verify --public-no-key` accepts the
  pristine archive and rejects a modified one (tamper-evidence via RootAuth).
- Compute-savings sanity: confirm no KDF/HKDF/AEAD calls occur on the
  unencrypted create/extract paths (instrumentation test).

---

## 17. Why this reduces computation (rationale)

| Stage | v41 (incl. `--insecure-zero-key`) | v0.42 unencrypted |
|---|---|---|
| Password KDF (Argon2id) | only if passphrase | **never** |
| HKDF subkey schedule (8 subkeys) | always | **skipped** |
| Per-byte AEAD encrypt/decrypt | always (over **all** payload + metadata) | **skipped** |
| Per-byte AEAD authentication tag | always | **skipped** |
| Per-object nonce derivation | always | **skipped** |
| Keyed HMAC over headers/footers | always | replaced by unkeyed SHA-256 over the same tiny inputs (negligible) |
| zstd compression | always | **unchanged** (functional requirement) |
| Per-block CRC32C | always | **unchanged** (HW-accelerated; the only per-byte hashing left) |
| Reed-Solomon FEC | always | **unchanged** (functional requirement) |
| RootAuth merkle/sign | only if requested | only if requested (**unchanged**) |

The per-byte cryptographic work — the dominant cost on large archives — drops
to zero in unencrypted mode. The remaining per-byte work (zstd, CRC32C, FEC) is
exactly the work an unencrypted archiver would do anyway.
