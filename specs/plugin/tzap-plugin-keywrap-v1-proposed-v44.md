# tzap-plugin-keywrap-v1 - proposed v44 recipient key wrapping

Specification for the first recipient key-wrap plugin profile for tzap v44
archives with `KdfAlgo::RecipientWrap`.

Status: proposed v44 implementation target for the RecipientWrap key-wrap
profile. The current released v43 core/CLI do not implement `RecipientWrap` or
`--encrypt-to-cert`. A dedicated `tzap-plugin-keywrap` crate may host this
profile, and the `--encrypt-to-cert` CLI semantics below describe the v44 target
behavior. Targets `specs/tzap-format-revisedv44.md`, especially
`KeyWrapTableV1` and `RecipientRecordV1`.

## 1. Scope

In scope:

- interpreting `RecipientRecordV1.profile_payload` for key-wrap profile
  `0x0001`;
- wrapping a 32-byte archive `master_key` to one X.509 recipient certificate;
- unwrapping a candidate `master_key` with a local recipient private key;
- certificate public-key and KeyUsage checks for recipient encryption;
- API outcome wording for no-match, invalid, and successful unwrap results.

Not in scope:

- `KeyWrapTableV1` core framing, digest, CMRA recovery, or replicated-copy
  comparison;
- `CryptoHeader.header_hmac`, archive subkey derivation, AEAD object
  decryption, RootAuth, or public no-key verification;
- RootAuth signing certificates or signer trust policy;
- certificate enrollment, private-key storage, hardware-token UX, revocation
  fetching, OCSP, CRLs, timestamping, or mandatory EKU policy;
- detached recipient sidecars or post-creation recipient grants.

Those are core v44, signing plugin, deployment, or future-plugin
responsibilities.

## 2. Separation From Signing

Recipient wrapping answers: "which private key can recover this archive
`master_key`?"

RootAuth signing answers: "which trusted identity signed this archive root?"

This plugin MUST NOT treat a RootAuth signing certificate as a recipient
certificate merely because both are X.509. Writers and deployments SHOULD use
separate certificates and key usages:

| Use | Expected certificate role |
|---|---|
| RootAuth signing | `digitalSignature` signing key |
| Recipient wrapping | HPKE/key-agreement recipient key |

Shared certificate parsing helpers are allowed. Shared semantics are not.

## 3. Core Contract Dependency

This profile operates only when core has already:

1. Parsed `CryptoHeader.kdf_algo = RecipientWrap`.
2. Parsed RecipientWrap KdfParams from the v44 spec.
3. Bounded and structurally parsed `KeyWrapTableV1`.
4. Bounded and structurally parsed one `RecipientRecordV1`.
5. Verified common record framing: `record_length`, `flags = 0`, reserved bytes,
   variable string bounds, and `recipient_identity_digest =
   SHA-256(recipient_identity_bytes)`.

Core passes the profile:

- `archive_uuid`;
- `session_id`;
- `format_version = 1`;
- `volume_format_rev = 44`;
- the exact `RecipientRecordV1` common fields;
- exact `recipient_identity_bytes`;
- exact `profile_payload`;
- one or more local private-key handles or private-key lookup callbacks.

The profile returns only a candidate 32-byte `master_key` or a typed failure.
Core decides whether that key is correct by deriving `mac_key` and verifying
`CryptoHeader.header_hmac`. A profile success before core HMAC verification is
only "this recipient payload decrypted"; it is not archive authenticity.

## 4. Profile Registration

```text
profile_id = 0x0001
name       = "x509-hpke-recipient-v1"
```

When `RecipientRecordV1.profile_id = 0x0001`, this specification is the sole
interpretation for `profile_payload`.

Unknown `profile_id` values are not malformed at the table level. Core may skip
unknown records while searching for a locally usable recipient.

## 5. Recipient Identity

Supported `RecipientRecordV1.recipient_identity_type` values:

| Type | Meaning | Status |
|---:|---|---|
| 2 | DER X.509 leaf certificate | supported |

For any other `recipient_identity_type`, the profile returns
`UnsupportedRecipientIdentity` for that record. If
`recipient_identity_type = 2` but `recipient_identity_bytes` is not exactly one
DER X.509 leaf certificate, the record is malformed and the profile returns
`InvalidRecord`.

`recipient_identity_bytes` MUST contain exactly one DER-encoded X.509 leaf
certificate. PEM is a CLI/input encoding only; writers serialize DER into
`RecipientRecordV1`.

The profile computes:

```text
recipient_cert_digest = SHA-256(recipient_identity_bytes)
recipient_spki_digest = SHA-256(leaf SubjectPublicKeyInfo DER)
```

The common core `recipient_identity_digest` MUST equal `recipient_cert_digest`.
Implementations SHOULD expose `recipient_spki_digest` as the stable key id in
diagnostics and machine-readable reports.

## 6. Supported Recipient Public Keys

The default v1 profile supports HPKE base mode (RFC 9180) with these suites:

| Suite name | KEM | KDF | AEAD | `enc_length` | `ciphertext_length` |
|---|---:|---:|---:|---:|---:|
| `x25519-hkdfsha256-chacha20poly1305` | `0x0020` DHKEM(X25519, HKDF-SHA256) | `0x0001` HKDF-SHA256 | `0x0003` ChaCha20Poly1305 | 32 | 48 |
| `p256-hkdfsha256-aes256gcm` | `0x0010` DHKEM(P-256, HKDF-SHA256) | `0x0001` HKDF-SHA256 | `0x0002` AES-256-GCM | 65 | 48 |

The P-256 `enc` value is the 65-byte uncompressed SEC1 encoded ephemeral public
key used by RFC 9180 DHKEM(P-256). `ciphertext_length` is exactly 48 bytes for
both suites: the 32-byte `master_key` plaintext plus the suite AEAD's 16-byte
authentication tag. Readers MUST reject overlong encodings, alternate point
encodings, or ciphertext lengths other than the table value.

Writers SHOULD prefer X25519 when recipient infrastructure supports it. Readers
MUST reject suites outside this table unless a future profile assigns new
semantics.

RSA recipient certificates, Ed25519/Ed448 signing certificates, ECDSA-only
signing certificates, and EC certificates with explicit parameters are
unsupported by this v1 profile.

## 7. Recipient Certificate Checks

Writers MUST verify that the leaf certificate public key is compatible with the
selected HPKE KEM before creating a record.

If the leaf certificate contains a KeyUsage extension, the extension MUST permit
`keyAgreement`. A recipient certificate whose KeyUsage permits only
`digitalSignature` MUST NOT be used for recipient wrapping.

This v1 profile does not define a mandatory EKU. If deployment policy defines a
recipient-encryption EKU or trust anchor, writers and readers MAY enforce it,
but they MUST label that as deployment policy rather than default v1 profile
behavior.

Readers MAY use a local certificate store to find a private key whose public key
matches `recipient_spki_digest`. A reader that finds a private key but whose
deployment policy rejects the recipient certificate MUST return
`CertificatePolicyRejected` without attempting unwrap.

## 8. Profile Payload

`RecipientRecordV1.profile_payload` for `profile_id = 0x0001` is:

```rust
#[repr(C, packed)]
struct X509HpkeRecipientPayloadV1 {
    payload_version:             u16,    // 1
    hpke_kem_id:                 u16,
    hpke_kdf_id:                 u16,
    hpke_aead_id:                u16,

    enc_length:                  u16,
    ciphertext_length:           u16,
    flags:                       u32,    // reserved, MUST be zero

    key_wrap_context_digest:     [u8; 32],
    _reserved:                   [u8; 16],

    // enc:                      [u8; enc_length]
    // ciphertext:               [u8; ciphertext_length]
}
```

The fixed payload header is 64 bytes. Readers MUST reject a payload unless:

- `payload_version = 1`;
- the HPKE suite is one of §6;
- `flags = 0` and `_reserved` is all zero;
- `enc_length` and `ciphertext_length` equal the selected HPKE suite's exact
  wire lengths from §6;
- `64 + enc_length + ciphertext_length == profile_payload_length`;
- `key_wrap_context_digest` equals the digest in §9.

The HPKE plaintext is exactly the 32-byte archive `master_key`. No length prefix,
algorithm identifier, or padding is included in the HPKE plaintext.

## 9. Key-Wrap Context

The profile binds each HPKE operation to the archive identity, recipient
identity, and selected HPKE suite without depending on the circular
`key_wrap_table_digest`.

```text
key_wrap_context_digest = SHA-256(
    "tzap-keywrap-x509-hpke-v1-context\0"
    || archive_uuid
    || session_id
    || LE16(format_version)
    || LE16(volume_format_rev)
    || LE16(profile_id)
    || LE16(recipient_identity_type)
    || recipient_identity_digest
    || recipient_spki_digest
    || LE16(hpke_kem_id)
    || LE16(hpke_kdf_id)
    || LE16(hpke_aead_id)
)
```

HPKE uses:

```text
info = "tzap-x509-hpke-recipient-v1\0" || key_wrap_context_digest
aad  = "tzap-keywrap-master-key-v44\0" || key_wrap_context_digest
```

The writer calls HPKE Seal in base mode with the recipient public key, `info`,
`aad`, and plaintext `master_key`. The reader calls HPKE Open in base mode with
the matching private key, `enc`, `info`, `aad`, and `ciphertext`.

If HPKE Open succeeds but returns a plaintext length other than 32 bytes, the
record is invalid.

## 10. Outcomes

```rust
enum X509HpkeRecipientOutcome {
    NoMatchingPrivateKey,
    UnsupportedRecipientIdentity,
    UnsupportedSuite,
    CertificatePolicyRejected,
    InvalidRecord,
    UnwrappedCandidateMasterKey { recipient_spki_digest },
}
```

`UnwrappedCandidateMasterKey` means only that the profile decrypted a 32-byte
candidate key from this record. Core MUST still verify `CryptoHeader.header_hmac`
with that candidate before reporting archive access.

`NoMatchingPrivateKey` means the record is structurally valid for this profile,
but no available local private key matches the recipient certificate public key
or `recipient_spki_digest`.
`UnsupportedRecipientIdentity` means `recipient_identity_type` is not `2` for
this profile. `UnsupportedSuite` means the record's HPKE suite is outside §6 or
is incompatible with the recipient certificate public key.
`CertificatePolicyRejected` means a local private key matched the recipient
certificate, but an explicit deployment recipient-certificate policy rejected
that certificate before unwrap. `InvalidRecord` means the record selected this
profile but has malformed identity bytes, malformed profile payload framing,
failed certificate KeyUsage rules, or failed HPKE authentication.

If HPKE Open fails authentication, the profile returns `InvalidRecord` for that
record. Core MAY continue trying other records unless local policy treats a
record targeting the same private key as a hard failure.

## 11. Evaluation Order

1. Core validates common `RecipientRecordV1` framing.
2. If `recipient_identity_type != 2`, the profile returns
   `UnsupportedRecipientIdentity`. Otherwise it parses
   `recipient_identity_bytes` as exactly one DER X.509 leaf.
3. The profile extracts and validates the leaf SubjectPublicKeyInfo.
4. The profile enforces supported HPKE suite and KeyUsage rules.
5. The profile finds a local private key matching the recipient public key or
   returns `NoMatchingPrivateKey`.
6. The profile applies any deployment recipient-certificate policy, returning
   `CertificatePolicyRejected` if that policy rejects the matched certificate.
7. The profile recomputes `key_wrap_context_digest`.
8. The profile runs HPKE Open.
9. The profile returns a 32-byte candidate `master_key` to core.
10. Core derives `mac_key` and verifies `CryptoHeader.header_hmac`.
11. Only after core HMAC verification succeeds may the caller report that the
    local recipient key opened the archive.

## 12. CLI/API Wording

Target create flags:

```text
tzap create --encrypt-to-cert bob-device.pem --encrypt-to-cert ops.pem -o backup.tzap ./data
```

Target extract behavior:

```text
tzap extract backup.tzap -C restored
```

The reader may discover a matching private key from the OS certificate store,
hardware token, or configured key path. A UI may still require OS login, PIN,
Touch ID, hardware-token touch, or enterprise approval. That is not a tzap
archive password.

Diagnostics SHOULD distinguish:

- no recipient record matched local private keys;
- a matching private key existed but policy rejected the certificate;
- HPKE opened a candidate key but core rejected it through `CryptoHeader` HMAC;
- archive RootAuth signer verification failed or was not requested.

## 13. Required Test Vectors

1. Successful X25519 recipient unwrap: one recipient record, matching private
   key, core HMAC accepts recovered `master_key`.
2. Successful P-256 recipient unwrap: one recipient record, matching private key,
   core HMAC accepts recovered `master_key`.
3. Multi-recipient table: Bob, Carol, and Ops records wrap the same `master_key`;
   each matching private key can open independently, and no reader requires all
   private keys.
4. No local match: structurally valid records but no local private key.
5. Wrong private key: HPKE Open fails or core HMAC rejects the candidate key.
6. Certificate misuse: leaf KeyUsage permits only `digitalSignature`; writer and
   reader reject for recipient wrapping.
7. Unsupported suite: valid framing with an unassigned HPKE suite returns
   `UnsupportedSuite`.
8. Unsupported or malformed recipient identity: valid common framing with a
   non-2 `recipient_identity_type` returns `UnsupportedRecipientIdentity`; type
   2 with non-DER or multiple-certificate bytes returns `InvalidRecord`.
9. Certificate policy rejection: a record targets a local private key but
   deployment policy rejects the recipient certificate; the profile returns
   `CertificatePolicyRejected` without attempting unwrap.
10. Table binding: flipping any byte in `KeyWrapTableV1` causes core's
   `key_wrap_table_digest` check or `CryptoHeader.header_hmac` check to fail
   before payload decryption.
11. Signing separation: a RootAuth signing certificate does not satisfy recipient
   unwrap unless a separate recipient record and matching recipient private key
   are present.
