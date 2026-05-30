# tzap-plugin-x509-chain-v1 - proposed v43 X.509 root authenticator

Specification for the optional X.509 certificate-chain authenticator profile for
tzap v43 root authentication.

Status: implementation target for the current `tzap-plugin-signing::x509_chain`
module and tzap CLI X.509 RootAuth flags. Targets
`specs/tzap-format-revisedv43.md` and
`root_auth_spec_id = "tzap-root-auth-v0.43\0"` padded to 24 bytes.

## 1. Scope

In scope:

- one X.509 chain authenticator profile over core's recomputed `archive_root`;
- `authenticator_id = 0x0003`;
- `signer_identity_type = 2` for a DER X.509 leaf certificate;
- the exact bytes written into `RootAuthFooterV1.authenticator_value`;
- certificate-chain verification with caller-supplied trusted roots and/or
  OpenSSL default trust roots;
- API and CLI outcome wording for key-holding and public no-key verification
  modes.

Not in scope:

- `archive_root` construction;
- `RootAuthFooterV1` layout and footer CRC;
- CMRA and locator recovery;
- Ed25519 authenticator behavior;
- certificate enrollment, private-key storage, trust-store management,
  revocation fetching, OCSP, CRLs, timestamp-authority protocols, or a mandatory
  document-signing EKU policy.

Those are core v43, deployment, or future-plugin responsibilities.

## 2. Core Contract Dependency

This profile operates only when all of these are true:

1. `RootAuthFooterV1.root_auth_spec_id` is the exact 24-byte padded
   `"tzap-root-auth-v0.43\0"` value.
2. The archive has `VolumeHeader.volume_format_rev = 43`.
3. Core has wire-validated `RootAuthFooterV1`.
4. Core has recomputed `archive_root` according to the v43 spec.
5. Core has proven the recomputed `archive_root` equals the
   `RootAuthFooterV1.archive_root` field.

The profile MUST NOT accept an `archive_root` supplied only by the stored footer
field. The root must come from core recomputation.

This profile is **protection-mode independent** (v43 §5.1). It signs and verifies
`archive_root` identically for encrypted and unencrypted archives, because
`archive_root` is recomputed by core over the stored object/block bytes in either
mode and the certificate key pair is unrelated to any archive encryption key. A
signed unencrypted (`aead_algo = None`) archive is therefore tamper-evident and
verifiable with no archive key.

## 3. Scheme Registration

```text
authenticator_id = 0x0003
name             = "x509-chain-archiveroot-v1"
```

When a `RootAuthFooterV1` selects `authenticator_id = 0x0003`, this profile is
the sole authenticator interpretation for that footer.

## 4. Signer Identity

Supported `RootAuthFooterV1.signer_identity_type` values for this profile:

| Type | Meaning | Status |
|---:|---|---|
| 2 | DER X.509 leaf certificate | supported |

`signer_identity_bytes` MUST contain exactly one DER-encoded X.509 leaf
certificate. PEM input is a CLI/API convenience only; the wire value is DER.

Writers MUST normalize the leaf certificate to DER before computing
`signer_identity_digest` and before serializing `RootAuthFooterV1`. Writers MUST
verify that the private key used to sign the authenticator matches the public key
inside the leaf certificate.

Readers MUST reject this profile unless `signer_identity_type = 2` and
`signer_identity_bytes` parses as exactly one DER X.509 certificate. The leaf
certificate public key is the verifier key for the RootAuth signature.

Embedded certificates are not trust anchors. A verifier MUST require at least
one caller-supplied trusted root or an explicit request to use the platform or
OpenSSL default trust roots.

## 5. Authenticator Value

The profile fills `RootAuthFooterV1.authenticator_value` with a variable-length
byte string:

```rust
struct X509ChainAuthenticatorV1 {
    magic:                     [u8; 4],  // b"TZXC"
    version:                   u16,      // 1
    sig_scheme:                u16,      // 1 = OpenSSL EVP SHA-256 signature
    signed_at_unix_seconds:    i64,      // signer-claimed Unix timestamp
    chain_digest:              [u8; 32],
    signature_length:          u32,
    signature_capacity:        u32,
    chain_certificate_count:   u32,

    // Followed by:
    //   signature:             [u8; signature_capacity]
    //   chain certificates:
    //     cert_der_length:     u32
    //     cert_der:            [u8; cert_der_length]
}
```

All integer fields are little-endian. The fixed header is exactly 60 bytes.

`signature` stores the first `signature_length` bytes as the actual signature.
The remaining `signature_capacity - signature_length` bytes MUST be zero.
`signature_capacity` lets writers reserve the maximum signature size for the
selected OpenSSL key type while supporting variable-length encodings such as
ECDSA.

`authenticator_value_length` MUST equal:

```text
60
+ signature_capacity
+ sum(4 + cert_der_length for each embedded chain certificate)
```

The final `authenticator_value_length` MUST still satisfy the v43
`RootAuthFooterV1.authenticator_value_length` cap.

## 5.1 Chain Digest

`chain_digest` commits to the embedded untrusted chain certificates:

```text
chain_digest = SHA-256(
    "tzap-x509-chain-v1\0"
    || LE32(chain_certificate_count)
    || for each embedded chain certificate, in serialized order:
       LE32(cert_der_length)
       || cert_der
)
```

The leaf certificate is not part of `chain_digest`; it is carried by
`signer_identity_bytes` and covered by core's `signer_identity_digest`.

An empty embedded chain is valid. In that case the digest still includes the
domain string and `LE32(0)`.

## 5.2 Signing Input

The profile signs a domain-separated digest of core root-auth fields and X.509
profile fields:

```text
SIGNING_INPUT = SHA-512(
    "tzap-sig-x509-v1\0"
    || root_auth_spec_id          // exact 24 bytes from RootAuthFooterV1
    || archive_uuid               // exact 16 bytes from RootAuthFooterV1
    || session_id                 // exact 16 bytes from RootAuthFooterV1
    || archive_root               // recomputed core value, 32 bytes
    || LE64(signed_at_unix_seconds)
    || chain_digest
)
```

`LE64(signed_at_unix_seconds)` is the two's-complement little-endian encoding of
the signed 64-bit timestamp.

The OpenSSL signature input is the 64-byte `SIGNING_INPUT` value. For
`sig_scheme = 1`, implementations use OpenSSL EVP signing and verification with
`MessageDigest::sha256()` and the leaf certificate public-key algorithm.

The profile MUST NOT sign raw archive bytes, raw footer bytes, or a stored
`archive_root` that core has not recomputed and equality-checked.

## 5.3 Signature Algorithm Profile

`sig_scheme = 1` means "OpenSSL EVP signature with SHA-256 over
`SIGNING_INPUT`." The exact public-key signature algorithm is determined by the
leaf certificate public key and private key, subject to OpenSSL support.

Writers MUST reject Ed25519 and Ed448 private keys for this profile. Readers
MUST reject authenticators whose leaf public key cannot be used with OpenSSL EVP
SHA-256 verification.

Writers SHOULD use certificates and keys whose OpenSSL EVP SHA-256 behavior is
stable and broadly interoperable, such as RSA or ECDSA. This profile does not
assign separate on-wire `sig_scheme` values for RSA-PKCS1, RSA-PSS, ECDSA, or
other OpenSSL key classes.

## 6. Verification Inputs

Core passes the profile:

- validated `root_auth_spec_id`;
- `archive_uuid`;
- `session_id`;
- recomputed `archive_root`;
- `signer_identity_type`;
- exact `signer_identity_bytes`;
- exact `authenticator_value`;
- caller-supplied trusted root certificates, as DER;
- whether OpenSSL default trust roots may be used.

The profile MUST NOT read archive files, parse archive metadata, perform FEC,
decrypt objects, or decide public observation windows.

## 7. Parser and Validation Rules

Readers MUST reject this authenticator value unless:

- length is at least 60 bytes;
- `magic = "TZXC"`;
- `version = 1`;
- `sig_scheme = 1`;
- `signature_length <= signature_capacity`;
- the byte string contains exactly `signature_capacity` signature bytes after
  the fixed header;
- all bytes after `signature_length` and before `signature_capacity` are zero;
- `chain_certificate_count` can be parsed without unbounded allocation;
- each embedded chain certificate has a complete `LE32(length) || DER` record;
- no trailing bytes remain after the declared certificates;
- every embedded certificate parses as DER X.509;
- recomputed `chain_digest` equals the stored `chain_digest`.

After parsing, readers MUST:

1. Build `SIGNING_INPUT` from the recomputed core `archive_root`, not from an
   untrusted stored value.
2. Verify the RootAuth signature with the leaf certificate public key.
3. Build an X.509 store from caller-supplied trusted roots and, only when
   explicitly requested, OpenSSL default trust roots.
4. Add embedded chain certificates as untrusted intermediates.
5. Verify the certificate path at `signed_at_unix_seconds`.

RootAuth verification MUST fail if either signature verification or certificate
path verification fails.

## 8. Trust and Time Policy

`signed_at_unix_seconds` is signer-claimed metadata. It is authenticated by the
RootAuth signature, and it is used as the X.509 path-validation time, but it is
not a trusted timestamp.

Successful verification means:

- the recomputed v43 `archive_root` matched the stored footer commitment;
- the leaf certificate public key verified the X.509 RootAuth signature;
- the leaf certificate chained to an accepted trust root at the signer-claimed
  time.

Successful verification MUST NOT be described as proof that the signature was
created at that time unless a separate trusted timestamp profile is used.

This v1 profile does not perform revocation checking. Implementations MUST NOT
claim CRL, OCSP, or freshness validation for this profile unless a future
profile or deployment policy performs those checks separately.

This v1 profile does not define a mandatory EKU or leaf KeyUsage policy beyond
the certificate path validation performed by OpenSSL. Deployments that require a
document-signing, code-signing, or private-purpose EKU must enforce that policy
outside this profile or define a future stricter profile.

## 9. Outcomes

```rust
enum X509RootAuthOutcome {
    Invalid,
    UnsupportedIdentity,
    UntrustedChain,
    RootAuthContentVerified { report },
    PublicDataBlockCommitmentVerified { report },
}
```

`RootAuthContentVerified` is available only when core has completed key-holding
v43 full-archive content verification and root-auth recomputation.

`PublicDataBlockCommitmentVerified` is available only when core has completed
the v43 public no-key observation path. It proves only that a certificate chain
accepted by the caller's trust policy signed a commitment to the observed
data-block set (ciphertext blocks in an encryption mode; plaintext blocks in
unencrypted mode) and opaque component digests. In an encryption mode it does
not prove plaintext, file list, IndexRoot, HMAC-authenticated metadata, physical
completeness, or recovery margin; in unencrypted mode the data blocks are
plaintext, so the commitment covers the plaintext data directly, but it still
does not prove the file list/IndexRoot contents, physical completeness, or
recovery margin.

`UntrustedChain` means the RootAuth signature may be structurally well-formed,
but no accepted trust anchor validated the certificate path. It MUST NOT be
described as origin authenticity or public commitment verification.

`UnsupportedIdentity` means `signer_identity_type` is not `2` for this profile
or the selected RootAuth authenticator is not `0x0003`.

## 10. Report Fields

Successful verification SHOULD expose:

- `signed_at_unix_seconds`;
- `subject`;
- `issuer`;
- `serial_number_hex`;
- leaf certificate SHA-256 fingerprint;
- verified chain subjects in OpenSSL chain order;
- trust anchor subject when available.

CLI and JSON output MUST label the timestamp source as `signer_claimed`.

## 11. Evaluation Order

1. Core validates and recomputes v43 root-auth inputs.
2. The profile confirms `authenticator_id = 0x0003`.
3. The profile confirms `signer_identity_type = 2` and parses the leaf
   certificate.
4. The profile parses `authenticator_value`.
5. The profile recomputes and checks `chain_digest`.
6. The profile builds `SIGNING_INPUT`.
7. The profile verifies the signature with the leaf certificate public key.
8. The profile verifies the certificate path with caller-approved trust roots at
   `signed_at_unix_seconds`.
9. If verification succeeds and core is in key-holding full verification mode,
   return `RootAuthContentVerified`.
10. If verification succeeds and core is in public no-key mode, return
    `PublicDataBlockCommitmentVerified`.

## 12. CLI Profile

For archive creation, the CLI profile maps:

- `--signing-cert FILE` to `signer_identity_bytes`;
- `--signing-private-key FILE` to the private key used for `sig_scheme = 1`;
- `--signing-chain FILE` to one or more embedded untrusted chain certificates.

For verification, the CLI profile maps:

- `--trusted-ca-cert FILE` to caller-supplied trusted roots;
- `--trusted-system-roots` to OpenSSL default trust roots.

Verification MUST reject a request that mixes Ed25519 trust options with X.509
trust options in the same RootAuth verification operation.

`--public-no-key` with X.509 trust uses the same authenticator verification, but
the resulting status is `public_data_block_commitment_verified` and must be
accompanied by the v43 public no-key diagnostics.

## 13. Partial Operations

This profile MUST NOT return a verified outcome for partial/random single-file
extraction unless core has already completed the full v43 verification required
for that outcome.

Partial operations may report root auth as deferred or unavailable.

## 14. Required Test Vectors

1. `RootAuthContentVerified`: matching trusted root, valid key-holding v43 full
   verification, valid chain at `signed_at_unix_seconds`.
2. `PublicDataBlockCommitmentVerified`: matching trusted root, no archive key,
   complete public data-block observation set. Cover both an encrypted archive
   (ciphertext blocks) and an unencrypted archive (`aead_algo = None`, plaintext
   blocks).
3. `UntrustedChain`: valid signature and embedded chain, wrong trusted root.
4. `Invalid`: flipped `archive_root`, wrong signing domain, wrong certificate
   public key, malformed signature value, non-zero signature padding, malformed
   certificate DER, chain digest mismatch, trailing authenticator bytes.
5. `UnsupportedIdentity`: unknown `signer_identity_type` with otherwise valid
   core footer wire checks.
6. Missing trust policy: no caller-supplied trusted roots and no explicit system
   roots request.
7. Stored footer `archive_root` differs from core recomputation: core rejects
   before profile success is possible.
