# tzap-plugin-x509-chain-v2 - proposed v44 X.509 root authenticator

Specification for the optional X.509 certificate-chain authenticator profile for
tzap v44 root authentication.

Status: implementation target for the current `tzap-plugin-signing::x509_chain`
module and tzap CLI X.509 RootAuth flags. Targets
`specs/tzap-format-revisedv44.md` and
`root_auth_spec_id` as the 20 ASCII bytes `tzap-root-auth-v0.44` followed by
four zero bytes.
This v2 document keeps the v1 X.509 authenticator wire profile and updates its
core contract for v44 archive-root inputs.

## 1. Scope

In scope:

- one X.509 chain authenticator profile over core's recomputed `archive_root`;
- `authenticator_id = 0x0003`;
- `signer_identity_type = 2` for a DER X.509 leaf certificate;
- the exact bytes written into `RootAuthFooterV1.authenticator_value`;
- certificate-chain verification with caller-supplied trusted roots and/or
  explicitly requested OpenSSL default trust roots;
- API and CLI outcome wording for full RootAuth and public no-key verification
  modes.

Not in scope:

- `archive_root` construction;
- `RootAuthFooterV1` layout and footer CRC;
- `KeyWrapTableV1` parsing, recipient-certificate matching, or archive-key
  unwrap;
- CMRA and locator recovery;
- Ed25519 authenticator behavior;
- certificate enrollment, private-key storage, trust-store management,
  revocation fetching, OCSP, CRLs, timestamp-authority protocols, or a mandatory
  document-signing EKU policy. The v1 wire profile does define the minimal leaf
  KeyUsage handling required for archive-signature use (§8).

Those are core v44, deployment, or RecipientWrap key-wrap profile
responsibilities.

## 2. Core Contract Dependency

This profile operates only when all of these are true:

1. `RootAuthFooterV1.root_auth_spec_id` is the exact 24-byte value consisting
   of the 20 ASCII bytes `tzap-root-auth-v0.44` followed by four zero bytes.
2. The archive has `VolumeHeader.volume_format_rev = 44`.
3. Core has wire-validated `RootAuthFooterV1`.
4. Core has recomputed `archive_root` according to the v44 spec.
5. Core has proven the recomputed `archive_root` equals the
   `RootAuthFooterV1.archive_root` field.

The profile MUST NOT accept an `archive_root` supplied only by the stored footer
field. The root must come from core recomputation.

This profile is **protection-mode independent** (v44 §5.1). It signs and verifies
`archive_root` identically for encrypted and unencrypted archives, because
`archive_root` is recomputed by core over the stored object/block bytes in either
mode and the certificate key pair is unrelated to any archive encryption key. A
signed unencrypted (`aead_algo = None`) archive is therefore tamper-evident and
verifiable with no archive key.

For v44 recipient-wrap archives (`kdf_algo = RecipientWrap`), this profile is
also key-access independent. X.509 RootAuth certificates identify who signed the
archive root; recipient certificates identify who can unwrap the archive
`master_key`. This profile MUST NOT inspect recipient records, select recipient
certificates, unwrap `master_key`, or treat a signing certificate as a recipient
encryption certificate merely because both use X.509 syntax.

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
one caller-supplied trusted root or an explicit request to use OpenSSL's
configured default trust roots. This v1 profile does not define platform-native
trust-root lookup as a separate authority source; an implementation that offers
platform-native roots MUST expose and label that as deployment policy outside
the default v1 profile.

## 5. Authenticator Value

The profile fills `RootAuthFooterV1.authenticator_value` with a variable-length
byte string:

```rust
struct X509ChainAuthenticatorV1 {
    magic:                     [u8; 4],  // b"TZXC"
    version:                   u16,      // 1
    sig_scheme:                u16,      // see §5.3
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
selected explicit signature scheme while supporting variable-length encodings
such as ECDSA.

`authenticator_value_length` MUST equal:

```text
60
+ signature_capacity
+ sum(4 + cert_der_length for each embedded chain certificate)
```

The final `authenticator_value_length` MUST still satisfy the v44
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

The signature input is the 64-byte `SIGNING_INPUT` value. The selected
`sig_scheme` in §5.3 signs and verifies that value as the message. The SHA-256
named by each scheme hashes exactly those 64 bytes; implementations MUST NOT
pre-hash them with an extra, profile-specific digest or sign raw archive bytes.

The profile MUST NOT sign raw archive bytes, raw footer bytes, or a stored
`archive_root` that core has not recomputed and equality-checked.

## 5.3 Signature Algorithm Profile

`sig_scheme` is an explicit on-wire algorithm identifier. Implementations MUST
NOT infer an alternate signature algorithm from OpenSSL defaults, key type
metadata, certificate signatureAlgorithm fields, or provider configuration.

| `sig_scheme` | Name | Required verification behavior |
|---:|---|---|
| 1 | `rsa-pkcs1-sha256` | RSASSA-PKCS1-v1_5 signature over SHA-256(`SIGNING_INPUT`) using a leaf RSA public key whose SubjectPublicKeyInfo algorithm is unconstrained `rsaEncryption`. The encoded signature length MUST equal the RSA modulus length in bytes. Readers MUST reject RSASSA-PSS-constrained public keys for this scheme. |
| 2 | `ecdsa-sha256-der` | ECDSA signature over SHA-256(`SIGNING_INPUT`) using a leaf named-curve EC public key on one of the v1 allowed curves below. Signature bytes are DER `Ecdsa-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`) and MUST be a single complete DER value. `r` and `s` MUST be positive, minimally encoded DER integers in the range `1..n-1`, where `n` is the curve order, and `s` MUST be low-S (`s <= n/2`). Readers MUST reject explicit-parameter EC keys, unsupported named curves, high-S signatures, and otherwise non-canonical DER. |
| 3 | `rsa-pss-sha256` | RSASSA-PSS signature over SHA-256(`SIGNING_INPUT`) using a leaf RSA public key, MGF1-SHA-256, salt length exactly 32 bytes, trailer field `0xBC`. The encoded signature length MUST equal the RSA modulus length in bytes. If the SubjectPublicKeyInfo algorithm is RSASSA-PSS and carries parameters, those parameters MUST exactly match this row; unconstrained `rsaEncryption` keys are also valid. |

The v1 allowed ECDSA curves are exactly:

| Curve | Common names / OID |
|---|---|
| NIST P-256 | `prime256v1`, `secp256r1`, OID `1.2.840.10045.3.1.7` |
| NIST P-384 | `secp384r1`, OID `1.3.132.0.34` |
| NIST P-521 | `secp521r1`, OID `1.3.132.0.35` |

Readers MUST reject any other EC curve for `ecdsa-sha256-der`, even if the
local crypto provider can verify it. Writers MUST reject unsupported EC private
keys for this profile unless a future profile assigns a new scheme or curve
registry.

Writers MUST set a scheme compatible with the leaf public key and signing
private key. Readers MUST reject a scheme/key mismatch, a signature whose length,
encoding, key algorithm, or algorithm parameters violate the selected row, or an
RSA-PSS signature verified with any salt length, MGF digest, or trailer field
other than the values above. Writers MUST emit canonical low-S ECDSA signatures;
readers MUST NOT accept a high-S alternate encoding of the same ECDSA signature.

Writers MUST reject Ed25519 and Ed448 private keys for this profile. Readers
MUST reject authenticators whose leaf public key cannot be used with one of the
registered schemes above.

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
- whether OpenSSL default trust roots may be used by explicit request;
- the chain-validation time policy and validation time. The default v1 policy is
  `verifier_current_time`, using the verifier's current clock at the time of
  verification.

The profile MUST NOT read archive files, parse archive metadata, perform FEC,
decrypt objects, or decide public observation windows.

## 7. Parser and Validation Rules

Readers MUST reject this authenticator value unless:

- length is at least 60 bytes;
- `magic = "TZXC"`;
- `version = 1`;
- `sig_scheme` is one of `1`, `2`, or `3` as defined in §5.3;
- `signature_length > 0`;
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
2. Verify the RootAuth signature with the leaf certificate public key and the
   exact `sig_scheme` parameters from §5.3.
3. Enforce the v1 leaf KeyUsage rule in §8.
4. Require at least one caller-supplied trusted root or an explicit request to
   use OpenSSL default trust roots.
5. Build an X.509 store from caller-supplied trusted roots and, only when
   explicitly requested, OpenSSL default trust roots.
6. Add embedded chain certificates as untrusted intermediates.
7. Verify the certificate path at the selected chain-validation time. The
   default v1 profile uses verifier current time. `signed_at_unix_seconds` MUST
   NOT be used as the chain-validation time for a successful v1 result unless a
   separate trusted timestamp profile or explicit deployment policy supplies
   independent evidence that binds the archive signature to that time.

RootAuth verification MUST fail if signature verification, KeyUsage enforcement,
or certificate path verification fails.

## 8. Trust and Time Policy

`signed_at_unix_seconds` is signer-claimed metadata. It is authenticated by the
RootAuth signature, but it is not a trusted timestamp and MUST NOT by itself
select the X.509 path-validation time for `RootAuthContentVerified` or
`PublicDataBlockCommitmentVerified`. The default path-validation time basis for
this v1 profile is `verifier_current_time`.

Successful verification means:

- the recomputed v44 `archive_root` matched the stored footer commitment;
- the leaf certificate public key verified the X.509 RootAuth signature;
- the leaf certificate chained to an accepted trust root at the selected
  chain-validation time.

Successful verification MUST NOT be described as proof that the signature was
created at `signed_at_unix_seconds`, as proof of freshness, or as proof of
revocation status unless a separate trusted timestamp/revocation profile or
deployment policy supplies those checks. A v1 success under the default policy
does mean that the certificate path was valid according to the accepted trust
roots at the verifier's selected validation time.

This v1 profile does not perform revocation checking. Implementations MUST NOT
claim CRL, OCSP, or freshness validation for this profile unless a future
profile or deployment policy performs those checks separately.

CLI, JSON, and API reports MUST label the time policy explicitly:
`x509_time_policy = verifier_current_time` by default,
`chain_time_basis = verifier_current_time`, the exact
`chain_validation_time_unix_seconds`, the signer-claimed
`signed_at_unix_seconds`, `trusted_timestamp = false`, and
`revocation_checked = false`. Reports MUST also label
`key_usage_policy = archive_signature_minimal` and `eku_policy = none` under the
default v1 profile, unless a future profile or explicit deployment policy adds
different evidence and labels it separately. Implementations MAY report whether
the chain would also validate at `signed_at_unix_seconds`, but that diagnostic
MUST NOT be used to upgrade a failed default-policy verification into a
successful v1 RootAuth outcome.

This v1 profile enforces one minimal leaf KeyUsage rule because the leaf public
key is used to verify an archive signature: if the leaf certificate contains a
KeyUsage extension, that extension MUST permit either `digitalSignature` or
`contentCommitment`/`nonRepudiation`; a certificate that has KeyUsage but only
permits unrelated uses such as key encipherment MUST be rejected. If KeyUsage is
absent, the v1 profile imposes no additional KeyUsage restriction beyond normal
path validation.

This v1 profile does not define a mandatory EKU policy. If an EKU extension is
present, default v1 verification records it for diagnostics but does not require
a document-signing, code-signing, or private-purpose OID. Deployments that
require an EKU must enforce that policy outside this profile or define a future
stricter profile, and reports MUST label that deployment policy separately from
the default v1 outcome.

## 9. Outcomes

```rust
enum X509RootAuthOutcome {
    Invalid,
    UnsupportedIdentity,
    MissingTrustPolicy,
    UntrustedChain,
    RootAuthContentVerified { report },
    PublicDataBlockCommitmentVerified { report },
}
```

`RootAuthContentVerified` is available only when core has completed full v44
RootAuth verification: archive-wide content verification and root-auth
recomputation. In an encryption mode this requires the archive key; in
unencrypted mode it does not require any archive key or password. In
RecipientWrap mode, core must have recovered `master_key` through a key-wrap
profile or equivalent trusted API before this outcome is possible.

`PublicDataBlockCommitmentVerified` is available only when core has completed
the v44 public no-key observation path. It proves only that a certificate chain
accepted by the caller's trust policy signed a commitment to the observed
data-block set (ciphertext blocks in an encryption mode; plaintext blocks in
unencrypted mode) and opaque component digests. In an encryption mode it does
not prove plaintext recovery, decoded file/content authenticity, file list,
IndexRoot, encrypted-mode authenticated metadata, physical completeness, or
recovery margin; in unencrypted mode the commitment covers the observed
plaintext data BlockRecord payloads directly, but it still does not prove
decoded file/content authenticity, file-list/IndexRoot contents, physical
completeness, or recovery margin.

`MissingTrustPolicy` means the caller supplied neither trusted root
certificates nor an explicit request to use OpenSSL's configured default trust
roots. It is a verifier-configuration failure, not evidence that the embedded
chain is trusted or untrusted. CLI and API reports MUST include an action such
as supplying `--trusted-ca-cert FILE` or `--trusted-system-roots`.

`UntrustedChain` means the RootAuth signature may be structurally well-formed
and a trust policy was supplied, but no accepted trust anchor validated the
certificate path at the selected chain-validation time. It MUST NOT be described
as origin authenticity or public commitment verification.

`UnsupportedIdentity` means `signer_identity_type` is not `2` for this profile
only. An unsupported `authenticator_id` is a core unsupported-authenticator /
root-auth-unavailable result before this profile is selected, not an
`X509RootAuthOutcome`.

`Invalid` means this profile was selected but the type-2 identity bytes are not
exactly one DER X.509 leaf certificate, the authenticator value is malformed,
the chain digest mismatches, the signature scheme or key parameters are
unsupported or mismatched, signature verification fails, or the v1 leaf KeyUsage
rule fails.

## 10. Report Fields

Successful verification SHOULD expose:

- `signed_at_unix_seconds`;
- `signature_scheme`;
- `chain_validation_time_unix_seconds`;
- `subject`;
- `issuer`;
- `serial_number_hex`;
- leaf certificate SHA-256 fingerprint;
- verified chain subjects in OpenSSL chain order;
- trust anchor subject when available;
- `trust_store_policy = caller_roots`, `openssl_default_roots`, or
  `caller_roots_plus_openssl_default_roots`;
- `x509_time_policy = verifier_current_time` by default;
- `chain_time_basis = verifier_current_time`;
- `trusted_timestamp = false`;
- `revocation_checked = false`;
- `key_usage_policy = archive_signature_minimal`;
- `eku_policy = none`.

CLI and JSON output MUST label `signed_at_unix_seconds` as `signer_claimed` and
MUST label the chain-validation time separately. They MUST NOT label a
v1-profile success as fresh, TSA-backed, or revocation-checked unless those
claims come from an explicitly separate policy or future profile field.

## 11. Evaluation Order

1. Core validates and recomputes v44 root-auth inputs.
2. Core selects this profile for `authenticator_id = 0x0003`.
3. The profile confirms `signer_identity_type = 2` and parses the leaf
   certificate. If `signer_identity_type != 2`, return `UnsupportedIdentity`.
   If the leaf certificate bytes are not exactly one DER X.509 certificate,
   return `Invalid`.
4. The profile parses `authenticator_value`.
   If parsing fails, return `Invalid`.
5. The profile recomputes and checks `chain_digest`. If it mismatches, return
   `Invalid`.
6. The profile builds `SIGNING_INPUT`.
7. The profile verifies the signature with the leaf certificate public key.
   If verification fails, return `Invalid`.
8. The profile enforces the leaf KeyUsage rule from §8. If the rule fails,
   return `Invalid`.
9. If no caller-supplied trusted roots are present and OpenSSL default trust
   roots were not explicitly requested, return `MissingTrustPolicy`.
10. The profile verifies the certificate path with caller-approved trust roots at
   the selected chain-validation time. If path validation fails, return
   `UntrustedChain`.
11. If verification succeeds and core is in full RootAuth verification mode,
   return `RootAuthContentVerified`.
12. If verification succeeds and core is in public no-key mode, return
    `PublicDataBlockCommitmentVerified`.

## 12. CLI Profile

For archive creation, the CLI profile maps:

- `--signing-cert FILE` to `signer_identity_bytes`;
- `--signing-private-key FILE` to the private key used for the selected
  `sig_scheme`;
- `--signing-chain FILE` to one or more embedded untrusted chain certificates;
- `--x509-signature-scheme {rsa-pkcs1-sha256,ecdsa-sha256-der,rsa-pss-sha256}`
  to the on-wire `sig_scheme`.

If `--x509-signature-scheme` is omitted, writers MUST choose
`rsa-pkcs1-sha256` for unconstrained RSA keys and `ecdsa-sha256-der` for
allowed named-curve EC keys from §5.3. Writers MUST reject EC keys on curves
outside the v1 allowed set unless an explicit future profile supports them.
Writers MUST use `rsa-pss-sha256` only when explicitly requested; a constrained
RSASSA-PSS key without an explicit compatible scheme is rejected.

For verification, the CLI profile maps:

- `--trusted-ca-cert FILE` to caller-supplied trusted roots;
- `--trusted-system-roots` to OpenSSL default trust roots.

Unless a future CLI flag or deployment policy explicitly supplies a validation
time with separate evidence, CLI verification uses verifier current time for
X.509 path validation. The CLI MUST NOT use `signed_at_unix_seconds` as the
chain-validation time merely because it is present in the signed authenticator.

Verification MUST reject a request that mixes Ed25519 trust options with X.509
trust options in the same RootAuth verification operation.

The CLI MUST NOT describe `--trusted-system-roots` as platform-native root
validation. This flag allows OpenSSL's configured default trust roots. If a
product wrapper adds a separate platform-native root option, it is outside this
v1 profile and its reports MUST use a distinct trust-store policy label.

`--public-no-key` with X.509 trust uses the same authenticator verification, but
the resulting status is `public_data_block_commitment_verified` and must be
accompanied by the v44 public no-key diagnostics.

## 13. Partial Operations

This profile MUST NOT return a verified outcome for partial/random single-file
extraction unless core has already completed the full v44 verification required
for that outcome.

Partial operations may report root auth as deferred or unavailable.

## 14. Required Test Vectors

1. `RootAuthContentVerified`: matching trusted root, valid full v44 RootAuth
   verification, valid chain at the selected chain-validation time. Cover an
   encrypted archive with a raw/passphrase archive key, a RecipientWrap archive
   after core has recovered `master_key`, and an unencrypted archive with no
   password/key material.
2. `PublicDataBlockCommitmentVerified`: matching trusted root, no archive key,
   complete public data-block observation set. Cover both an encrypted archive
   (ciphertext blocks) and an unencrypted archive (`aead_algo = None`, plaintext
   blocks).
3. `UntrustedChain`: valid signature and embedded chain, wrong trusted root.
4. `Invalid`: flipped `archive_root`, wrong signing domain, wrong certificate
   public key, unsupported or mismatched `sig_scheme`, RSA-PSS parameter
   mismatch, malformed ECDSA DER signature value, non-zero signature padding,
   malformed certificate DER, chain digest mismatch, trailing authenticator
   bytes.
5. `UnsupportedIdentity`: unknown `signer_identity_type` with otherwise valid
   core footer wire checks.
6. `MissingTrustPolicy`: no caller-supplied trusted roots and no explicit
   `--trusted-system-roots` request.
   Repeat with only `--trusted-system-roots` and verify success, when the chain
   validates, reports `trust_store_policy = openssl_default_roots`; repeat with
   both caller roots and OpenSSL defaults and verify
   `trust_store_policy = caller_roots_plus_openssl_default_roots`.
7. Stored footer `archive_root` differs from core recomputation: core rejects
   before profile success is possible.
8. Signature schemes: valid RSA-PKCS1-SHA256 (`sig_scheme = 1`), valid
   ECDSA-SHA256-DER (`sig_scheme = 2`) on P-256, P-384, and P-521, valid
   RSA-PSS-SHA256 with salt length 32 (`sig_scheme = 3`), and rejection when
   any of those signatures is verified under another scheme. Include an EC key
   on an unsupported named curve and verify readers and writers reject it even
   when the local crypto provider supports that curve.
9. Time labelling: under the default `verifier_current_time` policy, a chain
   that validates at `signed_at_unix_seconds` but is expired at current
   verification time MUST fail as `UntrustedChain`, while still reporting
   `signed_at_unix_seconds` as signer-claimed metadata. Such a case may succeed
   only when an explicit future profile or deployment policy selects a different
   chain-validation time with separate evidence, and the report MUST label that
   non-default time basis separately.
10. Leaf KeyUsage: a valid chain whose leaf KeyUsage contains
    `digitalSignature` or `contentCommitment`/`nonRepudiation` succeeds; a leaf
    with KeyUsage present but limited to unrelated uses such as key encipherment
    fails; a leaf with no KeyUsage extension follows normal path validation and
    reports `key_usage_policy = archive_signature_minimal`.
11. EKU reporting: a leaf with no EKU, code-signing EKU, document-signing EKU,
    or an unrelated EKU is handled the same under the default v1 profile, while
    reports expose `eku_policy = none` and do not imply a document-signing or
    freshness policy.
