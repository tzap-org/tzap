# tzap-plugin-signing-v5 - proposed v43 Ed25519 root authenticator

Specification for the optional Ed25519 signing authenticator profile for tzap
v43 root authentication.

Status: implementation target for the v43 core helper API. Targets
`specs/tzap-format-revisedv43.md` and
`root_auth_spec_id = "tzap-root-auth-v0.43\0"` padded to 24 bytes.

## 1. Scope

In scope:

- one Ed25519 authenticator profile over core's recomputed `archive_root`;
- the exact bytes written into `RootAuthFooterV1.authenticator_value`;
- `authenticator_id = 0x0002`;
- the strict Ed25519 verification profile;
- API outcome wording for key-holding and public no-key verification modes.

Not in scope:

- `archive_root` construction;
- `RootAuthFooterV1` layout and footer CRC;
- CMRA and locator recovery;
- key-holding versus public no-key source-authority rules;
- CLI key-management UX, X.509, timestamping, trust stores, revocation, or
  certificate policy.

Those are core v43 or future-plugin responsibilities.

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
mode and the Ed25519 key is unrelated to any archive encryption key. A signed
unencrypted (`aead_algo = None`) archive is therefore tamper-evident and
verifiable with no archive key.

## 3. Scheme Registration

```text
authenticator_id = 0x0002
name             = "ed25519-archiveroot-v1"
```

When a `RootAuthFooterV1` selects `authenticator_id = 0x0002`, this profile is
the sole authenticator interpretation for that footer.

## 4. Authenticator Value

The profile fills `RootAuthFooterV1.authenticator_value` with:

```rust
struct Ed25519ArchiveRootSignatureV1 {
    sig_scheme:   u16,       // 1 = Ed25519 pure, RFC 8032
    _reserved:    u16,       // MUST be zero
    signature:    [u8; 64],  // Ed25519 signature over SIGNING_INPUT
}
```

`authenticator_value_length` MUST equal 68.

Readers MUST reject this authenticator value unless:

- length is exactly 68;
- `sig_scheme = 1`;
- `_reserved = 0`;
- `signature` is exactly 64 bytes.

## 4.1 Signing Input

The profile signs a domain-separated digest of core root-auth fields:

```text
SIGNING_INPUT = SHA-512(
    "tzap-sig-ed25519-v1\0"
    || root_auth_spec_id          // exact 24 bytes from RootAuthFooterV1
    || archive_uuid               // exact 16 bytes from RootAuthFooterV1
    || session_id                 // exact 16 bytes from RootAuthFooterV1
    || archive_root               // recomputed core value, 32 bytes
)
```

The Ed25519 message is the 64-byte `SIGNING_INPUT` digest. The profile MUST NOT
sign raw archive bytes, raw footer bytes, or a stored `archive_root` that core
has not recomputed and equality-checked.

## 4.2 Strict Ed25519 Profile

The algorithm is RFC 8032 Ed25519 pure, not Ed25519ph.

Readers MUST reject:

- non-canonical public keys;
- small-order public keys;
- non-canonical `R`;
- non-canonical `S`;
- signatures that fail strict cofactored verification.

## 5. Signer Identity

Supported `RootAuthFooterV1.signer_identity_type` values for this profile:

| Type | Meaning | Status |
|---:|---|---|
| 0 | no embedded identity | supported, caller key required |
| 1 | raw Ed25519 public key, 32 bytes | supported |
| 2 | X.509 chain | reserved |

For type 1, `signer_identity_length` MUST equal 32 and
`signer_identity_bytes` MUST be the Ed25519 public key bytes.

An embedded public key alone is not a trust anchor. Without a caller-supplied
trusted key or trust policy, a valid embedded-key signature is self-consistent
only.

## 6. Verification Inputs

Core passes the profile:

- validated `root_auth_spec_id`;
- `archive_uuid`;
- `session_id`;
- recomputed `archive_root`;
- `signer_identity_type`;
- exact `signer_identity_bytes`;
- exact `authenticator_value`;
- optional caller-supplied trusted Ed25519 key bytes.

The profile MUST NOT read archive files, parse metadata, perform FEC, decrypt
objects, or decide public observation windows.

## 7. Outcomes

```rust
enum Ed25519RootAuthOutcome {
    Invalid,
    UnsupportedIdentity,
    SelfSignedConsistent,
    RootAuthContentVerified { key_id },
    PublicDataBlockCommitmentVerified { key_id },
}
```

`RootAuthContentVerified` is available only when core has completed key-holding
v43 full-archive content verification and root-auth recomputation.

`PublicDataBlockCommitmentVerified` is available only when core has completed
the v43 public no-key observation path. It proves only that a trusted key signed
a commitment to the observed data-block set (ciphertext blocks in an encryption
mode; plaintext blocks in unencrypted mode) and opaque component digests. In an
encryption mode it does not prove plaintext, file list, IndexRoot,
HMAC-authenticated metadata, physical completeness, or recovery margin; in
unencrypted mode the data blocks are plaintext, so the commitment covers the
plaintext data directly, but it still does not prove the file list/IndexRoot
contents, physical completeness, or recovery margin.

`SelfSignedConsistent` means the signature validates against an embedded key
but no caller trust anchor matched. It MUST NOT be described as origin
authenticity.

## 8. Evaluation Order

1. Core validates and recomputes v43 root-auth inputs.
2. The profile parses `authenticator_value`.
3. The profile selects a verification key:
   - caller-supplied trusted key if provided;
   - embedded raw Ed25519 key only for `SelfSignedConsistent`;
   - otherwise `UnsupportedIdentity`.
4. The profile builds `SIGNING_INPUT`.
5. The profile verifies the Ed25519 signature using the strict profile.
6. If verification fails, return `Invalid`.
7. If verification succeeds with caller trust and core is in key-holding full
   verification mode, return `RootAuthContentVerified`.
8. If verification succeeds with caller trust and core is in public no-key
   mode, return `PublicDataBlockCommitmentVerified`.
9. If verification succeeds only with an embedded untrusted key, return
   `SelfSignedConsistent`.

## 9. Partial Operations

This profile MUST NOT return a verified outcome for partial/random single-file
extraction unless core has already completed the full v43 verification required
for that outcome.

Partial operations may report root auth as deferred or unavailable.

## 10. Required Test Vectors

1. `RootAuthContentVerified`: matching caller key, valid key-holding v43 full
   verification.
2. `PublicDataBlockCommitmentVerified`: matching caller key, no archive key,
   complete public data-block observation set. Cover both an encrypted archive
   (ciphertext blocks) and an unencrypted archive (`aead_algo = None`, plaintext
   blocks).
3. `SelfSignedConsistent`: embedded raw public key, no caller trusted key.
4. `Invalid`: flipped `archive_root`, wrong domain, wrong key, malformed
   signature value, non-canonical public key, non-canonical signature.
5. `UnsupportedIdentity`: unknown `signer_identity_type` with otherwise valid
   core footer wire checks.
6. Stored footer `archive_root` differs from core recomputation: core rejects
   before profile success is possible.
