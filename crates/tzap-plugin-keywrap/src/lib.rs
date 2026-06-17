#![forbid(unsafe_code)]

use openssl::pkey::PKey;
use openssl::x509::X509;
use sha2::{Digest, Sha256};
use tzap_core::format::{FORMAT_VERSION, VOLUME_FORMAT_REV_44};
use x509_parser::parse_x509_certificate;

/// Profile identifier for key-wrap v1 recipient records.
pub const KEYWRAP_PROFILE_ID: u16 = 0x0001;

/// Recipient identity type for a DER-encoded x509 leaf certificate.
pub const KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES: u16 = 2;

const KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN: usize = 64;
pub const KEYWRAP_PAYLOAD_VERSION: u16 = 1;
const KEY_WRAP_CONTEXT_DOMAIN: &[u8] = b"tzap-keywrap-x509-hpke-v1-context\0";

const X25519_KEM_ID: u16 = 0x0020;
const P256_KEM_ID: u16 = 0x0010;
const HKDF_SHA256_KDF_ID: u16 = 0x0001;
const CHACHA20POLY1305_AEAD_ID: u16 = 0x0003;
const AES256GCM_AEAD_ID: u16 = 0x0002;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HpkeSuite {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    enc_length: usize,
    ciphertext_length: usize,
}

impl HpkeSuite {
    fn for_profile(hpke_kem_id: u16, hpke_kdf_id: u16, hpke_aead_id: u16) -> Option<Self> {
        let suites = [
            Self {
                kem_id: X25519_KEM_ID,
                kdf_id: HKDF_SHA256_KDF_ID,
                aead_id: CHACHA20POLY1305_AEAD_ID,
                enc_length: 32,
                ciphertext_length: 48,
            },
            Self {
                kem_id: P256_KEM_ID,
                kdf_id: HKDF_SHA256_KDF_ID,
                aead_id: AES256GCM_AEAD_ID,
                enc_length: 65,
                ciphertext_length: 48,
            },
        ];

        for suite in suites {
            if suite.kem_id == hpke_kem_id && suite.kdf_id == hpke_kdf_id && suite.aead_id == hpke_aead_id {
                return Some(suite);
            }
        }

        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveIdentity {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub format_version: u16,
    pub volume_format_rev: u16,
}

impl Default for ArchiveIdentity {
    fn default() -> Self {
        Self {
            archive_uuid: [0u8; 16],
            session_id: [0u8; 16],
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_44,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecordMetadata {
    pub profile_id: u16,
    pub recipient_identity_type: u16,
    pub recipient_identity_digest: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecordInput {
    pub archive_identity: ArchiveIdentity,
    pub metadata: RecipientRecordMetadata,
    pub recipient_identity_bytes: Vec<u8>,
    pub profile_payload_bytes: Vec<u8>,
}

/// Abstraction for locating a private key for profile-specific decryption.
pub trait PrivateKeyLookup {
    fn lookup_private_key(
        &self,
        archive_identity: &ArchiveIdentity,
        metadata: &RecipientRecordMetadata,
        recipient_identity_bytes: &[u8],
    ) -> Option<Vec<u8>>;

    fn is_recipient_certificate_accepted(
        &self,
        _archive_identity: &ArchiveIdentity,
        _metadata: &RecipientRecordMetadata,
        _recipient_identity_bytes: &[u8],
        _recipient_spki_digest: &[u8; 32],
    ) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyWrapOutcome {
    UnsupportedProfileId,
    UnsupportedArchiveIdentity,
    UnsupportedRecipientIdentity,
    UnsupportedSuite,
    CertificatePolicyRejected,
    InvalidRecord,
    NoMatchingPrivateKey,
    StubProfileConstructed {
        recipient_spki_digest: [u8; 32],
    },
}

#[derive(Debug, Clone)]
struct ParsedRecipientIdentity {
    recipient_identity_digest: [u8; 32],
    recipient_spki_digest: [u8; 32],
}

#[derive(Debug, Clone)]
struct ParsedProfilePayload {
    suite: HpkeSuite,
    recipient_spki_digest: [u8; 32],
    enc: Vec<u8>,
    ciphertext: Vec<u8>,
    key_wrap_context_digest: [u8; 32],
}

/// Dispatch a single key-wrap recipient record to the profile parser.
///
/// For `profile_id == KEYWRAP_PROFILE_ID`, this validates:
/// - recipient identity parsing for X.509 type=2 records
/// - profile payload framing
/// - context digest computation
/// - supported HPKE suites and fixed lengths
///
/// It does not yet execute HPKE Open.
pub fn dispatch_key_wrap_record<L>(
    input: RecipientRecordInput,
    private_key_lookup: &L,
) -> KeyWrapOutcome
where
    L: PrivateKeyLookup + ?Sized,
{
    if input.archive_identity.format_version != FORMAT_VERSION
        || input.archive_identity.volume_format_rev != VOLUME_FORMAT_REV_44
    {
        return KeyWrapOutcome::UnsupportedArchiveIdentity;
    }

    if input.metadata.profile_id != KEYWRAP_PROFILE_ID {
        return KeyWrapOutcome::UnsupportedProfileId;
    }

    if input.metadata.recipient_identity_type != KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES {
        return KeyWrapOutcome::UnsupportedRecipientIdentity;
    }

    let parsed_identity = match parse_x509_recipient_identity(&input.recipient_identity_bytes) {
        Ok(identity) => identity,
        Err(outcome) => return outcome,
    };

    if parsed_identity.recipient_identity_digest != input.metadata.recipient_identity_digest {
        return KeyWrapOutcome::InvalidRecord;
    }

    let payload = match parse_profile_payload(&input.profile_payload_bytes, &input.archive_identity, &input.metadata, &parsed_identity) {
        Ok(payload) => payload,
        Err(outcome) => return outcome,
    };

    let _private_key = match private_key_lookup.lookup_private_key(
        &input.archive_identity,
        &input.metadata,
        &input.recipient_identity_bytes,
    ) {
        Some(private_key) => private_key,
        None => return KeyWrapOutcome::NoMatchingPrivateKey,
    };

    if !private_key_lookup.is_recipient_certificate_accepted(
        &input.archive_identity,
        &input.metadata,
        &input.recipient_identity_bytes,
        &payload.recipient_spki_digest,
    ) {
        return KeyWrapOutcome::CertificatePolicyRejected;
    }

    let _ = payload; // preserve parsed payload for future HPKE stages.
    KeyWrapOutcome::StubProfileConstructed {
        recipient_spki_digest: parsed_identity.recipient_spki_digest,
    }
}

fn parse_x509_recipient_identity(
    recipient_identity_bytes: &[u8],
) -> Result<ParsedRecipientIdentity, KeyWrapOutcome> {
    let (remaining, parsed_cert) = parse_x509_certificate(recipient_identity_bytes)
        .map_err(|_error| KeyWrapOutcome::InvalidRecord)?;

    if !remaining.is_empty() {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    if let Ok(Some(key_usage)) = parsed_cert.key_usage() {
        if !key_usage.value.key_agreement() {
            return Err(KeyWrapOutcome::InvalidRecord);
        }
    }

    let openssl_cert = X509::from_der(recipient_identity_bytes).map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let openssl_public_key: PKey<_> = openssl_cert.public_key().map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let spki_der = openssl_public_key
        .public_key_to_der()
        .map_err(|_| KeyWrapOutcome::InvalidRecord)?;
    let recipient_identity_digest = sha256_digest(recipient_identity_bytes);
    let recipient_spki_digest = sha256_digest(&spki_der);

    Ok(ParsedRecipientIdentity {
        recipient_identity_digest,
        recipient_spki_digest,
    })
}

fn parse_profile_payload(
    profile_payload_bytes: &[u8],
    archive_identity: &ArchiveIdentity,
    metadata: &RecipientRecordMetadata,
    identity: &ParsedRecipientIdentity,
) -> Result<ParsedProfilePayload, KeyWrapOutcome> {
    if profile_payload_bytes.len() < KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let payload_version = u16::from_le_bytes(profile_payload_bytes[0..2].try_into().unwrap());
    let hpke_kem_id = u16::from_le_bytes(profile_payload_bytes[2..4].try_into().unwrap());
    let hpke_kdf_id = u16::from_le_bytes(profile_payload_bytes[4..6].try_into().unwrap());
    let hpke_aead_id = u16::from_le_bytes(profile_payload_bytes[6..8].try_into().unwrap());
    let enc_length = usize::from(u16::from_le_bytes(profile_payload_bytes[8..10].try_into().unwrap()));
    let ciphertext_length = usize::from(u16::from_le_bytes(profile_payload_bytes[10..12].try_into().unwrap()));
    let flags = u32::from_le_bytes(profile_payload_bytes[12..16].try_into().unwrap());
    let key_wrap_context_digest = profile_payload_bytes[16..48].try_into().unwrap();

    if flags != 0 {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    if !profile_payload_bytes[48..KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN]
        .iter()
        .all(|value| *value == 0)
    {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    if payload_version != KEYWRAP_PAYLOAD_VERSION {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let suite = HpkeSuite::for_profile(hpke_kem_id, hpke_kdf_id, hpke_aead_id)
        .ok_or(KeyWrapOutcome::UnsupportedSuite)?;

    if enc_length != suite.enc_length || ciphertext_length != suite.ciphertext_length {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let expected_length = KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN
        .checked_add(enc_length)
        .and_then(|value| value.checked_add(ciphertext_length))
        .ok_or(KeyWrapOutcome::InvalidRecord)?;

    if profile_payload_bytes.len() != expected_length {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let header_digest = compute_key_wrap_context_digest(
        archive_identity,
        metadata,
        identity,
        suite,
    );

    if header_digest != key_wrap_context_digest {
        return Err(KeyWrapOutcome::InvalidRecord);
    }

    let mut key_wrap_context_digest_array = [0u8; 32];
    key_wrap_context_digest_array.copy_from_slice(&key_wrap_context_digest);

    let enc = profile_payload_bytes[64..64 + enc_length].to_vec();
    let ciphertext =
        profile_payload_bytes[64 + enc_length..64 + enc_length + ciphertext_length].to_vec();

    Ok(ParsedProfilePayload {
        suite,
        recipient_spki_digest: identity.recipient_spki_digest,
        enc,
        ciphertext,
        key_wrap_context_digest: key_wrap_context_digest_array,
    })
}

fn compute_key_wrap_context_digest(
    archive_identity: &ArchiveIdentity,
    metadata: &RecipientRecordMetadata,
    identity: &ParsedRecipientIdentity,
    suite: HpkeSuite,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(KEY_WRAP_CONTEXT_DOMAIN);
    hasher.update(&archive_identity.archive_uuid);
    hasher.update(&archive_identity.session_id);
    hasher.update(archive_identity.format_version.to_le_bytes());
    hasher.update(archive_identity.volume_format_rev.to_le_bytes());
    hasher.update(metadata.profile_id.to_le_bytes());
    hasher.update(metadata.recipient_identity_type.to_le_bytes());
    hasher.update(identity.recipient_identity_digest);
    hasher.update(identity.recipient_spki_digest);
    hasher.update(suite.kem_id.to_le_bytes());
    hasher.update(suite.kdf_id.to_le_bytes());
    hasher.update(suite.aead_id.to_le_bytes());

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn sha256_digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use openssl::{
        asn1::Asn1Time,
        bn::{BigNum, MsbOption},
        hash::MessageDigest,
        pkey::PKey,
        rand::rand_bytes,
        rsa::Rsa,
        x509::{
            extension::BasicConstraints,
            extension::KeyUsage,
            X509,
            X509NameBuilder,
        },
    };

    #[derive(Debug)]
    struct NoMatchLookup;

    impl PrivateKeyLookup for NoMatchLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            None
        }
    }

    #[derive(Debug)]
    struct MatchLookup;

    impl PrivateKeyLookup for MatchLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            Some(vec![0x99; 32])
        }
    }

    #[derive(Debug)]
    struct RejectLookup;

    impl PrivateKeyLookup for RejectLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            Some(vec![0xAA; 32])
        }

        fn is_recipient_certificate_accepted(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
            _: &[u8; 32],
        ) -> bool {
            false
        }
    }

    fn archive_identity() -> ArchiveIdentity {
        let mut archive_uuid = [0u8; 16];
        let mut session_id = [0u8; 16];
        rand_bytes(&mut archive_uuid).unwrap();
        rand_bytes(&mut session_id).unwrap();

        ArchiveIdentity {
            archive_uuid,
            session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_44,
        }
    }

    fn test_certificate_der() -> Vec<u8> {
        make_self_signed_certificate(None)
    }

    fn test_certificate_der_with_bad_key_usage() -> Vec<u8> {
        let key_usage = KeyUsage::new().critical().digital_signature().build().unwrap();
        make_self_signed_certificate(Some(key_usage)).to_vec()
    }

    fn make_self_signed_certificate(
        key_usage_ext: Option<openssl::x509::extension::X509Extension>,
    ) -> Vec<u8> {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "tzap-keywrap-test").unwrap();
        let name = name.build();

        let mut certificate = X509::builder().unwrap();
        certificate
            .set_version(2)
            .unwrap();
        certificate
            .set_serial_number(&random_serial_number())
            .unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        certificate
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        certificate
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        if let Some(key_usage_ext) = key_usage_ext {
            certificate.append_extension(key_usage_ext).unwrap();
        }
        certificate.sign(&key, MessageDigest::sha256()).unwrap();

        certificate.build().to_der().unwrap()
    }

    fn random_serial_number() -> openssl::asn1::Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }

    fn make_payload(
        archive_identity: &ArchiveIdentity,
        metadata: &RecipientRecordMetadata,
        identity: &ParsedRecipientIdentity,
        suite: HpkeSuite,
    ) -> Vec<u8> {
        make_payload_with_lengths(
            archive_identity,
            metadata,
            identity,
            suite,
            suite.enc_length,
            suite.ciphertext_length,
        )
    }

    fn make_payload_with_lengths(
        archive_identity: &ArchiveIdentity,
        metadata: &RecipientRecordMetadata,
        identity: &ParsedRecipientIdentity,
        suite: HpkeSuite,
        enc_len: usize,
        ciphertext_len: usize,
    ) -> Vec<u8> {
        let mut payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN + enc_len + ciphertext_len];
        payload[0..2].copy_from_slice(&KEYWRAP_PAYLOAD_VERSION.to_le_bytes());
        payload[2..4].copy_from_slice(&suite.kem_id.to_le_bytes());
        payload[4..6].copy_from_slice(&suite.kdf_id.to_le_bytes());
        payload[6..8].copy_from_slice(&suite.aead_id.to_le_bytes());
        payload[8..10].copy_from_slice(&u16::try_from(enc_len).unwrap().to_le_bytes());
        payload[10..12].copy_from_slice(&u16::try_from(ciphertext_len).unwrap().to_le_bytes());
        payload[16..48].copy_from_slice(&compute_key_wrap_context_digest(
            archive_identity,
            metadata,
            identity,
            suite,
        ));

        let enc_start = KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN;
        let enc_end = enc_start + enc_len;
        let ct_end = enc_end + ciphertext_len;
        for value in payload[enc_start..enc_end].iter_mut() {
            *value = 0xAA;
        }
        for value in payload[enc_end..ct_end].iter_mut() {
            *value = 0x55;
        }

        payload
    }

    fn recipient_record_input_with_payload(profile_payload: Vec<u8>, cert_der: &[u8]) -> RecipientRecordInput {
        let identity_digest = sha256_digest(cert_der);
        RecipientRecordInput {
            archive_identity: archive_identity(),
            metadata: RecipientRecordMetadata {
                profile_id: KEYWRAP_PROFILE_ID,
                recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                recipient_identity_digest: identity_digest,
            },
            recipient_identity_bytes: cert_der.to_vec(),
            profile_payload_bytes: profile_payload,
        }
    }

    #[test]
    fn malformed_recipient_identity_is_invalid() {
        let cert_der = b"not-a-certificate".to_vec();
        let profile_payload = vec![0u8; KEYWRAP_PROFILE_PAYLOAD_HEADER_LEN];

        let input = recipient_record_input_with_payload(profile_payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn unsupported_identity_type_is_returned() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();

        let archive_identity = archive_identity();
        let suite = HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
            .unwrap();
        let payload = make_payload(
            &archive_identity,
            &RecipientRecordMetadata {
                profile_id: KEYWRAP_PROFILE_ID,
                recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                recipient_identity_digest: identity.recipient_identity_digest,
            },
            &identity,
            suite,
        );
        let mut input = recipient_record_input_with_payload(payload, &cert_der);
        input.metadata.recipient_identity_type = 0;

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::UnsupportedRecipientIdentity));
    }

    #[test]
    fn unsupported_suite_is_invalid() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };

        let unsupported_suite = HpkeSuite {
            kem_id: 0x00ff,
            kdf_id: 0x00ff,
            aead_id: 0x00ff,
            enc_length: 0,
            ciphertext_length: 0,
        };

        let payload = make_payload_with_lengths(
            &archive_identity,
            &metadata,
            &identity,
            unsupported_suite,
            0,
            0,
        );

        let input = recipient_record_input_with_payload(payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::UnsupportedSuite));
    }

    #[test]
    fn wrong_lengths_rejected_as_invalid_record() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite = HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID)
            .unwrap();

        let payload = make_payload_with_lengths(&archive_identity, &metadata, &identity, suite, suite.enc_length - 1, suite.ciphertext_length);
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn wrong_context_digest_is_invalid_record() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite = HpkeSuite::for_profile(P256_KEM_ID, HKDF_SHA256_KDF_ID, AES256GCM_AEAD_ID).unwrap();
        let mut payload = make_payload(&archive_identity, &metadata, &identity, suite);
        payload[16] ^= 0xFF;

        let input = recipient_record_input_with_payload(payload, &cert_der);
        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn valid_structure_with_no_matching_private_key_is_no_matching() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID).unwrap();
        let payload = make_payload(&archive_identity, &metadata, &identity, suite);
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::NoMatchingPrivateKey));
    }

    #[test]
    fn key_usage_without_key_agreement_is_invalid_record() {
        let cert_der = test_certificate_der_with_bad_key_usage();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite = HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID).unwrap();
        let payload = make_payload(&archive_identity, &metadata, &identity, suite);
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &NoMatchLookup);

        assert!(matches!(result, KeyWrapOutcome::InvalidRecord));
    }

    #[test]
    fn certificate_policy_rejection_is_reported() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(X25519_KEM_ID, HKDF_SHA256_KDF_ID, CHACHA20POLY1305_AEAD_ID).unwrap();
        let payload = make_payload(&archive_identity, &metadata, &identity, suite);
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &RejectLookup);

        assert!(matches!(result, KeyWrapOutcome::CertificatePolicyRejected));
    }

    #[test]
    fn profile_is_dispatched_when_private_key_is_found() {
        let cert_der = test_certificate_der();
        let identity = parse_x509_recipient_identity(&cert_der).unwrap();
        let archive_identity = archive_identity();
        let metadata = RecipientRecordMetadata {
            profile_id: KEYWRAP_PROFILE_ID,
            recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
            recipient_identity_digest: identity.recipient_identity_digest,
        };
        let suite =
            HpkeSuite::for_profile(P256_KEM_ID, HKDF_SHA256_KDF_ID, AES256GCM_AEAD_ID).unwrap();
        let payload = make_payload(&archive_identity, &metadata, &identity, suite);
        let input = recipient_record_input_with_payload(payload, &cert_der);

        let result = dispatch_key_wrap_record(input, &MatchLookup);

        assert!(matches!(
            result,
            KeyWrapOutcome::StubProfileConstructed {
                recipient_spki_digest: actual_digest
            } if actual_digest == identity.recipient_spki_digest
        ));
    }
}
