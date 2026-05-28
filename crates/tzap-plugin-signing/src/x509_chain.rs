use std::fmt;

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{Id, PKey, Private};
use openssl::sign::{Signer, Verifier};
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509NameRef, X509StoreContext, X509};
use sha2::{Digest, Sha256, Sha512};
use tzap_core::format::ROOT_AUTH_SPEC_ID;
use tzap_core::wire::RootAuthFooterV1;
use tzap_core::writer::{RootAuthSigningRequest, RootAuthWriterConfig};

pub const X509_AUTHENTICATOR_ID: u16 = 0x0003;
pub const X509_SIGNER_IDENTITY_TYPE_DER_CERT: u16 = 2;

const MAGIC: &[u8; 4] = b"TZXC";
const VERSION: u16 = 1;
const SIG_SCHEME_OPENSSL_SHA256: u16 = 1;
const X509_SIGNING_DOMAIN: &[u8] = b"tzap-sig-x509-v1\0";
const X509_CHAIN_DOMAIN: &[u8] = b"tzap-x509-chain-v1\0";
const AUTHENTICATOR_FIXED_LEN: usize = 60;
const SHA256_LEN: usize = 32;

#[derive(Debug)]
pub enum X509RootAuthError {
    Invalid(&'static str),
    Crypto(ErrorStack),
    Chain(String),
}

impl fmt::Display for X509RootAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Crypto(err) => write!(formatter, "{err}"),
            Self::Chain(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for X509RootAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ErrorStack> for X509RootAuthError {
    fn from(err: ErrorStack) -> Self {
        Self::Crypto(err)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509RootAuthReport {
    pub signed_at_unix_seconds: i64,
    pub subject: String,
    pub issuer: String,
    pub serial_number_hex: String,
    pub certificate_sha256: [u8; SHA256_LEN],
    pub verified_chain_subjects: Vec<String>,
    pub trust_anchor_subject: Option<String>,
}

#[derive(Debug)]
pub struct X509RootAuthSigner {
    leaf_certificate_der: Vec<u8>,
    private_key: PKey<Private>,
    chain_certificate_der: Vec<Vec<u8>>,
    signed_at_unix_seconds: i64,
    signature_capacity: usize,
}

impl X509RootAuthSigner {
    pub fn from_pem_or_der(
        leaf_certificate_bytes: &[u8],
        private_key_bytes: &[u8],
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
    ) -> Result<Self, X509RootAuthError> {
        let leaf_certificate_der = certificate_der_from_pem_or_der(leaf_certificate_bytes)?;
        let private_key = private_key_from_pem_or_der(private_key_bytes)?;
        Self::new(
            leaf_certificate_der,
            private_key,
            chain_certificate_der,
            signed_at_unix_seconds,
        )
    }

    pub fn new(
        leaf_certificate_der: Vec<u8>,
        private_key: PKey<Private>,
        chain_certificate_der: Vec<Vec<u8>>,
        signed_at_unix_seconds: i64,
    ) -> Result<Self, X509RootAuthError> {
        let leaf_certificate = X509::from_der(&leaf_certificate_der)?;
        let leaf_certificate_der = leaf_certificate.to_der()?;
        let leaf_public_key = leaf_certificate.public_key()?;
        if !leaf_public_key.public_eq(&private_key) {
            return Err(X509RootAuthError::Invalid(
                "certificate public key does not match private key",
            ));
        }
        if matches!(private_key.id(), Id::ED25519 | Id::ED448) {
            return Err(X509RootAuthError::Invalid(
                "EdDSA X.509 keys are not supported by this RootAuth profile",
            ));
        }
        let chain_certificate_der = normalize_certificate_der_chain(chain_certificate_der)?;
        let signature_capacity = private_key.size();
        let signer = Self {
            leaf_certificate_der,
            private_key,
            chain_certificate_der,
            signed_at_unix_seconds,
            signature_capacity,
        };
        signer.authenticator_value_length()?;
        Ok(signer)
    }

    pub fn signer_identity(&self) -> &[u8] {
        &self.leaf_certificate_der
    }

    pub fn authenticator_value_length(&self) -> Result<u32, X509RootAuthError> {
        authenticator_value_len(self.signature_capacity, &self.chain_certificate_der)
    }

    pub fn root_auth_writer_config(&self) -> Result<RootAuthWriterConfig<'_>, X509RootAuthError> {
        Ok(RootAuthWriterConfig {
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity: self.signer_identity(),
            authenticator_value_length: self.authenticator_value_length()?,
        })
    }

    pub fn authenticator_value_for_request(
        &self,
        request: &RootAuthSigningRequest,
    ) -> Result<Vec<u8>, X509RootAuthError> {
        let chain_digest = chain_digest(&self.chain_certificate_der)?;
        let signing_input = signing_input(
            &request.archive_uuid,
            &request.session_id,
            &request.archive_root,
            self.signed_at_unix_seconds,
            &chain_digest,
        );
        let mut signer = Signer::new(MessageDigest::sha256(), &self.private_key)?;
        signer.update(&signing_input)?;
        let signature = signer.sign_to_vec()?;
        if signature.len() > self.signature_capacity {
            return Err(X509RootAuthError::Invalid(
                "signature exceeded reserved authenticator capacity",
            ));
        }

        let mut out = Vec::with_capacity(self.authenticator_value_length()? as usize);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&SIG_SCHEME_OPENSSL_SHA256.to_le_bytes());
        out.extend_from_slice(&self.signed_at_unix_seconds.to_le_bytes());
        out.extend_from_slice(&chain_digest);
        out.extend_from_slice(&u32_len(signature.len(), "signature length")?.to_le_bytes());
        out.extend_from_slice(
            &u32_len(self.signature_capacity, "signature capacity")?.to_le_bytes(),
        );
        out.extend_from_slice(
            &u32_len(self.chain_certificate_der.len(), "chain count")?.to_le_bytes(),
        );
        out.extend_from_slice(&signature);
        out.resize(out.len() + (self.signature_capacity - signature.len()), 0);
        for cert_der in &self.chain_certificate_der {
            out.extend_from_slice(
                &u32_len(cert_der.len(), "chain certificate length")?.to_le_bytes(),
            );
            out.extend_from_slice(cert_der);
        }
        Ok(out)
    }
}

pub fn signing_input(
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    archive_root: &[u8; 32],
    signed_at_unix_seconds: i64,
    chain_digest: &[u8; SHA256_LEN],
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(X509_SIGNING_DOMAIN);
    hasher.update(ROOT_AUTH_SPEC_ID);
    hasher.update(archive_uuid);
    hasher.update(session_id);
    hasher.update(archive_root);
    hasher.update(signed_at_unix_seconds.to_le_bytes());
    hasher.update(chain_digest);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

pub fn certificate_der_from_pem_or_der(bytes: &[u8]) -> Result<Vec<u8>, X509RootAuthError> {
    if let Ok(cert) = X509::from_pem(bytes) {
        return Ok(cert.to_der()?);
    }
    Ok(X509::from_der(bytes)?.to_der()?)
}

pub fn certificates_der_from_pem_or_der(bytes: &[u8]) -> Result<Vec<Vec<u8>>, X509RootAuthError> {
    if let Ok(certs) = X509::stack_from_pem(bytes) {
        if certs.is_empty() {
            return Err(X509RootAuthError::Invalid("certificate PEM file is empty"));
        }
        return certs
            .into_iter()
            .map(|cert| cert.to_der().map_err(Into::into))
            .collect();
    }
    Ok(vec![X509::from_der(bytes)?.to_der()?])
}

fn normalize_certificate_der_chain(
    chain_certificate_der: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, X509RootAuthError> {
    chain_certificate_der
        .into_iter()
        .map(|cert_der| Ok(X509::from_der(&cert_der)?.to_der()?))
        .collect()
}

pub fn verify_root_auth_footer(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    trusted_roots_der: &[Vec<u8>],
    use_system_roots: bool,
) -> Result<X509RootAuthReport, X509RootAuthError> {
    if footer.authenticator_id != X509_AUTHENTICATOR_ID {
        return Err(X509RootAuthError::Invalid("unsupported authenticator id"));
    }
    if footer.signer_identity_type != X509_SIGNER_IDENTITY_TYPE_DER_CERT {
        return Err(X509RootAuthError::Invalid(
            "unsupported signer identity type",
        ));
    }
    if trusted_roots_der.is_empty() && !use_system_roots {
        return Err(X509RootAuthError::Invalid(
            "X.509 verification requires trusted roots",
        ));
    }

    let leaf_certificate = X509::from_der(&footer.signer_identity_bytes)?;
    let parsed = parse_authenticator_value(&footer.authenticator_value)?;
    let signing_input = signing_input(
        &footer.archive_uuid,
        &footer.session_id,
        archive_root,
        parsed.signed_at_unix_seconds,
        &parsed.chain_digest,
    );
    let leaf_public_key = leaf_certificate.public_key()?;
    let mut verifier = Verifier::new(MessageDigest::sha256(), &leaf_public_key)?;
    verifier.update(&signing_input)?;
    if !verifier.verify(&parsed.signature)? {
        return Err(X509RootAuthError::Invalid(
            "X.509 RootAuth signature failed",
        ));
    }

    let verified_chain_subjects = verify_certificate_chain(
        &leaf_certificate,
        &parsed.chain_certificate_der,
        trusted_roots_der,
        use_system_roots,
        parsed.signed_at_unix_seconds,
    )?;
    let fingerprint = leaf_certificate.digest(MessageDigest::sha256())?;
    let mut certificate_sha256 = [0u8; SHA256_LEN];
    certificate_sha256.copy_from_slice(&fingerprint);
    let trust_anchor_subject = verified_chain_subjects.last().cloned();

    Ok(X509RootAuthReport {
        signed_at_unix_seconds: parsed.signed_at_unix_seconds,
        subject: name_to_string(leaf_certificate.subject_name()),
        issuer: name_to_string(leaf_certificate.issuer_name()),
        serial_number_hex: leaf_certificate
            .serial_number()
            .to_bn()?
            .to_hex_str()?
            .to_string(),
        certificate_sha256,
        verified_chain_subjects,
        trust_anchor_subject,
    })
}

#[derive(Debug)]
struct ParsedAuthenticator {
    signed_at_unix_seconds: i64,
    chain_digest: [u8; SHA256_LEN],
    signature: Vec<u8>,
    chain_certificate_der: Vec<Vec<u8>>,
}

fn private_key_from_pem_or_der(bytes: &[u8]) -> Result<PKey<Private>, X509RootAuthError> {
    if let Ok(key) = PKey::private_key_from_pem(bytes) {
        return Ok(key);
    }
    Ok(PKey::private_key_from_der(bytes)?)
}

fn parse_authenticator_value(value: &[u8]) -> Result<ParsedAuthenticator, X509RootAuthError> {
    if value.len() < AUTHENTICATOR_FIXED_LEN {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator is too short",
        ));
    }
    if &value[0..4] != MAGIC {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator magic mismatch",
        ));
    }
    if read_u16(value, 4)? != VERSION {
        return Err(X509RootAuthError::Invalid(
            "unsupported X.509 authenticator version",
        ));
    }
    if read_u16(value, 6)? != SIG_SCHEME_OPENSSL_SHA256 {
        return Err(X509RootAuthError::Invalid(
            "unsupported X.509 signature scheme",
        ));
    }
    let signed_at_unix_seconds = read_i64(value, 8)?;
    let mut parsed_chain_digest = [0u8; SHA256_LEN];
    parsed_chain_digest.copy_from_slice(&value[16..48]);
    let signature_len = read_u32(value, 48)? as usize;
    let signature_capacity = read_u32(value, 52)? as usize;
    let chain_count = read_u32(value, 56)? as usize;
    if signature_len > signature_capacity {
        return Err(X509RootAuthError::Invalid(
            "X.509 signature length exceeds capacity",
        ));
    }
    let mut offset = AUTHENTICATOR_FIXED_LEN
        .checked_add(signature_capacity)
        .ok_or(X509RootAuthError::Invalid(
            "X.509 authenticator length overflow",
        ))?;
    if value.len() < offset {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator signature is truncated",
        ));
    }
    if chain_count > value.len().saturating_sub(offset) / 4 {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator chain count exceeds payload",
        ));
    }
    let signature_start = AUTHENTICATOR_FIXED_LEN;
    let signature_end = signature_start + signature_len;
    if value[signature_end..offset].iter().any(|byte| *byte != 0) {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator signature padding is non-zero",
        ));
    }
    let signature = value[signature_start..signature_end].to_vec();
    let mut chain_certificate_der = Vec::new();
    for _ in 0..chain_count {
        let cert_len = read_u32(value, offset)? as usize;
        offset = offset.checked_add(4).ok_or(X509RootAuthError::Invalid(
            "X.509 authenticator length overflow",
        ))?;
        let cert_end = offset
            .checked_add(cert_len)
            .ok_or(X509RootAuthError::Invalid(
                "X.509 authenticator length overflow",
            ))?;
        if cert_end > value.len() {
            return Err(X509RootAuthError::Invalid(
                "X.509 authenticator certificate chain is truncated",
            ));
        }
        chain_certificate_der.push(value[offset..cert_end].to_vec());
        offset = cert_end;
    }
    if offset != value.len() {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator has trailing bytes",
        ));
    }
    if chain_digest(&chain_certificate_der)? != parsed_chain_digest {
        return Err(X509RootAuthError::Invalid(
            "X.509 authenticator chain digest mismatch",
        ));
    }
    Ok(ParsedAuthenticator {
        signed_at_unix_seconds,
        chain_digest: parsed_chain_digest,
        signature,
        chain_certificate_der,
    })
}

fn verify_certificate_chain(
    leaf_certificate: &X509,
    chain_certificate_der: &[Vec<u8>],
    trusted_roots_der: &[Vec<u8>],
    use_system_roots: bool,
    signed_at_unix_seconds: i64,
) -> Result<Vec<String>, X509RootAuthError> {
    let mut store_builder = X509StoreBuilder::new()?;
    for root_der in trusted_roots_der {
        store_builder.add_cert(X509::from_der(root_der)?)?;
    }
    if use_system_roots {
        store_builder.set_default_paths()?;
    }
    let mut params = X509VerifyParam::new()?;
    params.set_time(signed_at_unix_seconds as _);
    store_builder.set_param(&params)?;
    let store = store_builder.build();

    let mut chain = Stack::new()?;
    for cert_der in chain_certificate_der {
        chain.push(X509::from_der(cert_der)?)?;
    }
    let mut context = X509StoreContext::new()?;
    let mut verify_error = None;
    let mut subjects = Vec::new();
    let verified = context.init(&store, leaf_certificate, &chain, |ctx| {
        let ok = ctx.verify_cert()?;
        if ok {
            if let Some(chain) = ctx.chain() {
                subjects = chain
                    .iter()
                    .map(|cert| name_to_string(cert.subject_name()))
                    .collect();
            }
        } else {
            verify_error = Some(format!("{} at depth {}", ctx.error(), ctx.error_depth()));
        }
        Ok(ok)
    })?;
    if !verified {
        return Err(X509RootAuthError::Chain(verify_error.unwrap_or_else(
            || "certificate chain verification failed".to_string(),
        )));
    }
    if subjects.is_empty() {
        subjects.push(name_to_string(leaf_certificate.subject_name()));
    }
    Ok(subjects)
}

fn chain_digest(chain_certificate_der: &[Vec<u8>]) -> Result<[u8; SHA256_LEN], X509RootAuthError> {
    let mut hasher = Sha256::new();
    hasher.update(X509_CHAIN_DOMAIN);
    hasher.update(u32_len(chain_certificate_der.len(), "chain count")?.to_le_bytes());
    for cert_der in chain_certificate_der {
        hasher.update(u32_len(cert_der.len(), "chain certificate length")?.to_le_bytes());
        hasher.update(cert_der);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; SHA256_LEN];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn authenticator_value_len(
    signature_capacity: usize,
    chain_certificate_der: &[Vec<u8>],
) -> Result<u32, X509RootAuthError> {
    let chain_len = chain_certificate_der
        .iter()
        .try_fold(0usize, |acc, cert_der| {
            acc.checked_add(4)
                .and_then(|value| value.checked_add(cert_der.len()))
                .ok_or(X509RootAuthError::Invalid(
                    "X.509 authenticator length overflow",
                ))
        })?;
    let total = AUTHENTICATOR_FIXED_LEN
        .checked_add(signature_capacity)
        .and_then(|value| value.checked_add(chain_len))
        .ok_or(X509RootAuthError::Invalid(
            "X.509 authenticator length overflow",
        ))?;
    u32_len(total, "authenticator value length")
}

fn name_to_string(name: &X509NameRef) -> String {
    let mut parts = Vec::new();
    for entry in name.entries() {
        let key = entry.object().nid().short_name().unwrap_or("OID");
        let value = entry
            .data()
            .as_utf8()
            .map(|value| value.to_string())
            .unwrap_or_else(|_| encode_hex(entry.data().as_slice()));
        parts.push(format!("{key}={value}"));
    }
    parts.join(", ")
}

fn read_u16(value: &[u8], offset: usize) -> Result<u16, X509RootAuthError> {
    let bytes = value
        .get(offset..offset + 2)
        .ok_or(X509RootAuthError::Invalid(
            "X.509 authenticator is truncated",
        ))?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(value: &[u8], offset: usize) -> Result<u32, X509RootAuthError> {
    let bytes = value
        .get(offset..offset + 4)
        .ok_or(X509RootAuthError::Invalid(
            "X.509 authenticator is truncated",
        ))?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_i64(value: &[u8], offset: usize) -> Result<i64, X509RootAuthError> {
    let bytes = value
        .get(offset..offset + 8)
        .ok_or(X509RootAuthError::Invalid(
            "X.509 authenticator is truncated",
        ))?;
    Ok(i64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn u32_len(len: usize, field: &'static str) -> Result<u32, X509RootAuthError> {
    u32::try_from(len).map_err(|_| match field {
        "signature length" => X509RootAuthError::Invalid("X.509 signature length overflow"),
        "signature capacity" => X509RootAuthError::Invalid("X.509 signature capacity overflow"),
        "chain count" => X509RootAuthError::Invalid("X.509 chain count overflow"),
        "chain certificate length" => {
            X509RootAuthError::Invalid("X.509 chain certificate length overflow")
        }
        _ => X509RootAuthError::Invalid("X.509 authenticator length overflow"),
    })
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = fmt::Write::write_fmt(&mut output, format_args!("{:02x}", byte));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKeyRef;
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{BasicConstraints, KeyUsage};
    use openssl::x509::{X509NameBuilder, X509Ref};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn x509_authenticator_round_trips_with_trusted_root() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert(
            "Acme Release Signing",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        let signed_at = now_unix_seconds();
        let signer =
            X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at)
                .unwrap();
        let request = RootAuthSigningRequest {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let value = signer.authenticator_value_for_request(&request).unwrap();
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: value,
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let report = verify_root_auth_footer(
            &footer,
            &request.archive_root,
            &[root_cert.to_der().unwrap()],
            false,
        )
        .unwrap();

        assert_eq!(report.signed_at_unix_seconds, signed_at);
        assert!(report.subject.contains("CN=Acme Release Signing"));
        assert!(report.issuer.contains("CN=Acme Test Root CA"));
        assert_eq!(
            report.trust_anchor_subject.as_deref(),
            Some("CN=Acme Test Root CA")
        );
    }

    #[test]
    fn rejects_wrong_trusted_root() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (wrong_root_cert, _) = test_ca_cert("Wrong Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert(
            "Acme Release Signing",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        let signed_at = now_unix_seconds();
        let signer =
            X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at)
                .unwrap();
        let request = RootAuthSigningRequest {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: signer.authenticator_value_for_request(&request).unwrap(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let err = verify_root_auth_footer(
            &footer,
            &request.archive_root,
            &[wrong_root_cert.to_der().unwrap()],
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("certificate"));
    }

    #[test]
    fn signer_rejects_invalid_chain_certificate_der() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert(
            "Acme Release Signing",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        let err = X509RootAuthSigner::new(
            leaf_cert.to_der().unwrap(),
            leaf_key,
            vec![b"not a DER certificate".to_vec()],
            now_unix_seconds(),
        )
        .unwrap_err();

        assert!(matches!(err, X509RootAuthError::Crypto(_)));
    }

    #[test]
    fn rejects_impossible_chain_count_without_large_allocation() {
        let (root_cert, root_key) = test_ca_cert("Acme Test Root CA");
        let (leaf_cert, leaf_key) = test_leaf_cert(
            "Acme Release Signing",
            root_cert.as_ref(),
            root_key.as_ref(),
        );
        let signed_at = now_unix_seconds();
        let signer =
            X509RootAuthSigner::new(leaf_cert.to_der().unwrap(), leaf_key, Vec::new(), signed_at)
                .unwrap();
        let request = RootAuthSigningRequest {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let mut value = signer.authenticator_value_for_request(&request).unwrap();
        value[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            authenticator_id: X509_AUTHENTICATOR_ID,
            signer_identity_type: X509_SIGNER_IDENTITY_TYPE_DER_CERT,
            signer_identity_bytes: leaf_cert.to_der().unwrap(),
            authenticator_value: value,
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        let err = verify_root_auth_footer(
            &footer,
            &request.archive_root,
            &[root_cert.to_der().unwrap()],
            false,
        )
        .unwrap_err();

        assert!(err.to_string().contains("chain count"));
    }

    fn test_ca_cert(cn: &str) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn test_leaf_cert(
        cn: &str,
        ca_cert: &X509Ref,
        ca_key: &PKeyRef<Private>,
    ) -> (X509, PKey<Private>) {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", cn).unwrap();
        let name = name.build();
        let mut builder = X509::builder().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(&random_serial_number()).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    fn random_serial_number() -> openssl::asn1::Asn1Integer {
        let mut serial = BigNum::new().unwrap();
        serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        serial.to_asn1_integer().unwrap()
    }

    fn now_unix_seconds() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }
}
