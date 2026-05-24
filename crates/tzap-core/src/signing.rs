use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::format::{FormatError, ROOT_AUTH_SPEC_ID};
use crate::reader::RootAuthVerification;
use crate::wire::RootAuthFooterV1;
use crate::writer::RootAuthSigningRequest;

pub const ED25519_AUTHENTICATOR_ID: u16 = 0x0002;
pub const ED25519_AUTHENTICATOR_VALUE_LEN: u32 = 68;

const ED25519_SIG_SCHEME_PURE: u16 = 1;
const ED25519_SIGNING_DOMAIN: &[u8] = b"tzap-sig-ed25519-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519VerificationMode {
    KeyHoldingRootAuth,
    PublicNoKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed25519RootAuthOutcome {
    Invalid,
    UnsupportedIdentity,
    SelfSignedConsistent,
    RootAuthContentVerified { key_id: [u8; 32] },
    PublicDataBlockCommitmentVerified { key_id: [u8; 32] },
}

pub fn ed25519_signing_input(
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    archive_root: &[u8; 32],
) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(ED25519_SIGNING_DOMAIN);
    hasher.update(ROOT_AUTH_SPEC_ID);
    hasher.update(archive_uuid);
    hasher.update(session_id);
    hasher.update(archive_root);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

pub fn ed25519_authenticator_value(
    signing_key: &SigningKey,
    request: &RootAuthSigningRequest,
) -> [u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize] {
    let signing_input = ed25519_signing_input(
        &request.archive_uuid,
        &request.session_id,
        &request.archive_root,
    );
    let signature: Signature = signing_key.sign(&signing_input);
    let mut out = [0u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize];
    out[0..2].copy_from_slice(&ED25519_SIG_SCHEME_PURE.to_le_bytes());
    out[4..68].copy_from_slice(&signature.to_bytes());
    out
}

pub fn verify_ed25519_root_auth(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    trusted_public_key: Option<[u8; 32]>,
    mode: Ed25519VerificationMode,
) -> Result<Ed25519RootAuthOutcome, FormatError> {
    if footer.authenticator_id != ED25519_AUTHENTICATOR_ID {
        return Ok(Ed25519RootAuthOutcome::UnsupportedIdentity);
    }
    let Some(signature) = parse_ed25519_authenticator_value(&footer.authenticator_value)? else {
        return Ok(Ed25519RootAuthOutcome::Invalid);
    };

    let (verifying_key, trusted) = match trusted_public_key {
        Some(key_bytes) => {
            if footer.signer_identity_type == 1 && footer.signer_identity_bytes != key_bytes {
                return Ok(Ed25519RootAuthOutcome::Invalid);
            }
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ok(Ed25519RootAuthOutcome::Invalid);
            };
            (key, true)
        }
        None if footer.signer_identity_type == 1 && footer.signer_identity_bytes.len() == 32 => {
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(&footer.signer_identity_bytes);
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ok(Ed25519RootAuthOutcome::Invalid);
            };
            (key, false)
        }
        _ => return Ok(Ed25519RootAuthOutcome::UnsupportedIdentity),
    };

    let signing_input =
        ed25519_signing_input(&footer.archive_uuid, &footer.session_id, archive_root);
    if verifying_key
        .verify_strict(&signing_input, &signature)
        .is_err()
    {
        return Ok(Ed25519RootAuthOutcome::Invalid);
    }

    if !trusted {
        return Ok(Ed25519RootAuthOutcome::SelfSignedConsistent);
    }
    let key_id = verifying_key.to_bytes();
    Ok(match mode {
        Ed25519VerificationMode::KeyHoldingRootAuth => {
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id }
        }
        Ed25519VerificationMode::PublicNoKey => {
            Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { key_id }
        }
    })
}

pub fn verify_ed25519_after_root_auth(
    verification: &RootAuthVerification,
    footer: &RootAuthFooterV1,
    trusted_public_key: Option<[u8; 32]>,
) -> Result<Ed25519RootAuthOutcome, FormatError> {
    verify_ed25519_root_auth(
        footer,
        &verification.archive_root,
        trusted_public_key,
        Ed25519VerificationMode::KeyHoldingRootAuth,
    )
}

fn parse_ed25519_authenticator_value(value: &[u8]) -> Result<Option<Signature>, FormatError> {
    if value.len() != ED25519_AUTHENTICATOR_VALUE_LEN as usize {
        return Ok(None);
    }
    let sig_scheme = u16::from_le_bytes([value[0], value[1]]);
    let reserved = u16::from_le_bytes([value[2], value[3]]);
    if sig_scheme != ED25519_SIG_SCHEME_PURE || reserved != 0 {
        return Ok(None);
    }
    let Ok(signature) = Signature::from_slice(&value[4..68]) else {
        return Ok(None);
    };
    Ok(Some(signature))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ed25519_authenticator_value_round_trips_strict_profile() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let request = RootAuthSigningRequest {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            archive_root: [3; 32],
        };
        let value = ed25519_authenticator_value(&signing_key, &request);
        let footer = RootAuthFooterV1 {
            archive_uuid: request.archive_uuid,
            session_id: request.session_id,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: signing_key.verifying_key().to_bytes().to_vec(),
            authenticator_value: value.to_vec(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: request.archive_root,
            footer_crc32c: 0,
        };

        assert_eq!(
            verify_ed25519_root_auth(
                &footer,
                &request.archive_root,
                Some(signing_key.verifying_key().to_bytes()),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            )
            .unwrap(),
            Ed25519RootAuthOutcome::RootAuthContentVerified {
                key_id: signing_key.verifying_key().to_bytes()
            }
        );
        assert_eq!(
            verify_ed25519_root_auth(
                &footer,
                &request.archive_root,
                None,
                Ed25519VerificationMode::KeyHoldingRootAuth,
            )
            .unwrap(),
            Ed25519RootAuthOutcome::SelfSignedConsistent
        );
    }
}
