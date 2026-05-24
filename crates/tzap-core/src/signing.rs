use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};
use tzap_plugin_signing::ed25519_raw::{
    authenticator_value as ed25519_raw_authenticator_value,
    verify_root_auth as verify_ed25519_raw_root_auth, Ed25519RootAuthVerifierInput,
};

use crate::format::{FormatError, ROOT_AUTH_SPEC_ID};
use crate::reader::RootAuthVerification;
use crate::wire::RootAuthFooterV1;
use crate::writer::RootAuthSigningRequest;

pub use tzap_plugin_signing::ed25519_raw::{
    Ed25519RootAuthOutcome, Ed25519VerificationMode, ED25519_AUTHENTICATOR_ID,
    ED25519_AUTHENTICATOR_VALUE_LEN,
};

const ED25519_SIGNING_DOMAIN: &[u8] = b"tzap-sig-ed25519-v1\0";

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
    ed25519_raw_authenticator_value(signing_key, &signing_input)
}

pub fn verify_ed25519_root_auth(
    footer: &RootAuthFooterV1,
    archive_root: &[u8; 32],
    trusted_public_key: Option<[u8; 32]>,
    mode: Ed25519VerificationMode,
) -> Result<Ed25519RootAuthOutcome, FormatError> {
    let signing_input =
        ed25519_signing_input(&footer.archive_uuid, &footer.session_id, archive_root);
    Ok(verify_ed25519_raw_root_auth(
        Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: footer.authenticator_id,
            signer_identity_type: footer.signer_identity_type,
            signer_identity_bytes: &footer.signer_identity_bytes,
            authenticator_value: &footer.authenticator_value,
        },
        trusted_public_key,
        mode,
    ))
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
