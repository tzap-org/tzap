use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

pub const ED25519_AUTHENTICATOR_ID: u16 = 0x0002;
pub const ED25519_AUTHENTICATOR_VALUE_LEN: u32 = 68;

const ED25519_SIG_SCHEME_PURE: u16 = 1;

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

#[derive(Debug, Clone, Copy)]
pub struct Ed25519RootAuthVerifierInput<'a> {
    pub signing_input: &'a [u8; 64],
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: &'a [u8],
    pub authenticator_value: &'a [u8],
}

pub fn authenticator_value(
    signing_key: &SigningKey,
    signing_input: &[u8; 64],
) -> [u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize] {
    let signature: Signature = signing_key.sign(signing_input);
    let mut out = [0u8; ED25519_AUTHENTICATOR_VALUE_LEN as usize];
    out[0..2].copy_from_slice(&ED25519_SIG_SCHEME_PURE.to_le_bytes());
    out[4..68].copy_from_slice(&signature.to_bytes());
    out
}

pub fn verify_root_auth(
    input: Ed25519RootAuthVerifierInput<'_>,
    trusted_public_key: Option<[u8; 32]>,
    mode: Ed25519VerificationMode,
) -> Ed25519RootAuthOutcome {
    if input.authenticator_id != ED25519_AUTHENTICATOR_ID {
        return Ed25519RootAuthOutcome::UnsupportedIdentity;
    }
    let Some(signature) = parse_authenticator_value(input.authenticator_value) else {
        return Ed25519RootAuthOutcome::Invalid;
    };

    let (verifying_key, trusted) = match (trusted_public_key, input.signer_identity_type) {
        (Some(key_bytes), 0) => {
            if !input.signer_identity_bytes.is_empty() {
                return Ed25519RootAuthOutcome::Invalid;
            }
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ed25519RootAuthOutcome::Invalid;
            };
            (key, true)
        }
        (Some(key_bytes), 1) => {
            if input.signer_identity_bytes.len() != 32 || input.signer_identity_bytes != key_bytes {
                return Ed25519RootAuthOutcome::Invalid;
            }
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ed25519RootAuthOutcome::Invalid;
            };
            (key, true)
        }
        (Some(_), _) => return Ed25519RootAuthOutcome::UnsupportedIdentity,
        (None, 1) => {
            if input.signer_identity_bytes.len() != 32 {
                return Ed25519RootAuthOutcome::Invalid;
            }
            let mut key_bytes = [0u8; 32];
            key_bytes.copy_from_slice(input.signer_identity_bytes);
            let Ok(key) = VerifyingKey::from_bytes(&key_bytes) else {
                return Ed25519RootAuthOutcome::Invalid;
            };
            (key, false)
        }
        (None, _) => return Ed25519RootAuthOutcome::UnsupportedIdentity,
    };

    if verifying_key
        .verify_strict(input.signing_input, &signature)
        .is_err()
    {
        return Ed25519RootAuthOutcome::Invalid;
    }

    if !trusted {
        return Ed25519RootAuthOutcome::SelfSignedConsistent;
    }
    let key_id = verifying_key.to_bytes();
    match mode {
        Ed25519VerificationMode::KeyHoldingRootAuth => {
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id }
        }
        Ed25519VerificationMode::PublicNoKey => {
            Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { key_id }
        }
    }
}

fn parse_authenticator_value(value: &[u8]) -> Option<Signature> {
    if value.len() != ED25519_AUTHENTICATOR_VALUE_LEN as usize {
        return None;
    }
    let sig_scheme = u16::from_le_bytes([value[0], value[1]]);
    let reserved = u16::from_le_bytes([value[2], value[3]]);
    if sig_scheme != ED25519_SIG_SCHEME_PURE || reserved != 0 {
        return None;
    }
    Signature::from_slice(&value[4..68]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn ed25519_authenticator_value_round_trips_strict_profile() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [7u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: &public_key,
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id: public_key }
        );
        assert_eq!(
            verify_root_auth(input, None, Ed25519VerificationMode::KeyHoldingRootAuth),
            Ed25519RootAuthOutcome::SelfSignedConsistent
        );
        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::PublicNoKey,
            ),
            Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { key_id: public_key }
        );
    }

    #[test]
    fn rejects_malformed_authenticator_value() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [9u8; 64];
        let mut value = authenticator_value(&signing_key, &signing_input);
        value[2] = 1;
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: &public_key,
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );

        let wrong_length = &value[..value.len() - 1];
        let input = Ed25519RootAuthVerifierInput {
            authenticator_value: wrong_length,
            ..input
        };
        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn rejects_trusted_key_mismatch_with_embedded_identity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let other_key = SigningKey::generate(&mut OsRng);
        let signing_input = [11u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: &public_key,
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(other_key.verifying_key().to_bytes()),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn verifies_type_zero_only_with_trusted_key_and_empty_identity() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [13u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 0,
            signer_identity_bytes: &[],
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::RootAuthContentVerified { key_id: public_key }
        );
        assert_eq!(
            verify_root_auth(input, None, Ed25519VerificationMode::KeyHoldingRootAuth),
            Ed25519RootAuthOutcome::UnsupportedIdentity
        );

        let nonempty_identity = [1u8];
        let input = Ed25519RootAuthVerifierInput {
            signer_identity_bytes: &nonempty_identity,
            ..input
        };
        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::Invalid
        );
    }

    #[test]
    fn rejects_unsupported_identity_even_with_trusted_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let signing_input = [15u8; 64];
        let value = authenticator_value(&signing_key, &signing_input);
        let input = Ed25519RootAuthVerifierInput {
            signing_input: &signing_input,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 2,
            signer_identity_bytes: &[],
            authenticator_value: &value,
        };

        assert_eq!(
            verify_root_auth(
                input,
                Some(public_key),
                Ed25519VerificationMode::KeyHoldingRootAuth,
            ),
            Ed25519RootAuthOutcome::UnsupportedIdentity
        );
    }
}
