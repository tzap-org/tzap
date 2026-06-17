//! Minimal key-wrap profile boundary for tzap v44 recipient wrapping.
//!
//! This crate intentionally does not implement HPKE or certificate parsing yet. It
//! only provides typed inputs/outcomes and a dispatcher entrypoint for profile id
//! `0x0001` so the core crate can begin driving recipient-wrap flow.

#![forbid(unsafe_code)]

use tzap_core::format::{FORMAT_VERSION, VOLUME_FORMAT_REV_44};

/// Profile identifier for key-wrap v1 recipient records.
pub const KEYWRAP_PROFILE_ID: u16 = 0x0001;

/// Supported recipient identity kind for the current profile stub.
pub const KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES: u16 = 1;

/// Archive-wide identity tuple that gates top-level profile dispatch decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Shared recipient record metadata for key-wrap profile handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientRecordMetadata {
    pub profile_id: u16,
    pub recipient_identity_type: u16,
    pub recipient_identity_digest: [u8; 32],
}

/// Input needed by a key-wrap profile dispatcher.
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
}

/// Outcomes for key-wrap dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyWrapOutcome {
    UnsupportedProfileId,
    UnsupportedArchiveIdentity,
    UnsupportedRecipientIdentity,
    MissingPrivateKey,
    StubProfileConstructed {
        /// Placeholder profile payload from the dispatcher.
        profile_payload_bytes: Vec<u8>,
    },
}

/// Dispatch a single key-wrap recipient record to the registered profile.
///
/// For `profile_id == KEYWRAP_PROFILE_ID`, only identity tuple validation is
/// applied. HPKE record construction is intentionally left as a stub here.
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

    let Some(_private_key) = private_key_lookup.lookup_private_key(
        &input.archive_identity,
        &input.metadata,
        &input.recipient_identity_bytes,
    ) else {
        return KeyWrapOutcome::MissingPrivateKey;
    };

    KeyWrapOutcome::StubProfileConstructed {
        profile_payload_bytes: input.profile_payload_bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct NoOpLookup;

    impl PrivateKeyLookup for NoOpLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            Some(vec![0x11u8; 32])
        }
    }

    #[derive(Debug)]
    struct EmptyLookup;

    impl PrivateKeyLookup for EmptyLookup {
        fn lookup_private_key(
            &self,
            _: &ArchiveIdentity,
            _: &RecipientRecordMetadata,
            _: &[u8],
        ) -> Option<Vec<u8>> {
            None
        }
    }

    fn sample_identity() -> ArchiveIdentity {
        ArchiveIdentity {
            archive_uuid: [1; 16],
            session_id: [2; 16],
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV_44,
        }
    }

    #[test]
    fn unsupported_profile_is_reported() {
        let result = dispatch_key_wrap_record(
            RecipientRecordInput {
                archive_identity: sample_identity(),
                metadata: RecipientRecordMetadata {
                    profile_id: 0xBEEF,
                    recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                    recipient_identity_digest: [0u8; 32],
                },
                recipient_identity_bytes: b"alice".to_vec(),
                profile_payload_bytes: vec![1, 2, 3],
            },
            &NoOpLookup,
        );

        assert!(matches!(result, KeyWrapOutcome::UnsupportedProfileId));
    }

    #[test]
    fn unsupported_recipient_identity_is_reported() {
        let result = dispatch_key_wrap_record(
            RecipientRecordInput {
                archive_identity: sample_identity(),
                metadata: RecipientRecordMetadata {
                    profile_id: KEYWRAP_PROFILE_ID,
                    recipient_identity_type: 0xDEAD,
                    recipient_identity_digest: [0u8; 32],
                },
                recipient_identity_bytes: b"alice".to_vec(),
                profile_payload_bytes: vec![1, 2, 3],
            },
            &NoOpLookup,
        );

        assert!(matches!(result, KeyWrapOutcome::UnsupportedRecipientIdentity));
    }

    #[test]
    fn missing_private_key_is_reported() {
        let result = dispatch_key_wrap_record(
            RecipientRecordInput {
                archive_identity: sample_identity(),
                metadata: RecipientRecordMetadata {
                    profile_id: KEYWRAP_PROFILE_ID,
                    recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                    recipient_identity_digest: [0u8; 32],
                },
                recipient_identity_bytes: b"alice".to_vec(),
                profile_payload_bytes: vec![1, 2, 3],
            },
            &EmptyLookup,
        );

        assert!(matches!(result, KeyWrapOutcome::MissingPrivateKey));
    }

    #[test]
    fn dispatch_stubs_on_present_private_key() {
        let result = dispatch_key_wrap_record(
            RecipientRecordInput {
                archive_identity: sample_identity(),
                metadata: RecipientRecordMetadata {
                    profile_id: KEYWRAP_PROFILE_ID,
                    recipient_identity_type: KEYWRAP_RECIPIENT_IDENTITY_TYPE_BYTES,
                    recipient_identity_digest: [0u8; 32],
                },
                recipient_identity_bytes: b"alice".to_vec(),
                profile_payload_bytes: vec![1, 2, 3],
            },
            &NoOpLookup,
        );

        assert!(matches!(
            result,
            KeyWrapOutcome::StubProfileConstructed {
                profile_payload_bytes: _,
            }
        ));
    }
}
