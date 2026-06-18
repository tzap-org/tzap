use tzap_core::format::{
    BLOCK_RECORD_FRAMING_LEN, CRITICAL_METADATA_IMAGE_FIXED_LEN,
    CRITICAL_METADATA_RECOVERY_HEADER_LEN, CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN,
    CRITICAL_RECOVERY_LOCATOR_LEN, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION, IMAGE_CRC_LEN,
    MANIFEST_FOOTER_LEN, VOLUME_FORMAT_REV, VOLUME_TRAILER_LEN,
};
use tzap_core::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage, CriticalMetadataRecoveryHeader,
    CriticalMetadataRecoveryShard, CriticalRecoveryLocator, CryptoHeader, CryptoHeaderFixed,
    ManifestFooter, RootAuthFooterV1, VolumeHeader, VolumeTrailer,
};
use tzap_plugin_signing::ed25519_raw::{
    verify_root_auth_footer, Ed25519VerificationMode, ED25519_AUTHENTICATOR_ID,
};

const FUZZ_BLOCK_SIZES: [usize; 4] = [1, 16, 256, 4096];

pub fn parse_fixed_structures(data: &[u8]) {
    let _ = VolumeHeader::parse(data);
    let _ = ManifestFooter::parse(data);
    let _ = VolumeTrailer::parse(data);
    let _ = RootAuthFooterV1::parse(data);
    let _ = CriticalMetadataImage::parse(data);
    let _ = BootstrapSidecarHeader::parse(data);

    if data.len() <= 128 {
        let footer = RootAuthFooterV1 {
            archive_uuid: [0; 16],
            session_id: [0; 16],
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            authenticator_id: ED25519_AUTHENTICATOR_ID,
            signer_identity_type: 1,
            signer_identity_bytes: [1; 32].to_vec(),
            authenticator_value: data.to_vec(),
            total_data_block_count: 0,
            critical_metadata_digest: [0; 32],
            index_digest: [0; 32],
            fec_layout_digest: [0; 32],
            data_block_merkle_root: [0; 32],
            signer_identity_digest: [0; 32],
            archive_root: [0; 32],
            footer_crc32c: 0,
        };
        let _ = verify_root_auth_footer(
            &footer,
            &[0; 32],
            Some([1; 32]),
            Ed25519VerificationMode::PublicNoKey,
        );
    }

    if data.len() >= CRITICAL_METADATA_RECOVERY_HEADER_LEN {
        let _ =
            CriticalMetadataRecoveryHeader::parse(&data[..CRITICAL_METADATA_RECOVERY_HEADER_LEN]);
    }
    if data.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let _ = CriticalRecoveryLocator::parse(&data[..CRITICAL_RECOVERY_LOCATOR_LEN]);
    }

    if data.len() <= u32::MAX as usize {
        let declared_len = data.len() as u32;
        let _ = CryptoHeader::parse(data, declared_len)
            .and_then(|header| header.validate_extension_semantics().map(|_| header));
    }

    if data.len() >= CRYPTO_HEADER_FIXED_LEN && data.len() <= u32::MAX as usize {
        let declared_len = data.len() as u32;
        let _ = CryptoHeaderFixed::parse(&data[..CRYPTO_HEADER_FIXED_LEN], declared_len);
    }

    for block_size in FUZZ_BLOCK_SIZES {
        let record_len = block_size + BLOCK_RECORD_FRAMING_LEN;
        if data.len() >= record_len {
            let _ = BlockRecord::parse(&data[..record_len], block_size);
        }
    }

    if data.len() >= MANIFEST_FOOTER_LEN {
        let _ = ManifestFooter::parse(&data[..MANIFEST_FOOTER_LEN]);
    }
    if data.len() >= VOLUME_TRAILER_LEN {
        let _ = VolumeTrailer::parse(&data[..VOLUME_TRAILER_LEN]);
    }
    if data.len() >= CRITICAL_METADATA_IMAGE_FIXED_LEN + IMAGE_CRC_LEN {
        let _ = CriticalMetadataImage::parse(data);
    }
    for shard_size in [1usize, 16, 512] {
        let row_len = CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size;
        if data.len() >= row_len {
            let _ = CriticalMetadataRecoveryShard::parse(&data[..row_len], shard_size);
        }
    }
}
