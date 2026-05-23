#![allow(dead_code)]

use tzap_core::compression::{decompress_exact_zstd_frame, validate_exact_zstd_frame};
use tzap_core::format::{
    BLOCK_RECORD_FRAMING_LEN, CRYPTO_HEADER_FIXED_LEN, MANIFEST_FOOTER_LEN, VOLUME_TRAILER_LEN,
};
use tzap_core::metadata::{
    DirectoryHintShardEntry, DirectoryHintTable, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
};
use tzap_core::padding::depad_suffix_padding;
use tzap_core::wire::{
    BlockRecord, BootstrapSidecarHeader, CryptoHeader, CryptoHeaderFixed, ManifestFooter,
    VolumeHeader, VolumeTrailer,
};

const FUZZ_BLOCK_SIZES: [usize; 4] = [1, 16, 256, 4096];
const MAX_FUZZ_DECOMPRESSED_SIZE: usize = 64 * 1024;

pub fn parse_fixed_structures(data: &[u8]) {
    let _ = VolumeHeader::parse(data);
    let _ = ManifestFooter::parse(data);
    let _ = VolumeTrailer::parse(data);
    let _ = BootstrapSidecarHeader::parse(data);

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
}

pub fn parse_metadata(data: &[u8]) {
    let limits = MetadataLimits::default();
    let _ = IndexRoot::parse(data, false, limits);
    let _ = IndexRoot::parse(data, true, limits);

    let locating_shard = ShardEntry {
        shard_index: 0,
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: data.len().min(u32::MAX as usize) as u32,
        file_count: 1,
        first_path_hash: [0; 8],
        last_path_hash: [0xff; 8],
    };
    let _ = IndexShard::parse(data, &locating_shard, limits);

    let locating_hint = DirectoryHintShardEntry {
        hint_shard_index: 0,
        first_dir_hash: [0; 8],
        last_dir_hash: [0xff; 8],
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: data.len().min(u32::MAX as usize) as u32,
        entry_count: 1,
    };
    let _ = DirectoryHintTable::parse(data, &locating_hint, 1, limits);
}

pub fn parse_compressed_and_padding(data: &[u8]) {
    let _ = validate_exact_zstd_frame(data);
    if data.len() >= 4 {
        let expected_size = u32::from_le_bytes(data[..4].try_into().expect("slice length checked"))
            as usize;
        let expected_size = expected_size.min(MAX_FUZZ_DECOMPRESSED_SIZE);
        let _ = validate_exact_zstd_frame(&data[4..]);
        let _ = decompress_exact_zstd_frame(&data[4..], expected_size);
    }
    let _ = depad_suffix_padding(data);
}
