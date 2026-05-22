#![no_main]

use libfuzzer_sys::fuzz_target;
use tzap_core::metadata::{DirectoryHintShardEntry, DirectoryHintTable, IndexRoot, MetadataLimits};

fuzz_target!(|data: &[u8]| {
    let limits = MetadataLimits::default();
    let _ = IndexRoot::parse(data, false, limits);
    let _ = IndexRoot::parse(data, true, limits);

    let locating = DirectoryHintShardEntry {
        hint_shard_index: 0,
        first_dir_hash: [0; 8],
        last_dir_hash: [0xff; 8],
        first_block_index: 0,
        data_block_count: 1,
        parity_block_count: 0,
        encrypted_size: 4096,
        decompressed_size: data.len() as u32,
        entry_count: 1,
    };
    let _ = DirectoryHintTable::parse(data, &locating, 1, limits);
});
