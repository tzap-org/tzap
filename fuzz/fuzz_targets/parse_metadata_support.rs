use tzap_core::metadata::{
    DirectoryHintShardEntry, DirectoryHintTable, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
};

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
