use std::collections::{BTreeMap, BTreeSet, HashMap};

use sha2::{Digest, Sha256};

use crate::compression::decompress_exact_zstd_frame;
use crate::crypto::{decrypt_padded_aead_object, verify_hmac, HmacDomain, MasterKey, Subkeys};
use crate::fec::repair_data_gf16;
use crate::format::{
    BlockKind, FormatError, BLOCK_RECORD_FRAMING_LEN, MANIFEST_FOOTER_LEN, VOLUME_HEADER_LEN,
    VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    normalize_lookup_file_path, EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexShard,
    MetadataLimits, ShardEntry,
};
use crate::wire::{
    BlockRecord, CryptoHeader, CryptoHeaderFixed, ManifestFooter, VolumeHeader, VolumeTrailer,
};

const TRAILER_HMAC_COVERED_LEN: usize = 96;
const MANIFEST_HMAC_COVERED_LEN: usize = 104;
const DEFAULT_MAX_VERIFY_TAR_SIZE: usize = 128 * 1024 * 1024;
const DIRECTORY_HINT_REQUIRED_FILE_COUNT: u64 = 100_000;
const TAR_BLOCK_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderOptions {
    pub max_trailing_garbage_scan: usize,
    pub max_verify_tar_size: usize,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_trailing_garbage_scan: 0,
            max_verify_tar_size: DEFAULT_MAX_VERIFY_TAR_SIZE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub file_data_size: u64,
}

#[derive(Debug, Clone)]
pub struct OpenedArchive {
    options: ReaderOptions,
    subkeys: Subkeys,
    blocks: BTreeMap<u64, BlockRecord>,
    pub volume_header: VolumeHeader,
    pub crypto_header: CryptoHeaderFixed,
    pub manifest_footer: ManifestFooter,
    pub volume_trailer: VolumeTrailer,
    pub index_root: IndexRoot,
}

#[derive(Debug, Clone, Copy)]
struct ObjectExtent {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

pub fn open_archive<'a>(
    bytes: &'a [u8],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_with_options(bytes, master_key, ReaderOptions::default())
}

impl OpenedArchive {
    pub fn open_with_options(
        bytes: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        if bytes.len() < VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN {
            return Err(FormatError::InvalidLength {
                structure: "archive",
                expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
                actual: bytes.len(),
            });
        }

        let volume_header = VolumeHeader::parse(slice(bytes, 0, VOLUME_HEADER_LEN, "archive")?)?;
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_len = volume_header.crypto_header_length as usize;
        let crypto_end = checked_add(crypto_start, crypto_len, "CryptoHeader")?;
        let crypto_bytes = slice(bytes, crypto_start, crypto_len, "CryptoHeader")?;
        let parsed_crypto = CryptoHeader::parse(crypto_bytes, volume_header.crypto_header_length)?;
        let subkeys = Subkeys::derive(
            master_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )?;
        verify_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            parsed_crypto.hmac_covered_bytes,
            &parsed_crypto.header_hmac,
        )?;
        parsed_crypto.validate_extension_semantics()?;
        validate_m7_supported_volume(&volume_header, &parsed_crypto.fixed)?;

        let (trailer_offset, volume_trailer) =
            locate_trailer(bytes, &subkeys, &volume_header, options)?;
        validate_trailer_identity(&volume_header, &volume_trailer)?;

        let manifest_offset = to_usize(volume_trailer.manifest_footer_offset, "ManifestFooter")?;
        let manifest_end = checked_add(manifest_offset, MANIFEST_FOOTER_LEN, "ManifestFooter")?;
        if manifest_end != trailer_offset {
            return Err(FormatError::InvalidArchive(
                "ManifestFooter does not end at selected trailer",
            ));
        }
        let manifest_bytes = slice(
            bytes,
            manifest_offset,
            MANIFEST_FOOTER_LEN,
            "ManifestFooter",
        )?;
        let manifest_footer = ManifestFooter::parse(manifest_bytes)?;
        validate_manifest_footer(&volume_header, &manifest_footer, &subkeys, manifest_bytes)?;
        manifest_footer.validate_index_root_extent(parsed_crypto.fixed.block_size)?;

        let blocks = parse_block_region(
            bytes,
            crypto_end,
            manifest_offset,
            parsed_crypto.fixed.block_size as usize,
            &volume_header,
            &volume_trailer,
        )?;

        let limits = metadata_limits(&parsed_crypto.fixed);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            &subkeys,
            &volume_header,
            &parsed_crypto.fixed,
            ObjectExtent {
                first_block_index: manifest_footer.index_root_first_block,
                data_block_count: manifest_footer.index_root_data_block_count,
                parity_block_count: manifest_footer.index_root_parity_block_count,
                encrypted_size: manifest_footer.index_root_encrypted_size,
            },
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            parsed_crypto.fixed.index_root_fec_data_shards,
            parsed_crypto.fixed.index_root_fec_parity_shards,
            manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(&index_root_plaintext, false, limits)?;

        Ok(Self {
            options,
            subkeys,
            blocks,
            volume_header,
            crypto_header: parsed_crypto.fixed,
            manifest_footer,
            volume_trailer,
            index_root,
        })
    }

    pub fn list_files(&self) -> Result<Vec<ArchiveEntry>, FormatError> {
        let mut final_entries = BTreeMap::<String, (u64, u64)>::new();
        for shard in self.load_all_index_shards()? {
            for (idx, file) in shard.files.iter().enumerate() {
                let path = utf8_path(
                    shard
                        .file_path(idx)
                        .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?,
                )?;
                let start =
                    shard
                        .tar_member_group_start(idx)
                        .ok_or(FormatError::InvalidArchive(
                            "FileEntry tar member start is missing",
                        ))?;
                final_entries
                    .entry(path)
                    .and_modify(|(best_start, file_data_size)| {
                        if start > *best_start {
                            *best_start = start;
                            *file_data_size = file.file_data_size;
                        }
                    })
                    .or_insert((start, file.file_data_size));
            }
        }
        Ok(final_entries
            .into_iter()
            .map(|(path, (_, file_data_size))| ArchiveEntry {
                path,
                file_data_size,
            })
            .collect())
    }

    pub fn extract_file(&self, path: &str) -> Result<Option<Vec<u8>>, FormatError> {
        let normalized = normalize_lookup_file_path(path, self.crypto_header.max_path_length)?;
        let candidate_indexes = self
            .index_root
            .candidate_shards_for_path(&normalized, self.metadata_limits())?;
        let mut winner: Option<(IndexShard, usize, u64)> = None;

        for row_index in candidate_indexes {
            let locating =
                self.index_root
                    .shards
                    .get(row_index)
                    .ok_or(FormatError::InvalidArchive(
                        "candidate shard row is out of bounds",
                    ))?;
            let shard = self.load_index_shard(locating)?;
            if let Some(file_index) = shard.lookup_file_index(&normalized) {
                let start =
                    shard
                        .tar_member_group_start(file_index)
                        .ok_or(FormatError::InvalidArchive(
                            "FileEntry tar member start is missing",
                        ))?;
                if winner
                    .as_ref()
                    .map(|(_, _, best_start)| start > *best_start)
                    .unwrap_or(true)
                {
                    winner = Some((shard, file_index, start));
                }
            }
        }

        winner
            .map(|(shard, file_index, _)| self.extract_loaded_file(&shard, file_index))
            .transpose()
    }

    pub fn verify(&self) -> Result<(), FormatError> {
        let shards = self.load_all_index_shards()?;
        let mut file_count = 0u64;
        let mut frames = BTreeMap::<u64, FrameEntry>::new();
        let mut envelopes = BTreeMap::<u64, EnvelopeEntry>::new();

        for shard in &shards {
            file_count = file_count
                .checked_add(shard.files.len() as u64)
                .ok_or(FormatError::InvalidArchive("file count overflow"))?;
            for frame in &shard.frames {
                if let Some(existing) = frames.insert(frame.frame_index, frame.clone()) {
                    if existing != *frame {
                        return Err(FormatError::InvalidArchive(
                            "duplicate FrameEntry rows do not match",
                        ));
                    }
                }
            }
            for envelope in &shard.envelopes {
                if let Some(existing) = envelopes.insert(envelope.envelope_index, envelope.clone())
                {
                    if existing != *envelope {
                        return Err(FormatError::InvalidArchive(
                            "duplicate EnvelopeEntry rows do not match",
                        ));
                    }
                }
            }
        }

        if file_count != self.index_root.header.file_count {
            return Err(FormatError::InvalidArchive(
                "IndexRoot file_count does not match decoded shards",
            ));
        }
        if self.index_root.header.file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT
            && self.index_root.directory_hint_shards.is_empty()
        {
            return Err(FormatError::InvalidArchive(
                "IndexRoot file_count requires directory hints",
            ));
        }
        if !self.index_root.directory_hint_shards.is_empty() {
            return Err(FormatError::ReaderUnsupported(
                "M7 verify does not validate directory hint shards",
            ));
        }
        verify_dense_keys(&frames, self.index_root.header.frame_count, "FrameEntry")?;
        verify_dense_keys(
            &envelopes,
            self.index_root.header.envelope_count,
            "EnvelopeEntry",
        )?;
        validate_envelope_frame_coverage(&frames, &envelopes)?;
        self.validate_encrypted_object_block_ranges(&envelopes)?;

        let payload_block_count = envelopes.values().try_fold(0u64, |sum, envelope| {
            sum.checked_add(envelope.data_block_count as u64)
                .ok_or(FormatError::InvalidArchive("payload block count overflow"))
        })?;
        if payload_block_count != self.index_root.header.payload_block_count {
            return Err(FormatError::InvalidArchive(
                "IndexRoot payload_block_count does not match envelopes",
            ));
        }

        let tar_len = to_usize(self.index_root.header.tar_total_size, "tar stream")?;
        if tar_len > self.options.max_verify_tar_size {
            return Err(FormatError::ReaderUnsupported(
                "verify tar stream exceeds configured in-memory cap",
            ));
        }
        let mut tar_stream = vec![0u8; tar_len];
        let mut covered = vec![false; tar_len];
        let mut envelope_cache = HashMap::<u64, Vec<u8>>::new();

        for frame in frames.values() {
            let envelope =
                envelopes
                    .get(&frame.envelope_index)
                    .ok_or(FormatError::InvalidArchive(
                        "FrameEntry references missing EnvelopeEntry",
                    ))?;
            if !envelope_cache.contains_key(&envelope.envelope_index) {
                envelope_cache.insert(
                    envelope.envelope_index,
                    self.load_payload_envelope(envelope)?,
                );
            }
            let envelope_plaintext = envelope_cache
                .get(&envelope.envelope_index)
                .expect("inserted above");
            let compressed = slice(
                envelope_plaintext,
                frame.offset_in_envelope as usize,
                frame.compressed_size as usize,
                "FrameEntry",
            )?;
            let decoded =
                decompress_exact_zstd_frame(compressed, frame.decompressed_size as usize)?;
            let start = to_usize(frame.tar_stream_offset, "tar stream")?;
            let end = checked_add(start, decoded.len(), "tar stream")?;
            if end > tar_stream.len() {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry exceeds IndexRoot tar_total_size",
                ));
            }
            if covered[start..end].iter().any(|value| *value) {
                return Err(FormatError::InvalidArchive("decoded frames overlap"));
            }
            tar_stream[start..end].copy_from_slice(&decoded);
            covered[start..end].fill(true);
        }

        if covered.iter().any(|value| !*value) {
            return Err(FormatError::InvalidArchive("decoded frames leave tar gap"));
        }
        if sha256_bytes(&tar_stream) != self.index_root.header.content_sha256 {
            return Err(FormatError::InvalidArchive(
                "IndexRoot content_sha256 does not match decoded tar stream",
            ));
        }

        let mut file_extents = Vec::new();
        for shard in &shards {
            for idx in 0..shard.files.len() {
                let file = &shard.files[idx];
                let start =
                    shard
                        .tar_member_group_start(idx)
                        .ok_or(FormatError::InvalidArchive(
                            "FileEntry tar member start is missing",
                        ))?;
                file_extents.push((start, file.tar_member_group_size));
                let _ = self.extract_loaded_file(shard, idx)?;
            }
        }
        validate_file_extent_coverage_ranges(&file_extents, tar_len)?;

        Ok(())
    }

    fn load_all_index_shards(&self) -> Result<Vec<IndexShard>, FormatError> {
        self.index_root
            .shards
            .iter()
            .map(|entry| self.load_index_shard(entry))
            .collect()
    }

    fn load_index_shard(&self, entry: &ShardEntry) -> Result<IndexShard, FormatError> {
        let plaintext = load_metadata_object_from_parts(
            &self.blocks,
            &self.subkeys,
            &self.volume_header,
            &self.crypto_header,
            ObjectExtent {
                first_block_index: entry.first_block_index,
                data_block_count: entry.data_block_count,
                parity_block_count: entry.parity_block_count,
                encrypted_size: entry.encrypted_size,
            },
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            &self.subkeys.index_shard_key,
            &self.subkeys.index_nonce_seed,
            b"idxshard",
            entry.shard_index,
            self.crypto_header.index_fec_data_shards,
            self.crypto_header.index_fec_parity_shards,
            entry.decompressed_size,
        )?;
        IndexShard::parse(&plaintext, entry, self.metadata_limits())
    }

    fn load_payload_envelope(&self, envelope: &EnvelopeEntry) -> Result<Vec<u8>, FormatError> {
        let plaintext = load_decrypted_object_from_parts(
            &self.blocks,
            &self.volume_header,
            &self.crypto_header,
            ObjectExtent {
                first_block_index: envelope.first_block_index,
                data_block_count: envelope.data_block_count,
                parity_block_count: envelope.parity_block_count,
                encrypted_size: envelope.encrypted_size,
            },
            BlockKind::PayloadData,
            BlockKind::PayloadParity,
            &self.subkeys.enc_key,
            &self.subkeys.nonce_seed,
            b"envelope",
            envelope.envelope_index,
            self.crypto_header.fec_data_shards,
            self.crypto_header.fec_parity_shards,
        )?;
        if plaintext.len() != envelope.plaintext_size as usize {
            return Err(FormatError::InvalidArchive(
                "payload envelope plaintext_size mismatch",
            ));
        }
        Ok(plaintext)
    }

    fn extract_loaded_file(
        &self,
        shard: &IndexShard,
        file_index: usize,
    ) -> Result<Vec<u8>, FormatError> {
        let file = shard
            .files
            .get(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
        let expected_path = shard
            .file_path(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
        let frames = frame_range_for_file(shard, file)?;
        let mut envelope_cache = HashMap::<u64, Vec<u8>>::new();
        let mut decoded = Vec::new();

        for frame in frames {
            let envelope = shard
                .envelopes
                .iter()
                .find(|entry| entry.envelope_index == frame.envelope_index)
                .ok_or(FormatError::InvalidArchive(
                    "FrameEntry references missing EnvelopeEntry",
                ))?;
            if !envelope_cache.contains_key(&envelope.envelope_index) {
                envelope_cache.insert(
                    envelope.envelope_index,
                    self.load_payload_envelope(envelope)?,
                );
            }
            let envelope_plaintext = envelope_cache
                .get(&envelope.envelope_index)
                .expect("inserted above");
            let compressed = slice(
                envelope_plaintext,
                frame.offset_in_envelope as usize,
                frame.compressed_size as usize,
                "FrameEntry",
            )?;
            decoded.extend_from_slice(&decompress_exact_zstd_frame(
                compressed,
                frame.decompressed_size as usize,
            )?);
        }

        let offset = file.offset_in_first_frame_plaintext as usize;
        let group_len = to_usize(file.tar_member_group_size, "FileEntry")?;
        let group = slice(&decoded, offset, group_len, "FileEntry")?;
        parse_tar_regular_payload(group, expected_path, file)
    }

    fn metadata_limits(&self) -> MetadataLimits {
        metadata_limits(&self.crypto_header)
    }

    fn validate_encrypted_object_block_ranges(
        &self,
        envelopes: &BTreeMap<u64, EnvelopeEntry>,
    ) -> Result<(), FormatError> {
        let mut ranges = Vec::new();
        ranges.push(object_block_range(
            self.manifest_footer.index_root_first_block,
            self.manifest_footer.index_root_data_block_count,
            self.manifest_footer.index_root_parity_block_count,
            "IndexRoot",
        )?);
        for shard in &self.index_root.shards {
            ranges.push(object_block_range(
                shard.first_block_index,
                shard.data_block_count,
                shard.parity_block_count,
                "IndexShard",
            )?);
        }
        for envelope in envelopes.values() {
            ranges.push(object_block_range(
                envelope.first_block_index,
                envelope.data_block_count,
                envelope.parity_block_count,
                "EnvelopeEntry",
            )?);
        }
        validate_non_overlapping_object_ranges(&mut ranges)
    }
}

fn locate_trailer(
    bytes: &[u8],
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    options: ReaderOptions,
) -> Result<(usize, VolumeTrailer), FormatError> {
    let canonical_offset =
        bytes
            .len()
            .checked_sub(VOLUME_TRAILER_LEN)
            .ok_or(FormatError::InvalidLength {
                structure: "VolumeTrailer",
                expected: VOLUME_TRAILER_LEN,
                actual: bytes.len(),
            })?;
    match parse_authenticated_trailer(bytes, canonical_offset, subkeys, volume_header) {
        Ok(trailer) => {
            if trailer.bytes_written != canonical_offset as u64 {
                return Err(FormatError::InvalidArchive(
                    "VolumeTrailer bytes_written does not match selected trailer offset",
                ));
            }
            return Ok((canonical_offset, trailer));
        }
        Err(err) if options.max_trailing_garbage_scan == 0 => return Err(err),
        Err(_) => {}
    }

    let scan_start = canonical_offset.saturating_sub(options.max_trailing_garbage_scan);
    for offset in (scan_start..canonical_offset).rev() {
        if let Ok(trailer) = parse_authenticated_trailer(bytes, offset, subkeys, volume_header) {
            if trailer.bytes_written == offset as u64 {
                return Ok((offset, trailer));
            }
        }
    }

    Err(FormatError::InvalidArchive(
        "no authenticated VolumeTrailer found",
    ))
}

fn parse_authenticated_trailer(
    bytes: &[u8],
    offset: usize,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
) -> Result<VolumeTrailer, FormatError> {
    let raw = slice(bytes, offset, VOLUME_TRAILER_LEN, "VolumeTrailer")?;
    let trailer = VolumeTrailer::parse(raw)?;
    verify_hmac(
        HmacDomain::VolumeTrailer,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &raw[..TRAILER_HMAC_COVERED_LEN],
        &trailer.trailer_hmac,
    )?;
    Ok(trailer)
}

fn validate_m7_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported(
            "M7 reader supports only single-volume archives",
        ));
    }
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    if crypto_header.has_dictionary != 0 {
        return Err(FormatError::ReaderUnsupported(
            "M7 reader does not support dictionary archives",
        ));
    }
    Ok(())
}

fn validate_trailer_identity(
    volume_header: &VolumeHeader,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    if trailer.archive_uuid != volume_header.archive_uuid
        || trailer.session_id != volume_header.session_id
        || trailer.volume_index != volume_header.volume_index
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer identity does not match VolumeHeader",
        ));
    }
    Ok(())
}

fn validate_manifest_footer(
    volume_header: &VolumeHeader,
    footer: &ManifestFooter,
    subkeys: &Subkeys,
    raw: &[u8],
) -> Result<(), FormatError> {
    if footer.archive_uuid != volume_header.archive_uuid
        || footer.session_id != volume_header.session_id
        || footer.volume_index != volume_header.volume_index
    {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter identity does not match VolumeHeader",
        ));
    }
    if footer.total_volumes != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter total_volumes does not match stripe_width",
        ));
    }
    if footer.is_authoritative != 1 {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter is not authoritative",
        ));
    }
    verify_hmac(
        HmacDomain::ManifestFooter,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &raw[..MANIFEST_HMAC_COVERED_LEN],
        &footer.manifest_hmac,
    )
}

fn parse_block_region(
    bytes: &[u8],
    start: usize,
    end: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
    trailer: &VolumeTrailer,
) -> Result<BTreeMap<u64, BlockRecord>, FormatError> {
    if end < start {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter starts before BlockRecord region",
        ));
    }
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let region_len = end - start;
    if region_len % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "BlockRecord region length is not aligned",
        ));
    }
    let observed_count = region_len / record_len;
    if observed_count as u64 != trailer.block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match BlockRecord region",
        ));
    }

    let mut blocks = BTreeMap::new();
    let mut previous_index = None;
    for idx in 0..observed_count {
        let offset = start + idx * record_len;
        let record =
            BlockRecord::parse(slice(bytes, offset, record_len, "BlockRecord")?, block_size)?;
        if record.block_index % volume_header.stripe_width as u64
            != volume_header.volume_index as u64
        {
            return Err(FormatError::InvalidArchive(
                "BlockRecord index does not belong to this volume",
            ));
        }
        if let Some(previous) = previous_index {
            if record.block_index != previous + volume_header.stripe_width as u64 {
                return Err(FormatError::InvalidArchive(
                    "BlockRecords are not strictly consecutive",
                ));
            }
        }
        previous_index = Some(record.block_index);
        if blocks.insert(record.block_index, record).is_some() {
            return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
        }
    }

    Ok(blocks)
}

fn load_metadata_object_from_parts(
    blocks: &BTreeMap<u64, BlockRecord>,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
    decompressed_size: u32,
) -> Result<Vec<u8>, FormatError> {
    let compressed = load_decrypted_object_from_parts(
        blocks,
        volume_header,
        crypto_header,
        extent,
        data_kind,
        parity_kind,
        key,
        nonce_seed,
        domain,
        counter,
        class_data_shard_max,
        class_parity_shard_max,
    )?;
    let _ = subkeys;
    decompress_exact_zstd_frame(&compressed, decompressed_size as usize)
}

fn load_decrypted_object_from_parts(
    blocks: &BTreeMap<u64, BlockRecord>,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
) -> Result<Vec<u8>, FormatError> {
    validate_object_extent(
        extent,
        crypto_header,
        class_data_shard_max,
        class_parity_shard_max,
    )?;
    let block_size = crypto_header.block_size as usize;
    let data_count = extent.data_block_count as usize;
    let parity_count = extent.parity_block_count as usize;
    let mut data_shards = Vec::with_capacity(data_count);
    let mut parity_shards = Vec::with_capacity(parity_count);

    for offset in 0..data_count {
        let block_index = checked_u64_add(extent.first_block_index, offset as u64, "object")?;
        let record = blocks
            .get(&block_index)
            .ok_or(FormatError::InvalidArchive("object data block is missing"))?;
        if record.kind != data_kind {
            return Err(FormatError::InvalidArchive(
                "object data block has unexpected kind",
            ));
        }
        let should_be_last = offset + 1 == data_count;
        if record.is_last_data() != should_be_last {
            return Err(FormatError::InvalidArchive(
                "object last-data flag is not on the final data block",
            ));
        }
        data_shards.push(Some(record.payload.clone()));
    }

    for offset in 0..parity_count {
        let block_index = checked_u64_add(
            extent.first_block_index,
            data_count as u64 + offset as u64,
            "object",
        )?;
        let record = blocks.get(&block_index).ok_or(FormatError::InvalidArchive(
            "object parity block is missing",
        ))?;
        if record.kind != parity_kind {
            return Err(FormatError::InvalidArchive(
                "object parity block has unexpected kind",
            ));
        }
        if record.is_last_data() {
            return Err(FormatError::InvalidArchive(
                "object parity block has last-data flag",
            ));
        }
        parity_shards.push(Some(record.payload.clone()));
    }

    let repaired = repair_data_gf16(&data_shards, &parity_shards, block_size)?;
    let mut encrypted = Vec::with_capacity(extent.encrypted_size as usize);
    for shard in repaired {
        encrypted.extend_from_slice(&shard);
    }
    if encrypted.len() != extent.encrypted_size as usize {
        return Err(FormatError::InvalidArchive(
            "object encrypted size does not match repaired shards",
        ));
    }

    decrypt_padded_aead_object(
        crypto_header.aead_algo,
        key,
        nonce_seed,
        domain,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        counter,
        &encrypted,
    )
}

fn validate_object_extent(
    extent: ObjectExtent,
    crypto_header: &CryptoHeaderFixed,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
) -> Result<(), FormatError> {
    if extent.data_block_count == 0 || extent.encrypted_size == 0 {
        return Err(FormatError::InvalidArchive(
            "encrypted object has zero data blocks or size",
        ));
    }
    if extent.data_block_count > class_data_shard_max as u32 {
        return Err(FormatError::InvalidArchive(
            "encrypted object exceeds its class data-shard maximum",
        ));
    }
    if extent.parity_block_count > class_parity_shard_max as u32 {
        return Err(FormatError::InvalidArchive(
            "encrypted object exceeds its class parity-shard maximum",
        ));
    }
    let total = extent.data_block_count as u64 + extent.parity_block_count as u64;
    if total > 65_535 {
        return Err(FormatError::FecTooManyShards(total as usize));
    }
    let expected = extent.data_block_count as u64 * crypto_header.block_size as u64;
    if expected != extent.encrypted_size as u64 {
        return Err(FormatError::InvalidArchive(
            "encrypted object size is not data_block_count * block_size",
        ));
    }
    if extent.encrypted_size as usize <= crypto_header.aead_algo.tag_len() {
        return Err(FormatError::InvalidArchive(
            "encrypted object is too small for AEAD tag",
        ));
    }
    Ok(())
}

fn frame_range_for_file<'b>(
    shard: &'b IndexShard,
    file: &FileEntry,
) -> Result<Vec<&'b FrameEntry>, FormatError> {
    let mut frames = Vec::with_capacity(file.frame_count as usize);
    for offset in 0..file.frame_count as u64 {
        let frame_index =
            file.first_frame_index
                .checked_add(offset)
                .ok_or(FormatError::InvalidArchive(
                    "FileEntry frame range overflow",
                ))?;
        let frame = shard
            .frames
            .iter()
            .find(|entry| entry.frame_index == frame_index)
            .ok_or(FormatError::InvalidArchive(
                "FileEntry references missing FrameEntry",
            ))?;
        frames.push(frame);
    }
    Ok(frames)
}

fn parse_tar_regular_payload(
    group: &[u8],
    expected_path: &[u8],
    file: &FileEntry,
) -> Result<Vec<u8>, FormatError> {
    if group.len() < TAR_BLOCK_LEN {
        return Err(FormatError::InvalidArchive(
            "tar member group is smaller than one block",
        ));
    }
    let header = &group[..TAR_BLOCK_LEN];
    if header.iter().all(|byte| *byte == 0) {
        return Err(FormatError::InvalidArchive("tar member header is empty"));
    }
    verify_tar_checksum(header)?;
    let name = nul_trimmed(&header[0..100]);
    if name != expected_path {
        return Err(FormatError::InvalidArchive(
            "tar member path does not match FileEntry path",
        ));
    }
    if !matches!(header[156], 0 | b'0') {
        return Err(FormatError::ReaderUnsupported(
            "M7 reader extracts only regular file tar members",
        ));
    }
    let size = parse_tar_octal(&header[124..136])?;
    if size != file.file_data_size {
        return Err(FormatError::InvalidArchive(
            "tar member size does not match FileEntry file_data_size",
        ));
    }
    let size = to_usize(size, "tar member")?;
    let data_end = checked_add(TAR_BLOCK_LEN, size, "tar member")?;
    let padded_end = checked_add(data_end, padding_to_512(size), "tar member")?;
    if padded_end != group.len() {
        return Err(FormatError::InvalidArchive(
            "tar member group size does not match tar header size and padding",
        ));
    }
    if group[data_end..].iter().any(|byte| *byte != 0) {
        return Err(FormatError::InvalidArchive(
            "tar member padding is non-zero",
        ));
    }
    Ok(slice(group, TAR_BLOCK_LEN, size, "tar member")?.to_vec())
}

fn verify_tar_checksum(header: &[u8]) -> Result<(), FormatError> {
    let stored = parse_tar_octal(&header[148..156])?;
    let mut sum = 0u64;
    for (idx, byte) in header.iter().enumerate() {
        if (148..156).contains(&idx) {
            sum += b' ' as u64;
        } else {
            sum += *byte as u64;
        }
    }
    if stored != sum {
        return Err(FormatError::InvalidArchive("tar header checksum mismatch"));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, FormatError> {
    let mut value = 0u64;
    let mut saw_digit = false;
    for byte in field {
        match *byte {
            0 | b' ' if saw_digit => break,
            0 | b' ' => {}
            b'0'..=b'7' => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|acc| acc.checked_add((*byte - b'0') as u64))
                    .ok_or(FormatError::InvalidArchive("tar octal field overflow"))?;
            }
            _ => return Err(FormatError::InvalidArchive("malformed tar octal field")),
        }
    }
    Ok(value)
}

fn nul_trimmed(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn metadata_limits(crypto_header: &CryptoHeaderFixed) -> MetadataLimits {
    MetadataLimits {
        block_size: crypto_header.block_size,
        max_path_length: crypto_header.max_path_length,
        ..MetadataLimits::default()
    }
}

fn verify_dense_keys<T>(
    entries: &BTreeMap<u64, T>,
    expected_count: u64,
    structure: &'static str,
) -> Result<(), FormatError> {
    if entries.len() as u64 != expected_count {
        return Err(FormatError::InvalidArchive(
            "decoded table count does not match IndexRoot",
        ));
    }
    for expected in 0..expected_count {
        if !entries.contains_key(&expected) {
            return Err(FormatError::InvalidMetadata {
                structure,
                reason: "global index coverage has a gap",
            });
        }
    }
    Ok(())
}

fn validate_envelope_frame_coverage(
    frames: &BTreeMap<u64, FrameEntry>,
    envelopes: &BTreeMap<u64, EnvelopeEntry>,
) -> Result<(), FormatError> {
    let mut accounted_frames = BTreeSet::new();
    for envelope in envelopes.values() {
        let first = envelope.first_frame_index;
        let end =
            first
                .checked_add(envelope.frame_count as u64)
                .ok_or(FormatError::InvalidArchive(
                    "EnvelopeEntry frame range overflow",
                ))?;
        let mut ranges = Vec::with_capacity(envelope.frame_count as usize);
        for frame_index in first..end {
            let frame = frames.get(&frame_index).ok_or(FormatError::InvalidArchive(
                "EnvelopeEntry references missing FrameEntry",
            ))?;
            if frame.envelope_index != envelope.envelope_index {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry envelope_index does not match containing EnvelopeEntry",
                ));
            }
            if !accounted_frames.insert(frame_index) {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry is covered by multiple EnvelopeEntries",
                ));
            }
            let start = frame.offset_in_envelope as usize;
            let end = checked_add(start, frame.compressed_size as usize, "FrameEntry")?;
            if end > envelope.plaintext_size as usize {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry exceeds EnvelopeEntry plaintext_size",
                ));
            }
            ranges.push((start, end));
        }
        validate_exact_coverage_ranges(
            &mut ranges,
            envelope.plaintext_size as usize,
            "EnvelopeEntry frame coverage has a gap or overlap",
        )?;
    }

    for frame_index in frames.keys() {
        if !accounted_frames.contains(frame_index) {
            return Err(FormatError::InvalidArchive(
                "FrameEntry is not covered by any EnvelopeEntry",
            ));
        }
    }
    Ok(())
}

fn validate_file_extent_coverage_ranges(
    extents: &[(u64, u64)],
    tar_len: usize,
) -> Result<(), FormatError> {
    let mut ranges = Vec::with_capacity(extents.len());
    for (start, len) in extents {
        let start = to_usize(*start, "FileEntry")?;
        let len = to_usize(*len, "FileEntry")?;
        let end = checked_add(start, len, "FileEntry")?;
        if end > tar_len {
            return Err(FormatError::InvalidArchive(
                "FileEntry extent exceeds IndexRoot tar_total_size",
            ));
        }
        ranges.push((start, end));
    }
    validate_exact_coverage_ranges(
        &mut ranges,
        tar_len,
        "FileEntry extents do not cover tar stream exactly",
    )
}

fn validate_exact_coverage_ranges(
    ranges: &mut [(usize, usize)],
    expected_end: usize,
    reason: &'static str,
) -> Result<(), FormatError> {
    ranges.sort_unstable();
    let mut cursor = 0usize;
    for (start, end) in ranges.iter().copied() {
        if start != cursor || end < start {
            return Err(FormatError::InvalidArchive(reason));
        }
        cursor = end;
    }
    if cursor != expected_end {
        return Err(FormatError::InvalidArchive(reason));
    }
    Ok(())
}

fn object_block_range(
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    structure: &'static str,
) -> Result<(u64, u64), FormatError> {
    let total = data_block_count as u64 + parity_block_count as u64;
    if total == 0 {
        return Err(FormatError::InvalidArchive(structure));
    }
    let end = checked_u64_add(first_block_index, total, structure)?;
    Ok((first_block_index, end))
}

fn validate_non_overlapping_object_ranges(ranges: &mut [(u64, u64)]) -> Result<(), FormatError> {
    ranges.sort_unstable();
    for pair in ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(FormatError::InvalidArchive(
                "encrypted object block ranges overlap",
            ));
        }
    }
    Ok(())
}

fn utf8_path(bytes: &[u8]) -> Result<String, FormatError> {
    std::str::from_utf8(bytes)
        .map(|path| path.to_owned())
        .map_err(|_| FormatError::UnsafeArchivePath)
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn padding_to_512(len: usize) -> usize {
    let remainder = len % TAR_BLOCK_LEN;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN - remainder
    }
}

fn slice<'b>(
    bytes: &'b [u8],
    offset: usize,
    len: usize,
    structure: &'static str,
) -> Result<&'b [u8], FormatError> {
    let end = checked_add(offset, len, structure)?;
    bytes.get(offset..end).ok_or(FormatError::InvalidLength {
        structure,
        expected: end,
        actual: bytes.len(),
    })
}

fn checked_add(lhs: usize, rhs: usize, structure: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::InvalidArchive(structure))
}

fn checked_u64_add(lhs: u64, rhs: u64, structure: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::InvalidArchive(structure))
}

fn to_usize(value: u64, structure: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::InvalidArchive(structure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{AeadAlgo, CompressionAlgo, FecAlgo, KdfAlgo};
    use crate::writer::{write_archive, write_empty_archive, RegularFile, WriterOptions};

    fn master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x42; 32]).unwrap()
    }

    #[test]
    fn opens_lists_verifies_and_extracts_one_file_archive() {
        let archive = write_archive(
            &[RegularFile::new("dir/hello.txt", b"hello m7")],
            &master_key(),
            WriterOptions::default(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/hello.txt".to_string(),
                file_data_size: 8
            }]
        );
        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("dir/hello.txt").unwrap(),
            Some(b"hello m7".to_vec())
        );
        assert_eq!(opened.extract_file("missing.txt").unwrap(), None);
    }

    #[test]
    fn opens_and_verifies_empty_archive() {
        let archive = write_empty_archive(&master_key()).unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert!(opened.list_files().unwrap().is_empty());
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_wrong_key_before_metadata_release() {
        let archive = write_empty_archive(&master_key()).unwrap();
        let wrong = MasterKey::from_raw_key(&[0x43; 32]).unwrap();

        assert_eq!(
            open_archive(&archive.bytes, &wrong).unwrap_err(),
            FormatError::HmacMismatch {
                structure: "CryptoHeader"
            }
        );
    }

    #[test]
    fn rejects_payload_tamper_even_with_recomputed_block_crc() {
        let mut archive = write_archive(
            &[RegularFile::new("file.txt", b"authenticated")],
            &master_key(),
            WriterOptions::default(),
        )
        .unwrap()
        .bytes;
        let volume = VolumeHeader::parse(&archive[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = VOLUME_HEADER_LEN + usize::try_from(volume.crypto_header_length).unwrap();
        archive[crypto_end + 16] ^= 1;
        let block_size = 4096usize;
        let crc_offset = crypto_end + 16 + block_size;
        let crc = crc32c::crc32c(&archive[crypto_end..crc_offset]);
        archive[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        let opened = open_archive(&archive, &master_key()).unwrap();
        assert_eq!(opened.verify().unwrap_err(), FormatError::AeadFailure);
    }

    #[test]
    fn list_and_extract_use_final_view_for_duplicate_paths() {
        let archive = write_archive(
            &[
                RegularFile::new("same.txt", b"old"),
                RegularFile::new("same.txt", b"newer"),
            ],
            &master_key(),
            WriterOptions::default(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "same.txt".to_string(),
                file_data_size: 5
            }]
        );
        assert_eq!(
            opened.extract_file("same.txt").unwrap(),
            Some(b"newer".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn verify_helper_rejects_envelope_frame_coverage_gap() {
        let frames = BTreeMap::from([(
            0,
            FrameEntry {
                frame_index: 0,
                envelope_index: 0,
                offset_in_envelope: 0,
                compressed_size: 10,
                decompressed_size: 512,
                flags: 0,
                tar_stream_offset: 0,
            },
        )]);
        let envelopes = BTreeMap::from([(
            0,
            EnvelopeEntry {
                envelope_index: 0,
                first_block_index: 0,
                data_block_count: 1,
                parity_block_count: 1,
                encrypted_size: 4096,
                plaintext_size: 11,
                first_frame_index: 0,
                frame_count: 1,
            },
        )]);

        assert_eq!(
            validate_envelope_frame_coverage(&frames, &envelopes).unwrap_err(),
            FormatError::InvalidArchive("EnvelopeEntry frame coverage has a gap or overlap")
        );
    }

    #[test]
    fn verify_helper_rejects_file_extent_gaps_and_overlaps() {
        assert!(validate_file_extent_coverage_ranges(&[(512, 512), (0, 512)], 1024).is_ok());
        assert_eq!(
            validate_file_extent_coverage_ranges(&[(0, 512), (1024, 512)], 1536).unwrap_err(),
            FormatError::InvalidArchive("FileEntry extents do not cover tar stream exactly")
        );
        assert_eq!(
            validate_file_extent_coverage_ranges(&[(0, 1024), (512, 512)], 1024).unwrap_err(),
            FormatError::InvalidArchive("FileEntry extents do not cover tar stream exactly")
        );
    }

    #[test]
    fn object_extent_rejects_parity_above_class_cap() {
        let crypto_header = CryptoHeaderFixed {
            length: 0,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 1024,
            envelope_target_size: 4096,
            block_size: 4096,
            fec_data_shards: 1,
            fec_parity_shards: 1,
            index_fec_data_shards: 1,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 1,
            index_root_fec_parity_shards: 1,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        };
        let extent = ObjectExtent {
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 2,
            encrypted_size: 4096,
        };

        assert_eq!(
            validate_object_extent(extent, &crypto_header, 1, 1).unwrap_err(),
            FormatError::InvalidArchive("encrypted object exceeds its class parity-shard maximum")
        );
    }
}
