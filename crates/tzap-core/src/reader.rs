use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;

use sha2::{Digest, Sha256};

use crate::compression::{
    decompress_exact_zstd_frame, decompress_exact_zstd_frame_with_dictionary,
    validate_exact_zstd_frame,
};
use crate::crypto::{decrypt_padded_aead_object, verify_hmac, HmacDomain, MasterKey, Subkeys};
use crate::fec::repair_data_gf16;
use crate::format::{
    BlockKind, FormatError, BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN,
    MANIFEST_FOOTER_LEN, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, DirectoryHintShardEntry, DirectoryHintTable,
    EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
};
use crate::tar_model::{
    parse_tar_member_group, restore_tar_member, validate_tar_stream_total_extraction_size,
    MetadataDiagnostic, OwnedTarMember, SafeExtractionOptions, TarEntryKind,
};
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CryptoHeader, CryptoHeaderFixed, ManifestFooter,
    VolumeHeader, VolumeTrailer,
};

const TRAILER_HMAC_COVERED_LEN: usize = 96;
const MANIFEST_HMAC_COVERED_LEN: usize = 104;
const SIDECAR_HMAC_COVERED_LEN: usize = 92;
const DEFAULT_MAX_VERIFY_TAR_SIZE: usize = 128 * 1024 * 1024;
const DEFAULT_MAX_TRAILING_GARBAGE_SCAN: usize = 1024 * 1024;
const DEFAULT_MAX_TOTAL_EXTRACTION_SIZE: u64 = 100 * 1024 * 1024 * 1024;
const DIRECTORY_HINT_REQUIRED_FILE_COUNT: u64 = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderOptions {
    pub max_trailing_garbage_scan: usize,
    pub max_verify_tar_size: usize,
    pub max_total_extraction_size: u64,
}

impl Default for ReaderOptions {
    fn default() -> Self {
        Self {
            max_trailing_garbage_scan: DEFAULT_MAX_TRAILING_GARBAGE_SCAN,
            max_verify_tar_size: DEFAULT_MAX_VERIFY_TAR_SIZE,
            max_total_extraction_size: DEFAULT_MAX_TOTAL_EXTRACTION_SIZE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub file_data_size: u64,
    pub kind: TarEntryKind,
    pub mode: u32,
    pub mtime: u64,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedArchiveMember {
    pub path: String,
    pub kind: TarEntryKind,
    pub data: Vec<u8>,
    pub link_target: Option<String>,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct OpenedArchive {
    options: ReaderOptions,
    observed_archive_bytes: u64,
    subkeys: Subkeys,
    blocks: BTreeMap<u64, BlockRecord>,
    pub volume_header: VolumeHeader,
    pub crypto_header: CryptoHeaderFixed,
    pub manifest_footer: ManifestFooter,
    pub volume_trailer: VolumeTrailer,
    pub index_root: IndexRoot,
    payload_dictionary: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
struct ObjectExtent {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

type DirectoryHintMap = BTreeMap<Vec<u8>, BTreeSet<u32>>;

pub fn open_archive<'a>(
    bytes: &'a [u8],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_with_options(bytes, master_key, ReaderOptions::default())
}

pub fn open_archive_volumes(
    volumes: &[&[u8]],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_volumes_with_options(volumes, master_key, ReaderOptions::default())
}

pub fn open_archive_with_bootstrap_sidecar(
    bytes: &[u8],
    bootstrap_sidecar: &[u8],
    master_key: &MasterKey,
) -> Result<OpenedArchive, FormatError> {
    OpenedArchive::open_with_bootstrap_sidecar_options(
        bytes,
        bootstrap_sidecar,
        master_key,
        ReaderOptions::default(),
    )
}

pub fn open_non_seekable_archive(
    bytes: &[u8],
    master_key: &MasterKey,
    bootstrap_sidecar: Option<&[u8]>,
) -> Result<OpenedArchive, FormatError> {
    match bootstrap_sidecar {
        Some(sidecar) => open_archive_with_bootstrap_sidecar(bytes, sidecar, master_key),
        None => Err(FormatError::ReaderUnsupported(
            "non-seekable random access requires a bootstrap sidecar",
        )),
    }
}

pub fn sequential_extract_tar_stream(
    bytes: &[u8],
    master_key: &MasterKey,
) -> Result<Vec<u8>, FormatError> {
    sequential_extract_tar_stream_with_options(bytes, master_key, ReaderOptions::default())
}

impl OpenedArchive {
    pub fn open_with_options(
        bytes: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        Self::open_volumes_with_options(&[bytes], master_key, options)
    }

    pub fn open_volumes_with_options(
        volumes: &[&[u8]],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        if volumes.is_empty() {
            return Err(FormatError::InvalidArchive("no volumes supplied"));
        }

        let observed_archive_bytes =
            observed_archive_size(volumes.iter().map(|volume| volume.len() as u64))?;
        let mut first: Option<ParsedSeekableVolume> = None;
        let mut seen_volume_indexes = BTreeSet::new();
        let mut blocks = BTreeMap::new();
        let mut erased_block_indices = BTreeSet::new();

        for volume_bytes in volumes {
            let parsed = parse_seekable_volume(volume_bytes, master_key, options)?;
            if !seen_volume_indexes.insert(parsed.volume_header.volume_index) {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if let Some(first) = &first {
                validate_volume_set_member(first, &parsed)?;
            }

            for (block_index, record) in &parsed.blocks {
                if blocks.insert(*block_index, record.clone()).is_some() {
                    return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
                }
            }
            for block_index in &parsed.erased_block_indices {
                erased_block_indices.insert(*block_index);
            }

            if first.is_none() {
                first = Some(parsed);
            }
        }

        let first = first.ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
        if seen_volume_indexes.len() == first.crypto_header.stripe_width as usize {
            validate_complete_global_block_coverage(&blocks, &erased_block_indices)?;
        }

        let limits = metadata_limits(&first.crypto_header);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            &first.subkeys,
            &first.volume_header,
            &first.crypto_header,
            ObjectExtent {
                first_block_index: first.manifest_footer.index_root_first_block,
                data_block_count: first.manifest_footer.index_root_data_block_count,
                parity_block_count: first.manifest_footer.index_root_parity_block_count,
                encrypted_size: first.manifest_footer.index_root_encrypted_size,
            },
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            &first.subkeys.index_root_key,
            &first.subkeys.index_nonce_seed,
            b"idxroot",
            0,
            first.crypto_header.index_root_fec_data_shards,
            first.crypto_header.index_root_fec_parity_shards,
            first.manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            first.crypto_header.has_dictionary != 0,
            limits,
        )?;
        let payload_dictionary = load_archive_dictionary(
            &blocks,
            &first.subkeys,
            &first.volume_header,
            &first.crypto_header,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            subkeys: first.subkeys,
            blocks,
            volume_header: first.volume_header,
            crypto_header: first.crypto_header,
            manifest_footer: first.manifest_footer,
            volume_trailer: first.volume_trailer,
            index_root,
            payload_dictionary,
        })
    }

    pub fn open_with_bootstrap_sidecar_options(
        bytes: &[u8],
        bootstrap_sidecar: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
    ) -> Result<Self, FormatError> {
        let observed_archive_bytes =
            observed_archive_size([bytes.len() as u64, bootstrap_sidecar.len() as u64])?;
        if bytes.len() < VOLUME_HEADER_LEN {
            return Err(FormatError::InvalidLength {
                structure: "archive",
                expected: VOLUME_HEADER_LEN,
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
        validate_m9_supported_volume(&volume_header, &parsed_crypto.fixed)?;

        let sidecar = parse_trusted_bootstrap_sidecar(
            bootstrap_sidecar,
            &volume_header,
            &parsed_crypto.fixed,
            &subkeys,
        )?;

        let (mut blocks, terminal_offset, observed_block_count) = parse_stream_block_prefix(
            bytes,
            crypto_end,
            parsed_crypto.fixed.block_size as usize,
            &volume_header,
        )?;
        insert_sidecar_records(&mut blocks, sidecar.index_root_records)?;

        let (terminal_manifest, volume_trailer) = parse_terminal_material(
            bytes,
            terminal_offset,
            observed_block_count,
            &subkeys,
            &volume_header,
            parsed_crypto.fixed.block_size,
        )?;
        if terminal_manifest != sidecar.manifest_footer {
            return Err(FormatError::InvalidArchive(
                "bootstrap sidecar conflicts with terminal ManifestFooter",
            ));
        }

        let limits = metadata_limits(&parsed_crypto.fixed);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            &subkeys,
            &volume_header,
            &parsed_crypto.fixed,
            ObjectExtent {
                first_block_index: sidecar.manifest_footer.index_root_first_block,
                data_block_count: sidecar.manifest_footer.index_root_data_block_count,
                parity_block_count: sidecar.manifest_footer.index_root_parity_block_count,
                encrypted_size: sidecar.manifest_footer.index_root_encrypted_size,
            },
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            parsed_crypto.fixed.index_root_fec_data_shards,
            parsed_crypto.fixed.index_root_fec_parity_shards,
            sidecar.manifest_footer.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            parsed_crypto.fixed.has_dictionary != 0,
            limits,
        )?;
        if parsed_crypto.fixed.has_dictionary != 0 {
            let (offset, length) =
                sidecar
                    .dictionary_records_section
                    .ok_or(FormatError::ReaderUnsupported(
                        "dictionary bootstrap required",
                    ))?;
            let dictionary_records = parse_sidecar_block_records(
                bootstrap_sidecar,
                offset,
                length,
                parsed_crypto.fixed.block_size as usize,
                dictionary_extent_from_index_root(&index_root)?,
                BlockKind::DictionaryData,
                BlockKind::DictionaryParity,
                "dictionary",
            )?;
            insert_sidecar_records(&mut blocks, dictionary_records)?;
        }
        let payload_dictionary = load_archive_dictionary(
            &blocks,
            &subkeys,
            &volume_header,
            &parsed_crypto.fixed,
            &index_root,
        )?;

        Ok(Self {
            options,
            observed_archive_bytes,
            subkeys,
            blocks,
            volume_header,
            crypto_header: parsed_crypto.fixed,
            manifest_footer: sidecar.manifest_footer,
            volume_trailer,
            index_root,
            payload_dictionary,
        })
    }

    pub fn list_files(&self) -> Result<Vec<ArchiveEntry>, FormatError> {
        #[derive(Clone, Copy)]
        struct WinningEntry {
            start: u64,
            file_data_size: u64,
            shard_index: usize,
            file_index: usize,
        }

        let shards = self.load_all_index_shards()?;
        let mut final_entries = BTreeMap::<String, WinningEntry>::new();
        for (shard_index, shard) in shards.iter().enumerate() {
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
                if let Some(winner) = final_entries.get_mut(&path) {
                    if start >= winner.start {
                        winner.start = start;
                        winner.file_data_size = file.file_data_size;
                        winner.shard_index = shard_index;
                        winner.file_index = idx;
                    }
                } else {
                    final_entries.insert(
                        path,
                        WinningEntry {
                            start,
                            file_data_size: file.file_data_size,
                            shard_index,
                            file_index: idx,
                        },
                    );
                }
            }
        }
        final_entries
            .into_iter()
            .map(|(path, winner)| {
                let shard = &shards[winner.shard_index];
                let member =
                    self.decode_loaded_owned_tar_member(shard, winner.file_index, false)?;
                Ok(ArchiveEntry {
                    path,
                    file_data_size: winner.file_data_size,
                    kind: member.kind,
                    mode: member.mode,
                    mtime: member.mtime,
                    diagnostics: member.diagnostics,
                })
            })
            .collect()
    }

    pub fn extract_file(&self, path: &str) -> Result<Option<Vec<u8>>, FormatError> {
        self.extract_member(path)?
            .map(|member| {
                if member.kind != TarEntryKind::Regular {
                    return Err(FormatError::ReaderUnsupported(
                        "extract_file returns only regular file payloads",
                    ));
                }
                Ok(member.data)
            })
            .transpose()
    }

    pub fn extract_member(
        &self,
        path: &str,
    ) -> Result<Option<ExtractedArchiveMember>, FormatError> {
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
            .map(|(shard, file_index, _)| self.extract_loaded_member(&shard, file_index))
            .transpose()
    }

    pub fn extract_file_to(
        &self,
        path: &str,
        root: &std::path::Path,
        options: SafeExtractionOptions,
    ) -> Result<Option<Vec<MetadataDiagnostic>>, FormatError> {
        self.extract_owned_tar_member(path)?
            .map(|member| restore_tar_member(root, &member, options))
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

        let tar_len = self.index_root.header.tar_total_size;
        let mut content_hasher = Sha256::new();
        let mut tar_cursor = 0u64;
        let mut cached_envelope_index = None;
        let mut cached_envelope_plaintext = Vec::new();

        for frame in frames.values() {
            let envelope =
                envelopes
                    .get(&frame.envelope_index)
                    .ok_or(FormatError::InvalidArchive(
                        "FrameEntry references missing EnvelopeEntry",
                    ))?;
            if cached_envelope_index != Some(envelope.envelope_index) {
                cached_envelope_plaintext = self.load_payload_envelope(envelope)?;
                cached_envelope_index = Some(envelope.envelope_index);
            }
            let compressed = slice(
                &cached_envelope_plaintext,
                frame.offset_in_envelope as usize,
                frame.compressed_size as usize,
                "FrameEntry",
            )?;
            let decoded = self.decompress_payload_frame(compressed, frame.decompressed_size)?;
            if frame.tar_stream_offset != tar_cursor {
                return Err(FormatError::InvalidArchive(
                    "decoded frames leave tar gap or overlap",
                ));
            }
            tar_cursor = tar_cursor
                .checked_add(decoded.len() as u64)
                .ok_or(FormatError::InvalidArchive("tar stream size overflow"))?;
            if tar_cursor > tar_len {
                return Err(FormatError::InvalidArchive(
                    "FrameEntry exceeds IndexRoot tar_total_size",
                ));
            }
            content_hasher.update(&decoded);
        }

        if tar_cursor != tar_len {
            return Err(FormatError::InvalidArchive("decoded frames leave tar gap"));
        }
        if content_hasher.finalize().as_slice() != self.index_root.header.content_sha256 {
            return Err(FormatError::InvalidArchive(
                "IndexRoot content_sha256 does not match decoded tar stream",
            ));
        }

        let mut file_extents = Vec::new();
        let mut directory_hint_map = DirectoryHintMap::new();
        for (shard_row_index, shard) in shards.iter().enumerate() {
            let shard_row_index = u32::try_from(shard_row_index)
                .map_err(|_| FormatError::InvalidArchive("shard row index overflow"))?;
            for idx in 0..shard.files.len() {
                let file = &shard.files[idx];
                let start =
                    shard
                        .tar_member_group_start(idx)
                        .ok_or(FormatError::InvalidArchive(
                            "FileEntry tar member start is missing",
                        ))?;
                file_extents.push((start, file.tar_member_group_size));
                let member = self.decode_loaded_owned_tar_member(shard, idx, false)?;
                let path = shard
                    .file_path(idx)
                    .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?;
                add_expected_directory_hint_rows(
                    &mut directory_hint_map,
                    shard_row_index,
                    path,
                    member.kind,
                );
            }
        }
        validate_file_extent_coverage_ranges(&file_extents, tar_len)?;
        if !self.index_root.directory_hint_shards.is_empty() {
            let hint_tables = self.load_all_directory_hint_tables()?;
            validate_directory_hint_tables_against_expected(&hint_tables, &directory_hint_map)?;
        }

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

    fn load_all_directory_hint_tables(&self) -> Result<Vec<DirectoryHintTable>, FormatError> {
        self.index_root
            .directory_hint_shards
            .iter()
            .map(|entry| self.load_directory_hint_table(entry))
            .collect()
    }

    fn load_directory_hint_table(
        &self,
        entry: &DirectoryHintShardEntry,
    ) -> Result<DirectoryHintTable, FormatError> {
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
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            &self.subkeys.dir_hint_key,
            &self.subkeys.index_nonce_seed,
            b"dirhint",
            entry.hint_shard_index,
            self.crypto_header.index_fec_data_shards,
            self.crypto_header.index_fec_parity_shards,
            entry.decompressed_size,
        )?;
        DirectoryHintTable::parse(
            &plaintext,
            entry,
            self.index_root.header.shard_count,
            self.metadata_limits(),
        )
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

    fn extract_owned_tar_member(&self, path: &str) -> Result<Option<OwnedTarMember>, FormatError> {
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
            .map(|(shard, file_index, _)| self.extract_loaded_owned_tar_member(&shard, file_index))
            .transpose()
    }

    fn extract_loaded_member(
        &self,
        shard: &IndexShard,
        file_index: usize,
    ) -> Result<ExtractedArchiveMember, FormatError> {
        let member = self.extract_loaded_owned_tar_member(shard, file_index)?;
        Ok(ExtractedArchiveMember {
            path: utf8_path(&member.path)?,
            kind: member.kind,
            data: member.data,
            link_target: member
                .link_target
                .map(|target| utf8_path(&target))
                .transpose()?,
            diagnostics: member.diagnostics,
        })
    }

    fn extract_loaded_owned_tar_member(
        &self,
        shard: &IndexShard,
        file_index: usize,
    ) -> Result<OwnedTarMember, FormatError> {
        self.decode_loaded_owned_tar_member(shard, file_index, true)
    }

    fn decode_loaded_owned_tar_member(
        &self,
        shard: &IndexShard,
        file_index: usize,
        enforce_extraction_cap: bool,
    ) -> Result<OwnedTarMember, FormatError> {
        let file = shard
            .files
            .get(file_index)
            .ok_or(FormatError::InvalidArchive("FileEntry index out of bounds"))?;
        if enforce_extraction_cap {
            self.validate_total_extraction_size(file.file_data_size)?;
        }
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
            decoded.extend_from_slice(
                &self.decompress_payload_frame(compressed, frame.decompressed_size)?,
            );
        }

        let offset = file.offset_in_first_frame_plaintext as usize;
        let group_len = to_usize(file.tar_member_group_size, "FileEntry")?;
        let group = slice(&decoded, offset, group_len, "FileEntry")?;
        let member = parse_tar_member_group(group, self.crypto_header.max_path_length)?;
        if member.path != expected_path {
            return Err(FormatError::InvalidArchive(
                "tar member path does not match FileEntry path",
            ));
        }
        if member.logical_size != file.file_data_size {
            return Err(FormatError::InvalidArchive(
                "tar member size does not match FileEntry file_data_size",
            ));
        }
        Ok(member.to_owned_member())
    }

    fn metadata_limits(&self) -> MetadataLimits {
        metadata_limits(&self.crypto_header)
    }

    fn validate_total_extraction_size(&self, logical_size: u64) -> Result<(), FormatError> {
        let cap = total_extraction_size_cap(self.options, self.observed_archive_bytes);
        if logical_size > cap {
            return Err(FormatError::ReaderUnsupported(
                "total extraction size exceeds configured cap",
            ));
        }
        Ok(())
    }

    fn decompress_payload_frame(
        &self,
        compressed: &[u8],
        decompressed_size: u32,
    ) -> Result<Vec<u8>, FormatError> {
        if let Some(dictionary) = &self.payload_dictionary {
            decompress_exact_zstd_frame_with_dictionary(
                compressed,
                decompressed_size as usize,
                dictionary,
            )
        } else {
            decompress_exact_zstd_frame(compressed, decompressed_size as usize)
        }
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
        for hint in &self.index_root.directory_hint_shards {
            ranges.push(object_block_range(
                hint.first_block_index,
                hint.data_block_count,
                hint.parity_block_count,
                "DirectoryHintShardEntry",
            )?);
        }
        if self.crypto_header.has_dictionary != 0 {
            ranges.push(object_block_range(
                self.index_root.header.dictionary_first_block,
                self.index_root.header.dictionary_data_block_count,
                self.index_root.header.dictionary_parity_block_count,
                "dictionary",
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

#[derive(Debug)]
struct ParsedSeekableVolume {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    crypto_header_bytes: Vec<u8>,
    subkeys: Subkeys,
    manifest_footer: ManifestFooter,
    volume_trailer: VolumeTrailer,
    blocks: BTreeMap<u64, BlockRecord>,
    erased_block_indices: BTreeSet<u64>,
}

fn parse_seekable_volume(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<ParsedSeekableVolume, FormatError> {
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
    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed)?;

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

    let block_region = parse_block_region(
        bytes,
        crypto_end,
        manifest_offset,
        parsed_crypto.fixed.block_size as usize,
        &volume_header,
        &volume_trailer,
    )?;

    Ok(ParsedSeekableVolume {
        volume_header,
        crypto_header: parsed_crypto.fixed,
        crypto_header_bytes: crypto_bytes.to_vec(),
        subkeys,
        manifest_footer,
        volume_trailer,
        blocks: block_region.blocks,
        erased_block_indices: block_region.erased_block_indices,
    })
}

fn validate_seekable_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    Ok(())
}

fn validate_volume_set_member(
    first: &ParsedSeekableVolume,
    candidate: &ParsedSeekableVolume,
) -> Result<(), FormatError> {
    if candidate.volume_header.archive_uuid != first.volume_header.archive_uuid
        || candidate.volume_header.session_id != first.volume_header.session_id
    {
        return Err(FormatError::InvalidArchive(
            "mixed archive or session IDs in volume set",
        ));
    }
    if candidate.crypto_header_bytes != first.crypto_header_bytes
        || candidate.crypto_header != first.crypto_header
    {
        return Err(FormatError::InvalidArchive("CryptoHeader copies differ"));
    }
    if !manifest_bootstrap_fields_match(&first.manifest_footer, &candidate.manifest_footer) {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter bootstrap fields differ",
        ));
    }
    Ok(())
}

fn manifest_bootstrap_fields_match(left: &ManifestFooter, right: &ManifestFooter) -> bool {
    left.archive_uuid == right.archive_uuid
        && left.session_id == right.session_id
        && left.is_authoritative == right.is_authoritative
        && left.total_volumes == right.total_volumes
        && left.index_root_first_block == right.index_root_first_block
        && left.index_root_data_block_count == right.index_root_data_block_count
        && left.index_root_parity_block_count == right.index_root_parity_block_count
        && left.index_root_encrypted_size == right.index_root_encrypted_size
        && left.index_root_decompressed_size == right.index_root_decompressed_size
}

fn validate_complete_global_block_coverage(
    blocks: &BTreeMap<u64, BlockRecord>,
    erased_block_indices: &BTreeSet<u64>,
) -> Result<(), FormatError> {
    let mut expected = 0u64;
    let mut block_iter = blocks.keys().copied().peekable();
    let mut erasure_iter = erased_block_indices.iter().copied().peekable();

    loop {
        let next_block = block_iter.peek().copied();
        let next_erasure = erasure_iter.peek().copied();
        let next = match (next_block, next_erasure) {
            (Some(block), Some(erasure)) if block == erasure => {
                return Err(FormatError::InvalidArchive(
                    "BlockRecord index is both present and erased",
                ));
            }
            (Some(block), Some(erasure)) => block.min(erasure),
            (Some(block), None) => block,
            (None, Some(erasure)) => erasure,
            (None, None) => return Ok(()),
        };

        if next != expected {
            return Err(FormatError::InvalidArchive(
                "complete volume set has missing global blocks",
            ));
        }
        if next_block == Some(next) {
            block_iter.next();
        }
        if next_erasure == Some(next) {
            erasure_iter.next();
        }
        expected = expected
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("global block index overflow"))?;
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

fn validate_m9_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported(
            "M9 reader supports only single-volume archives",
        ));
    }
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct TrustedBootstrapSidecar {
    manifest_footer: ManifestFooter,
    index_root_records: Vec<BlockRecord>,
    dictionary_records_section: Option<(u64, u64)>,
}

fn parse_trusted_bootstrap_sidecar(
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    subkeys: &Subkeys,
) -> Result<TrustedBootstrapSidecar, FormatError> {
    let header_bytes = slice(
        bytes,
        0,
        BOOTSTRAP_SIDECAR_HEADER_LEN,
        "BootstrapSidecarHeader",
    )?;
    let header = BootstrapSidecarHeader::parse(header_bytes)?;
    if header.archive_uuid != volume_header.archive_uuid
        || header.session_id != volume_header.session_id
    {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar identity does not match VolumeHeader",
        ));
    }
    verify_hmac(
        HmacDomain::BootstrapSidecar,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &header_bytes[..SIDECAR_HMAC_COVERED_LEN],
        &header.sidecar_hmac,
    )?;
    header.validate_packed_layout(bytes.len() as u64)?;
    validate_sidecar_size_cap(&header, crypto_header, bytes.len() as u64)?;

    if !header.has_manifest_footer() || !header.has_index_root_records() {
        return Err(FormatError::ReaderUnsupported(
            "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
        ));
    }
    if header.has_dictionary_records() {
        if crypto_header.has_dictionary == 0 {
            return Err(FormatError::InvalidArchive(
                "bootstrap sidecar has dictionary records while has_dictionary is false",
            ));
        }
    } else if crypto_header.has_dictionary != 0 {
        return Err(FormatError::ReaderUnsupported(
            "dictionary bootstrap required",
        ));
    }

    let manifest_offset = to_usize(header.manifest_footer_offset, "BootstrapSidecarHeader")?;
    let manifest_bytes = slice(
        bytes,
        manifest_offset,
        MANIFEST_FOOTER_LEN,
        "ManifestFooter",
    )?;
    let manifest_footer = ManifestFooter::parse(manifest_bytes)?;
    validate_sidecar_manifest_footer(
        volume_header,
        crypto_header,
        &manifest_footer,
        subkeys,
        manifest_bytes,
    )?;
    manifest_footer.validate_index_root_extent(crypto_header.block_size)?;

    let index_root_records = parse_sidecar_block_records(
        bytes,
        header.index_root_records_offset,
        header.index_root_records_length,
        crypto_header.block_size as usize,
        ObjectExtent {
            first_block_index: manifest_footer.index_root_first_block,
            data_block_count: manifest_footer.index_root_data_block_count,
            parity_block_count: manifest_footer.index_root_parity_block_count,
            encrypted_size: manifest_footer.index_root_encrypted_size,
        },
        BlockKind::IndexRootData,
        BlockKind::IndexRootParity,
        "IndexRoot",
    )?;

    Ok(TrustedBootstrapSidecar {
        manifest_footer,
        index_root_records,
        dictionary_records_section: header.has_dictionary_records().then_some((
            header.dictionary_records_offset,
            header.dictionary_records_length,
        )),
    })
}

fn insert_sidecar_records(
    blocks: &mut BTreeMap<u64, BlockRecord>,
    records: Vec<BlockRecord>,
) -> Result<(), FormatError> {
    for record in records {
        if let Some(existing) = blocks.insert(record.block_index, record.clone()) {
            if existing != record {
                return Err(FormatError::InvalidArchive(
                    "bootstrap sidecar conflicts with volume BlockRecord",
                ));
            }
        }
    }
    Ok(())
}

fn validate_sidecar_manifest_footer(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    footer: &ManifestFooter,
    subkeys: &Subkeys,
    raw: &[u8],
) -> Result<(), FormatError> {
    if footer.archive_uuid != volume_header.archive_uuid
        || footer.session_id != volume_header.session_id
    {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter identity does not match VolumeHeader",
        ));
    }
    if footer.volume_index != 0 {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter volume_index must be zero",
        ));
    }
    if footer.total_volumes != crypto_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter total_volumes does not match stripe_width",
        ));
    }
    if footer.is_authoritative != 1 {
        return Err(FormatError::InvalidArchive(
            "sidecar ManifestFooter is not authoritative",
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

fn validate_sidecar_size_cap(
    header: &BootstrapSidecarHeader,
    crypto_header: &CryptoHeaderFixed,
    file_size: u64,
) -> Result<(), FormatError> {
    let record_len = checked_u64_add(
        crypto_header.block_size as u64,
        BLOCK_RECORD_FRAMING_LEN as u64,
        "bootstrap sidecar cap overflow",
    )?;
    let max_index_records = crypto_header.index_root_fec_data_shards as u64
        + crypto_header.index_root_fec_parity_shards as u64;
    let max_record_section_bytes = checked_u64_mul(
        max_index_records,
        record_len,
        "bootstrap sidecar cap overflow",
    )?;
    if header.index_root_records_length % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar IndexRoot records length is not aligned",
        ));
    }
    if header.index_root_records_length / record_len > max_index_records {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar IndexRoot records exceed resource cap",
        ));
    }
    if header.dictionary_records_length % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar dictionary records length is not aligned",
        ));
    }
    if header.dictionary_records_length / record_len > max_index_records {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar dictionary records exceed resource cap",
        ));
    }

    let mut cap = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    if header.has_manifest_footer() {
        cap = cap
            .checked_add(MANIFEST_FOOTER_LEN as u64)
            .ok_or(FormatError::InvalidArchive(
                "bootstrap sidecar cap overflow",
            ))?;
    }
    if header.has_index_root_records() {
        cap = checked_u64_add(
            cap,
            max_record_section_bytes,
            "bootstrap sidecar cap overflow",
        )?;
    }
    if header.has_dictionary_records() {
        cap = checked_u64_add(
            cap,
            max_record_section_bytes,
            "bootstrap sidecar cap overflow",
        )?;
    }
    if file_size > cap {
        return Err(FormatError::InvalidArchive(
            "bootstrap sidecar exceeds resource cap",
        ));
    }
    Ok(())
}

fn parse_sidecar_block_records(
    sidecar_bytes: &[u8],
    offset: u64,
    length: u64,
    block_size: usize,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    structure: &'static str,
) -> Result<Vec<BlockRecord>, FormatError> {
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    if length % record_len as u64 != 0 {
        return Err(FormatError::InvalidArchive(
            "sidecar BlockRecord section is not aligned",
        ));
    }
    let expected_count = extent.data_block_count as usize + extent.parity_block_count as usize;
    let actual_count = usize::try_from(length / record_len as u64)
        .map_err(|_| FormatError::InvalidArchive("sidecar BlockRecord count overflow"))?;
    if actual_count != expected_count {
        return Err(FormatError::InvalidArchive(
            "sidecar BlockRecord section does not match declared extent",
        ));
    }
    let start = to_usize(offset, "BootstrapSidecarHeader")?;
    let raw = slice(
        sidecar_bytes,
        start,
        to_usize(length, "BootstrapSidecarHeader")?,
        "BootstrapSidecarHeader",
    )?;
    let mut records = Vec::with_capacity(expected_count);

    for idx in 0..expected_count {
        let record = BlockRecord::parse(
            slice(raw, idx * record_len, record_len, "BlockRecord")?,
            block_size,
        )?;
        let expected_block_index =
            checked_u64_add(extent.first_block_index, idx as u64, structure)?;
        if record.block_index != expected_block_index {
            return Err(FormatError::InvalidArchive(
                "sidecar BlockRecord section has missing or duplicate blocks",
            ));
        }
        let expected_kind = if idx < extent.data_block_count as usize {
            data_kind
        } else {
            parity_kind
        };
        if record.kind != expected_kind {
            return Err(FormatError::InvalidArchive(
                "sidecar BlockRecord section has wrong kind",
            ));
        }
        let should_be_last = idx + 1 == extent.data_block_count as usize;
        if idx < extent.data_block_count as usize && record.is_last_data() != should_be_last {
            return Err(FormatError::InvalidArchive(
                "sidecar BlockRecord section has wrong last-data flag",
            ));
        }
        records.push(record);
    }

    Ok(records)
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

#[derive(Debug)]
struct ParsedBlockRegion {
    blocks: BTreeMap<u64, BlockRecord>,
    erased_block_indices: BTreeSet<u64>,
}

fn parse_block_region(
    bytes: &[u8],
    start: usize,
    end: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
    trailer: &VolumeTrailer,
) -> Result<ParsedBlockRegion, FormatError> {
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
    let mut erased_block_indices = BTreeSet::new();
    for idx in 0..observed_count {
        let offset = start + idx * record_len;
        let expected_block_index = checked_u64_add(
            volume_header.volume_index as u64,
            checked_u64_mul(
                idx as u64,
                volume_header.stripe_width as u64,
                "BlockRecord index overflow",
            )?,
            "BlockRecord index overflow",
        )?;
        let raw = slice(bytes, offset, record_len, "BlockRecord")?;
        match BlockRecord::parse(raw, block_size) {
            Ok(record) => {
                if record.block_index != expected_block_index {
                    return Err(FormatError::InvalidArchive(
                        "BlockRecord index does not match volume position",
                    ));
                }
                if blocks.insert(record.block_index, record).is_some() {
                    return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
                }
            }
            Err(err) if block_record_error_is_recoverable_erasure(&err) => {
                if !erased_block_indices.insert(expected_block_index) {
                    return Err(FormatError::InvalidArchive(
                        "duplicate erased BlockRecord index",
                    ));
                }
            }
            Err(err) => return Err(err),
        }
    }

    Ok(ParsedBlockRegion {
        blocks,
        erased_block_indices,
    })
}

fn block_record_error_is_recoverable_erasure(error: &FormatError) -> bool {
    match error {
        FormatError::BadCrc { structure }
        | FormatError::BadMagic { structure }
        | FormatError::NonZeroReserved { structure } => *structure == "BlockRecord",
        _ => false,
    }
}

fn checked_u64_mul(lhs: u64, rhs: u64, reason: &'static str) -> Result<u64, FormatError> {
    lhs.checked_mul(rhs)
        .ok_or(FormatError::InvalidArchive(reason))
}

fn parse_stream_block_prefix(
    bytes: &[u8],
    start: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
) -> Result<(BTreeMap<u64, BlockRecord>, usize, u64), FormatError> {
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let mut blocks = BTreeMap::new();
    let mut offset = start;
    let mut observed_block_count = 0u64;

    while bytes.get(offset..offset + 4) == Some(b"TZBK") {
        let expected_block_index =
            expected_stream_block_index(volume_header, observed_block_count)?;
        let raw = slice(bytes, offset, record_len, "BlockRecord")?;
        match BlockRecord::parse(raw, block_size) {
            Ok(record) => {
                if record.block_index != expected_block_index {
                    return Err(FormatError::InvalidArchive(
                        "BlockRecord index does not match stream position",
                    ));
                }
                if blocks.insert(record.block_index, record).is_some() {
                    return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
                }
            }
            Err(err) if block_record_error_is_recoverable_erasure(&err) => {}
            Err(err) => return Err(err),
        }
        offset = checked_add(offset, record_len, "BlockRecord")?;
        observed_block_count = observed_block_count
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("BlockRecord count overflow"))?;
    }

    Ok((blocks, offset, observed_block_count))
}

fn expected_stream_block_index(
    volume_header: &VolumeHeader,
    observed_block_count: u64,
) -> Result<u64, FormatError> {
    checked_u64_add(
        volume_header.volume_index as u64,
        checked_u64_mul(
            observed_block_count,
            volume_header.stripe_width as u64,
            "BlockRecord index overflow",
        )?,
        "BlockRecord index overflow",
    )
}

fn parse_sequential_block_or_erasure(
    bytes: &[u8],
    offset: usize,
    record_len: usize,
    block_size: usize,
    volume_header: &VolumeHeader,
    observed_block_count: u64,
) -> Result<Option<BlockRecord>, FormatError> {
    let expected_block_index = expected_stream_block_index(volume_header, observed_block_count)?;
    let raw = slice(bytes, offset, record_len, "BlockRecord")?;
    match BlockRecord::parse(raw, block_size) {
        Ok(record) => {
            if record.block_index != expected_block_index {
                return Err(FormatError::InvalidArchive(
                    "BlockRecord index does not match stream position",
                ));
            }
            Ok(Some(record))
        }
        Err(err) if block_record_error_is_recoverable_erasure(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn parse_terminal_material(
    bytes: &[u8],
    manifest_offset: usize,
    observed_block_count: u64,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    block_size: u32,
) -> Result<(ManifestFooter, VolumeTrailer), FormatError> {
    let manifest_end = checked_add(manifest_offset, MANIFEST_FOOTER_LEN, "ManifestFooter")?;
    let trailer_end = checked_add(manifest_end, VOLUME_TRAILER_LEN, "VolumeTrailer")?;
    if trailer_end != bytes.len() {
        return Err(FormatError::InvalidArchive(
            "terminal ManifestFooter/VolumeTrailer is not packed at stream end",
        ));
    }

    let manifest_bytes = slice(
        bytes,
        manifest_offset,
        MANIFEST_FOOTER_LEN,
        "ManifestFooter",
    )?;
    let manifest_footer = ManifestFooter::parse(manifest_bytes)?;
    validate_manifest_footer(volume_header, &manifest_footer, subkeys, manifest_bytes)?;
    manifest_footer.validate_index_root_extent(block_size)?;

    let trailer = parse_authenticated_trailer(bytes, manifest_end, subkeys, volume_header)?;
    validate_trailer_identity(volume_header, &trailer)?;
    if trailer.manifest_footer_offset != manifest_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer ManifestFooter offset does not match observed stream offset",
        ));
    }
    if trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32 {
        return Err(FormatError::InvalidManifestFooterLength(
            trailer.manifest_footer_length,
        ));
    }
    if trailer.bytes_written != manifest_end as u64 {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer bytes_written does not match observed trailer offset",
        ));
    }
    if trailer.block_count != observed_block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match observed stream",
        ));
    }

    Ok((manifest_footer, trailer))
}

#[derive(Debug, Default)]
struct PendingSequentialEnvelope {
    data_shards: Vec<Option<Vec<u8>>>,
    parity_shards: Vec<Option<Vec<u8>>>,
    saw_last_data: bool,
    awaiting_tentative_parity: bool,
}

impl PendingSequentialEnvelope {
    fn is_empty(&self) -> bool {
        self.data_shards.is_empty() && self.parity_shards.is_empty()
    }
}

fn handle_sequential_payload_erasure(
    pending: &mut PendingSequentialEnvelope,
    crypto_header: &CryptoHeaderFixed,
    metadata_seen: bool,
) -> Result<(), FormatError> {
    if metadata_seen || pending.saw_last_data {
        return Err(FormatError::BadCrc {
            structure: "BlockRecord",
        });
    }
    if !sequential_payload_parity_is_guaranteed(crypto_header) {
        return Err(FormatError::BadCrc {
            structure: "BlockRecord",
        });
    }
    pending.data_shards.push(None);
    pending.awaiting_tentative_parity = true;
    if pending.data_shards.len() > crypto_header.fec_data_shards as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope exceeds data-shard cap",
        ));
    }
    Ok(())
}

fn sequential_payload_parity_is_guaranteed(crypto_header: &CryptoHeaderFixed) -> bool {
    crypto_header.fec_parity_shards > 0
        && (crypto_header.volume_loss_tolerance > 0 || crypto_header.bit_rot_buffer_pct > 0)
}

fn sequential_extract_tar_stream_with_options(
    bytes: &[u8],
    master_key: &MasterKey,
    options: ReaderOptions,
) -> Result<Vec<u8>, FormatError> {
    if bytes.len() < VOLUME_HEADER_LEN {
        return Err(FormatError::InvalidLength {
            structure: "archive",
            expected: VOLUME_HEADER_LEN,
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
    validate_sequential_supported_volume(&volume_header, &parsed_crypto.fixed)?;

    let block_size = parsed_crypto.fixed.block_size as usize;
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let mut offset = crypto_end;
    let mut observed_block_count = 0u64;
    let mut metadata_seen = false;
    let mut pending = PendingSequentialEnvelope::default();
    let mut next_envelope_index = 0u64;
    let mut tar_stream = Vec::new();

    while bytes.get(offset..offset + 4) == Some(b"TZBK") {
        let record = parse_sequential_block_or_erasure(
            bytes,
            offset,
            record_len,
            block_size,
            &volume_header,
            observed_block_count,
        )?;
        observed_block_count = observed_block_count
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("BlockRecord count overflow"))?;
        let Some(record) = record else {
            handle_sequential_payload_erasure(&mut pending, &parsed_crypto.fixed, metadata_seen)?;
            offset = checked_add(offset, record_len, "BlockRecord")?;
            continue;
        };

        match record.kind {
            BlockKind::PayloadData => {
                if metadata_seen {
                    return Err(FormatError::InvalidArchive(
                        "payload BlockRecord appears after metadata",
                    ));
                }
                if pending.awaiting_tentative_parity {
                    return Err(FormatError::InvalidArchive(
                        "sequential payload envelope boundary is ambiguous after CRC erasure",
                    ));
                }
                if pending.saw_last_data {
                    finalize_sequential_envelope(
                        &mut pending,
                        &parsed_crypto.fixed,
                        &subkeys,
                        &volume_header,
                        &mut next_envelope_index,
                        &mut tar_stream,
                    )?;
                }
                let is_last_data = record.is_last_data();
                pending.data_shards.push(Some(record.payload));
                if is_last_data {
                    pending.saw_last_data = true;
                }
                if pending.data_shards.len() > parsed_crypto.fixed.fec_data_shards as usize {
                    return Err(FormatError::InvalidArchive(
                        "sequential payload envelope exceeds data-shard cap",
                    ));
                }
            }
            BlockKind::PayloadParity => {
                if metadata_seen {
                    return Err(FormatError::InvalidArchive(
                        "payload parity BlockRecord appears after metadata",
                    ));
                }
                if pending.awaiting_tentative_parity {
                    pending.awaiting_tentative_parity = false;
                    pending.saw_last_data = true;
                } else if pending.data_shards.is_empty() || !pending.saw_last_data {
                    return Err(FormatError::InvalidArchive(
                        "payload parity appears before envelope data is complete",
                    ));
                }
                pending.parity_shards.push(Some(record.payload));
                if pending.parity_shards.len() > parsed_crypto.fixed.fec_parity_shards as usize {
                    return Err(FormatError::InvalidArchive(
                        "sequential payload envelope exceeds parity-shard cap",
                    ));
                }
            }
            _ => {
                if !pending.is_empty() {
                    finalize_sequential_envelope(
                        &mut pending,
                        &parsed_crypto.fixed,
                        &subkeys,
                        &volume_header,
                        &mut next_envelope_index,
                        &mut tar_stream,
                    )?;
                }
                metadata_seen = true;
            }
        }

        offset = checked_add(offset, record_len, "BlockRecord")?;
    }

    if !pending.is_empty() {
        finalize_sequential_envelope(
            &mut pending,
            &parsed_crypto.fixed,
            &subkeys,
            &volume_header,
            &mut next_envelope_index,
            &mut tar_stream,
        )?;
    }

    parse_terminal_material(
        bytes,
        offset,
        observed_block_count,
        &subkeys,
        &volume_header,
        parsed_crypto.fixed.block_size,
    )?;
    let observed_archive_bytes = observed_archive_size([bytes.len() as u64])?;
    validate_tar_stream_total_extraction_size(
        &tar_stream,
        parsed_crypto.fixed.max_path_length,
        total_extraction_size_cap(options, observed_archive_bytes),
    )?;
    Ok(tar_stream)
}

fn validate_sequential_supported_volume(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported(
            "M9 sequential reader supports only single-volume archives",
        ));
    }
    if crypto_header.stripe_width != volume_header.stripe_width {
        return Err(FormatError::InvalidArchive(
            "VolumeHeader and CryptoHeader stripe_width differ",
        ));
    }
    if crypto_header.has_dictionary != 0 {
        return Err(FormatError::ReaderUnsupported(
            "dictionary bootstrap required for non-seekable sequential extraction",
        ));
    }
    Ok(())
}

fn finalize_sequential_envelope(
    pending: &mut PendingSequentialEnvelope,
    crypto_header: &CryptoHeaderFixed,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    next_envelope_index: &mut u64,
    tar_stream: &mut Vec<u8>,
) -> Result<(), FormatError> {
    if !pending.saw_last_data {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope is missing last-data flag",
        ));
    }
    if pending.data_shards.len() > crypto_header.fec_data_shards as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope exceeds data-shard cap",
        ));
    }
    if pending.parity_shards.len() > crypto_header.fec_parity_shards as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope exceeds parity-shard cap",
        ));
    }
    let required_parity = required_object_parity(pending.data_shards.len() as u64, crypto_header)?;
    if pending.parity_shards.len() < required_parity as usize {
        return Err(FormatError::InvalidArchive(
            "sequential payload envelope has insufficient parity for recovery settings",
        ));
    }

    let repaired = repair_data_gf16(
        &pending.data_shards,
        &pending.parity_shards,
        crypto_header.block_size as usize,
    )?;
    let mut encrypted = Vec::with_capacity(repaired.len() * crypto_header.block_size as usize);
    for shard in repaired {
        encrypted.extend_from_slice(&shard);
    }
    let plaintext = decrypt_padded_aead_object(
        crypto_header.aead_algo,
        &subkeys.enc_key,
        &subkeys.nonce_seed,
        b"envelope",
        &volume_header.archive_uuid,
        &volume_header.session_id,
        *next_envelope_index,
        &encrypted,
    )?;
    decode_concatenated_zstd_frames(&plaintext, None, tar_stream)?;
    *next_envelope_index = next_envelope_index
        .checked_add(1)
        .ok_or(FormatError::InvalidArchive("envelope counter overflow"))?;
    *pending = PendingSequentialEnvelope::default();
    Ok(())
}

fn decode_concatenated_zstd_frames(
    plaintext: &[u8],
    dictionary: Option<&[u8]>,
    output: &mut Vec<u8>,
) -> Result<(), FormatError> {
    let mut cursor = 0usize;
    while cursor < plaintext.len() {
        let frame_len = zstd_safe::find_frame_compressed_size(&plaintext[cursor..])
            .map_err(|_| FormatError::InvalidZstdFrame)?;
        if frame_len == 0 {
            return Err(FormatError::InvalidZstdFrame);
        }
        let end = checked_add(cursor, frame_len, "zstd frame")?;
        validate_exact_zstd_frame(&plaintext[cursor..end])?;
        let decoded = if let Some(dictionary) = dictionary {
            let mut decoder =
                zstd::stream::Decoder::with_dictionary(&plaintext[cursor..end], dictionary)
                    .map_err(|_| FormatError::ZstdDecompressionFailure)?;
            let mut decoded = Vec::new();
            decoder
                .read_to_end(&mut decoded)
                .map_err(|_| FormatError::ZstdDecompressionFailure)?;
            decoded
        } else {
            zstd::stream::decode_all(&plaintext[cursor..end])
                .map_err(|_| FormatError::ZstdDecompressionFailure)?
        };
        output.extend_from_slice(&decoded);
        cursor = end;
    }
    Ok(())
}

fn load_archive_dictionary(
    blocks: &BTreeMap<u64, BlockRecord>,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    index_root: &IndexRoot,
) -> Result<Option<Vec<u8>>, FormatError> {
    if crypto_header.has_dictionary == 0 {
        return Ok(None);
    }
    let plaintext = load_metadata_object_from_parts(
        blocks,
        subkeys,
        volume_header,
        crypto_header,
        dictionary_extent_from_index_root(index_root)?,
        BlockKind::DictionaryData,
        BlockKind::DictionaryParity,
        &subkeys.dictionary_key,
        &subkeys.index_nonce_seed,
        b"dict",
        0,
        crypto_header.index_root_fec_data_shards,
        crypto_header.index_root_fec_parity_shards,
        index_root.header.dictionary_decompressed_size,
    )?;
    Ok(Some(plaintext))
}

fn dictionary_extent_from_index_root(index_root: &IndexRoot) -> Result<ObjectExtent, FormatError> {
    if index_root.header.dictionary_data_block_count == 0
        || index_root.header.dictionary_encrypted_size == 0
        || index_root.header.dictionary_decompressed_size == 0
    {
        return Err(FormatError::InvalidArchive("dictionary bootstrap required"));
    }
    Ok(ObjectExtent {
        first_block_index: index_root.header.dictionary_first_block,
        data_block_count: index_root.header.dictionary_data_block_count,
        parity_block_count: index_root.header.dictionary_parity_block_count,
        encrypted_size: index_root.header.dictionary_encrypted_size,
    })
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
        if let Some(record) = blocks.get(&block_index) {
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
        } else {
            data_shards.push(None);
        }
    }

    for offset in 0..parity_count {
        let block_index = checked_u64_add(
            extent.first_block_index,
            data_count as u64 + offset as u64,
            "object",
        )?;
        if let Some(record) = blocks.get(&block_index) {
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
        } else {
            parity_shards.push(None);
        }
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
    let required_parity = required_object_parity(extent.data_block_count as u64, crypto_header)?;
    if extent.parity_block_count < required_parity {
        return Err(FormatError::InvalidArchive(
            "encrypted object has insufficient parity for recovery settings",
        ));
    }
    let total = checked_u64_add(
        extent.data_block_count as u64,
        extent.parity_block_count as u64,
        "encrypted object shard count overflow",
    )?;
    if total > 65_535 {
        return Err(FormatError::FecTooManyShards(total as usize));
    }
    let expected = checked_u64_mul(
        extent.data_block_count as u64,
        crypto_header.block_size as u64,
        "encrypted object size overflow",
    )?;
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

fn required_object_parity(
    data_block_count: u64,
    crypto_header: &CryptoHeaderFixed,
) -> Result<u32, FormatError> {
    let min_parity =
        if crypto_header.volume_loss_tolerance > 0 || crypto_header.bit_rot_buffer_pct > 0 {
            1
        } else {
            0
        };
    let mut parity = 0u64;
    for _ in 0..100 {
        let total = data_block_count
            .checked_add(parity)
            .ok_or(FormatError::InvalidArchive("parity total overflow"))?;
        let by_volume = checked_u64_mul(
            crypto_header.volume_loss_tolerance as u64,
            ceil_div_u64(total, crypto_header.stripe_width as u64)?,
            "volume-loss parity overflow",
        )?;
        let by_bitrot = ceil_div_u64(
            checked_u64_mul(
                total,
                crypto_header.bit_rot_buffer_pct as u64,
                "bit-rot parity overflow",
            )?,
            100,
        )?;
        let next = by_volume
            .checked_add(by_bitrot)
            .ok_or(FormatError::InvalidArchive("parity overflow"))?
            .max(min_parity);
        if next == parity {
            return u32::try_from(next)
                .map_err(|_| FormatError::InvalidArchive("parity count overflow"));
        }
        parity = next;
    }
    Err(FormatError::InvalidArchive(
        "parity calculation did not converge",
    ))
}

fn ceil_div_u64(numerator: u64, denominator: u64) -> Result<u64, FormatError> {
    if denominator == 0 {
        return Err(FormatError::InvalidArchive("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .ok_or(FormatError::InvalidArchive("ceiling division overflow"))
        .map(|value| value / denominator)
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

fn metadata_limits(crypto_header: &CryptoHeaderFixed) -> MetadataLimits {
    MetadataLimits {
        block_size: crypto_header.block_size,
        max_path_length: crypto_header.max_path_length,
        max_payload_data_shards: crypto_header.fec_data_shards,
        max_payload_parity_shards: crypto_header.fec_parity_shards,
        max_index_data_shards: crypto_header.index_fec_data_shards,
        max_index_parity_shards: crypto_header.index_fec_parity_shards,
        max_index_root_data_shards: crypto_header.index_root_fec_data_shards,
        max_index_root_parity_shards: crypto_header.index_root_fec_parity_shards,
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
    tar_len: u64,
) -> Result<(), FormatError> {
    let mut ranges = Vec::with_capacity(extents.len());
    for (start, len) in extents {
        let end = checked_u64_add(*start, *len, "FileEntry")?;
        if end > tar_len {
            return Err(FormatError::InvalidArchive(
                "FileEntry extent exceeds IndexRoot tar_total_size",
            ));
        }
        ranges.push((*start, end));
    }
    validate_exact_coverage_ranges_u64(
        &mut ranges,
        tar_len,
        "FileEntry extents do not cover tar stream exactly",
    )
}

fn add_expected_directory_hint_rows(
    map: &mut DirectoryHintMap,
    shard_row_index: u32,
    path: &[u8],
    kind: TarEntryKind,
) {
    map.entry(Vec::new()).or_default().insert(shard_row_index);
    for (idx, byte) in path.iter().enumerate() {
        if *byte == b'/' {
            map.entry(path[..idx].to_vec())
                .or_default()
                .insert(shard_row_index);
        }
    }
    if kind == TarEntryKind::Directory {
        map.entry(path.to_vec())
            .or_default()
            .insert(shard_row_index);
    }
}

fn validate_directory_hint_tables_against_expected(
    tables: &[DirectoryHintTable],
    expected: &DirectoryHintMap,
) -> Result<(), FormatError> {
    let mut actual = Vec::new();
    let mut previous_key: Option<([u8; 8], Vec<u8>)> = None;

    for table in tables {
        for entry_index in 0..table.entries.len() {
            let path = table
                .entry_path(entry_index)
                .ok_or(FormatError::InvalidArchive(
                    "DirectoryHintEntry path is missing",
                ))?;
            let key = (hash_prefix(path), path.to_vec());
            if let Some(previous) = &previous_key {
                if previous >= &key {
                    return Err(FormatError::InvalidArchive(
                        "DirectoryHintEntry rows are not globally sorted",
                    ));
                }
            }
            previous_key = Some(key);

            let rows =
                table
                    .shard_rows_for_entry(entry_index)
                    .ok_or(FormatError::InvalidArchive(
                        "DirectoryHintEntry shard rows are missing",
                    ))?;
            actual.push((path.to_vec(), rows.to_vec()));
        }
    }

    if actual != sorted_directory_hint_rows(expected) {
        return Err(FormatError::InvalidArchive(
            "directory hint map does not match decoded files",
        ));
    }
    Ok(())
}

fn sorted_directory_hint_rows(map: &DirectoryHintMap) -> Vec<(Vec<u8>, Vec<u32>)> {
    let mut rows = map
        .iter()
        .map(|(path, shard_rows)| {
            (
                path.clone(),
                shard_rows.iter().copied().collect::<Vec<u32>>(),
            )
        })
        .collect::<Vec<_>>();
    rows.sort_by(|(left_path, _), (right_path, _)| {
        hash_prefix(left_path)
            .cmp(&hash_prefix(right_path))
            .then_with(|| left_path.cmp(right_path))
    });
    rows
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

fn validate_exact_coverage_ranges_u64(
    ranges: &mut [(u64, u64)],
    expected_end: u64,
    reason: &'static str,
) -> Result<(), FormatError> {
    ranges.sort_unstable();
    let mut cursor = 0u64;
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

fn observed_archive_size(sizes: impl IntoIterator<Item = u64>) -> Result<u64, FormatError> {
    sizes.into_iter().try_fold(0u64, |sum, size| {
        sum.checked_add(size).ok_or(FormatError::InvalidArchive(
            "observed archive size overflow",
        ))
    })
}

fn total_extraction_size_cap(options: ReaderOptions, observed_archive_bytes: u64) -> u64 {
    options
        .max_total_extraction_size
        .min(observed_archive_bytes.saturating_mul(10))
}

fn utf8_path(bytes: &[u8]) -> Result<String, FormatError> {
    std::str::from_utf8(bytes)
        .map(|path| path.to_owned())
        .map_err(|_| FormatError::UnsafeArchivePath)
}

#[cfg(test)]
fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
    use crate::compression::compress_zstd_frame;
    use crate::crypto::{compute_hmac, encrypt_padded_aead_object};
    use crate::format::{
        AeadAlgo, CompressionAlgo, FecAlgo, KdfAlgo, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION,
        VOLUME_FORMAT_REV,
    };
    use crate::metadata::{
        DirectoryHintEntry, DirectoryHintTableHeader, IndexRootHeader, IndexShardHeader,
        ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
    };
    use crate::writer::{write_archive, write_archive_with_dictionary, RegularFile, WriterOptions};

    fn master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x42; 32]).unwrap()
    }

    fn dictionary() -> &'static [u8] {
        b"dir/dict.txt common words common words common words dictionary payload"
    }

    fn single_stream_options() -> WriterOptions {
        WriterOptions {
            stripe_width: 1,
            volume_loss_tolerance: 0,
            ..WriterOptions::default()
        }
    }

    #[test]
    fn opens_lists_verifies_and_extracts_one_file_archive() {
        let archive = write_archive(
            &[RegularFile::new("dir/hello.txt", b"hello m7")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/hello.txt".to_string(),
                file_data_size: 8,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: 0,
                diagnostics: Vec::new(),
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
    fn safe_extract_writes_regular_file_under_root() {
        let archive = write_archive(
            &[RegularFile::new("dir/hello.txt", b"safe m8")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();

        opened
            .extract_file_to(
                "dir/hello.txt",
                tmp.path(),
                SafeExtractionOptions::default(),
            )
            .unwrap()
            .unwrap();

        assert_eq!(
            std::fs::read(tmp.path().join("dir").join("hello.txt")).unwrap(),
            b"safe m8"
        );
    }

    #[test]
    fn safe_extract_rejects_overwriting_existing_file_by_default() {
        let archive = write_archive(
            &[RegularFile::new("hello.txt", b"new")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("hello.txt"), b"old").unwrap();

        assert_eq!(
            opened
                .extract_file_to("hello.txt", tmp.path(), SafeExtractionOptions::default())
                .unwrap_err(),
            FormatError::UnsafeOverwrite
        );
        assert_eq!(std::fs::read(tmp.path().join("hello.txt")).unwrap(), b"old");
    }

    #[test]
    fn opens_and_verifies_empty_archive() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert!(opened.list_files().unwrap().is_empty());
        opened.verify().unwrap();
    }

    #[test]
    fn default_reader_options_allow_v36_trailing_garbage_scan() {
        let archive = write_archive(
            &[RegularFile::new("garbage-tolerant.txt", b"still intact")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut with_trailing_garbage = archive.bytes.clone();
        with_trailing_garbage.extend_from_slice(b"ignored trailing bytes");

        let opened = open_archive(&with_trailing_garbage, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("garbage-tolerant.txt").unwrap(),
            Some(b"still intact".to_vec())
        );
    }

    #[test]
    fn rejects_wrong_key_before_metadata_release() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
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
            single_stream_options(),
        )
        .unwrap()
        .bytes;
        let volume = VolumeHeader::parse(&archive[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = VOLUME_HEADER_LEN + usize::try_from(volume.crypto_header_length).unwrap();
        let crypto = CryptoHeader::parse(
            &archive[VOLUME_HEADER_LEN..crypto_end],
            volume.crypto_header_length,
        )
        .unwrap();
        let block_size = crypto.fixed.block_size as usize;
        archive[crypto_end + 16] ^= 1;
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
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "same.txt".to_string(),
                file_data_size: 5,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: 0,
                diagnostics: Vec::new(),
            }]
        );
        assert_eq!(
            opened.extract_file("same.txt").unwrap(),
            Some(b"newer".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn extract_file_does_not_decrypt_unselected_payload_envelope() {
        // This fixture corrupts only the unselected envelope, proving selected
        // extraction does not decrypt unrelated payload envelopes.
        let (mut opened, broken_payload_block) = multi_envelope_reader_fixture();
        corrupt_payload_record(&mut opened.blocks, broken_payload_block);

        assert_eq!(
            opened.extract_file("healthy.txt").unwrap(),
            Some(b"healthy payload\n".to_vec())
        );
        assert_eq!(
            opened.extract_file("broken.txt").unwrap_err(),
            FormatError::AeadFailure
        );
        assert_eq!(opened.verify().unwrap_err(), FormatError::AeadFailure);
    }

    #[test]
    fn bootstrap_sidecar_opens_lists_verifies_and_extracts() {
        let archive = write_archive(
            &[RegularFile::new("dir/sidecar.txt", b"hello sidecar")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive_with_bootstrap_sidecar(
            &archive.bytes,
            &archive.bootstrap_sidecar,
            &master_key(),
        )
        .unwrap();

        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/sidecar.txt".to_string(),
                file_data_size: 13,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: 0,
                diagnostics: Vec::new(),
            }]
        );
        assert_eq!(
            opened.extract_file("dir/sidecar.txt").unwrap(),
            Some(b"hello sidecar".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_archive_opens_lists_verifies_and_extracts_seekable() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dir/dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(opened.crypto_header.has_dictionary, 1);
        assert!(opened.index_root.header.dictionary_data_block_count > 0);
        assert_eq!(
            opened.list_files().unwrap(),
            vec![ArchiveEntry {
                path: "dir/dict.txt".to_string(),
                file_data_size: 44,
                kind: TarEntryKind::Regular,
                mode: 0o644,
                mtime: 0,
                diagnostics: Vec::new(),
            }]
        );
        assert_eq!(
            opened.extract_file("dir/dict.txt").unwrap(),
            Some(b"common words common words dictionary payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_object_tamper_fails_before_payload_decompression() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dir/dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = VOLUME_HEADER_LEN + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let dictionary_offset =
            crypto_end + opened.index_root.header.dictionary_first_block as usize * record_len;

        let mut tampered = archive.bytes.clone();
        tampered[dictionary_offset + 16] ^= 0x01;
        let crc_offset = dictionary_offset + 16 + opened.crypto_header.block_size as usize;
        let crc = crc32c::crc32c(&tampered[dictionary_offset..crc_offset]);
        tampered[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());

        assert_eq!(
            open_archive(&tampered, &master_key()).unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn dictionary_archive_bootstraps_from_sidecar_for_non_seekable_open() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dict-sidecar.txt",
                b"common words common words sidecar payload",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_non_seekable_archive(
            &archive.bytes,
            &master_key(),
            Some(&archive.bootstrap_sidecar),
        )
        .unwrap();

        assert_eq!(
            opened.extract_file("dict-sidecar.txt").unwrap(),
            Some(b"common words common words sidecar payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn bootstrap_sidecar_treats_crc_failed_payload_block_as_erasure() {
        let archive = write_archive(
            &[RegularFile::new(
                "sidecar-erasure.txt",
                b"repair through sidecar",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_first_block_record_payload(&mut corrupted);

        let opened = open_archive_with_bootstrap_sidecar(
            &corrupted,
            &archive.bootstrap_sidecar,
            &master_key(),
        )
        .unwrap();
        assert_eq!(
            opened.extract_file("sidecar-erasure.txt").unwrap(),
            Some(b"repair through sidecar".to_vec())
        );
    }

    #[test]
    fn extraction_rejects_logical_payload_above_total_size_cap() {
        let archive = write_archive(
            &[RegularFile::new("cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut options = ReaderOptions::default();
        options.max_total_extraction_size = 3;
        let opened =
            OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

        assert_eq!(
            opened.extract_file("cap.txt").unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn verify_does_not_apply_extraction_payload_cap() {
        let archive = write_archive(
            &[RegularFile::new("verify-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut options = ReaderOptions::default();
        options.max_total_extraction_size = 3;
        let opened =
            OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("verify-cap.txt").unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn verify_streams_past_legacy_in_memory_tar_cap() {
        let data = vec![0x5a; 4096];
        let archive = write_archive(
            &[RegularFile::new("verify-large.txt", &data)],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut options = ReaderOptions::default();
        options.max_verify_tar_size = 1;
        let opened =
            OpenedArchive::open_with_options(&archive.bytes, &master_key(), options).unwrap();

        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_sidecar_requires_dictionary_record_section() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new("dict-missing.txt", b"common words")],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let header = BootstrapSidecarHeader::parse(
            &archive.bootstrap_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN],
        )
        .unwrap();
        let mut missing_dictionary =
            archive.bootstrap_sidecar[..header.dictionary_records_offset as usize].to_vec();
        rewrite_sidecar_header(&mut missing_dictionary, &master_key(), |header| {
            header.flags &= !0x04;
            header.dictionary_records_offset = 0;
            header.dictionary_records_length = 0;
        });

        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &missing_dictionary, &master_key())
                .unwrap_err(),
            FormatError::ReaderUnsupported("dictionary bootstrap required")
        );
    }

    #[test]
    fn dictionary_sidecar_records_are_validated_against_dictionary_extent() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new("dict-sidecar-kind.txt", b"common words")],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();

        let mut wrong_kind = archive.bootstrap_sidecar.clone();
        mutate_sidecar_dictionary_record(&mut wrong_kind, 0, |record| {
            record.kind = BlockKind::IndexRootData;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_kind, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong kind")
        );

        let mut wrong_last = archive.bootstrap_sidecar.clone();
        mutate_sidecar_dictionary_record(&mut wrong_last, 0, |record| {
            record.flags = 0;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_last, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong last-data flag")
        );
    }

    #[test]
    fn non_seekable_random_access_requires_sidecar() {
        let archive = write_archive(
            &[RegularFile::new("file.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), None).unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable random access requires a bootstrap sidecar"
            )
        );
        assert!(open_non_seekable_archive(
            &archive.bytes,
            &master_key(),
            Some(&archive.bootstrap_sidecar)
        )
        .is_ok());
    }

    #[test]
    fn sequential_extracts_dictionary_free_tar_stream() {
        let archive = write_archive(
            &[RegularFile::new("seq.txt", b"streaming")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        let tar_stream = sequential_extract_tar_stream(&archive.bytes, &master_key()).unwrap();
        let member = parse_tar_member_group(&tar_stream, 4096).unwrap();
        assert_eq!(member.path, b"seq.txt");
        assert_eq!(member.data, b"streaming");
    }

    #[test]
    fn sequential_rejects_logical_payload_above_total_size_cap() {
        let archive = write_archive(
            &[RegularFile::new("seq-cap.txt", b"payload")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut options = ReaderOptions::default();
        options.max_total_extraction_size = 3;

        assert_eq!(
            sequential_extract_tar_stream_with_options(&archive.bytes, &master_key(), options)
                .unwrap_err(),
            FormatError::ReaderUnsupported("total extraction size exceeds configured cap")
        );
    }

    #[test]
    fn sequential_repairs_crc_failed_payload_data_when_parity_is_guaranteed() {
        let archive = write_archive(
            &[RegularFile::new("seq-erasure.txt", b"stream repair")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_first_block_record_payload(&mut corrupted);

        let tar_stream = sequential_extract_tar_stream(&corrupted, &master_key()).unwrap();
        let member = parse_tar_member_group(&tar_stream, 4096).unwrap();
        assert_eq!(member.path, b"seq-erasure.txt");
        assert_eq!(member.data, b"stream repair");
    }

    #[test]
    fn sequential_rejects_crc_failed_payload_data_without_guaranteed_parity() {
        let archive = write_archive(
            &[RegularFile::new("seq-no-parity.txt", b"no repair")],
            &master_key(),
            WriterOptions {
                bit_rot_buffer_pct: 0,
                fec_parity_shards: 0,
                index_fec_parity_shards: 0,
                index_root_fec_parity_shards: 0,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_first_block_record_payload(&mut corrupted);

        assert_eq!(
            sequential_extract_tar_stream(&corrupted, &master_key()).unwrap_err(),
            FormatError::BadCrc {
                structure: "BlockRecord"
            }
        );
    }

    #[test]
    fn sequential_rejects_when_terminal_authentication_fails() {
        let archive = write_archive(
            &[RegularFile::new("seq.txt", b"streaming")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        let trailer_hmac_offset = corrupted.len() - VOLUME_TRAILER_LEN + TRAILER_HMAC_COVERED_LEN;
        corrupted[trailer_hmac_offset] ^= 0x01;

        assert_eq!(
            sequential_extract_tar_stream(&corrupted, &master_key()).unwrap_err(),
            FormatError::HmacMismatch {
                structure: "VolumeTrailer"
            }
        );
    }

    #[test]
    fn sequential_zstd_stream_rejects_skippable_frame_segments() {
        let skippable = [0x50, 0x2a, 0x4d, 0x18, 0, 0, 0, 0];
        let mut output = Vec::new();

        assert_eq!(
            decode_concatenated_zstd_frames(&skippable, None, &mut output).unwrap_err(),
            FormatError::NotStandardZstdFrame
        );
        assert!(output.is_empty());
    }

    #[test]
    fn bootstrap_sidecar_rejects_bad_flags_and_trailing_bytes() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut bad_flags = archive.bootstrap_sidecar.clone();
        rewrite_sidecar_header(&mut bad_flags, &master_key(), |header| {
            header.flags |= 0x08;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &bad_flags, &master_key())
                .unwrap_err(),
            FormatError::UnknownBootstrapSidecarFlags(0x0b)
        );

        let mut trailing = archive.bootstrap_sidecar.clone();
        trailing.push(0);
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &trailing, &master_key())
                .unwrap_err(),
            FormatError::NonCanonicalBootstrapSidecarLayout
        );
    }

    #[test]
    fn bootstrap_sidecar_rejects_bad_manifest_footer_semantics() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut wrong_volume = archive.bootstrap_sidecar.clone();
        mutate_sidecar_manifest(&mut wrong_volume, &master_key(), |footer| {
            footer.volume_index = 1;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_volume, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar ManifestFooter volume_index must be zero")
        );

        let mut non_authoritative = archive.bootstrap_sidecar.clone();
        mutate_sidecar_manifest(&mut non_authoritative, &master_key(), |footer| {
            footer.is_authoritative = 0;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &non_authoritative, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar ManifestFooter is not authoritative")
        );
    }

    #[test]
    fn bootstrap_sidecar_rejects_dictionary_section_for_no_dictionary_archive() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut with_dictionary = archive.bootstrap_sidecar.clone();
        let header =
            BootstrapSidecarHeader::parse(&with_dictionary[..BOOTSTRAP_SIDECAR_HEADER_LEN])
                .unwrap();
        let record_len = sidecar_record_len(&with_dictionary);
        let first_record = header.index_root_records_offset as usize;
        let copied_record = with_dictionary[first_record..first_record + record_len].to_vec();
        let dictionary_offset = with_dictionary.len() as u64;
        with_dictionary.extend_from_slice(&copied_record);
        rewrite_sidecar_header(&mut with_dictionary, &master_key(), |header| {
            header.flags |= 0x04;
            header.dictionary_records_offset = dictionary_offset;
            header.dictionary_records_length = record_len as u64;
        });

        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &with_dictionary, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "bootstrap sidecar has dictionary records while has_dictionary is false"
            )
        );
    }

    #[test]
    fn bootstrap_sidecar_rejects_missing_duplicate_wrong_kind_and_wrong_last_flag() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut missing = archive.bootstrap_sidecar.clone();
        let record_len = sidecar_record_len(&missing);
        let new_len = missing.len() - record_len;
        missing.truncate(new_len);
        rewrite_sidecar_header(&mut missing, &master_key(), |header| {
            header.index_root_records_length -= record_len as u64;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &missing, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "sidecar BlockRecord section does not match declared extent"
            )
        );

        let mut duplicate = archive.bootstrap_sidecar.clone();
        mutate_sidecar_index_record(&mut duplicate, 1, |record| {
            record.block_index -= 1;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &duplicate, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "sidecar BlockRecord section has missing or duplicate blocks"
            )
        );

        let mut misordered = archive.bootstrap_sidecar.clone();
        swap_sidecar_index_records(&mut misordered, 0, 1);
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &misordered, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive(
                "sidecar BlockRecord section has missing or duplicate blocks"
            )
        );

        let mut wrong_kind = archive.bootstrap_sidecar.clone();
        mutate_sidecar_index_record(&mut wrong_kind, 0, |record| {
            record.kind = BlockKind::PayloadData;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_kind, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong kind")
        );

        let mut wrong_last = archive.bootstrap_sidecar.clone();
        mutate_sidecar_index_record(&mut wrong_last, 0, |record| {
            record.flags = 0;
        });
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &wrong_last, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("sidecar BlockRecord section has wrong last-data flag")
        );
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
    fn expected_directory_hint_rows_include_ancestors_and_directory_entries() {
        let mut map = DirectoryHintMap::new();
        add_expected_directory_hint_rows(&mut map, 2, b"foo/bar/baz.txt", TarEntryKind::Regular);
        add_expected_directory_hint_rows(&mut map, 4, b"foo/bar", TarEntryKind::Directory);

        assert_eq!(map.get(&Vec::new()), Some(&BTreeSet::from([2, 4])));
        assert_eq!(map.get(&b"foo".to_vec()), Some(&BTreeSet::from([2, 4])));
        assert_eq!(map.get(&b"foo/bar".to_vec()), Some(&BTreeSet::from([2, 4])));
        assert!(!map.contains_key(&b"foo/bar/baz.txt".to_vec()));
        assert!(!map.contains_key(&b"foobar".to_vec()));
    }

    #[test]
    fn directory_hint_validation_requires_exact_global_map() {
        let mut expected = DirectoryHintMap::new();
        add_expected_directory_hint_rows(&mut expected, 0, b"foo/bar.txt", TarEntryKind::Regular);
        add_expected_directory_hint_rows(&mut expected, 1, b"foo", TarEntryKind::Directory);
        let rows = sorted_directory_hint_rows(&expected);
        let table = directory_hint_table_from_rows(7, &rows, 2);

        validate_directory_hint_tables_against_expected(&[table.clone()], &expected).unwrap();

        let mut incomplete = expected.clone();
        incomplete.get_mut(&b"foo".to_vec()).unwrap().remove(&1);
        assert_eq!(
            validate_directory_hint_tables_against_expected(&[table], &incomplete).unwrap_err(),
            FormatError::InvalidArchive("directory hint map does not match decoded files")
        );
    }

    #[test]
    fn directory_hint_validation_rejects_global_order_mismatch() {
        let mut expected = DirectoryHintMap::new();
        expected.insert(Vec::new(), BTreeSet::from([0]));
        expected.insert(b"alpha".to_vec(), BTreeSet::from([0]));
        let rows = sorted_directory_hint_rows(&expected);
        let first = directory_hint_table_from_rows(8, &rows[..1], 1);
        let second = directory_hint_table_from_rows(9, &rows[1..], 1);

        assert_eq!(
            validate_directory_hint_tables_against_expected(&[second, first], &expected)
                .unwrap_err(),
            FormatError::InvalidArchive("DirectoryHintEntry rows are not globally sorted")
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

    #[test]
    fn object_extent_rejects_parity_below_recoverability_requirement() {
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
            stripe_width: 2,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        };
        let extent = ObjectExtent {
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
        };

        assert_eq!(
            validate_object_extent(extent, &crypto_header, 1, 1).unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object has insufficient parity for recovery settings"
            )
        );
    }

    #[test]
    fn opens_complete_multi_volume_archive() {
        let files = [RegularFile::new("alpha.txt", b"hello from volume stripes")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        assert_eq!(archive.volumes.len(), 2);

        let volume_refs = archive
            .volumes
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();

        assert_eq!(opened.volume_header.stripe_width, 2);
        assert_eq!(opened.list_files().unwrap()[0].path, "alpha.txt");
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"hello from volume stripes".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn recovers_from_one_missing_volume_when_parity_allows() {
        let files = [RegularFile::new("alpha.txt", b"recover me")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        let recovered =
            open_archive_volumes(&[archive.volumes[1].as_slice()], &master_key()).unwrap();
        assert_eq!(
            recovered.extract_file("alpha.txt").unwrap(),
            Some(b"recover me".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn recovers_from_crc_corrupted_block_when_parity_allows() {
        let files = [RegularFile::new("alpha.txt", b"repair corrupt block")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        corrupt_first_block_record_payload(&mut volumes[0]);

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let recovered = open_archive_volumes(&volume_refs, &master_key()).unwrap();

        assert_eq!(
            recovered.extract_file("alpha.txt").unwrap(),
            Some(b"repair corrupt block".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn rejects_block_record_at_wrong_stripe_position() {
        let files = [RegularFile::new("alpha.txt", b"wrong stripe")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        mutate_first_block_record(&mut volumes[0], |record| {
            record.block_index += 2;
        });

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        assert_eq!(
            open_archive_volumes(&volume_refs, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("BlockRecord index does not match volume position")
        );
    }

    #[test]
    fn rejects_duplicate_authenticated_volume_indexes() {
        let files = [RegularFile::new("alpha.txt", b"duplicates")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        assert_eq!(
            open_archive_volumes(
                &[archive.volumes[0].as_slice(), archive.volumes[0].as_slice()],
                &master_key()
            )
            .unwrap_err(),
            FormatError::InvalidArchive("duplicate authenticated volume index")
        );
    }

    fn directory_hint_table_from_rows(
        hint_shard_index: u64,
        rows: &[(Vec<u8>, Vec<u32>)],
        shard_count: u32,
    ) -> DirectoryHintTable {
        let mut entries = Vec::new();
        let mut shard_row_indexes = Vec::new();
        let mut string_pool = Vec::new();

        for (path, rows) in rows {
            let path_offset = if path.is_empty() {
                0
            } else {
                let offset = string_pool.len() as u64;
                string_pool.extend_from_slice(path);
                offset
            };
            let shard_list_start_index = shard_row_indexes.len() as u32;
            shard_row_indexes.extend_from_slice(rows);
            entries.push(DirectoryHintEntry {
                dir_hash: hash_prefix(path),
                path_offset,
                path_length: path.len() as u32,
                shard_list_start_index,
                shard_count: rows.len() as u32,
            });
        }

        let table_bytes =
            directory_hint_table_bytes(hint_shard_index, entries, shard_row_indexes, string_pool);
        let locating = DirectoryHintShardEntry {
            hint_shard_index,
            first_dir_hash: hash_prefix(&rows.first().unwrap().0),
            last_dir_hash: hash_prefix(&rows.last().unwrap().0),
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: table_bytes.len() as u32,
            entry_count: rows.len() as u64,
        };
        DirectoryHintTable::parse(
            &table_bytes,
            &locating,
            shard_count,
            MetadataLimits::default(),
        )
        .unwrap()
    }

    fn directory_hint_table_bytes(
        hint_shard_index: u64,
        entries: Vec<DirectoryHintEntry>,
        shard_row_indexes: Vec<u32>,
        string_pool: Vec<u8>,
    ) -> Vec<u8> {
        let header_len = DirectoryHintTableHeader {
            version: 1,
            hint_shard_index,
            entry_count: 0,
            entry_table_offset: 0,
            shard_list_offset: 0,
            string_pool_offset: 0,
            string_pool_size: 0,
        }
        .to_bytes()
        .len();
        let entry_len = entries
            .first()
            .map(|entry| entry.to_bytes().len())
            .unwrap_or(0);
        let shard_list_offset = if entries.is_empty() {
            0
        } else {
            header_len + entries.len() * entry_len
        };
        let string_pool_offset = if string_pool.is_empty() {
            0
        } else {
            shard_list_offset + shard_row_indexes.len() * 4
        };

        let header = DirectoryHintTableHeader {
            version: 1,
            hint_shard_index,
            entry_count: entries.len() as u64,
            entry_table_offset: if entries.is_empty() {
                0
            } else {
                header_len as u64
            },
            shard_list_offset: shard_list_offset as u64,
            string_pool_offset: string_pool_offset as u64,
            string_pool_size: string_pool.len() as u64,
        };

        let mut out = Vec::new();
        out.extend_from_slice(&header.to_bytes());
        for entry in entries {
            out.extend_from_slice(&entry.to_bytes());
        }
        for row in shard_row_indexes {
            out.extend_from_slice(&row.to_le_bytes());
        }
        out.extend_from_slice(&string_pool);
        out
    }

    fn corrupt_first_block_record_payload(volume: &mut [u8]) {
        let (record_offset, _) = first_block_record(volume);
        volume[record_offset + 16] ^= 0x55;
    }

    fn mutate_first_block_record(volume: &mut [u8], mutate: impl FnOnce(&mut BlockRecord)) {
        let (record_offset, record_len) = first_block_record(volume);
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record = BlockRecord::parse(
            &volume[record_offset..record_offset + record_len],
            block_size,
        )
        .unwrap();
        mutate(&mut record);
        volume[record_offset..record_offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn first_block_record(volume: &[u8]) -> (usize, usize) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_offset = crypto_end;
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        assert!(volume.len() >= record_offset + record_len);
        (record_offset, record_len)
    }

    fn rewrite_sidecar_header(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut BootstrapSidecarHeader),
    ) {
        let mut header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        mutate(&mut header);
        header.sidecar_hmac = [0u8; 32];
        let mut header_bytes = header.to_bytes();
        let subkeys =
            Subkeys::derive(master_key, &header.archive_uuid, &header.session_id).unwrap();
        header.sidecar_hmac = compute_hmac(
            HmacDomain::BootstrapSidecar,
            &subkeys.mac_key,
            &header.archive_uuid,
            &header.session_id,
            &header_bytes[..SIDECAR_HMAC_COVERED_LEN],
        );
        header_bytes = header.to_bytes();
        sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header_bytes);
    }

    fn mutate_sidecar_manifest(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut ManifestFooter),
    ) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let offset = header.manifest_footer_offset as usize;
        let mut footer =
            ManifestFooter::parse(&sidecar[offset..offset + MANIFEST_FOOTER_LEN]).unwrap();
        mutate(&mut footer);
        footer.manifest_hmac = [0u8; 32];
        let mut footer_bytes = footer.to_bytes();
        let subkeys =
            Subkeys::derive(master_key, &footer.archive_uuid, &footer.session_id).unwrap();
        footer.manifest_hmac = compute_hmac(
            HmacDomain::ManifestFooter,
            &subkeys.mac_key,
            &footer.archive_uuid,
            &footer.session_id,
            &footer_bytes[..MANIFEST_HMAC_COVERED_LEN],
        );
        footer_bytes = footer.to_bytes();
        sidecar[offset..offset + MANIFEST_FOOTER_LEN].copy_from_slice(&footer_bytes);
    }

    fn mutate_sidecar_index_record(
        sidecar: &mut [u8],
        record_index: usize,
        mutate: impl FnOnce(&mut BlockRecord),
    ) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let record_len = sidecar_record_len(sidecar);
        let offset = header.index_root_records_offset as usize + record_index * record_len;
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record =
            BlockRecord::parse(&sidecar[offset..offset + record_len], block_size).unwrap();
        mutate(&mut record);
        sidecar[offset..offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn mutate_sidecar_dictionary_record(
        sidecar: &mut [u8],
        record_index: usize,
        mutate: impl FnOnce(&mut BlockRecord),
    ) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let record_len = sidecar_record_len(sidecar);
        let offset = header.dictionary_records_offset as usize + record_index * record_len;
        let block_size = record_len - BLOCK_RECORD_FRAMING_LEN;
        let mut record =
            BlockRecord::parse(&sidecar[offset..offset + record_len], block_size).unwrap();
        mutate(&mut record);
        sidecar[offset..offset + record_len].copy_from_slice(&record.to_bytes());
    }

    fn swap_sidecar_index_records(sidecar: &mut [u8], left: usize, right: usize) {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let record_len = sidecar_record_len(sidecar);
        let left_offset = header.index_root_records_offset as usize + left * record_len;
        let right_offset = header.index_root_records_offset as usize + right * record_len;
        for idx in 0..record_len {
            sidecar.swap(left_offset + idx, right_offset + idx);
        }
    }

    fn sidecar_record_len(sidecar: &[u8]) -> usize {
        let header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let footer_offset = header.manifest_footer_offset as usize;
        let footer =
            ManifestFooter::parse(&sidecar[footer_offset..footer_offset + MANIFEST_FOOTER_LEN])
                .unwrap();
        let index_record_count = footer.index_root_data_block_count as usize
            + footer.index_root_parity_block_count as usize;
        header.index_root_records_length as usize / index_record_count
    }

    #[derive(Debug)]
    struct TestObject {
        extent: ObjectExtent,
        records: Vec<BlockRecord>,
    }

    #[derive(Debug)]
    struct TestFileMeta {
        path: Vec<u8>,
        frame_index: u64,
        tar_stream_offset: u64,
        member_group_size: u64,
        file_data_size: u64,
    }

    fn multi_envelope_reader_fixture() -> (OpenedArchive, u64) {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;
        let mut blocks = BTreeMap::new();

        let healthy = test_member(b"healthy.txt", b"healthy payload\n");
        let broken = test_member(b"broken.txt", b"broken payload\n");
        let tar_stream = [healthy.as_slice(), broken.as_slice()].concat();

        let healthy_frame = compress_zstd_frame(&healthy, 1).unwrap();
        let broken_frame = compress_zstd_frame(&broken, 1).unwrap();

        let healthy_payload = encrypt_test_object(
            &healthy_frame,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            0,
            BlockKind::PayloadData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        let broken_payload = encrypt_test_object(
            &broken_frame,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            1,
            BlockKind::PayloadData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        let broken_payload_block = broken_payload.extent.first_block_index;
        insert_records(&mut blocks, &healthy_payload.records);
        insert_records(&mut blocks, &broken_payload.records);

        let frames = vec![
            FrameEntry {
                frame_index: 0,
                envelope_index: 0,
                offset_in_envelope: 0,
                compressed_size: healthy_frame.len() as u32,
                decompressed_size: healthy.len() as u32,
                flags: 0x0000_0003,
                tar_stream_offset: 0,
            },
            FrameEntry {
                frame_index: 1,
                envelope_index: 1,
                offset_in_envelope: 0,
                compressed_size: broken_frame.len() as u32,
                decompressed_size: broken.len() as u32,
                flags: 0x0000_0003,
                tar_stream_offset: healthy.len() as u64,
            },
        ];
        let envelopes = vec![
            EnvelopeEntry {
                envelope_index: 0,
                first_block_index: healthy_payload.extent.first_block_index,
                data_block_count: healthy_payload.extent.data_block_count,
                parity_block_count: 0,
                encrypted_size: healthy_payload.extent.encrypted_size,
                plaintext_size: healthy_frame.len() as u32,
                first_frame_index: 0,
                frame_count: 1,
            },
            EnvelopeEntry {
                envelope_index: 1,
                first_block_index: broken_payload.extent.first_block_index,
                data_block_count: broken_payload.extent.data_block_count,
                parity_block_count: 0,
                encrypted_size: broken_payload.extent.encrypted_size,
                plaintext_size: broken_frame.len() as u32,
                first_frame_index: 1,
                frame_count: 1,
            },
        ];
        let files = vec![
            TestFileMeta {
                path: b"healthy.txt".to_vec(),
                frame_index: 0,
                tar_stream_offset: 0,
                member_group_size: healthy.len() as u64,
                file_data_size: b"healthy payload\n".len() as u64,
            },
            TestFileMeta {
                path: b"broken.txt".to_vec(),
                frame_index: 1,
                tar_stream_offset: healthy.len() as u64,
                member_group_size: broken.len() as u64,
                file_data_size: b"broken payload\n".len() as u64,
            },
        ];

        let (index_shard_plaintext, first_path_hash, last_path_hash) =
            build_test_index_shard(&files, &frames, &envelopes);
        let index_shard = encrypt_test_object(
            &compress_zstd_frame(&index_shard_plaintext, 1).unwrap(),
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            0,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &index_shard.records);

        let shard_entry = ShardEntry {
            shard_index: 0,
            first_block_index: index_shard.extent.first_block_index,
            data_block_count: index_shard.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: index_shard.extent.encrypted_size,
            decompressed_size: index_shard_plaintext.len() as u32,
            file_count: files.len() as u32,
            first_path_hash,
            last_path_hash,
        };
        let mut root_header = IndexRootHeader::empty();
        root_header.frame_count = frames.len() as u64;
        root_header.envelope_count = envelopes.len() as u64;
        root_header.file_count = files.len() as u64;
        root_header.payload_block_count = healthy_payload.extent.data_block_count as u64
            + broken_payload.extent.data_block_count as u64;
        root_header.tar_total_size = tar_stream.len() as u64;
        root_header.content_sha256 = sha256_bytes(&tar_stream);
        let index_root = IndexRoot {
            header: root_header,
            shards: vec![shard_entry],
            directory_hint_shards: Vec::new(),
        };

        let index_root_plaintext = index_root.to_bytes();
        let index_root_object = encrypt_test_object(
            &compress_zstd_frame(&index_root_plaintext, 1).unwrap(),
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &index_root_object.records);

        let archive_uuid = volume_header.archive_uuid;
        let session_id = volume_header.session_id;
        let opened = OpenedArchive {
            options: ReaderOptions::default(),
            observed_archive_bytes: 1_000_000,
            subkeys,
            blocks,
            volume_header,
            crypto_header,
            manifest_footer: ManifestFooter {
                archive_uuid,
                session_id,
                volume_index: 0,
                is_authoritative: 1,
                total_volumes: 1,
                index_root_first_block: index_root_object.extent.first_block_index,
                index_root_data_block_count: index_root_object.extent.data_block_count,
                index_root_parity_block_count: 0,
                index_root_encrypted_size: index_root_object.extent.encrypted_size,
                index_root_decompressed_size: index_root_plaintext.len() as u32,
                manifest_hmac: [0u8; 32],
            },
            volume_trailer: VolumeTrailer {
                archive_uuid,
                session_id,
                volume_index: 0,
                block_count: next_block_index,
                bytes_written: 0,
                manifest_footer_offset: 0,
                manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
                closed_at_ns: 0,
                trailer_hmac: [0u8; 32],
            },
            index_root,
            payload_dictionary: None,
        };
        (opened, broken_payload_block)
    }

    fn test_volume_header() -> VolumeHeader {
        VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index: 0,
            stripe_width: 1,
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: CRYPTO_HEADER_FIXED_LEN as u32,
            header_crc32c: 0,
        }
    }

    fn test_crypto_header() -> CryptoHeaderFixed {
        CryptoHeaderFixed {
            length: CRYPTO_HEADER_FIXED_LEN as u32,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 4096,
            envelope_target_size: 8192,
            block_size: 4096,
            fec_data_shards: 4,
            fec_parity_shards: 0,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 0,
            index_root_fec_data_shards: 4,
            index_root_fec_parity_shards: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        }
    }

    fn encrypt_test_object(
        plaintext: &[u8],
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        next_block_index: &mut u64,
        crypto_header: &CryptoHeaderFixed,
        volume_header: &VolumeHeader,
    ) -> TestObject {
        let block_size = crypto_header.block_size as usize;
        let encrypted = encrypt_padded_aead_object(
            crypto_header.aead_algo,
            key,
            nonce_seed,
            domain,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            counter,
            block_size,
            plaintext,
        )
        .unwrap();
        assert_eq!(encrypted.len() % block_size, 0);

        let first_block_index = *next_block_index;
        let data_block_count = encrypted.len() / block_size;
        let records = encrypted
            .chunks(block_size)
            .enumerate()
            .map(|(index, payload)| BlockRecord {
                block_index: first_block_index + index as u64,
                kind: data_kind,
                flags: if index + 1 == data_block_count {
                    0x01
                } else {
                    0
                },
                payload: payload.to_vec(),
                record_crc32c: 0,
            })
            .collect::<Vec<_>>();
        *next_block_index += data_block_count as u64;

        TestObject {
            extent: ObjectExtent {
                first_block_index,
                data_block_count: data_block_count as u32,
                parity_block_count: 0,
                encrypted_size: encrypted.len() as u32,
            },
            records,
        }
    }

    fn insert_records(blocks: &mut BTreeMap<u64, BlockRecord>, records: &[BlockRecord]) {
        for record in records {
            assert!(blocks.insert(record.block_index, record.clone()).is_none());
        }
    }

    fn corrupt_payload_record(blocks: &mut BTreeMap<u64, BlockRecord>, block_index: u64) {
        let record = blocks.get_mut(&block_index).unwrap();
        assert_eq!(record.kind, BlockKind::PayloadData);
        record.payload[0] ^= 0x55;
    }

    fn build_test_index_shard(
        files: &[TestFileMeta],
        frames: &[FrameEntry],
        envelopes: &[EnvelopeEntry],
    ) -> (Vec<u8>, [u8; 8], [u8; 8]) {
        let mut sorted = files
            .iter()
            .map(|file| (hash_prefix(&file.path), file))
            .collect::<Vec<_>>();
        sorted.sort_by(|left, right| {
            (left.0, left.1.path.as_slice(), left.1.tar_stream_offset).cmp(&(
                right.0,
                right.1.path.as_slice(),
                right.1.tar_stream_offset,
            ))
        });

        let mut string_pool = Vec::new();
        let mut file_entries = Vec::with_capacity(sorted.len());
        for (path_hash, file) in &sorted {
            let path_offset = string_pool.len() as u32;
            string_pool.extend_from_slice(&file.path);
            file_entries.push(FileEntry {
                path_hash: *path_hash,
                path_offset,
                path_length: file.path.len() as u32,
                first_frame_index: file.frame_index,
                frame_count: 1,
                offset_in_first_frame_plaintext: 0,
                tar_member_group_size: file.member_group_size,
                file_data_size: file.file_data_size,
                flags: 0,
            });
        }

        let header = IndexShardHeader {
            version: 1,
            shard_index: 0,
            file_count: file_entries.len() as u32,
            frame_count: frames.len() as u32,
            envelope_count: envelopes.len() as u32,
            file_table_offset: INDEX_SHARD_HEADER_LEN as u32,
            frame_table_offset: (INDEX_SHARD_HEADER_LEN + file_entries.len() * FILE_ENTRY_LEN)
                as u32,
            envelope_table_offset: (INDEX_SHARD_HEADER_LEN
                + file_entries.len() * FILE_ENTRY_LEN
                + frames.len() * FRAME_ENTRY_LEN) as u32,
            string_pool_offset: (INDEX_SHARD_HEADER_LEN
                + file_entries.len() * FILE_ENTRY_LEN
                + frames.len() * FRAME_ENTRY_LEN
                + envelopes.len() * ENVELOPE_ENTRY_LEN) as u32,
            string_pool_size: string_pool.len() as u32,
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header.to_bytes());
        for entry in &file_entries {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in frames {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        for entry in envelopes {
            bytes.extend_from_slice(&entry.to_bytes());
        }
        bytes.extend_from_slice(&string_pool);

        (bytes, sorted.first().unwrap().0, sorted.last().unwrap().0)
    }

    fn test_member(path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&test_tar_header(path, data.len() as u64));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
        out
    }

    fn test_tar_header(path: &[u8], size: u64) -> [u8; 512] {
        let mut header = [0u8; 512];
        header[..path.len()].copy_from_slice(path);
        write_test_tar_octal(&mut header[100..108], 0o644);
        write_test_tar_octal(&mut header[108..116], 0);
        write_test_tar_octal(&mut header[116..124], 0);
        write_test_tar_octal(&mut header[124..136], size);
        write_test_tar_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_test_tar_checksum(&mut header[148..156], checksum);
        header
    }

    fn write_test_tar_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn write_test_tar_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    fn padding_to_512(len: usize) -> usize {
        let remainder = len % 512;
        if remainder == 0 {
            0
        } else {
            512 - remainder
        }
    }
}
