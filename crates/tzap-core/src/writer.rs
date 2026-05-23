use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compression::{compress_zstd_frame, compress_zstd_frame_with_dictionary};
use crate::crypto::{
    aead_encrypt, build_aad, compute_hmac, derive_nonce, HmacDomain, KdfParams, MasterKey, Subkeys,
};
use crate::fec::encode_parity_gf16;
use crate::format::{
    AeadAlgo, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, BLOCK_RECORD_FRAMING_LEN,
    BOOTSTRAP_SIDECAR_HEADER_LEN, CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN,
    CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, MANIFEST_FOOTER_LEN, VOLUME_FORMAT_REV,
    VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, DirectoryHintEntry, DirectoryHintShardEntry,
    DirectoryHintTableHeader, EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexRootHeader,
    IndexShardHeader, ShardEntry, DIRECTORY_HINT_ENTRY_LEN, DIRECTORY_HINT_TABLE_LEN,
    ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
};
use crate::padding::suffix_pad_for_aead;
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CryptoHeaderFixed, ManifestFooter, VolumeHeader,
    VolumeTrailer,
};

const TAR_BLOCK_LEN: usize = 512;
const MAX_REED_SOLOMON_GF16_SHARDS: u64 = 65_535;
const MIN_BLOCK_SIZE: u32 = 4096;
const DEFAULT_BLOCK_SIZE: u32 = 64 * 1024;
const DEFAULT_CHUNK_SIZE: u32 = 256 * 1024;
const DEFAULT_ENVELOPE_TARGET_SIZE: u32 = 1024 * 1024;
const DEFAULT_FEC_DATA_SHARDS: u16 = 224;
const DEFAULT_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_INDEX_FEC_DATA_SHARDS: u16 = 16;
const DEFAULT_INDEX_FEC_PARITY_SHARDS: u16 = 1;
const MIN_INDEX_ROOT_FEC_DATA_SHARDS: u16 = 16;
const DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS: u16 = MIN_INDEX_ROOT_FEC_DATA_SHARDS;
const DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_STRIPE_WIDTH: u32 = 8;
const DEFAULT_VOLUME_LOSS_TOLERANCE: u8 = 1;
const DEFAULT_BIT_ROT_BUFFER_PCT: u8 = 5;
const DEFAULT_FILES_PER_INDEX_SHARD: usize = 10_000;
const DIRECTORY_HINT_REQUIRED_FILE_COUNT: usize = 100_000;
const MAX_FILES_PER_INDEX_SHARD: usize = 1_000_000;
const MAX_HASH_PREFIX_RUN_FILES: usize = 50_000;
const DEFAULT_DIRECTORY_HINT_ENTRIES_PER_SHARD: usize = 10_000;

fn should_emit_directory_hints(file_count: usize) -> bool {
    file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub block_size: u32,
    pub chunk_size: u32,
    pub envelope_target_size: u32,
    pub stripe_width: u32,
    pub volume_loss_tolerance: u8,
    pub bit_rot_buffer_pct: u8,
    pub zstd_level: i32,
    pub aead_algo: AeadAlgo,
    pub fec_data_shards: u16,
    pub fec_parity_shards: u16,
    pub index_fec_data_shards: u16,
    pub index_fec_parity_shards: u16,
    pub index_root_fec_data_shards: u16,
    pub index_root_fec_parity_shards: u16,
    pub max_path_length: u32,
    pub target_volume_size: Option<u64>,
    pub archive_uuid: Option<[u8; 16]>,
    pub session_id: Option<[u8; 16]>,
    pub closed_at_ns: i64,
}

impl Default for WriterOptions {
    fn default() -> Self {
        Self {
            block_size: DEFAULT_BLOCK_SIZE,
            chunk_size: DEFAULT_CHUNK_SIZE,
            envelope_target_size: DEFAULT_ENVELOPE_TARGET_SIZE,
            stripe_width: DEFAULT_STRIPE_WIDTH,
            volume_loss_tolerance: DEFAULT_VOLUME_LOSS_TOLERANCE,
            bit_rot_buffer_pct: DEFAULT_BIT_ROT_BUFFER_PCT,
            zstd_level: 3,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_data_shards: DEFAULT_FEC_DATA_SHARDS,
            fec_parity_shards: DEFAULT_FEC_PARITY_SHARDS,
            index_fec_data_shards: DEFAULT_INDEX_FEC_DATA_SHARDS,
            index_fec_parity_shards: DEFAULT_INDEX_FEC_PARITY_SHARDS,
            index_root_fec_data_shards: DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS,
            index_root_fec_parity_shards: DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS,
            max_path_length: 4096,
            target_volume_size: None,
            archive_uuid: None,
            session_id: None,
            closed_at_ns: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegularFile<'a> {
    pub path: &'a str,
    pub contents: &'a [u8],
    pub mode: u32,
    pub mtime: u64,
}

impl<'a> RegularFile<'a> {
    pub fn new(path: &'a str, contents: &'a [u8]) -> Self {
        Self {
            path,
            contents,
            mode: 0o644,
            mtime: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenArchive {
    pub bytes: Vec<u8>,
    pub volumes: Vec<Vec<u8>>,
    pub bootstrap_sidecar: Vec<u8>,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
}

#[derive(Debug, Clone)]
struct TarMember {
    path: Vec<u8>,
    tar_member_group_start: u64,
    tar_member_group_size: u64,
    file_data_size: u64,
}

#[derive(Debug, Clone)]
struct PayloadFrame {
    frame_index: u64,
    envelope_index: u64,
    member_index: usize,
    offset_in_envelope: u32,
    compressed_size: u32,
    decompressed_size: u32,
    flags: u32,
    tar_stream_offset: u64,
}

#[derive(Debug, Clone)]
struct FileRow {
    path_hash: [u8; 8],
    path: Vec<u8>,
    member_index: usize,
    member: TarMember,
}

#[derive(Debug, Clone)]
struct PlannedIndexShard {
    shard_index: u64,
    plaintext: Vec<u8>,
    file_count: u32,
    first_path_hash: [u8; 8],
    last_path_hash: [u8; 8],
}

#[derive(Debug, Clone)]
struct PlannedDirectoryHintShard {
    hint_shard_index: u64,
    plaintext: Vec<u8>,
    entry_count: u64,
    first_dir_hash: [u8; 8],
    last_dir_hash: [u8; 8],
}

#[derive(Debug, Clone)]
struct PayloadEnvelope {
    envelope_index: u64,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PayloadObject {
    envelope_index: u64,
    plaintext_size: u32,
    object: EncryptedObject,
}

#[derive(Debug, Clone)]
struct EncryptedObject {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
    records: Vec<BlockRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObjectExtent {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannedEncryptedObject {
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MetadataObjectKind {
    IndexRoot,
    Dictionary,
}

impl MetadataObjectKind {
    fn too_large_error(self) -> FormatError {
        match self {
            Self::IndexRoot => FormatError::WriterUnsupported("IndexRoot too large"),
            Self::Dictionary => FormatError::WriterUnsupported("dictionary object too large"),
        }
    }
}

impl ObjectExtent {
    fn new(first_block_index: u64, plan: PlannedEncryptedObject) -> Result<Self, FormatError> {
        Ok(Self {
            first_block_index,
            data_block_count: plan.data_block_count,
            parity_block_count: plan.parity_block_count,
            encrypted_size: plan.encrypted_size,
        })
    }

    fn next_block_index(self) -> Result<u64, FormatError> {
        checked_u64_add(
            self.first_block_index,
            self.data_block_count as u64 + self.parity_block_count as u64,
            "next_block_index",
        )
    }
}

#[derive(Debug, Clone)]
struct PlannedDirectoryHintObject {
    hint_shard_index: u64,
    compressed: Vec<u8>,
    extent: ObjectExtent,
}

pub fn write_archive(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(files, master_key, options, None, &KdfParams::Raw)
}

pub fn write_archive_with_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(files, master_key, options, None, kdf_params)
}

pub fn write_archive_with_dictionary(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
) -> Result<WrittenArchive, FormatError> {
    if dictionary.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require a non-empty dictionary",
        ));
    }
    if files.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require at least one file",
        ));
    }
    if dictionary.len() > u32::MAX as usize {
        return Err(FormatError::WriterUnsupported(
            "dictionary decompressed size exceeds u32",
        ));
    }
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        &KdfParams::Raw,
    )
}

pub fn write_archive_with_dictionary_and_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    if dictionary.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require a non-empty dictionary",
        ));
    }
    if files.is_empty() {
        return Err(FormatError::WriterUnsupported(
            "dictionary archives require at least one file",
        ));
    }
    if dictionary.len() > u32::MAX as usize {
        return Err(FormatError::WriterUnsupported(
            "dictionary decompressed size exceeds u32",
        ));
    }
    write_archive_inner(files, master_key, options, Some(dictionary), kdf_params)
}

fn write_archive_inner(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    let mut requested_options = options;
    if requested_options.target_volume_size.is_some() {
        requested_options.stripe_width = requested_options
            .stripe_width
            .max(requested_options.volume_loss_tolerance as u32 + 1);
    }
    let archive_uuid = requested_options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = requested_options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    loop {
        let planned_options = plan_writer_options(requested_options)?;
        let archive = write_archive_once(
            files,
            master_key,
            planned_options,
            dictionary,
            kdf_params,
            archive_uuid,
            session_id,
        )?;

        let Some(target_volume_size) = planned_options.target_volume_size else {
            return Ok(archive);
        };
        let required_stripe_width =
            required_stripe_width_for_target(&archive, planned_options, target_volume_size)?;
        if required_stripe_width <= planned_options.stripe_width {
            return Ok(archive);
        }
        requested_options.stripe_width = required_stripe_width;
    }
}

fn write_archive_once(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    mut options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
) -> Result<WrittenArchive, FormatError> {
    let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id)?;
    let mut next_block_index = 0u64;
    let mut block_records = Vec::new();
    let (tar_stream, tar_members) = build_tar_stream(files, options.max_path_length)?;
    let tar_total_size = tar_stream.len() as u64;
    let content_sha256 = sha256_bytes(&tar_stream);

    let (payload_objects, frames, payload_block_count) = if tar_stream.is_empty() {
        (Vec::new(), Vec::new(), 0u64)
    } else {
        let (payload_envelopes, frames) =
            build_payload_envelopes(&tar_stream, &tar_members, options, dictionary)?;
        let mut objects = Vec::with_capacity(payload_envelopes.len());
        let mut payload_block_count = 0u64;
        for envelope in payload_envelopes {
            let plaintext_size = u32_len(envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?;
            let object = encrypt_object(
                &envelope.plaintext,
                &subkeys.enc_key,
                &subkeys.nonce_seed,
                b"envelope",
                envelope.envelope_index,
                BlockKind::PayloadData,
                BlockKind::PayloadParity,
                options.fec_data_shards,
                options.fec_parity_shards,
                &mut next_block_index,
                options,
                &archive_uuid,
                &session_id,
            )?;
            payload_block_count = checked_u64_add(
                payload_block_count,
                object.data_block_count as u64,
                "payload",
            )?;
            block_records.extend(object.records.clone());
            objects.push(PayloadObject {
                envelope_index: envelope.envelope_index,
                plaintext_size,
                object,
            });
        }
        (objects, frames, payload_block_count)
    };

    let (shard_file_rows, planned_index_shards) = if tar_members.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let rows = sorted_file_rows(&tar_members);
        let shard_file_rows = partition_file_rows(rows)?;
        let planned_index_shards =
            build_index_shard_plaintexts(&shard_file_rows, &frames, &payload_objects, options)?;
        (shard_file_rows, planned_index_shards)
    };

    let mut shard_entries = Vec::with_capacity(planned_index_shards.len());
    for planned in planned_index_shards {
        let compressed = compress_zstd_frame(&planned.plaintext, options.zstd_level)?;
        let object = encrypt_object(
            &compressed,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            planned.shard_index,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            &mut next_block_index,
            options,
            &archive_uuid,
            &session_id,
        )?;
        shard_entries.push(ShardEntry {
            shard_index: planned.shard_index,
            first_block_index: object.first_block_index,
            data_block_count: object.data_block_count,
            parity_block_count: object.parity_block_count,
            encrypted_size: object.encrypted_size,
            decompressed_size: u32_len(planned.plaintext.len(), "IndexShard")?,
            file_count: planned.file_count,
            first_path_hash: planned.first_path_hash,
            last_path_hash: planned.last_path_hash,
        });
        block_records.extend(object.records.clone());
    }
    let frame_count = frames.len() as u64;
    let envelope_count = payload_objects.len() as u64;

    let compressed_dictionary = dictionary
        .map(|dictionary| compress_zstd_frame(dictionary, options.zstd_level))
        .transpose()?;
    let dictionary_decompressed_size = dictionary
        .map(|dictionary| u32_len(dictionary.len(), "dictionary"))
        .transpose()?;
    let dictionary_plan = compressed_dictionary
        .as_ref()
        .map(|compressed| {
            plan_metadata_object_without_class(
                compressed.len(),
                options,
                MetadataObjectKind::Dictionary,
            )
        })
        .transpose()?;
    let dictionary_extent = dictionary_plan
        .map(|plan| ObjectExtent::new(next_block_index, plan))
        .transpose()?;
    let next_after_dictionary = if let Some(extent) = dictionary_extent {
        extent.next_block_index()?
    } else {
        next_block_index
    };

    let planned_directory_hint_shards = if should_emit_directory_hints(tar_members.len()) {
        build_directory_hint_plaintexts(&shard_file_rows, options)?
    } else {
        Vec::new()
    };
    let mut directory_hint_entries = Vec::with_capacity(planned_directory_hint_shards.len());
    let mut planned_directory_hint_objects =
        Vec::with_capacity(planned_directory_hint_shards.len());
    let mut planned_next_block_index = next_after_dictionary;
    for planned in planned_directory_hint_shards {
        let compressed = compress_zstd_frame(&planned.plaintext, options.zstd_level)?;
        let object_plan = plan_encrypted_object(
            compressed.len(),
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            options,
        )?;
        let extent = ObjectExtent::new(planned_next_block_index, object_plan)?;
        planned_next_block_index = extent.next_block_index()?;
        directory_hint_entries.push(DirectoryHintShardEntry {
            hint_shard_index: planned.hint_shard_index,
            first_dir_hash: planned.first_dir_hash,
            last_dir_hash: planned.last_dir_hash,
            first_block_index: extent.first_block_index,
            data_block_count: extent.data_block_count,
            parity_block_count: extent.parity_block_count,
            encrypted_size: extent.encrypted_size,
            decompressed_size: u32_len(planned.plaintext.len(), "DirectoryHintTable")?,
            entry_count: planned.entry_count,
        });
        planned_directory_hint_objects.push(PlannedDirectoryHintObject {
            hint_shard_index: planned.hint_shard_index,
            compressed,
            extent,
        });
    }

    let index_root_plaintext = build_index_root_plaintext(
        &shard_entries,
        frame_count,
        envelope_count,
        tar_members.len() as u64,
        payload_block_count,
        tar_total_size,
        content_sha256,
        &directory_hint_entries,
        dictionary_extent
            .zip(dictionary_decompressed_size)
            .map(|(extent, decompressed_size)| (extent, decompressed_size)),
    );
    let compressed_index_root = compress_zstd_frame(&index_root_plaintext, options.zstd_level)?;
    let metadata_class = plan_index_root_metadata_class(
        options,
        compressed_index_root.len(),
        compressed_dictionary.as_ref().map(Vec::len),
    )?;
    options = metadata_class.options;
    let crypto_header = build_crypto_header(
        options,
        dictionary.is_some(),
        &subkeys,
        &archive_uuid,
        &session_id,
        kdf_params,
    )?;

    let actual_dictionary_extent =
        if let (Some(compressed_dictionary), Some(expected_extent), Some(decompressed_size)) = (
            compressed_dictionary.as_ref(),
            dictionary_extent,
            dictionary_decompressed_size,
        ) {
            let object = encrypt_object(
                compressed_dictionary,
                &subkeys.dictionary_key,
                &subkeys.index_nonce_seed,
                b"dict",
                0,
                BlockKind::DictionaryData,
                BlockKind::DictionaryParity,
                options.index_root_fec_data_shards,
                options.index_root_fec_parity_shards,
                &mut next_block_index,
                options,
                &archive_uuid,
                &session_id,
            )
            .map_err(|err| map_metadata_encrypt_error(err, MetadataObjectKind::Dictionary))?;
            if let Some(dictionary_plan) = metadata_class.dictionary {
                validate_planned_object(&object, dictionary_plan)?;
            }
            validate_planned_extent(&object, expected_extent)?;
            block_records.extend(object.records.clone());
            Some((object, decompressed_size))
        } else {
            None
        };
    for planned in planned_directory_hint_objects {
        let object = encrypt_object(
            &planned.compressed,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            planned.hint_shard_index,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            &mut next_block_index,
            options,
            &archive_uuid,
            &session_id,
        )?;
        validate_planned_extent(&object, planned.extent)?;
        block_records.extend(object.records.clone());
    }
    let index_root_extent = encrypt_object(
        &compressed_index_root,
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        BlockKind::IndexRootParity,
        options.index_root_fec_data_shards,
        options.index_root_fec_parity_shards,
        &mut next_block_index,
        options,
        &archive_uuid,
        &session_id,
    )
    .map_err(|err| map_metadata_encrypt_error(err, MetadataObjectKind::IndexRoot))?;
    validate_planned_object(&index_root_extent, metadata_class.index_root)?;
    block_records.extend(index_root_extent.records.clone());

    let stripe_width = options.stripe_width as usize;
    let mut striped_records = vec![Vec::<BlockRecord>::new(); stripe_width];
    for record in &block_records {
        let volume_index = (record.block_index % options.stripe_width as u64) as usize;
        striped_records[volume_index].push(record.clone());
    }

    let mut volumes = Vec::with_capacity(stripe_width);
    let mut volume_zero_manifest = [0u8; MANIFEST_FOOTER_LEN];
    for (volume_index, records) in striped_records.iter().enumerate() {
        let volume_index = u32::try_from(volume_index)
            .map_err(|_| FormatError::WriterUnsupported("volume_index"))?;
        let volume_header = VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index,
            stripe_width: options.stripe_width,
            archive_uuid,
            session_id,
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: u32_len(crypto_header.len(), "CryptoHeader")?,
            header_crc32c: 0,
        };

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&volume_header.to_bytes());
        bytes.extend_from_slice(&crypto_header);
        for record in records {
            bytes.extend_from_slice(&record.to_bytes());
        }

        let manifest_footer_offset = bytes.len() as u64;
        let manifest_footer = build_manifest_footer(
            &subkeys,
            archive_uuid,
            session_id,
            volume_index,
            options.stripe_width,
            &index_root_extent,
            index_root_plaintext.len(),
        )?;
        bytes.extend_from_slice(&manifest_footer);

        let bytes_written = bytes.len() as u64;
        let trailer = build_volume_trailer(
            &subkeys,
            archive_uuid,
            session_id,
            volume_index,
            records.len() as u64,
            bytes_written,
            manifest_footer_offset,
            options.closed_at_ns,
        );
        bytes.extend_from_slice(&trailer);

        if volume_index == 0 {
            volume_zero_manifest = manifest_footer;
        }
        volumes.push(bytes);
    }

    let bootstrap_sidecar = if options.stripe_width == 1 {
        build_bootstrap_sidecar(
            &subkeys,
            archive_uuid,
            session_id,
            &volume_zero_manifest,
            &index_root_extent.records,
            actual_dictionary_extent
                .as_ref()
                .map(|(object, _)| object.records.as_slice()),
        )?
    } else {
        Vec::new()
    };

    Ok(WrittenArchive {
        bytes: volumes
            .first()
            .cloned()
            .ok_or(FormatError::WriterInvariant("no volumes emitted"))?,
        volumes,
        bootstrap_sidecar,
        archive_uuid,
        session_id,
    })
}

fn required_stripe_width_for_target(
    archive: &WrittenArchive,
    options: WriterOptions,
    target_volume_size: u64,
) -> Result<u32, FormatError> {
    let max_volume_size = archive
        .volumes
        .iter()
        .map(|volume| volume.len() as u64)
        .max()
        .unwrap_or(0);
    if max_volume_size <= target_volume_size {
        return Ok(options.stripe_width);
    }

    let first_volume = archive
        .volumes
        .first()
        .ok_or(FormatError::WriterInvariant("no volumes emitted"))?;
    let volume_header = VolumeHeader::parse(
        first_volume
            .get(..VOLUME_HEADER_LEN)
            .ok_or(FormatError::WriterInvariant("truncated emitted volume"))?,
    )?;
    let fixed_volume_overhead = VOLUME_HEADER_LEN as u64
        + volume_header.crypto_header_length as u64
        + MANIFEST_FOOTER_LEN as u64
        + VOLUME_TRAILER_LEN as u64;
    if target_volume_size <= fixed_volume_overhead {
        return Err(FormatError::WriterUnsupported(
            "volume-size is too small for per-volume metadata",
        ));
    }

    let block_record_len = options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let records_per_volume = (target_volume_size - fixed_volume_overhead) / block_record_len;
    if records_per_volume == 0 {
        return Err(FormatError::WriterUnsupported(
            "volume-size is too small for the configured block-size",
        ));
    }

    let total_records = archive.volumes.iter().try_fold(0u64, |total, volume| {
        let volume_len = volume.len() as u64;
        if volume_len < fixed_volume_overhead {
            return Err(FormatError::WriterInvariant("emitted volume too short"));
        }
        let record_bytes = volume_len - fixed_volume_overhead;
        total
            .checked_add(record_bytes / block_record_len)
            .ok_or(FormatError::WriterUnsupported("volume count overflow"))
    })?;
    let required = ceil_div(total_records, records_per_volume)?
        .max(options.volume_loss_tolerance as u64 + 1)
        .max(1);
    u32::try_from(required).map_err(|_| FormatError::WriterUnsupported("volume count"))
}

pub fn write_empty_archive(master_key: &MasterKey) -> Result<WrittenArchive, FormatError> {
    write_archive(&[], master_key, WriterOptions::default())
}

fn plan_writer_options(mut options: WriterOptions) -> Result<WriterOptions, FormatError> {
    if options.block_size < MIN_BLOCK_SIZE || options.block_size % 2 != 0 {
        return Err(FormatError::WriterUnsupported(
            "M6 writer requires an even block size of at least 4096",
        ));
    }
    if options.stripe_width == 0 {
        return Err(FormatError::WriterUnsupported(
            "stripe_width must be non-zero",
        ));
    }
    if options.volume_loss_tolerance as u32 >= options.stripe_width {
        return Err(FormatError::WriterUnsupported(
            "volume_loss_tolerance must be less than stripe_width",
        ));
    }
    if options.stripe_width == 1 && options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported(
            "single-volume archives cannot tolerate volume loss",
        ));
    }
    if matches!(options.target_volume_size, Some(0)) {
        return Err(FormatError::WriterUnsupported(
            "target_volume_size must be non-zero",
        ));
    }
    if options.bit_rot_buffer_pct > 100 {
        return Err(FormatError::WriterUnsupported(
            "bit_rot_buffer_pct must be at most 100",
        ));
    }
    if options.chunk_size == 0 || options.chunk_size > options.envelope_target_size {
        return Err(FormatError::WriterUnsupported(
            "chunk_size must be non-zero and no larger than envelope_target_size",
        ));
    }
    if options.fec_data_shards == 0
        || options.index_fec_data_shards == 0
        || options.index_root_fec_data_shards == 0
    {
        return Err(FormatError::WriterUnsupported(
            "FEC data shard class maxima must be non-zero",
        ));
    }
    options.index_root_fec_data_shards = options
        .index_root_fec_data_shards
        .max(MIN_INDEX_ROOT_FEC_DATA_SHARDS);
    options.fec_parity_shards = options.fec_parity_shards.max(compute_parity_u16(
        options.fec_data_shards as u64,
        options,
        "fec_parity_shards",
    )?);
    options.index_fec_parity_shards = options.index_fec_parity_shards.max(compute_parity_u16(
        options.index_fec_data_shards as u64,
        options,
        "index_fec_parity_shards",
    )?);
    options.index_root_fec_parity_shards =
        options.index_root_fec_parity_shards.max(compute_parity_u16(
            options.index_root_fec_data_shards as u64,
            options,
            "index_root_fec_parity_shards",
        )?);
    Ok(options)
}

fn build_crypto_header(
    options: WriterOptions,
    has_dictionary: bool,
    subkeys: &Subkeys,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
    kdf_params: &KdfParams,
) -> Result<Vec<u8>, FormatError> {
    let kdf_payload = serialize_kdf_params(kdf_params)?;
    let length = CRYPTO_HEADER_FIXED_LEN
        .checked_add(kdf_payload.len())
        .and_then(|value| value.checked_add(CRYPTO_EXTENSION_HEADER_LEN))
        .and_then(|value| value.checked_add(CRYPTO_HEADER_HMAC_LEN))
        .ok_or(FormatError::WriterUnsupported(
            "CryptoHeader length overflow",
        ))?;
    let kdf_algo = match kdf_params {
        KdfParams::Raw => KdfAlgo::Raw,
        KdfParams::Argon2id { .. } => KdfAlgo::Argon2id,
    };
    let fixed = CryptoHeaderFixed {
        length: length as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: options.aead_algo,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo,
        chunk_size: options.chunk_size,
        envelope_target_size: options.envelope_target_size,
        block_size: options.block_size,
        fec_data_shards: options.fec_data_shards,
        fec_parity_shards: options.fec_parity_shards,
        index_fec_data_shards: options.index_fec_data_shards,
        index_fec_parity_shards: options.index_fec_parity_shards,
        index_root_fec_data_shards: options.index_root_fec_data_shards,
        index_root_fec_parity_shards: options.index_root_fec_parity_shards,
        stripe_width: options.stripe_width,
        volume_loss_tolerance: options.volume_loss_tolerance,
        bit_rot_buffer_pct: options.bit_rot_buffer_pct,
        has_dictionary: if has_dictionary { 1 } else { 0 },
        max_path_length: options.max_path_length,
        expected_volume_size: options.target_volume_size.unwrap_or(0),
    };

    let mut bytes = fixed.to_bytes().to_vec();
    bytes.extend_from_slice(&kdf_payload);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let hmac = compute_hmac(
        HmacDomain::CryptoHeader,
        &subkeys.mac_key,
        archive_uuid,
        session_id,
        &bytes,
    );
    bytes.extend_from_slice(&hmac);
    Ok(bytes)
}

fn serialize_kdf_params(params: &KdfParams) -> Result<Vec<u8>, FormatError> {
    let mut bytes = Vec::new();
    match params {
        KdfParams::Raw => {
            bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
        }
        KdfParams::Argon2id {
            t_cost,
            m_cost_kib,
            parallelism,
            salt,
        } => {
            if *t_cost == 0 {
                return Err(FormatError::InvalidKdfParams("t_cost must be non-zero"));
            }
            if *parallelism == 0 {
                return Err(FormatError::InvalidKdfParams(
                    "parallelism must be non-zero",
                ));
            }
            let min_memory = parallelism
                .checked_mul(8)
                .ok_or(FormatError::InvalidKdfParams(
                    "m_cost_kib requirement overflow",
                ))?;
            if *m_cost_kib < min_memory {
                return Err(FormatError::InvalidKdfParams(
                    "m_cost_kib must be at least 8 * parallelism",
                ));
            }
            if !(8..=64).contains(&salt.len()) {
                return Err(FormatError::InvalidKdfParams(
                    "argon2id salt length must be 8..64",
                ));
            }
            let salt_len = u16::try_from(salt.len())
                .map_err(|_| FormatError::InvalidKdfParams("argon2id salt too long"))?;
            bytes.extend_from_slice(&(KdfAlgo::Argon2id as u16).to_le_bytes());
            bytes.extend_from_slice(&t_cost.to_le_bytes());
            bytes.extend_from_slice(&m_cost_kib.to_le_bytes());
            bytes.extend_from_slice(&parallelism.to_le_bytes());
            bytes.extend_from_slice(&salt_len.to_le_bytes());
            bytes.extend_from_slice(salt);
        }
    }
    Ok(bytes)
}

fn build_tar_stream(
    files: &[RegularFile<'_>],
    max_path_length: u32,
) -> Result<(Vec<u8>, Vec<TarMember>), FormatError> {
    let mut stream = Vec::new();
    let mut members = Vec::with_capacity(files.len());
    for file in files {
        let path = normalize_lookup_file_path(file.path, max_path_length)?;
        let start = stream.len() as u64;
        let member_group =
            build_regular_file_member_group(&path, file.contents, file.mode, file.mtime)?;
        stream.extend_from_slice(&member_group);
        members.push(TarMember {
            path,
            tar_member_group_start: start,
            tar_member_group_size: member_group.len() as u64,
            file_data_size: file.contents.len() as u64,
        });
    }
    Ok((stream, members))
}

fn build_payload_envelopes(
    tar_stream: &[u8],
    members: &[TarMember],
    options: WriterOptions,
    dictionary: Option<&[u8]>,
) -> Result<(Vec<PayloadEnvelope>, Vec<PayloadFrame>), FormatError> {
    let chunk_size = options.chunk_size as usize;
    if chunk_size == 0 {
        return Err(FormatError::WriterUnsupported(
            "chunk_size must be non-zero and no larger than envelope_target_size",
        ));
    }
    let envelope_target_size = options.envelope_target_size as usize;
    let mut envelopes = Vec::new();
    let mut current = PayloadEnvelope {
        envelope_index: 0,
        plaintext: Vec::new(),
    };
    let mut frames = Vec::new();
    let mut next_frame_index = 0u64;

    for (member_index, member) in members.iter().enumerate() {
        let start = member.tar_member_group_start as usize;
        let end = checked_usize_add(start, member.tar_member_group_size as usize, "tar member")?;
        let member_bytes = tar_stream
            .get(start..end)
            .ok_or(FormatError::WriterInvariant(
                "tar member range is out of bounds",
            ))?;
        let mut member_offset = 0usize;
        while member_offset < member_bytes.len() {
            let mut chunk_len = (member_bytes.len() - member_offset).min(chunk_size);
            let frame = loop {
                let end = checked_usize_add(member_offset, chunk_len, "payload chunk")?;
                let chunk = &member_bytes[member_offset..end];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary(chunk, options.zstd_level, dictionary)?
                } else {
                    compress_zstd_frame(chunk, options.zstd_level)?
                };
                if payload_object_can_fit(frame.len(), options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    ));
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            let next_len = checked_usize_add(current.plaintext.len(), frame.len(), "payload")?;
            if !current.plaintext.is_empty()
                && (next_len > envelope_target_size || !payload_object_can_fit(next_len, options)?)
            {
                envelopes.push(current);
                current = PayloadEnvelope {
                    envelope_index: envelopes.len() as u64,
                    plaintext: Vec::new(),
                };
            }

            if current.plaintext.is_empty() && !payload_object_can_fit(frame.len(), options)? {
                return Err(FormatError::WriterUnsupported(
                    "payload frame exceeds envelope object limits",
                ));
            }
            let offset = u32_len(current.plaintext.len(), "FrameEntry.offset_in_envelope")?;
            current.plaintext.extend_from_slice(&frame);
            let is_first_member_frame = member_offset == 0;
            let is_last_member_frame =
                checked_usize_add(member_offset, chunk_len, "payload chunk")? == member_bytes.len();
            let mut flags = 0u32;
            if is_first_member_frame {
                flags |= 0x0000_0001;
            }
            if is_last_member_frame {
                flags |= 0x0000_0002;
            }
            frames.push(PayloadFrame {
                frame_index: next_frame_index,
                envelope_index: current.envelope_index,
                member_index,
                offset_in_envelope: offset,
                compressed_size: u32_len(frame.len(), "FrameEntry.compressed_size")?,
                decompressed_size: u32_len(chunk_len, "FrameEntry.decompressed_size")?,
                flags,
                tar_stream_offset: checked_u64_add(
                    member.tar_member_group_start,
                    u64::try_from(member_offset)
                        .map_err(|_| FormatError::WriterUnsupported("chunk offset"))?,
                    "PayloadFrame.tar_stream_offset",
                )?,
            });
            next_frame_index = checked_u64_add(next_frame_index, 1, "PayloadFrame.frame_index")?;
            member_offset = checked_usize_add(member_offset, chunk_len, "payload chunk")?;
        }
    }
    if !current.plaintext.is_empty() {
        envelopes.push(current);
    }
    Ok((envelopes, frames))
}

fn sorted_file_rows(members: &[TarMember]) -> Vec<FileRow> {
    let mut rows = members
        .iter()
        .enumerate()
        .map(|(member_index, member)| FileRow {
            path_hash: hash_prefix(&member.path),
            path: member.path.clone(),
            member_index,
            member: member.clone(),
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        (
            left.path_hash,
            left.path.as_slice(),
            left.member.tar_member_group_start,
        )
            .cmp(&(
                right.path_hash,
                right.path.as_slice(),
                right.member.tar_member_group_start,
            ))
    });
    rows
}

fn partition_file_rows(rows: Vec<FileRow>) -> Result<Vec<Vec<FileRow>>, FormatError> {
    let mut shards = Vec::new();
    let mut start = 0usize;
    while start < rows.len() {
        let mut end = (start + DEFAULT_FILES_PER_INDEX_SHARD).min(rows.len());
        if end < rows.len() && rows[end - 1].path_hash == rows[end].path_hash {
            let boundary_hash = rows[end].path_hash;
            let mut run_start_in_shard = end - 1;
            while run_start_in_shard > start
                && rows[run_start_in_shard - 1].path_hash == boundary_hash
            {
                run_start_in_shard -= 1;
            }
            let mut full_run_start = run_start_in_shard;
            while full_run_start > 0 && rows[full_run_start - 1].path_hash == boundary_hash {
                full_run_start -= 1;
            }
            let mut full_run_end = end + 1;
            while full_run_end < rows.len() && rows[full_run_end].path_hash == boundary_hash {
                full_run_end += 1;
            }
            let full_run_len = full_run_end - full_run_start;
            end = if full_run_len <= MAX_HASH_PREFIX_RUN_FILES {
                full_run_end
            } else {
                (run_start_in_shard + MAX_HASH_PREFIX_RUN_FILES).min(full_run_end)
            };
        }
        if end - start > MAX_FILES_PER_INDEX_SHARD {
            return Err(FormatError::WriterUnsupported(
                "hash-prefix collision run exceeds max_files_per_index_shard",
            ));
        }
        shards.push(rows[start..end].to_vec());
        start = end;
    }
    Ok(shards)
}

fn build_index_shard_plaintexts(
    shard_rows: &[Vec<FileRow>],
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<Vec<PlannedIndexShard>, FormatError> {
    let mut planned = Vec::new();
    for rows in shard_rows {
        append_index_shards_for_rows(&mut planned, rows.clone(), frames, payloads, options)?;
    }
    Ok(planned)
}

fn append_index_shards_for_rows(
    planned: &mut Vec<PlannedIndexShard>,
    rows: Vec<FileRow>,
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<(), FormatError> {
    let shard_index =
        u64::try_from(planned.len()).map_err(|_| FormatError::WriterUnsupported("shard_index"))?;
    let candidate = build_index_shard_plaintext(shard_index, &rows, frames, payloads, options)?;
    let compressed = compress_zstd_frame(&candidate.plaintext, options.zstd_level)?;
    if index_object_can_fit(compressed.len(), options)? {
        planned.push(candidate);
        return Ok(());
    }
    if rows.len() == 1 {
        return Err(FormatError::WriterUnsupported(
            "single-file IndexShard exceeds index object limits",
        ));
    }
    let split_at = split_sorted_file_rows_for_object_limit(&rows);
    append_index_shards_for_rows(
        planned,
        rows[..split_at].to_vec(),
        frames,
        payloads,
        options,
    )?;
    append_index_shards_for_rows(
        planned,
        rows[split_at..].to_vec(),
        frames,
        payloads,
        options,
    )
}

fn split_sorted_file_rows_for_object_limit(rows: &[FileRow]) -> usize {
    let midpoint = rows.len() / 2;
    if rows[midpoint - 1].path_hash != rows[midpoint].path_hash {
        return midpoint;
    }

    let boundary_hash = rows[midpoint].path_hash;
    let mut left = midpoint;
    while left > 0 && rows[left - 1].path_hash == boundary_hash {
        left -= 1;
    }
    let mut right = midpoint;
    while right < rows.len() && rows[right].path_hash == boundary_hash {
        right += 1;
    }

    match (left > 0, right < rows.len()) {
        (true, true) if midpoint - left <= right - midpoint => left,
        (true, true) => right,
        (true, false) => left,
        (false, true) => right,
        (false, false) => midpoint,
    }
}

fn build_index_shard_plaintext(
    shard_index: u64,
    file_rows: &[FileRow],
    frames: &[PayloadFrame],
    payloads: &[PayloadObject],
    options: WriterOptions,
) -> Result<PlannedIndexShard, FormatError> {
    let mut string_pool = Vec::new();
    let mut file_entries = Vec::with_capacity(file_rows.len());
    let mut required_frame_indexes = BTreeSet::new();
    for row in file_rows {
        let path_offset = u32_len(string_pool.len(), "FileEntry.path_offset")?;
        string_pool.extend_from_slice(&row.path);
        let (first_frame_index, frame_count) = member_frame_range(row.member_index, frames)?;
        for offset in 0..frame_count as u64 {
            required_frame_indexes.insert(checked_u64_add(
                first_frame_index,
                offset,
                "FileEntry.frame_count",
            )?);
        }
        file_entries.push(FileEntry {
            path_hash: row.path_hash,
            path_offset,
            path_length: u32_len(row.path.len(), "FileEntry.path_length")?,
            first_frame_index,
            frame_count,
            offset_in_first_frame_plaintext: 0,
            tar_member_group_size: row.member.tar_member_group_size,
            file_data_size: row.member.file_data_size,
            flags: 0,
        });
    }

    let frame_entries = frames
        .iter()
        .filter(|frame| required_frame_indexes.contains(&frame.frame_index))
        .map(|frame| FrameEntry {
            frame_index: frame.frame_index,
            envelope_index: frame.envelope_index,
            offset_in_envelope: frame.offset_in_envelope,
            compressed_size: frame.compressed_size,
            decompressed_size: frame.decompressed_size,
            flags: frame.flags,
            tar_stream_offset: frame.tar_stream_offset,
        })
        .collect::<Vec<_>>();
    let required_envelope_indexes = frame_entries
        .iter()
        .map(|frame| frame.envelope_index)
        .collect::<BTreeSet<_>>();
    let envelope_entries = payloads
        .iter()
        .filter(|payload| required_envelope_indexes.contains(&payload.envelope_index))
        .map(|payload| {
            let (first_frame_index, frame_count) =
                envelope_frame_range(payload.envelope_index, frames)?;
            Ok(EnvelopeEntry {
                envelope_index: payload.envelope_index,
                first_block_index: payload.object.first_block_index,
                data_block_count: payload.object.data_block_count,
                parity_block_count: payload.object.parity_block_count,
                encrypted_size: payload.object.encrypted_size,
                plaintext_size: payload.plaintext_size,
                first_frame_index,
                frame_count,
            })
        })
        .collect::<Result<Vec<_>, FormatError>>()?;

    let plaintext = serialize_index_shard(
        shard_index,
        &file_entries,
        &frame_entries,
        &envelope_entries,
        &string_pool,
        options,
    )?;
    let first_path_hash = file_rows
        .first()
        .ok_or(FormatError::WriterInvariant("empty planned IndexShard"))?
        .path_hash;
    let last_path_hash = file_rows
        .last()
        .ok_or(FormatError::WriterInvariant("empty planned IndexShard"))?
        .path_hash;
    Ok(PlannedIndexShard {
        shard_index,
        plaintext,
        file_count: u32_len(file_rows.len(), "IndexShard.file_count")?,
        first_path_hash,
        last_path_hash,
    })
}

fn serialize_index_shard(
    shard_index: u64,
    files: &[FileEntry],
    frames: &[FrameEntry],
    envelopes: &[EnvelopeEntry],
    string_pool: &[u8],
    _options: WriterOptions,
) -> Result<Vec<u8>, FormatError> {
    let mut cursor = INDEX_SHARD_HEADER_LEN;
    let file_table_offset = table_offset(files.len(), cursor)?;
    cursor = checked_usize_add(cursor, files.len() * FILE_ENTRY_LEN, "IndexShard")?;
    let frame_table_offset = table_offset(frames.len(), cursor)?;
    cursor = checked_usize_add(cursor, frames.len() * FRAME_ENTRY_LEN, "IndexShard")?;
    let envelope_table_offset = table_offset(envelopes.len(), cursor)?;
    cursor = checked_usize_add(cursor, envelopes.len() * ENVELOPE_ENTRY_LEN, "IndexShard")?;
    let string_pool_offset = table_offset(string_pool.len(), cursor)?;

    let header = IndexShardHeader {
        version: 1,
        shard_index,
        file_count: u32_len(files.len(), "IndexShard.file_count")?,
        frame_count: u32_len(frames.len(), "IndexShard.frame_count")?,
        envelope_count: u32_len(envelopes.len(), "IndexShard.envelope_count")?,
        file_table_offset,
        frame_table_offset,
        envelope_table_offset,
        string_pool_offset,
        string_pool_size: u32_len(string_pool.len(), "IndexShard.string_pool_size")?,
    };

    let mut bytes = Vec::with_capacity(cursor + string_pool.len());
    bytes.extend_from_slice(&header.to_bytes());
    for entry in files {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for entry in frames {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for entry in envelopes {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    bytes.extend_from_slice(string_pool);
    Ok(bytes)
}

fn build_directory_hint_plaintexts(
    shard_rows: &[Vec<FileRow>],
    options: WriterOptions,
) -> Result<Vec<PlannedDirectoryHintShard>, FormatError> {
    let mut map = BTreeMap::<Vec<u8>, BTreeSet<u32>>::new();
    for (shard_row_index, rows) in shard_rows.iter().enumerate() {
        let shard_row_index = u32::try_from(shard_row_index)
            .map_err(|_| FormatError::WriterUnsupported("directory hint shard row index"))?;
        for row in rows {
            add_directory_hint_rows(&mut map, shard_row_index, &row.path);
        }
    }

    let rows = map
        .into_iter()
        .map(|(path, shard_rows)| (hash_prefix(&path), path, shard_rows))
        .collect::<Vec<_>>();
    let mut rows = rows;
    rows.sort_by(|left, right| (left.0, left.1.as_slice()).cmp(&(right.0, right.1.as_slice())));

    let mut planned = Vec::new();
    for chunk in rows.chunks(DEFAULT_DIRECTORY_HINT_ENTRIES_PER_SHARD) {
        append_directory_hint_shards_for_rows(&mut planned, chunk.to_vec(), options)?;
    }
    Ok(planned)
}

fn append_directory_hint_shards_for_rows(
    planned: &mut Vec<PlannedDirectoryHintShard>,
    rows: Vec<([u8; 8], Vec<u8>, BTreeSet<u32>)>,
    options: WriterOptions,
) -> Result<(), FormatError> {
    let hint_shard_index = u64::try_from(planned.len())
        .map_err(|_| FormatError::WriterUnsupported("hint_shard_index"))?;
    let candidate = build_directory_hint_plaintext(hint_shard_index, &rows)?;
    let compressed = compress_zstd_frame(&candidate.plaintext, options.zstd_level)?;
    if index_object_can_fit(compressed.len(), options)? {
        planned.push(candidate);
        return Ok(());
    }
    if rows.len() == 1 {
        return Err(FormatError::WriterUnsupported(
            "single DirectoryHintEntry exceeds index object limits",
        ));
    }
    let split_at = rows.len() / 2;
    append_directory_hint_shards_for_rows(planned, rows[..split_at].to_vec(), options)?;
    append_directory_hint_shards_for_rows(planned, rows[split_at..].to_vec(), options)
}

fn add_directory_hint_rows(
    map: &mut BTreeMap<Vec<u8>, BTreeSet<u32>>,
    shard_row_index: u32,
    path: &[u8],
) {
    map.entry(Vec::new()).or_default().insert(shard_row_index);
    let mut cursor = 0usize;
    while let Some(position) = path[cursor..].iter().position(|byte| *byte == b'/') {
        let slash = cursor + position;
        if slash > 0 {
            map.entry(path[..slash].to_vec())
                .or_default()
                .insert(shard_row_index);
        }
        cursor = slash + 1;
    }
}

fn build_directory_hint_plaintext(
    hint_shard_index: u64,
    rows: &[([u8; 8], Vec<u8>, BTreeSet<u32>)],
) -> Result<PlannedDirectoryHintShard, FormatError> {
    let mut entries = Vec::with_capacity(rows.len());
    let mut shard_row_indexes = Vec::new();
    let mut string_pool = Vec::new();

    for (dir_hash, path, shard_rows) in rows {
        let path_offset = if path.is_empty() {
            0
        } else {
            u64::try_from(string_pool.len())
                .map_err(|_| FormatError::WriterUnsupported("DirectoryHintEntry.path_offset"))?
        };
        if !path.is_empty() {
            string_pool.extend_from_slice(path);
        }
        let shard_list_start_index = u32_len(
            shard_row_indexes.len(),
            "DirectoryHintEntry.shard_list_start_index",
        )?;
        shard_row_indexes.extend(shard_rows.iter().copied());
        entries.push(DirectoryHintEntry {
            dir_hash: *dir_hash,
            path_offset,
            path_length: u32_len(path.len(), "DirectoryHintEntry.path_length")?,
            shard_list_start_index,
            shard_count: u32_len(shard_rows.len(), "DirectoryHintEntry.shard_count")?,
        });
    }

    let plaintext = serialize_directory_hint_table(
        hint_shard_index,
        &entries,
        &shard_row_indexes,
        &string_pool,
    )?;
    let first_dir_hash = rows
        .first()
        .ok_or(FormatError::WriterInvariant("empty directory hint shard"))?
        .0;
    let last_dir_hash = rows
        .last()
        .ok_or(FormatError::WriterInvariant("empty directory hint shard"))?
        .0;
    Ok(PlannedDirectoryHintShard {
        hint_shard_index,
        plaintext,
        entry_count: rows.len() as u64,
        first_dir_hash,
        last_dir_hash,
    })
}

fn serialize_directory_hint_table(
    hint_shard_index: u64,
    entries: &[DirectoryHintEntry],
    shard_row_indexes: &[u32],
    string_pool: &[u8],
) -> Result<Vec<u8>, FormatError> {
    let entry_table_offset = table_offset(entries.len(), DIRECTORY_HINT_TABLE_LEN)?;
    let shard_list_cursor = checked_usize_add(
        DIRECTORY_HINT_TABLE_LEN,
        entries.len() * DIRECTORY_HINT_ENTRY_LEN,
        "DirectoryHintTable",
    )?;
    let shard_list_offset = table_offset(shard_row_indexes.len(), shard_list_cursor)?;
    let string_pool_cursor = checked_usize_add(
        shard_list_cursor,
        shard_row_indexes.len() * 4,
        "DirectoryHintTable",
    )?;
    let string_pool_offset = if string_pool.is_empty() {
        0
    } else {
        u64::try_from(string_pool_cursor)
            .map_err(|_| FormatError::WriterUnsupported("DirectoryHintTable.string_pool_offset"))?
    };
    let header = DirectoryHintTableHeader {
        version: 1,
        hint_shard_index,
        entry_count: entries.len() as u64,
        entry_table_offset: entry_table_offset as u64,
        shard_list_offset: shard_list_offset as u64,
        string_pool_offset,
        string_pool_size: string_pool.len() as u64,
    };

    let mut bytes = Vec::with_capacity(string_pool_cursor + string_pool.len());
    bytes.extend_from_slice(&header.to_bytes());
    for entry in entries {
        bytes.extend_from_slice(&entry.to_bytes());
    }
    for row in shard_row_indexes {
        bytes.extend_from_slice(&row.to_le_bytes());
    }
    bytes.extend_from_slice(string_pool);
    Ok(bytes)
}

fn build_index_root_plaintext(
    shard_entries: &[ShardEntry],
    frame_count: u64,
    envelope_count: u64,
    file_count: u64,
    payload_block_count: u64,
    tar_total_size: u64,
    content_sha256: [u8; 32],
    directory_hint_entries: &[DirectoryHintShardEntry],
    dictionary_extent: Option<(ObjectExtent, u32)>,
) -> Vec<u8> {
    let mut header = IndexRootHeader::empty();
    header.frame_count = frame_count;
    header.envelope_count = envelope_count;
    header.file_count = file_count;
    header.payload_block_count = payload_block_count;
    header.tar_total_size = tar_total_size;
    header.content_sha256 = content_sha256;
    if let Some((dictionary, decompressed_size)) = dictionary_extent {
        header.dictionary_first_block = dictionary.first_block_index;
        header.dictionary_data_block_count = dictionary.data_block_count;
        header.dictionary_parity_block_count = dictionary.parity_block_count;
        header.dictionary_encrypted_size = dictionary.encrypted_size;
        header.dictionary_decompressed_size = decompressed_size;
    }
    let root = IndexRoot {
        header,
        shards: shard_entries.to_vec(),
        directory_hint_shards: directory_hint_entries.to_vec(),
    };
    root.to_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataClassPlan {
    options: WriterOptions,
    index_root: PlannedEncryptedObject,
    dictionary: Option<PlannedEncryptedObject>,
}

fn plan_index_root_metadata_class(
    mut options: WriterOptions,
    compressed_index_root_len: usize,
    compressed_dictionary_len: Option<usize>,
) -> Result<MetadataClassPlan, FormatError> {
    let index_root = plan_metadata_object_without_class(
        compressed_index_root_len,
        options,
        MetadataObjectKind::IndexRoot,
    )?;
    let dictionary = compressed_dictionary_len
        .map(|len| plan_metadata_object_without_class(len, options, MetadataObjectKind::Dictionary))
        .transpose()?;
    let required_data_shards = u32::from(options.index_root_fec_data_shards)
        .max(MIN_INDEX_ROOT_FEC_DATA_SHARDS as u32)
        .max(index_root.data_block_count)
        .max(dictionary.map(|plan| plan.data_block_count).unwrap_or(0));
    let required_data_shards = u16::try_from(required_data_shards)
        .map_err(|_| MetadataObjectKind::IndexRoot.too_large_error())?;
    options.index_root_fec_data_shards = required_data_shards;
    let required_parity_shards = compute_parity_u16(
        options.index_root_fec_data_shards as u64,
        options,
        "index_root_fec_parity_shards",
    )?;
    options.index_root_fec_parity_shards = options
        .index_root_fec_parity_shards
        .max(required_parity_shards);
    ensure_metadata_object_fits_class(index_root, options, MetadataObjectKind::IndexRoot)?;
    if let Some(dictionary) = dictionary {
        ensure_metadata_object_fits_class(dictionary, options, MetadataObjectKind::Dictionary)?;
    }
    Ok(MetadataClassPlan {
        options,
        index_root,
        dictionary,
    })
}

fn plan_metadata_object_without_class(
    payload_len: usize,
    options: WriterOptions,
    kind: MetadataObjectKind,
) -> Result<PlannedEncryptedObject, FormatError> {
    let plan = plan_encrypted_object_without_class(payload_len, options)
        .map_err(|_| kind.too_large_error())?;
    if plan.data_block_count > u16::MAX as u32 || plan.parity_block_count > u16::MAX as u32 {
        return Err(kind.too_large_error());
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)
        .map_err(|_| kind.too_large_error())?;
    Ok(plan)
}

fn ensure_metadata_object_fits_class(
    plan: PlannedEncryptedObject,
    options: WriterOptions,
    kind: MetadataObjectKind,
) -> Result<(), FormatError> {
    if plan.data_block_count > options.index_root_fec_data_shards as u32 {
        return Err(kind.too_large_error());
    }
    if plan.parity_block_count > options.index_root_fec_parity_shards as u32 {
        return Err(kind.too_large_error());
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)
        .map_err(|_| kind.too_large_error())
}

fn payload_object_can_fit(payload_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    encrypted_object_can_fit(
        payload_len,
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )
}

fn index_object_can_fit(payload_len: usize, options: WriterOptions) -> Result<bool, FormatError> {
    encrypted_object_can_fit(
        payload_len,
        options.index_fec_data_shards,
        options.index_fec_parity_shards,
        options,
    )
}

fn encrypted_object_can_fit(
    payload_len: usize,
    data_shard_max: u16,
    parity_shard_max: u16,
    options: WriterOptions,
) -> Result<bool, FormatError> {
    match plan_encrypted_object(payload_len, data_shard_max, parity_shard_max, options) {
        Ok(_) => Ok(true),
        Err(FormatError::WriterUnsupported("encrypted object exceeds u32 size limit"))
        | Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ))
        | Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ))
        | Err(FormatError::WriterUnsupported(
            "encrypted object exceeds ReedSolomonGF16 shard limit",
        )) => Ok(false),
        Err(err) => Err(err),
    }
}

fn plan_encrypted_object(
    payload_len: usize,
    data_shard_max: u16,
    parity_shard_max: u16,
    options: WriterOptions,
) -> Result<PlannedEncryptedObject, FormatError> {
    let plan = plan_encrypted_object_without_class(payload_len, options)?;
    if plan.data_block_count > data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ));
    }
    if plan.parity_block_count > parity_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ));
    }
    validate_object_shard_total(plan.data_block_count, plan.parity_block_count)?;
    Ok(plan)
}

fn plan_encrypted_object_without_class(
    payload_len: usize,
    options: WriterOptions,
) -> Result<PlannedEncryptedObject, FormatError> {
    let (data_block_count, encrypted_size) = encrypted_object_data_extent(payload_len, options)?;
    let parity_block_count = compute_parity(data_block_count as u64, options)?;
    Ok(PlannedEncryptedObject {
        data_block_count,
        parity_block_count,
        encrypted_size,
    })
}

fn encrypted_object_data_extent(
    payload_len: usize,
    options: WriterOptions,
) -> Result<(u32, u32), FormatError> {
    let block_size = options.block_size as usize;
    let tag_len = options.aead_algo.tag_len();
    let total_before_padding =
        payload_len
            .checked_add(tag_len)
            .ok_or(FormatError::WriterUnsupported(
                "encrypted object size overflow",
            ))?;
    let remainder = total_before_padding % block_size;
    let encrypted_size = if remainder == 0 {
        total_before_padding
            .checked_add(block_size)
            .ok_or(FormatError::WriterUnsupported(
                "encrypted object size overflow",
            ))?
    } else {
        total_before_padding
            .checked_add(block_size - remainder)
            .ok_or(FormatError::WriterUnsupported(
                "encrypted object size overflow",
            ))?
    };
    let encrypted_size = u32_len(encrypted_size, "encrypted_size")
        .map_err(|_| FormatError::WriterUnsupported("encrypted object exceeds u32 size limit"))?;
    Ok((encrypted_size / options.block_size, encrypted_size))
}

fn encrypt_object(
    payload: &[u8],
    key: &[u8; 32],
    nonce_seed: &[u8; 32],
    domain: &[u8],
    counter: u64,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    data_shard_max: u16,
    class_parity_shard_max: u16,
    next_block_index: &mut u64,
    options: WriterOptions,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
) -> Result<EncryptedObject, FormatError> {
    let block_size = options.block_size as usize;
    let padded = suffix_pad_for_aead(payload, options.aead_algo.tag_len(), block_size)?;
    let nonce = derive_nonce(
        nonce_seed,
        domain,
        archive_uuid,
        session_id,
        counter,
        options.aead_algo.nonce_len(),
    )?;
    let aad = build_aad(domain, archive_uuid, session_id, counter)?;
    let encrypted = aead_encrypt(options.aead_algo, key, &nonce, &aad, &padded)?;
    if encrypted.len() % block_size != 0 {
        return Err(FormatError::WriterInvariant(
            "encrypted object is not block aligned",
        ));
    }
    let encrypted_size = u32_len(encrypted.len(), "encrypted_size")?;
    let data_shards = encrypted
        .chunks(block_size)
        .map(|chunk| chunk.to_vec())
        .collect::<Vec<_>>();
    let data_block_count = u32_len(data_shards.len(), "data_block_count")?;
    if data_block_count == 0 {
        return Err(FormatError::WriterInvariant(
            "encrypted object has no data blocks",
        ));
    }
    if data_block_count > data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ));
    }
    let required_parity = compute_object_parity(
        data_block_count as u64,
        options,
        class_parity_shard_max as u32,
    )?;
    if required_parity > class_parity_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ));
    }
    validate_object_shard_total(data_block_count, required_parity)?;
    let parity_count = required_parity as u16;
    let parity_shards = if parity_count == 0 {
        Vec::new()
    } else {
        encode_parity_gf16(&data_shards, parity_count as usize)?
    };

    let first_block_index = *next_block_index;
    let mut records = Vec::with_capacity(data_shards.len() + parity_shards.len());
    for (index, payload) in data_shards.into_iter().enumerate() {
        records.push(BlockRecord {
            block_index: checked_u64_add(first_block_index, index as u64, "BlockRecord")?,
            kind: data_kind,
            flags: if index + 1 == data_block_count as usize {
                0x01
            } else {
                0
            },
            payload,
            record_crc32c: 0,
        });
    }
    let parity_first_block = checked_u64_add(first_block_index, data_block_count as u64, "FEC")?;
    for (index, payload) in parity_shards.into_iter().enumerate() {
        records.push(BlockRecord {
            block_index: checked_u64_add(parity_first_block, index as u64, "BlockRecord")?,
            kind: parity_kind,
            flags: 0,
            payload,
            record_crc32c: 0,
        });
    }

    *next_block_index = checked_u64_add(
        first_block_index,
        data_block_count as u64 + parity_count as u64,
        "next_block_index",
    )?;

    Ok(EncryptedObject {
        first_block_index,
        data_block_count,
        parity_block_count: parity_count as u32,
        encrypted_size,
        records,
    })
}

fn validate_planned_object(
    object: &EncryptedObject,
    expected: PlannedEncryptedObject,
) -> Result<(), FormatError> {
    if object.data_block_count != expected.data_block_count
        || object.parity_block_count != expected.parity_block_count
        || object.encrypted_size != expected.encrypted_size
    {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned sizing",
        ));
    }
    Ok(())
}

fn validate_planned_extent(
    object: &EncryptedObject,
    expected: ObjectExtent,
) -> Result<(), FormatError> {
    validate_planned_object(
        object,
        PlannedEncryptedObject {
            data_block_count: expected.data_block_count,
            parity_block_count: expected.parity_block_count,
            encrypted_size: expected.encrypted_size,
        },
    )?;
    if object.first_block_index != expected.first_block_index {
        return Err(FormatError::WriterInvariant(
            "encrypted object did not match planned extent",
        ));
    }
    Ok(())
}

fn map_metadata_encrypt_error(error: FormatError, kind: MetadataObjectKind) -> FormatError {
    match error {
        FormatError::WriterUnsupported("encrypted object exceeds u32 size limit")
        | FormatError::WriterUnsupported("encrypted object exceeds its data shard class maximum")
        | FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        )
        | FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit") => {
            kind.too_large_error()
        }
        other => other,
    }
}

fn build_manifest_footer(
    subkeys: &Subkeys,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
    total_volumes: u32,
    index_root_extent: &EncryptedObject,
    index_root_decompressed_size: usize,
) -> Result<[u8; MANIFEST_FOOTER_LEN], FormatError> {
    let mut footer = ManifestFooter {
        archive_uuid,
        session_id,
        volume_index,
        is_authoritative: 1,
        total_volumes,
        index_root_first_block: index_root_extent.first_block_index,
        index_root_data_block_count: index_root_extent.data_block_count,
        index_root_parity_block_count: index_root_extent.parity_block_count,
        index_root_encrypted_size: index_root_extent.encrypted_size,
        index_root_decompressed_size: u32_len(index_root_decompressed_size, "IndexRoot")?,
        manifest_hmac: [0u8; 32],
    };
    let mut bytes = footer.to_bytes();
    footer.manifest_hmac = compute_hmac(
        HmacDomain::ManifestFooter,
        &subkeys.mac_key,
        &archive_uuid,
        &session_id,
        &bytes[..104],
    );
    bytes = footer.to_bytes();
    Ok(bytes)
}

fn build_volume_trailer(
    subkeys: &Subkeys,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
    block_count: u64,
    bytes_written: u64,
    manifest_footer_offset: u64,
    closed_at_ns: i64,
) -> [u8; VOLUME_TRAILER_LEN] {
    let mut trailer = VolumeTrailer {
        archive_uuid,
        session_id,
        volume_index,
        block_count,
        bytes_written,
        manifest_footer_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        closed_at_ns,
        trailer_hmac: [0u8; 32],
    };
    let mut bytes = trailer.to_bytes();
    trailer.trailer_hmac = compute_hmac(
        HmacDomain::VolumeTrailer,
        &subkeys.mac_key,
        &archive_uuid,
        &session_id,
        &bytes[..96],
    );
    bytes = trailer.to_bytes();
    bytes
}

fn compute_object_parity(
    data_block_count: u64,
    options: WriterOptions,
    class_parity_shard_max: u32,
) -> Result<u32, FormatError> {
    let computed = compute_parity(data_block_count, options)?;
    if computed > class_parity_shard_max {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its parity shard class maximum",
        ));
    }
    Ok(computed)
}

fn validate_object_shard_total(
    data_block_count: u32,
    parity_block_count: u32,
) -> Result<(), FormatError> {
    let total = checked_u64_add(
        data_block_count as u64,
        parity_block_count as u64,
        "encrypted object shard total overflow",
    )?;
    if total > MAX_REED_SOLOMON_GF16_SHARDS {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds ReedSolomonGF16 shard limit",
        ));
    }
    Ok(())
}

fn compute_parity_u16(
    data_block_count: u64,
    options: WriterOptions,
    field: &'static str,
) -> Result<u16, FormatError> {
    let parity = compute_parity(data_block_count, options)?;
    u16::try_from(parity).map_err(|_| FormatError::WriterUnsupported(field))
}

fn compute_parity(data_block_count: u64, options: WriterOptions) -> Result<u32, FormatError> {
    let min_parity = if options.volume_loss_tolerance > 0 || options.bit_rot_buffer_pct > 0 {
        1u64
    } else {
        0u64
    };
    let mut parity = 0u64;
    for _ in 0..100 {
        let total = data_block_count
            .checked_add(parity)
            .ok_or(FormatError::WriterUnsupported("parity total overflow"))?;
        let by_volume = checked_u64_mul(
            options.volume_loss_tolerance as u64,
            ceil_div(total, options.stripe_width as u64)?,
            "volume-loss parity overflow",
        )?;
        let by_bitrot = ceil_div(
            checked_u64_mul(
                total,
                options.bit_rot_buffer_pct as u64,
                "bit-rot parity overflow",
            )?,
            100,
        )?;
        let next = by_volume
            .checked_add(by_bitrot)
            .ok_or(FormatError::WriterUnsupported("parity overflow"))?
            .max(min_parity);
        if next == parity {
            return u32::try_from(next).map_err(|_| FormatError::WriterUnsupported("parity count"));
        }
        parity = next;
    }
    Err(FormatError::WriterUnsupported(
        "parity calculation did not converge",
    ))
}

fn ceil_div(numerator: u64, denominator: u64) -> Result<u64, FormatError> {
    if denominator == 0 {
        return Err(FormatError::WriterUnsupported("division by zero"));
    }
    numerator
        .checked_add(denominator - 1)
        .ok_or(FormatError::WriterUnsupported("ceiling division overflow"))
        .map(|value| value / denominator)
}

fn checked_u64_mul(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_mul(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

fn build_bootstrap_sidecar(
    subkeys: &Subkeys,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    manifest_footer: &[u8; MANIFEST_FOOTER_LEN],
    index_root_records: &[BlockRecord],
    dictionary_records: Option<&[BlockRecord]>,
) -> Result<Vec<u8>, FormatError> {
    let index_records_len = index_root_records.iter().try_fold(0usize, |sum, record| {
        checked_usize_add(sum, record.to_bytes().len(), "bootstrap sidecar")
    })?;
    let dictionary_records_len = dictionary_records
        .unwrap_or(&[])
        .iter()
        .try_fold(0usize, |sum, record| {
            checked_usize_add(sum, record.to_bytes().len(), "bootstrap sidecar")
        })?;
    let manifest_offset = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
    let index_root_offset = manifest_offset + MANIFEST_FOOTER_LEN as u64;
    let dictionary_offset = if dictionary_records.is_some() {
        index_root_offset + index_records_len as u64
    } else {
        0
    };
    let mut header = BootstrapSidecarHeader {
        archive_uuid,
        session_id,
        flags: if dictionary_records.is_some() {
            0x07
        } else {
            0x03
        },
        manifest_footer_offset: manifest_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        index_root_records_offset: index_root_offset,
        index_root_records_length: index_records_len as u64,
        dictionary_records_offset: dictionary_offset,
        dictionary_records_length: dictionary_records_len as u64,
        sidecar_hmac: [0u8; 32],
        header_crc32c: 0,
    };
    let mut header_bytes = header.to_bytes();
    header.sidecar_hmac = compute_hmac(
        HmacDomain::BootstrapSidecar,
        &subkeys.mac_key,
        &archive_uuid,
        &session_id,
        &header_bytes[..92],
    );
    header_bytes = header.to_bytes();

    let mut sidecar = Vec::with_capacity(
        BOOTSTRAP_SIDECAR_HEADER_LEN
            + MANIFEST_FOOTER_LEN
            + index_records_len
            + dictionary_records_len,
    );
    sidecar.extend_from_slice(&header_bytes);
    sidecar.extend_from_slice(manifest_footer);
    for record in index_root_records {
        sidecar.extend_from_slice(&record.to_bytes());
    }
    if let Some(dictionary_records) = dictionary_records {
        for record in dictionary_records {
            sidecar.extend_from_slice(&record.to_bytes());
        }
    }
    Ok(sidecar)
}

fn build_regular_file_member_group(
    path: &[u8],
    contents: &[u8],
    mode: u32,
    mtime: u64,
) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    let header_path = if path_requires_pax(path) {
        let pax_payload = build_pax_record("path", path)?;
        let pax_header = build_ustar_header(
            b"PaxHeaders/path",
            pax_payload.len() as u64,
            0o644,
            mtime,
            b'x',
        )?;
        out.extend_from_slice(&pax_header);
        out.extend_from_slice(&pax_payload);
        out.resize(out.len() + padding_to_512(pax_payload.len()), 0);
        pax_ustar_fallback_path(path)
    } else {
        path.to_vec()
    };

    let header = build_ustar_header(&header_path, contents.len() as u64, mode, mtime, b'0')?;
    out.extend_from_slice(&header);
    out.extend_from_slice(contents);
    out.resize(out.len() + padding_to_512(contents.len()), 0);
    Ok(out)
}

fn path_requires_pax(path: &[u8]) -> bool {
    path.len() > 100 || !path.is_ascii()
}

fn pax_ustar_fallback_path(path: &[u8]) -> Vec<u8> {
    path.rsplit(|byte| *byte == b'/')
        .next()
        .filter(|component| !component.is_empty() && component.len() <= 100 && component.is_ascii())
        .map(|component| component.to_vec())
        .unwrap_or_else(|| b"pax-file".to_vec())
}

fn build_pax_record(key: &str, value: &[u8]) -> Result<Vec<u8>, FormatError> {
    let body_len = checked_usize_add(key.len(), 1, "PAX record")?;
    let body_len = checked_usize_add(body_len, value.len(), "PAX record")?;
    let body_len = checked_usize_add(body_len, 1, "PAX record")?;
    let mut digits = 1usize;
    loop {
        let len = checked_usize_add(digits, 1, "PAX record")?;
        let len = checked_usize_add(len, body_len, "PAX record")?;
        let next_digits = len.to_string().len();
        if next_digits == digits {
            let mut out = Vec::with_capacity(len);
            out.extend_from_slice(len.to_string().as_bytes());
            out.push(b' ');
            out.extend_from_slice(key.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value);
            out.push(b'\n');
            return Ok(out);
        }
        digits = next_digits;
    }
}

fn build_ustar_header(
    path: &[u8],
    size: u64,
    mode: u32,
    mtime: u64,
    typeflag: u8,
) -> Result<[u8; TAR_BLOCK_LEN], FormatError> {
    if path.len() > 100 {
        return Err(FormatError::WriterUnsupported(
            "ustar path exceeds name field",
        ));
    }
    let mut header = [0u8; TAR_BLOCK_LEN];
    header[0..path.len()].copy_from_slice(path);
    write_tar_octal(&mut header[100..108], mode as u64)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    write_tar_octal(&mut header[124..136], size)?;
    write_tar_octal(&mut header[136..148], mtime)?;
    header[148..156].fill(b' ');
    header[156] = typeflag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| *byte as u32).sum::<u32>() as u64;
    write_tar_checksum(&mut header[148..156], checksum)?;
    Ok(header)
}

fn write_tar_octal(field: &mut [u8], value: u64) -> Result<(), FormatError> {
    let digits = format!("{value:o}");
    if digits.len() + 1 > field.len() {
        return Err(FormatError::WriterUnsupported("tar octal field overflow"));
    }
    field.fill(0);
    let padding = field.len() - 1 - digits.len();
    for byte in &mut field[..padding] {
        *byte = b'0';
    }
    field[padding..padding + digits.len()].copy_from_slice(digits.as_bytes());
    Ok(())
}

fn write_tar_checksum(field: &mut [u8], value: u64) -> Result<(), FormatError> {
    let digits = format!("{value:06o}");
    if digits.len() != 6 {
        return Err(FormatError::WriterUnsupported(
            "tar checksum field overflow",
        ));
    }
    field[0..6].copy_from_slice(digits.as_bytes());
    field[6] = 0;
    field[7] = b' ';
    Ok(())
}

fn member_frame_range(
    member_index: usize,
    frames: &[PayloadFrame],
) -> Result<(u64, u32), FormatError> {
    let first = frames
        .iter()
        .find(|frame| frame.member_index == member_index)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("member frame is missing"))?;
    let count = frames
        .iter()
        .filter(|frame| frame.member_index == member_index)
        .count();
    Ok((first, u32_len(count, "FileEntry.frame_count")?))
}

fn envelope_frame_range(
    envelope_index: u64,
    frames: &[PayloadFrame],
) -> Result<(u64, u32), FormatError> {
    let first = frames
        .iter()
        .find(|frame| frame.envelope_index == envelope_index)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("envelope frame is missing"))?;
    let count = frames
        .iter()
        .filter(|frame| frame.envelope_index == envelope_index)
        .count();
    Ok((first, u32_len(count, "EnvelopeEntry.frame_count")?))
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

fn table_offset(len: usize, cursor: usize) -> Result<u32, FormatError> {
    if len == 0 {
        Ok(0)
    } else {
        u32_len(cursor, "table offset")
    }
}

fn u32_len(value: usize, field: &'static str) -> Result<u32, FormatError> {
    u32::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
}

fn checked_usize_add(lhs: usize, rhs: usize, field: &'static str) -> Result<usize, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

fn checked_u64_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{verify_hmac, Subkeys};
    use crate::metadata::{DirectoryHintTable, MetadataLimits};
    use crate::reader::open_archive;
    use crate::tar_model::parse_tar_member_group;
    use crate::wire::CryptoHeader;

    #[test]
    fn writer_defaults_use_v36_sizing_and_parallel_mode() {
        let options = WriterOptions::default();

        assert_eq!(options.chunk_size, 256 * 1024);
        assert_eq!(options.envelope_target_size, 1024 * 1024);
        assert_eq!(options.block_size, 64 * 1024);
        assert_eq!(options.stripe_width, 8);
        assert_eq!(options.volume_loss_tolerance, 1);
        assert_eq!(options.fec_data_shards, 224);
        assert_eq!(options.index_fec_data_shards, 16);
        assert_eq!(
            options.index_root_fec_data_shards,
            MIN_INDEX_ROOT_FEC_DATA_SHARDS
        );
        assert_eq!(options.bit_rot_buffer_pct, 5);
    }

    #[test]
    fn writer_partitions_multiple_default_sized_index_shards() {
        let members = (0..=DEFAULT_FILES_PER_INDEX_SHARD)
            .map(|idx| TarMember {
                path: format!("file-{idx:05}.txt").into_bytes(),
                tar_member_group_start: idx as u64 * 512,
                tar_member_group_size: 512,
                file_data_size: 0,
            })
            .collect::<Vec<_>>();

        let shards = partition_file_rows(sorted_file_rows(&members)).unwrap();

        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].len(), DEFAULT_FILES_PER_INDEX_SHARD);
        assert_eq!(shards[1].len(), 1);
    }

    #[test]
    fn writer_extends_shard_for_bounded_hash_prefix_run() {
        let mut rows = Vec::new();
        rows.extend((0..9_000).map(|idx| test_file_row(idx, [0u8; 8])));
        rows.extend((9_000..54_000).map(|idx| test_file_row(idx, [1u8; 8])));
        rows.push(test_file_row(54_000, [2u8; 8]));

        let shards = partition_file_rows(rows).unwrap();

        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].len(), 54_000);
        assert!(shards[0]
            .iter()
            .skip(9_000)
            .all(|row| row.path_hash == [1u8; 8]));
        assert_eq!(shards[1][0].path_hash, [2u8; 8]);
    }

    #[test]
    fn writer_splits_oversized_hash_prefix_run_at_writer_ceiling() {
        let rows = (0..MAX_HASH_PREFIX_RUN_FILES + 1)
            .map(|idx| test_file_row(idx, [7u8; 8]))
            .collect::<Vec<_>>();

        let shards = partition_file_rows(rows).unwrap();

        assert_eq!(shards.len(), 2);
        assert_eq!(shards[0].len(), MAX_HASH_PREFIX_RUN_FILES);
        assert_eq!(shards[1].len(), 1);
    }

    #[test]
    fn writer_builds_directory_hint_rows_for_ancestor_directories() {
        let shard_rows = vec![
            vec![FileRow {
                path_hash: hash_prefix(b"a/b/one.txt"),
                path: b"a/b/one.txt".to_vec(),
                member_index: 0,
                member: TarMember {
                    path: b"a/b/one.txt".to_vec(),
                    tar_member_group_start: 0,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                },
            }],
            vec![FileRow {
                path_hash: hash_prefix(b"a/c/two.txt"),
                path: b"a/c/two.txt".to_vec(),
                member_index: 1,
                member: TarMember {
                    path: b"a/c/two.txt".to_vec(),
                    tar_member_group_start: 512,
                    tar_member_group_size: 512,
                    file_data_size: 0,
                },
            }],
        ];

        let options = plan_writer_options(WriterOptions::default()).unwrap();
        let planned = build_directory_hint_plaintexts(&shard_rows, options).unwrap();
        assert_eq!(planned.len(), 1);
        let locating = DirectoryHintShardEntry {
            hint_shard_index: planned[0].hint_shard_index,
            first_dir_hash: planned[0].first_dir_hash,
            last_dir_hash: planned[0].last_dir_hash,
            first_block_index: 0,
            data_block_count: 1,
            parity_block_count: 0,
            encrypted_size: 4096,
            decompressed_size: planned[0].plaintext.len() as u32,
            entry_count: planned[0].entry_count,
        };
        let table = DirectoryHintTable::parse(
            &planned[0].plaintext,
            &locating,
            2,
            MetadataLimits::default(),
        )
        .unwrap();

        let root = table.lookup_directory_index(b"").unwrap();
        assert_eq!(table.shard_rows_for_entry(root).unwrap(), &[0, 1]);
        let a = table.lookup_directory_index(b"a").unwrap();
        assert_eq!(table.shard_rows_for_entry(a).unwrap(), &[0, 1]);
        let ab = table.lookup_directory_index(b"a/b").unwrap();
        assert_eq!(table.shard_rows_for_entry(ab).unwrap(), &[0]);
    }

    #[test]
    fn directory_hints_are_required_only_above_v36_threshold() {
        assert!(!should_emit_directory_hints(0));
        assert!(!should_emit_directory_hints(
            DIRECTORY_HINT_REQUIRED_FILE_COUNT
        ));
        assert!(should_emit_directory_hints(
            DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1
        ));
    }

    #[test]
    fn regular_file_writer_uses_local_pax_path_for_long_and_non_ascii_paths() {
        let long_path = format!("dir/{}.txt", "a".repeat(120));
        let unicode_path = "unicode/e\u{301}.txt";
        let files = [
            RegularFile::new(&long_path, b"long path"),
            RegularFile::new(unicode_path, b"unicode path"),
        ];

        let (tar_stream, members) = build_tar_stream(&files, 4096).unwrap();

        for (member, expected_path, expected_data) in [
            (&members[0], long_path.as_bytes(), b"long path".as_slice()),
            (
                &members[1],
                "unicode/\u{e9}.txt".as_bytes(),
                b"unicode path".as_slice(),
            ),
        ] {
            let start = member.tar_member_group_start as usize;
            let end = start + member.tar_member_group_size as usize;
            let group = &tar_stream[start..end];
            assert_eq!(group[156], b'x');
            let parsed = parse_tar_member_group(group, 4096).unwrap();
            assert_eq!(parsed.path, expected_path);
            assert_eq!(parsed.data, expected_data);
        }
    }

    #[test]
    fn writer_splits_large_payload_across_seekable_envelopes() {
        let master_key = MasterKey::from_raw_key(&[8u8; 32]).unwrap();
        let data = deterministic_bytes(2 * 1024 * 1024);
        let archive = write_archive(
            &[RegularFile::new("large.bin", &data)],
            &master_key,
            WriterOptions {
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                ..WriterOptions::default()
            },
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key).unwrap();

        assert_eq!(opened.list_files().unwrap()[0].path, "large.bin");
        assert_eq!(opened.extract_file("large.bin").unwrap(), Some(data));
        opened.verify().unwrap();
        assert!(opened.index_root.header.envelope_count > 1);
    }

    #[test]
    fn split_member_frames_carry_exact_boundary_flags() {
        let data = deterministic_bytes(12 * 1024);
        let files = [RegularFile::new("large.bin", &data)];
        let options = WriterOptions {
            chunk_size: 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        };
        let (tar_stream, members) = build_tar_stream(&files, options.max_path_length).unwrap();
        let (_, frames) = build_payload_envelopes(&tar_stream, &members, options, None).unwrap();

        assert!(frames.len() > 2);
        assert_eq!(frames.first().unwrap().flags, 0x0000_0001);
        assert_eq!(frames.last().unwrap().flags, 0x0000_0002);
        assert!(frames[1..frames.len() - 1]
            .iter()
            .all(|frame| frame.flags == 0));
    }

    #[test]
    fn writes_empty_archive_with_authentic_bootstrap_structures() {
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let archive = write_empty_archive(&master_key).unwrap();
        let bytes = archive.bytes;

        let volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(volume_header.archive_uuid, archive.archive_uuid);
        assert_eq!(volume_header.session_id, archive.session_id);

        let crypto_start = VOLUME_HEADER_LEN;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys =
            Subkeys::derive(&master_key, &archive.archive_uuid, &archive.session_id).unwrap();
        verify_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            crypto_header.hmac_covered_bytes,
            &crypto_header.header_hmac,
        )
        .unwrap();

        let trailer_offset = bytes.len() - VOLUME_TRAILER_LEN;
        let trailer = VolumeTrailer::parse(&bytes[trailer_offset..]).unwrap();
        assert_eq!(trailer.bytes_written, trailer_offset as u64);
        verify_hmac(
            HmacDomain::VolumeTrailer,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            &bytes[trailer_offset..trailer_offset + 96],
            &trailer.trailer_hmac,
        )
        .unwrap();

        let manifest_offset = trailer.manifest_footer_offset as usize;
        let manifest_end = manifest_offset + MANIFEST_FOOTER_LEN;
        let manifest = ManifestFooter::parse(&bytes[manifest_offset..manifest_end]).unwrap();
        assert_eq!(manifest.is_authoritative, 1);
        assert_eq!(manifest.total_volumes, DEFAULT_STRIPE_WIDTH);
        verify_hmac(
            HmacDomain::ManifestFooter,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            &bytes[manifest_offset..manifest_offset + 104],
            &manifest.manifest_hmac,
        )
        .unwrap();
    }

    #[test]
    fn parity_auto_scaling_matches_v36_examples() {
        let options = WriterOptions {
            fec_data_shards: 224,
            stripe_width: 8,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 5,
            ..WriterOptions::default()
        };

        assert_eq!(compute_parity(224, options).unwrap(), 48);
        assert_eq!(compute_parity(17, options).unwrap(), 5);
    }

    #[test]
    fn zero_parity_is_allowed_when_no_recovery_margin_is_requested() {
        let planned = plan_writer_options(WriterOptions {
            bit_rot_buffer_pct: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();

        assert_eq!(planned.fec_parity_shards, 0);
        assert_eq!(planned.index_fec_parity_shards, 0);
        assert_eq!(planned.index_root_fec_parity_shards, 0);
        assert_eq!(compute_parity(1, planned).unwrap(), 0);
    }

    #[test]
    fn index_root_data_shard_maximum_obeys_v36_minimum() {
        let planned = plan_writer_options(WriterOptions {
            index_root_fec_data_shards: 1,
            ..WriterOptions::default()
        })
        .unwrap();

        assert_eq!(
            planned.index_root_fec_data_shards,
            MIN_INDEX_ROOT_FEC_DATA_SHARDS
        );
    }

    #[test]
    fn metadata_class_planning_raises_index_root_class_above_default() {
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            index_root_fec_parity_shards: 0,
            bit_rot_buffer_pct: 0,
            ..WriterOptions::default()
        })
        .unwrap();
        let index_root_payload_len = payload_len_for_encrypted_data_blocks(64, options);

        let planned =
            plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap();

        assert_eq!(planned.index_root.data_block_count, 64);
        assert_eq!(planned.options.index_root_fec_data_shards, 64);
        assert_eq!(
            planned.options.index_root_fec_parity_shards,
            compute_parity_u16(
                planned.options.index_root_fec_data_shards as u64,
                planned.options,
                "index_root_fec_parity_shards",
            )
            .unwrap()
        );
    }

    #[test]
    fn metadata_class_planning_rejects_oversized_index_root() {
        let options = single_volume_metadata_test_options();
        let index_root_payload_len =
            payload_len_for_encrypted_data_blocks(u16::MAX as u32 + 1, options);

        let err =
            plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap_err();

        assert_eq!(err, FormatError::WriterUnsupported("IndexRoot too large"));
    }

    #[test]
    fn metadata_class_planning_rejects_index_root_u32_encrypted_size_overflow() {
        let options = single_volume_metadata_test_options();
        let index_root_payload_len = u32::MAX as usize - options.aead_algo.tag_len() + 1;

        let err =
            plan_index_root_metadata_class(options, index_root_payload_len, None).unwrap_err();

        assert_eq!(err, FormatError::WriterUnsupported("IndexRoot too large"));
    }

    #[test]
    fn metadata_class_planning_rejects_oversized_dictionary() {
        let options = single_volume_metadata_test_options();
        let dictionary_payload_len =
            payload_len_for_encrypted_data_blocks(u16::MAX as u32 + 1, options);

        let err =
            plan_index_root_metadata_class(options, 1, Some(dictionary_payload_len)).unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("dictionary object too large")
        );
    }

    #[test]
    fn metadata_class_planning_rejects_gf16_total_overflow_for_dictionary() {
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 8,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 5,
            ..WriterOptions::default()
        })
        .unwrap();
        let dictionary_payload_len = payload_len_for_encrypted_data_blocks(60_000, options);

        let err =
            plan_index_root_metadata_class(options, 1, Some(dictionary_payload_len)).unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("dictionary object too large")
        );
    }

    #[test]
    fn written_archive_authenticates_final_index_root_fec_class() {
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let dictionary = deterministic_bytes(80 * 1024);
        let file = RegularFile::new("uses-dictionary.txt", b"payload");
        let archive = write_archive_with_dictionary(
            &[file],
            &master_key,
            WriterOptions {
                block_size: MIN_BLOCK_SIZE,
                stripe_width: 1,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 0,
                index_root_fec_parity_shards: 0,
                ..WriterOptions::default()
            },
            &dictionary,
        )
        .unwrap();

        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = VOLUME_HEADER_LEN;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys =
            Subkeys::derive(&master_key, &archive.archive_uuid, &archive.session_id).unwrap();
        verify_hmac(
            HmacDomain::CryptoHeader,
            &subkeys.mac_key,
            &archive.archive_uuid,
            &archive.session_id,
            crypto_header.hmac_covered_bytes,
            &crypto_header.header_hmac,
        )
        .unwrap();

        assert!(crypto_header.fixed.index_root_fec_data_shards > MIN_INDEX_ROOT_FEC_DATA_SHARDS);
        assert_eq!(crypto_header.fixed.index_root_fec_parity_shards, 0);
        let opened = open_archive(&archive.bytes, &master_key).unwrap();
        assert_eq!(
            opened.extract_file("uses-dictionary.txt").unwrap(),
            Some(b"payload".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn object_parity_uses_per_object_recurrence_even_with_larger_class_max() {
        let options = WriterOptions {
            bit_rot_buffer_pct: 0,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            fec_parity_shards: 1,
            ..WriterOptions::default()
        };

        assert_eq!(compute_object_parity(1, options, 1).unwrap(), 0);
    }

    #[test]
    fn object_total_shards_obeys_reed_solomon_limit() {
        assert!(validate_object_shard_total(65_535, 0).is_ok());
        assert_eq!(
            validate_object_shard_total(65_535, 1).unwrap_err(),
            FormatError::WriterUnsupported("encrypted object exceeds ReedSolomonGF16 shard limit")
        );
    }

    #[test]
    fn argon2id_kdf_serialization_rejects_memory_requirement_overflow() {
        assert_eq!(
            serialize_kdf_params(&KdfParams::Argon2id {
                t_cost: 1,
                m_cost_kib: u32::MAX,
                parallelism: u32::MAX,
                salt: b"12345678".to_vec(),
            })
            .unwrap_err(),
            FormatError::InvalidKdfParams("m_cost_kib requirement overflow")
        );
    }

    fn deterministic_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x4d41_4d45u32;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            out.push((state >> 24) as u8);
        }
        out
    }

    fn single_volume_metadata_test_options() -> WriterOptions {
        plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap()
    }

    fn payload_len_for_encrypted_data_blocks(
        data_block_count: u32,
        options: WriterOptions,
    ) -> usize {
        assert!(data_block_count > 0);
        if data_block_count == 1 {
            return 1;
        }
        let block_size = options.block_size as usize;
        (data_block_count as usize - 1) * block_size - options.aead_algo.tag_len() + 1
    }

    fn test_file_row(idx: usize, path_hash: [u8; 8]) -> FileRow {
        let path = format!("file-{idx:05}.txt").into_bytes();
        FileRow {
            path_hash,
            path: path.clone(),
            member_index: idx,
            member: TarMember {
                path,
                tar_member_group_start: idx as u64 * 512,
                tar_member_group_size: 512,
                file_data_size: 0,
            },
        }
    }
}
