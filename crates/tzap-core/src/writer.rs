use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compression::{compress_zstd_frame, compress_zstd_frame_with_dictionary};
use crate::crypto::{
    aead_encrypt, build_aad, compute_hmac, derive_nonce, HmacDomain, MasterKey, Subkeys,
};
use crate::fec::encode_parity_gf16;
use crate::format::{
    AeadAlgo, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo,
    BOOTSTRAP_SIDECAR_HEADER_LEN, CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN,
    CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, MANIFEST_FOOTER_LEN, VOLUME_FORMAT_REV,
    VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, EnvelopeEntry, FileEntry, FrameEntry, IndexRoot,
    IndexRootHeader, IndexShardHeader, ShardEntry, ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN,
    FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
};
use crate::padding::suffix_pad_for_aead;
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CryptoHeaderFixed, ManifestFooter, VolumeHeader,
    VolumeTrailer,
};

const TAR_BLOCK_LEN: usize = 512;
const DEFAULT_BLOCK_SIZE: u32 = 4096;
const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;
const DEFAULT_ENVELOPE_TARGET_SIZE: u32 = 4 << 20;
const DEFAULT_FEC_DATA_SHARDS: u16 = 64;
const DEFAULT_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_INDEX_FEC_DATA_SHARDS: u16 = 64;
const DEFAULT_INDEX_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS: u16 = 64;
const DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS: u16 = 1;
const DEFAULT_MAX_FILES_PER_INDEX_SHARD: usize = 1_000_000;
const DIRECTORY_HINT_REQUIRED_FILE_COUNT: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterOptions {
    pub block_size: u32,
    pub chunk_size: u32,
    pub envelope_target_size: u32,
    pub zstd_level: i32,
    pub aead_algo: AeadAlgo,
    pub fec_data_shards: u16,
    pub fec_parity_shards: u16,
    pub index_fec_data_shards: u16,
    pub index_fec_parity_shards: u16,
    pub index_root_fec_data_shards: u16,
    pub index_root_fec_parity_shards: u16,
    pub max_path_length: u32,
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
            zstd_level: 3,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_data_shards: DEFAULT_FEC_DATA_SHARDS,
            fec_parity_shards: DEFAULT_FEC_PARITY_SHARDS,
            index_fec_data_shards: DEFAULT_INDEX_FEC_DATA_SHARDS,
            index_fec_parity_shards: DEFAULT_INDEX_FEC_PARITY_SHARDS,
            index_root_fec_data_shards: DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS,
            index_root_fec_parity_shards: DEFAULT_INDEX_ROOT_FEC_PARITY_SHARDS,
            max_path_length: 4096,
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
    offset_in_envelope: u32,
    compressed_size: u32,
    decompressed_size: u32,
    tar_stream_offset: u64,
}

#[derive(Debug, Clone)]
struct EncryptedObject {
    first_block_index: u64,
    data_block_count: u32,
    parity_block_count: u32,
    encrypted_size: u32,
    records: Vec<BlockRecord>,
}

pub fn write_archive(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(files, master_key, options, None)
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
    write_archive_inner(files, master_key, options, Some(dictionary))
}

fn write_archive_inner(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
) -> Result<WrittenArchive, FormatError> {
    validate_options(options)?;
    validate_m6_file_scope(files.len())?;

    let archive_uuid = options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(
        options,
        dictionary.is_some(),
        &subkeys,
        &archive_uuid,
        &session_id,
    )?;

    let mut next_block_index = 0u64;
    let mut block_records = Vec::new();
    let (tar_stream, tar_members) = build_tar_stream(files, options.max_path_length)?;
    let tar_total_size = tar_stream.len() as u64;
    let content_sha256 = sha256_bytes(&tar_stream);

    let (payload_extent, frames, payload_block_count) = if tar_stream.is_empty() {
        (None, Vec::new(), 0u64)
    } else {
        let (payload_plaintext, frames) =
            build_payload_envelope(&tar_stream, &tar_members, options, dictionary)?;
        let object = encrypt_object(
            &payload_plaintext,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            0,
            BlockKind::PayloadData,
            BlockKind::PayloadParity,
            options.fec_data_shards,
            options.fec_parity_shards,
            &mut next_block_index,
            options,
            &archive_uuid,
            &session_id,
        )?;
        let payload_block_count = object.data_block_count as u64;
        block_records.extend(object.records.clone());
        (Some(object), frames, payload_block_count)
    };

    let (index_shard_extent, shard_entries, frame_count, envelope_count) = if tar_members.is_empty()
    {
        (None, Vec::new(), 0u64, 0u64)
    } else {
        let payload = payload_extent
            .as_ref()
            .ok_or(FormatError::WriterInvariant("payload extent missing"))?;
        let index_shard_plaintext =
            build_single_index_shard(&tar_members, &frames, payload, options)?;
        let compressed = compress_zstd_frame(&index_shard_plaintext, options.zstd_level)?;
        let object = encrypt_object(
            &compressed,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            0,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            &mut next_block_index,
            options,
            &archive_uuid,
            &session_id,
        )?;
        let (first_hash, last_hash) = file_hash_bounds(&tar_members)?;
        let shard_entry = ShardEntry {
            shard_index: 0,
            first_block_index: object.first_block_index,
            data_block_count: object.data_block_count,
            parity_block_count: object.parity_block_count,
            encrypted_size: object.encrypted_size,
            decompressed_size: u32_len(index_shard_plaintext.len(), "IndexShard")?,
            file_count: u32_len(tar_members.len(), "IndexShard.file_count")?,
            first_path_hash: first_hash,
            last_path_hash: last_hash,
        };
        block_records.extend(object.records.clone());
        (Some(object), vec![shard_entry], frames.len() as u64, 1u64)
    };

    let dictionary_extent = if let Some(dictionary) = dictionary {
        let compressed_dictionary = compress_zstd_frame(dictionary, options.zstd_level)?;
        let object = encrypt_object(
            &compressed_dictionary,
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
        )?;
        block_records.extend(object.records.clone());
        Some((object, dictionary.len() as u32))
    } else {
        None
    };

    let index_root_plaintext = build_index_root_plaintext(
        &shard_entries,
        frame_count,
        envelope_count,
        tar_members.len() as u64,
        payload_block_count,
        tar_total_size,
        content_sha256,
        dictionary_extent
            .as_ref()
            .map(|(object, decompressed_size)| (object, *decompressed_size)),
    );
    let compressed_index_root = compress_zstd_frame(&index_root_plaintext, options.zstd_level)?;
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
    )?;
    block_records.extend(index_root_extent.records.clone());

    let volume_header = VolumeHeader {
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        volume_index: 0,
        stripe_width: 1,
        archive_uuid,
        session_id,
        crypto_header_offset: VOLUME_HEADER_LEN as u32,
        crypto_header_length: u32_len(crypto_header.len(), "CryptoHeader")?,
        header_crc32c: 0,
    };

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&volume_header.to_bytes());
    bytes.extend_from_slice(&crypto_header);
    for record in &block_records {
        bytes.extend_from_slice(&record.to_bytes());
    }

    let manifest_footer_offset = bytes.len() as u64;
    let manifest_footer = build_manifest_footer(
        &subkeys,
        archive_uuid,
        session_id,
        &index_root_extent,
        index_root_plaintext.len(),
    )?;
    bytes.extend_from_slice(&manifest_footer);

    let bytes_written = bytes.len() as u64;
    let trailer = build_volume_trailer(
        &subkeys,
        archive_uuid,
        session_id,
        block_records.len() as u64,
        bytes_written,
        manifest_footer_offset,
        options.closed_at_ns,
    );
    bytes.extend_from_slice(&trailer);

    let bootstrap_sidecar = build_bootstrap_sidecar(
        &subkeys,
        archive_uuid,
        session_id,
        &manifest_footer,
        &index_root_extent.records,
        dictionary_extent
            .as_ref()
            .map(|(object, _)| object.records.as_slice()),
    )?;

    let _ = index_shard_extent;

    Ok(WrittenArchive {
        bytes,
        bootstrap_sidecar,
        archive_uuid,
        session_id,
    })
}

pub fn write_empty_archive(master_key: &MasterKey) -> Result<WrittenArchive, FormatError> {
    write_archive(&[], master_key, WriterOptions::default())
}

fn validate_options(options: WriterOptions) -> Result<(), FormatError> {
    if options.block_size < DEFAULT_BLOCK_SIZE || options.block_size % 2 != 0 {
        return Err(FormatError::WriterUnsupported(
            "M6 writer requires an even block size of at least 4096",
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
    if options.fec_parity_shards == 0
        || options.index_fec_parity_shards == 0
        || options.index_root_fec_parity_shards == 0
    {
        return Err(FormatError::WriterUnsupported(
            "M6 writer keeps ReedSolomonGF16 parity enabled",
        ));
    }
    Ok(())
}

fn validate_m6_file_scope(file_count: usize) -> Result<(), FormatError> {
    if file_count > DEFAULT_MAX_FILES_PER_INDEX_SHARD {
        return Err(FormatError::WriterUnsupported(
            "M6 writer supports only one IndexShard",
        ));
    }
    if file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT {
        return Err(FormatError::WriterUnsupported(
            "M6 writer does not emit required directory hint shards",
        ));
    }
    Ok(())
}

fn build_crypto_header(
    options: WriterOptions,
    has_dictionary: bool,
    subkeys: &Subkeys,
    archive_uuid: &[u8; 16],
    session_id: &[u8; 16],
) -> Result<Vec<u8>, FormatError> {
    let length = CRYPTO_HEADER_FIXED_LEN + 2 + CRYPTO_EXTENSION_HEADER_LEN + CRYPTO_HEADER_HMAC_LEN;
    let fixed = CryptoHeaderFixed {
        length: length as u32,
        compression_algo: CompressionAlgo::ZstdFramed,
        aead_algo: options.aead_algo,
        fec_algo: FecAlgo::ReedSolomonGF16,
        kdf_algo: KdfAlgo::Raw,
        chunk_size: options.chunk_size,
        envelope_target_size: options.envelope_target_size,
        block_size: options.block_size,
        fec_data_shards: options.fec_data_shards,
        fec_parity_shards: options.fec_parity_shards,
        index_fec_data_shards: options.index_fec_data_shards,
        index_fec_parity_shards: options.index_fec_parity_shards,
        index_root_fec_data_shards: options.index_root_fec_data_shards,
        index_root_fec_parity_shards: options.index_root_fec_parity_shards,
        stripe_width: 1,
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        has_dictionary: if has_dictionary { 1 } else { 0 },
        max_path_length: options.max_path_length,
        expected_volume_size: 0,
    };

    let mut bytes = fixed.to_bytes().to_vec();
    bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
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

fn build_tar_stream(
    files: &[RegularFile<'_>],
    max_path_length: u32,
) -> Result<(Vec<u8>, Vec<TarMember>), FormatError> {
    let mut stream = Vec::new();
    let mut members = Vec::with_capacity(files.len());
    for file in files {
        let path = normalize_lookup_file_path(file.path, max_path_length)?;
        if path.len() > 100 {
            return Err(FormatError::WriterUnsupported(
                "M6 regular-file writer supports ustar paths up to 100 bytes",
            ));
        }
        let start = stream.len() as u64;
        let header =
            build_ustar_regular_header(&path, file.contents.len() as u64, file.mode, file.mtime)?;
        stream.extend_from_slice(&header);
        stream.extend_from_slice(file.contents);
        let data_padding = padding_to_512(file.contents.len());
        stream.resize(stream.len() + data_padding, 0);
        members.push(TarMember {
            path,
            tar_member_group_start: start,
            tar_member_group_size: (TAR_BLOCK_LEN + file.contents.len() + data_padding) as u64,
            file_data_size: file.contents.len() as u64,
        });
    }
    Ok((stream, members))
}

fn build_payload_envelope(
    tar_stream: &[u8],
    members: &[TarMember],
    options: WriterOptions,
    dictionary: Option<&[u8]>,
) -> Result<(Vec<u8>, Vec<PayloadFrame>), FormatError> {
    let mut plaintext = Vec::new();
    let mut frames = Vec::with_capacity(members.len());
    for (index, member) in members.iter().enumerate() {
        let start = member.tar_member_group_start as usize;
        let end = checked_usize_add(start, member.tar_member_group_size as usize, "tar member")?;
        let member_bytes = tar_stream
            .get(start..end)
            .ok_or(FormatError::WriterInvariant(
                "tar member range is out of bounds",
            ))?;
        let frame = if let Some(dictionary) = dictionary {
            compress_zstd_frame_with_dictionary(member_bytes, options.zstd_level, dictionary)?
        } else {
            compress_zstd_frame(member_bytes, options.zstd_level)?
        };
        let offset = u32_len(plaintext.len(), "FrameEntry.offset_in_envelope")?;
        plaintext.extend_from_slice(&frame);
        frames.push(PayloadFrame {
            frame_index: index as u64,
            offset_in_envelope: offset,
            compressed_size: u32_len(frame.len(), "FrameEntry.compressed_size")?,
            decompressed_size: u32_len(member_bytes.len(), "FrameEntry.decompressed_size")?,
            tar_stream_offset: member.tar_member_group_start,
        });
    }
    if plaintext.len() > options.envelope_target_size as usize {
        return Err(FormatError::WriterUnsupported(
            "M6 writer supports one small payload envelope",
        ));
    }
    Ok((plaintext, frames))
}

fn build_single_index_shard(
    members: &[TarMember],
    frames: &[PayloadFrame],
    payload: &EncryptedObject,
    options: WriterOptions,
) -> Result<Vec<u8>, FormatError> {
    let mut file_rows = members
        .iter()
        .map(|member| {
            let path_hash = hash_prefix(&member.path);
            Ok((path_hash, member.path.clone(), member.clone()))
        })
        .collect::<Result<Vec<_>, FormatError>>()?;
    file_rows.sort_by(|left, right| {
        (left.0, left.1.as_slice(), left.2.tar_member_group_start).cmp(&(
            right.0,
            right.1.as_slice(),
            right.2.tar_member_group_start,
        ))
    });

    let mut string_pool = Vec::new();
    let mut file_entries = Vec::with_capacity(file_rows.len());
    for (path_hash, path, member) in file_rows {
        let path_offset = u32_len(string_pool.len(), "FileEntry.path_offset")?;
        string_pool.extend_from_slice(&path);
        file_entries.push(FileEntry {
            path_hash,
            path_offset,
            path_length: u32_len(path.len(), "FileEntry.path_length")?,
            first_frame_index: member_frame_index(&member, frames)?,
            frame_count: 1,
            offset_in_first_frame_plaintext: 0,
            tar_member_group_size: member.tar_member_group_size,
            file_data_size: member.file_data_size,
            flags: 0,
        });
    }

    let frame_entries = frames
        .iter()
        .map(|frame| FrameEntry {
            frame_index: frame.frame_index,
            envelope_index: 0,
            offset_in_envelope: frame.offset_in_envelope,
            compressed_size: frame.compressed_size,
            decompressed_size: frame.decompressed_size,
            flags: 0x0000_0003,
            tar_stream_offset: frame.tar_stream_offset,
        })
        .collect::<Vec<_>>();
    let envelope_entries = vec![EnvelopeEntry {
        envelope_index: 0,
        first_block_index: payload.first_block_index,
        data_block_count: payload.data_block_count,
        parity_block_count: payload.parity_block_count,
        encrypted_size: payload.encrypted_size,
        plaintext_size: frames
            .last()
            .map(|frame| frame.offset_in_envelope + frame.compressed_size)
            .unwrap_or(0),
        first_frame_index: 0,
        frame_count: u32_len(frames.len(), "EnvelopeEntry.frame_count")?,
    }];

    serialize_index_shard(
        0,
        &file_entries,
        &frame_entries,
        &envelope_entries,
        &string_pool,
        options,
    )
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

fn build_index_root_plaintext(
    shard_entries: &[ShardEntry],
    frame_count: u64,
    envelope_count: u64,
    file_count: u64,
    payload_block_count: u64,
    tar_total_size: u64,
    content_sha256: [u8; 32],
    dictionary_extent: Option<(&EncryptedObject, u32)>,
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
        directory_hint_shards: Vec::new(),
    };
    root.to_bytes()
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
    parity_count: u16,
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

fn build_manifest_footer(
    subkeys: &Subkeys,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    index_root_extent: &EncryptedObject,
    index_root_decompressed_size: usize,
) -> Result<[u8; MANIFEST_FOOTER_LEN], FormatError> {
    let mut footer = ManifestFooter {
        archive_uuid,
        session_id,
        volume_index: 0,
        is_authoritative: 1,
        total_volumes: 1,
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
    block_count: u64,
    bytes_written: u64,
    manifest_footer_offset: u64,
    closed_at_ns: i64,
) -> [u8; VOLUME_TRAILER_LEN] {
    let mut trailer = VolumeTrailer {
        archive_uuid,
        session_id,
        volume_index: 0,
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

fn build_ustar_regular_header(
    path: &[u8],
    size: u64,
    mode: u32,
    mtime: u64,
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
    header[156] = b'0';
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

fn member_frame_index(member: &TarMember, frames: &[PayloadFrame]) -> Result<u64, FormatError> {
    frames
        .iter()
        .find(|frame| frame.tar_stream_offset == member.tar_member_group_start)
        .map(|frame| frame.frame_index)
        .ok_or(FormatError::WriterInvariant("member frame is missing"))
}

fn file_hash_bounds(members: &[TarMember]) -> Result<([u8; 8], [u8; 8]), FormatError> {
    let first = members
        .iter()
        .map(|member| hash_prefix(&member.path))
        .min()
        .ok_or(FormatError::WriterInvariant("missing first hash"))?;
    let last = members
        .iter()
        .map(|member| hash_prefix(&member.path))
        .max()
        .ok_or(FormatError::WriterInvariant("missing last hash"))?;
    Ok((first, last))
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
    use crate::wire::CryptoHeader;

    #[test]
    fn m6_scope_rejects_archives_that_require_directory_hints() {
        assert!(validate_m6_file_scope(DIRECTORY_HINT_REQUIRED_FILE_COUNT).is_ok());
        assert_eq!(
            validate_m6_file_scope(DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1).unwrap_err(),
            FormatError::WriterUnsupported(
                "M6 writer does not emit required directory hint shards"
            )
        );
    }

    #[test]
    fn m6_scope_rejects_archives_that_need_multiple_index_shards() {
        assert_eq!(
            validate_m6_file_scope(DEFAULT_MAX_FILES_PER_INDEX_SHARD + 1).unwrap_err(),
            FormatError::WriterUnsupported("M6 writer supports only one IndexShard")
        );
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
        assert_eq!(manifest.total_volumes, 1);
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
}
