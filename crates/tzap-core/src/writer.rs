use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::compression::{
    compress_zstd_frame_with_dictionary_and_jobs, compress_zstd_frame_with_jobs,
};
use crate::crypto::{
    aead_encrypt, build_aad, compute_hmac, derive_nonce, HmacDomain, KdfParams, MasterKey, Subkeys,
};
use crate::fec::encode_parity_gf16;
use crate::format::{
    AeadAlgo, ArchiveWriteError, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo,
    BLOCK_RECORD_FRAMING_LEN, BOOTSTRAP_SIDECAR_HEADER_LEN, CRITICAL_RECOVERY_LOCATOR_LEN,
    CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_HEADER_FIXED_LEN, CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION,
    MANIFEST_FOOTER_LEN, READER_MAX_CMRA_PARITY_PCT, READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS,
    READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN, READER_MAX_ROOT_AUTH_FOOTER_LEN,
    READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN, VOLUME_FORMAT_REV, VOLUME_HEADER_LEN,
    VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, validate_file_path_bytes, DirectoryHintEntry,
    DirectoryHintShardEntry, DirectoryHintTableHeader, EnvelopeEntry, FileEntry, FrameEntry,
    IndexRoot, IndexRootHeader, IndexShardHeader, ShardEntry, DIRECTORY_HINT_ENTRY_LEN,
    DIRECTORY_HINT_TABLE_LEN, ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN,
    INDEX_SHARD_HEADER_LEN,
};
use crate::padding::suffix_pad_for_aead;
use crate::root_auth::{
    archive_root, critical_metadata_digest, data_block_merkle_leaf_hash,
    data_block_merkle_root_from_leaf_hashes, fec_layout_digest, index_digest,
    root_auth_descriptor_digest, signer_identity_digest, ArchiveRootInputs,
    CriticalMetadataDigestInputs, FecLayoutObjectRow,
};
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage, CriticalMetadataRecoveryHeader,
    CriticalMetadataRecoveryShard, CriticalRecoveryLocator, CryptoHeader, CryptoHeaderFixed,
    ManifestFooter, RootAuthFooterV1, SerializedRegion, VolumeHeader, VolumeTrailer,
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
const CMRA_SHARD_SIZE: usize = 512;

fn default_jobs() -> usize {
    std::thread::available_parallelism()
        .map(|jobs| jobs.get())
        .unwrap_or(1)
}

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
    pub jobs: usize,
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
            jobs: default_jobs(),
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
pub struct RootAuthWriterConfig<'a> {
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity: &'a [u8],
    pub authenticator_value_length: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootAuthSigningRequest {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub archive_root: [u8; 32],
}

pub type RootAuthAuthenticator<'a> =
    dyn FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError> + 'a;

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

/// Re-openable source for one regular file written into an archive.
///
/// The writer may replan when options such as target volume sizing need another
/// pass, so implementations must return a fresh reader from each `open` call.
pub trait RegularFileSource {
    fn archive_path(&self) -> &str;
    fn file_data_size(&self) -> u64;
    fn mode(&self) -> u32;
    fn mtime(&self) -> u64;
    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError>;
}

impl RegularFileSource for RegularFile<'_> {
    fn archive_path(&self) -> &str {
        self.path
    }

    fn file_data_size(&self) -> u64 {
        self.contents.len() as u64
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> u64 {
        self.mtime
    }

    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        Ok(Box::new(Cursor::new(self.contents)))
    }
}

/// Streaming destination for archive volumes and optional bootstrap sidecar.
///
/// Calls arrive in archive order for each volume, but records are interleaved
/// across volumes according to the archive stripe layout.
pub trait ArchiveWriteSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError>;
    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError>;
    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenArchiveSummary {
    pub volume_count: usize,
    pub archive_bytes: u64,
    pub bootstrap_sidecar_bytes: u64,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub timings: WriterTimings,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriterTimings {
    pub total: Duration,
    pub plan_payload: Duration,
    pub plan_metadata: Duration,
    pub emit_payload: Duration,
    pub emit_metadata: Duration,
}

impl WriterTimings {
    fn add_assign(&mut self, other: Self) {
        self.total += other.total;
        self.plan_payload += other.plan_payload;
        self.plan_metadata += other.plan_metadata;
        self.emit_payload += other.emit_payload;
        self.emit_metadata += other.emit_metadata;
    }
}

/// In-memory sink used by the compatibility writer APIs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryArchiveSink {
    pub volumes: Vec<Vec<u8>>,
    pub bootstrap_sidecar: Vec<u8>,
}

impl ArchiveWriteSink for MemoryArchiveSink {
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        self.volumes = vec![Vec::new(); volume_count];
        self.bootstrap_sidecar.clear();
        Ok(())
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        let volume = self
            .volumes
            .get_mut(volume_index)
            .ok_or(FormatError::WriterInvariant(
                "volume sink index is out of bounds",
            ))?;
        volume.extend_from_slice(bytes);
        Ok(())
    }

    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        self.bootstrap_sidecar.extend_from_slice(bytes);
        Ok(())
    }
}

/// Completed archive artifacts produced by the compatibility writer APIs.
///
/// APIs returning this value build all volume bytes before returning. Use the
/// sink writer when archive bytes should be delivered incrementally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrittenArchive {
    pub bytes: Vec<u8>,
    pub volumes: Vec<Vec<u8>>,
    pub bootstrap_sidecar: Vec<u8>,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub timings: WriterTimings,
}

#[derive(Debug, Clone)]
struct TarMember {
    path: Vec<u8>,
    tar_member_group_start: u64,
    tar_member_group_size: u64,
    file_data_size: u64,
    mode: u32,
    mtime: u64,
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
#[cfg(test)]
struct PayloadEnvelope {
    envelope_index: u64,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone)]
struct PayloadObject {
    envelope_index: u64,
    plaintext_size: u32,
    object: ObjectExtent,
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

impl From<&EncryptedObject> for ObjectExtent {
    fn from(object: &EncryptedObject) -> Self {
        Self {
            first_block_index: object.first_block_index,
            data_block_count: object.data_block_count,
            parity_block_count: object.parity_block_count,
            encrypted_size: object.encrypted_size,
        }
    }
}

#[derive(Debug, Clone)]
struct PlannedDirectoryHintObject {
    hint_shard_index: u64,
    compressed: Vec<u8>,
    extent: ObjectExtent,
}

struct WriterPlan {
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    crypto_header: Vec<u8>,
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    index_root_plaintext: Vec<u8>,
    compressed_index_root: Vec<u8>,
    index_root_extent: ObjectExtent,
    index_shard_objects: Vec<PlannedIndexShardObject>,
    shard_entries: Vec<ShardEntry>,
    compressed_dictionary: Option<Vec<u8>>,
    dictionary_extent: Option<(ObjectExtent, u32)>,
    directory_hint_objects: Vec<PlannedDirectoryHintObject>,
    directory_hint_entries: Vec<DirectoryHintShardEntry>,
    root_auth_footer_length: Option<u32>,
    total_block_count: u64,
}

struct PlannedIndexShardObject {
    shard_index: u64,
    compressed: Vec<u8>,
    extent: ObjectExtent,
}

struct PayloadPlanning {
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    payload_block_count: u64,
    tar_total_size: u64,
    content_sha256: [u8; 32],
}

struct PayloadEnvelopeBuilder {
    envelope_index: u64,
    plaintext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamingRegularMember {
    pub archive_path: Vec<u8>,
    pub file_data_size: u64,
    pub mode: u32,
    pub mtime: u64,
}

struct WriterEmissionState {
    volume_headers: Vec<[u8; VOLUME_HEADER_LEN]>,
    bytes_written: Vec<u64>,
    record_counts: Vec<u64>,
    data_leaf_hashes: Vec<(u64, [u8; 32])>,
    next_block_index: u64,
}

pub(crate) struct StreamingArchiveWriter<'a, O: ArchiveWriteSink> {
    sink: &'a mut O,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    crypto_header: Vec<u8>,
    subkeys: Subkeys,
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    payload_block_count: u64,
    tar_total_size: u64,
    hasher: Sha256,
    next_frame_index: u64,
    envelope: PayloadEnvelopeBuilder,
    emission_state: WriterEmissionState,
}

pub fn write_archive(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        &KdfParams::Raw,
        None,
        None,
    )
}

pub fn write_archive_with_kdf(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
) -> Result<WrittenArchive, FormatError> {
    write_archive_inner(files, master_key, options, None, kdf_params, None, None)
}

pub fn write_archive_with_root_auth<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        &KdfParams::Raw,
        Some(root_auth),
        Some(&mut authenticator),
    )
}

pub fn write_archive_with_root_auth_and_kdf<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        None,
        kdf_params,
        Some(root_auth),
        Some(&mut authenticator),
    )
}

pub fn write_archive_with_dictionary_and_root_auth<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        &KdfParams::Raw,
        Some(root_auth),
        Some(&mut authenticator),
    )
}

pub fn write_archive_with_dictionary_kdf_and_root_auth<F>(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: &[u8],
    kdf_params: &KdfParams,
    root_auth: RootAuthWriterConfig<'_>,
    mut authenticator: F,
) -> Result<WrittenArchive, FormatError>
where
    F: FnMut(&RootAuthSigningRequest) -> Result<Vec<u8>, FormatError>,
{
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        kdf_params,
        Some(root_auth),
        Some(&mut authenticator),
    )
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
        None,
        None,
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
    write_archive_inner(
        files,
        master_key,
        options,
        Some(dictionary),
        kdf_params,
        None,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_archive_stream_inner(
        files,
        master_key,
        options,
        dictionary,
        kdf_params,
        root_auth,
        authenticator,
        sink,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_single_pass<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_single_pass_archive_to_sink(
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        sink,
        |writer| {
            for file in files {
                let archive_path =
                    normalize_lookup_file_path(file.archive_path(), options.max_path_length)?;
                let mut reader = file.open()?;
                writer.write_regular_member_from_reader(
                    StreamingRegularMember {
                        archive_path,
                        file_data_size: file.file_data_size(),
                        mode: file.mode(),
                        mtime: file.mtime(),
                    },
                    reader.as_mut(),
                )?;
            }
            Ok(())
        },
    )
}

#[doc(hidden)]
pub fn write_archive_sources_to_sink_unordered_probe<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_unordered_probe_archive_to_sink(files, master_key, options, kdf_params, sink)
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub fn write_archive_sources_to_sink_ordered_parallel_probe<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    write_ordered_parallel_archive_to_sink(
        files,
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        sink,
    )
}

fn write_archive_inner(
    files: &[RegularFile<'_>],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
) -> Result<WrittenArchive, FormatError> {
    let mut sink = MemoryArchiveSink::default();
    let summary = write_archive_stream_inner(
        files,
        master_key,
        options,
        dictionary,
        kdf_params,
        root_auth,
        authenticator,
        &mut sink,
    )
    .map_err(format_error_from_archive_write_error)?;
    Ok(WrittenArchive {
        bytes: sink
            .volumes
            .first()
            .cloned()
            .ok_or(FormatError::WriterInvariant("no volumes emitted"))?,
        volumes: sink.volumes,
        bootstrap_sidecar: sink.bootstrap_sidecar,
        archive_uuid: summary.archive_uuid,
        session_id: summary.session_id,
        timings: summary.timings,
    })
}

fn format_error_from_archive_write_error(error: ArchiveWriteError) -> FormatError {
    match error {
        ArchiveWriteError::Format(error) => error,
        ArchiveWriteError::Io(_) => {
            FormatError::WriterInvariant("in-memory archive writer returned I/O")
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_archive_stream_inner<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    mut authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let total_started = Instant::now();
    validate_dictionary_inputs(files.is_empty(), dictionary)?;
    if let Some(root_auth) = root_auth {
        validate_root_auth_writer_config(root_auth)?;
    }
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
    let mut accumulated_timings = WriterTimings::default();

    loop {
        let planned_options = plan_writer_options(requested_options)?;
        let timed_plan = build_writer_plan(
            files,
            master_key,
            planned_options,
            dictionary,
            kdf_params,
            archive_uuid,
            session_id,
            root_auth,
        )?;
        accumulated_timings.add_assign(timed_plan.timings);
        let plan = timed_plan.plan;
        if let Some(target_volume_size) = planned_options.target_volume_size {
            let required = required_stripe_width_for_plan(&plan, master_key, target_volume_size)?;
            if required > planned_options.stripe_width {
                requested_options.stripe_width = required;
                continue;
            }
        }
        let mut summary = emit_writer_plan(
            files,
            master_key,
            dictionary,
            root_auth,
            authenticator.take(),
            plan,
            sink,
        )?;
        summary.timings.add_assign(accumulated_timings);
        summary.timings.total = total_started.elapsed();
        return Ok(summary);
    }
}

fn validate_dictionary_inputs(
    files_are_empty: bool,
    dictionary: Option<&[u8]>,
) -> Result<(), FormatError> {
    if let Some(dictionary) = dictionary {
        if dictionary.is_empty() {
            return Err(FormatError::WriterUnsupported(
                "dictionary archives require a non-empty dictionary",
            ));
        }
        if files_are_empty {
            return Err(FormatError::WriterUnsupported(
                "dictionary archives require at least one file",
            ));
        }
        if dictionary.len() > u32::MAX as usize {
            return Err(FormatError::WriterUnsupported(
                "dictionary decompressed size exceeds u32",
            ));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
struct TimedWriterPlan {
    plan: WriterPlan,
    timings: WriterTimings,
}

fn build_writer_plan<S: RegularFileSource>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    root_auth: Option<RootAuthWriterConfig<'_>>,
) -> Result<TimedWriterPlan, ArchiveWriteError> {
    let mut next_block_index = 0u64;
    let payload_started = Instant::now();
    let payload = plan_payload_stream(files, options, dictionary, &mut next_block_index)?;
    let plan_payload = payload_started.elapsed();
    let metadata_started = Instant::now();
    let plan = build_writer_plan_from_payload(
        payload,
        next_block_index,
        master_key,
        options,
        dictionary,
        kdf_params,
        archive_uuid,
        session_id,
        root_auth,
    )?;
    Ok(TimedWriterPlan {
        plan,
        timings: WriterTimings {
            plan_payload,
            plan_metadata: metadata_started.elapsed(),
            ..WriterTimings::default()
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn build_writer_plan_from_payload(
    payload: PayloadPlanning,
    mut next_block_index: u64,
    master_key: &MasterKey,
    mut options: WriterOptions,
    dictionary: Option<&[u8]>,
    kdf_params: &KdfParams,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    root_auth: Option<RootAuthWriterConfig<'_>>,
) -> Result<WriterPlan, ArchiveWriteError> {
    let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id)?;
    let (shard_file_rows, planned_index_shards) = if payload.tar_members.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let rows = sorted_file_rows(&payload.tar_members);
        let shard_file_rows = partition_file_rows(rows)?;
        let planned_index_shards = build_index_shard_plaintexts(
            &shard_file_rows,
            &payload.frames,
            &payload.payload_objects,
            options,
        )?;
        (shard_file_rows, planned_index_shards)
    };

    let mut shard_entries = Vec::with_capacity(planned_index_shards.len());
    let mut index_shard_objects = Vec::with_capacity(planned_index_shards.len());
    for planned in planned_index_shards {
        let compressed =
            compress_zstd_frame_with_jobs(&planned.plaintext, options.zstd_level, options.jobs)?;
        let object_plan = plan_encrypted_object(
            compressed.len(),
            options.index_fec_data_shards,
            options.index_fec_parity_shards,
            options,
        )?;
        let extent = ObjectExtent::new(next_block_index, object_plan)?;
        next_block_index = extent.next_block_index()?;
        shard_entries.push(ShardEntry {
            shard_index: planned.shard_index,
            first_block_index: extent.first_block_index,
            data_block_count: extent.data_block_count,
            parity_block_count: extent.parity_block_count,
            encrypted_size: extent.encrypted_size,
            decompressed_size: u32_len(planned.plaintext.len(), "IndexShard")?,
            file_count: planned.file_count,
            first_path_hash: planned.first_path_hash,
            last_path_hash: planned.last_path_hash,
        });
        index_shard_objects.push(PlannedIndexShardObject {
            shard_index: planned.shard_index,
            compressed,
            extent,
        });
    }

    let compressed_dictionary = dictionary
        .map(|dictionary| {
            compress_zstd_frame_with_jobs(dictionary, options.zstd_level, options.jobs)
        })
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

    let planned_directory_hint_shards = if should_emit_directory_hints(payload.tar_members.len()) {
        build_directory_hint_plaintexts(&shard_file_rows, options)?
    } else {
        Vec::new()
    };
    let mut directory_hint_entries = Vec::with_capacity(planned_directory_hint_shards.len());
    let mut directory_hint_objects = Vec::with_capacity(planned_directory_hint_shards.len());
    let mut planned_next_block_index = next_after_dictionary;
    for planned in planned_directory_hint_shards {
        let compressed =
            compress_zstd_frame_with_jobs(&planned.plaintext, options.zstd_level, options.jobs)?;
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
        directory_hint_objects.push(PlannedDirectoryHintObject {
            hint_shard_index: planned.hint_shard_index,
            compressed,
            extent,
        });
    }

    let dictionary_extent = dictionary_extent.zip(dictionary_decompressed_size);
    let index_root_plaintext = build_index_root_plaintext(IndexRootPlaintextInput {
        shard_entries: &shard_entries,
        frame_count: payload.frames.len() as u64,
        envelope_count: payload.payload_objects.len() as u64,
        file_count: payload.tar_members.len() as u64,
        payload_block_count: payload.payload_block_count,
        tar_total_size: payload.tar_total_size,
        content_sha256: payload.content_sha256,
        directory_hint_entries: &directory_hint_entries,
        dictionary_extent,
    });
    let compressed_index_root =
        compress_zstd_frame_with_jobs(&index_root_plaintext, options.zstd_level, options.jobs)?;
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
    let index_root_extent = ObjectExtent::new(planned_next_block_index, metadata_class.index_root)?;
    let total_block_count = index_root_extent.next_block_index()?;
    let root_auth_footer_length = root_auth
        .map(|config| {
            root_auth_footer_wire_length(
                config.signer_identity.len(),
                config.authenticator_value_length as usize,
            )
        })
        .transpose()?;

    Ok(WriterPlan {
        options,
        archive_uuid,
        session_id,
        crypto_header,
        tar_members: payload.tar_members,
        frames: payload.frames,
        payload_objects: payload.payload_objects,
        index_root_plaintext,
        compressed_index_root,
        index_root_extent,
        index_shard_objects,
        shard_entries,
        compressed_dictionary,
        dictionary_extent,
        directory_hint_objects,
        directory_hint_entries,
        root_auth_footer_length,
        total_block_count,
    })
}

fn plan_payload_stream<S: RegularFileSource>(
    files: &[S],
    options: WriterOptions,
    dictionary: Option<&[u8]>,
    next_block_index: &mut u64,
) -> Result<PayloadPlanning, ArchiveWriteError> {
    let mut tar_members = Vec::with_capacity(files.len());
    let mut frames = Vec::new();
    let mut payload_objects = Vec::new();
    let mut tar_total_size = 0u64;
    let mut hasher = Sha256::new();
    let mut payload_block_count = 0u64;
    let mut next_frame_index = 0u64;
    let mut envelope = PayloadEnvelopeBuilder {
        envelope_index: 0,
        plaintext: Vec::new(),
    };

    for (member_index, file) in files.iter().enumerate() {
        let path = normalize_lookup_file_path(file.archive_path(), options.max_path_length)?;
        let prefix = build_regular_file_member_prefix(
            &path,
            file.file_data_size(),
            file.mode(),
            file.mtime(),
        )?;
        let member_start = tar_total_size;
        let member_group_size = checked_u64_add(
            prefix.len() as u64,
            checked_u64_add(
                file.file_data_size(),
                padding_to_512_u64(file.file_data_size()),
                "tar member",
            )?,
            "tar member",
        )?;
        tar_members.push(TarMember {
            path,
            tar_member_group_start: member_start,
            tar_member_group_size: member_group_size,
            file_data_size: file.file_data_size(),
            mode: file.mode(),
            mtime: file.mtime(),
        });
        let mut reader = StreamingMemberReader::new(file.open()?, prefix, file.file_data_size());
        let mut member_offset = 0u64;
        while member_offset < member_group_size {
            let remaining = member_group_size - member_offset;
            let max_chunk = remaining.min(options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader
                .read_exact(&mut chunk)
                .map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(
                        candidate,
                        options.zstd_level,
                        dictionary,
                        options.jobs,
                    )?
                } else {
                    compress_zstd_frame_with_jobs(candidate, options.zstd_level, options.jobs)?
                };
                if payload_object_can_fit(frame.len(), options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    )
                    .into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            let chunk = &chunk[..chunk_len];
            hasher.update(chunk);
            append_payload_frame_to_plan(
                PayloadFramePlanState {
                    envelope: &mut envelope,
                    payload_objects: &mut payload_objects,
                    payload_block_count: &mut payload_block_count,
                    next_block_index,
                    frames: &mut frames,
                    next_frame_index: &mut next_frame_index,
                    options,
                },
                PayloadFramePlanInput {
                    frame: &frame,
                    decompressed_size: chunk_len,
                    member_index,
                    member_start,
                    member_offset,
                    member_group_size,
                },
            )?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
            tar_total_size = checked_u64_add(tar_total_size, chunk_len as u64, "tar stream")?;
        }
    }

    if !envelope.plaintext.is_empty() {
        flush_payload_envelope_plan(
            &mut envelope,
            &mut payload_objects,
            &mut payload_block_count,
            next_block_index,
            options,
        )?;
    }
    let digest = hasher.finalize();
    let mut content_sha256 = [0u8; 32];
    content_sha256.copy_from_slice(&digest);
    Ok(PayloadPlanning {
        tar_members,
        frames,
        payload_objects,
        payload_block_count,
        tar_total_size,
        content_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn write_single_pass_archive_to_sink<O, F>(
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
    drive_members: F,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    O: ArchiveWriteSink,
    F: FnOnce(&mut StreamingArchiveWriter<'_, O>) -> Result<(), ArchiveWriteError>,
{
    let total_started = Instant::now();
    validate_single_pass_writer_options(options)?;
    if let Some(root_auth) = root_auth {
        validate_root_auth_writer_config(root_auth)?;
    }
    let options = plan_single_pass_writer_options(options)?;
    let archive_uuid = options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(
        options,
        false,
        &subkeys,
        &archive_uuid,
        &session_id,
        kdf_params,
    )?;
    let emission_state =
        begin_writer_emission_state(sink, options, &crypto_header, archive_uuid, session_id)?;

    let mut writer = StreamingArchiveWriter {
        sink,
        options,
        archive_uuid,
        session_id,
        crypto_header,
        subkeys,
        tar_members: Vec::new(),
        frames: Vec::new(),
        payload_objects: Vec::new(),
        payload_block_count: 0,
        tar_total_size: 0,
        hasher: Sha256::new(),
        next_frame_index: 0,
        envelope: PayloadEnvelopeBuilder {
            envelope_index: 0,
            plaintext: Vec::new(),
        },
        emission_state,
    };
    let emit_payload_started = Instant::now();
    drive_members(&mut writer)?;
    let emit_payload = emit_payload_started.elapsed();
    let mut summary = writer.finish(master_key, kdf_params, root_auth, authenticator)?;
    summary.timings.emit_payload += emit_payload;
    summary.timings.total = total_started.elapsed();
    Ok(summary)
}

struct UnorderedProbeJob {
    envelope_index: u64,
    plaintext: Vec<u8>,
}

struct UnorderedProbeResult {
    records: Vec<BlockRecord>,
}

struct OrderedFrameJob {
    frame_index: u64,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
    plaintext: Vec<u8>,
}

struct OrderedFrameResult {
    frame_index: u64,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
    decompressed_size: usize,
    frame: Vec<u8>,
}

struct OrderedEnvelopeJob {
    envelope_index: u64,
    plaintext: Vec<u8>,
    extent: ObjectExtent,
}

struct OrderedEnvelopeResult {
    envelope_index: u64,
    records: Vec<BlockRecord>,
}

struct OrderedParallelState {
    tar_members: Vec<TarMember>,
    frames: Vec<PayloadFrame>,
    payload_objects: Vec<PayloadObject>,
    payload_block_count: u64,
    tar_total_size: u64,
    hasher: Sha256,
    next_frame_job_index: u64,
    next_frame_result_index: u64,
    next_frame_metadata_index: u64,
    frame_buffer: std::collections::BTreeMap<u64, OrderedFrameResult>,
    envelope: PayloadEnvelopeBuilder,
    next_payload_block_index: u64,
    next_envelope_result_index: u64,
    envelope_buffer: std::collections::BTreeMap<u64, OrderedEnvelopeResult>,
}

impl OrderedParallelState {
    fn new(file_count: usize) -> Self {
        Self {
            tar_members: Vec::with_capacity(file_count),
            frames: Vec::new(),
            payload_objects: Vec::new(),
            payload_block_count: 0,
            tar_total_size: 0,
            hasher: Sha256::new(),
            next_frame_job_index: 0,
            next_frame_result_index: 0,
            next_frame_metadata_index: 0,
            frame_buffer: std::collections::BTreeMap::new(),
            envelope: PayloadEnvelopeBuilder {
                envelope_index: 0,
                plaintext: Vec::new(),
            },
            next_payload_block_index: 0,
            next_envelope_result_index: 0,
            envelope_buffer: std::collections::BTreeMap::new(),
        }
    }
}

fn write_unordered_probe_archive_to_sink<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let total_started = Instant::now();
    validate_single_pass_writer_options(options)?;
    let options = plan_single_pass_writer_options(options)?;
    let archive_uuid = options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(
        options,
        false,
        &subkeys,
        &archive_uuid,
        &session_id,
        kdf_params,
    )?;
    let mut state =
        begin_writer_emission_state(sink, options, &crypto_header, archive_uuid, session_id)?;
    let worker_count = options.jobs.max(1);
    let job_buffer = worker_count.saturating_mul(2).max(1);
    let batch_target = (options.envelope_target_size as usize)
        .saturating_mul(4)
        .max(options.chunk_size as usize);
    let emit_payload_started = Instant::now();
    let subkeys = std::sync::Arc::new(subkeys);
    let next_block_index = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut jobs_sent = 0usize;
    let mut results_received = 0usize;

    std::thread::scope(|scope| -> Result<(), ArchiveWriteError> {
        let (job_tx, job_rx) = std::sync::mpsc::sync_channel::<UnorderedProbeJob>(job_buffer);
        let (result_tx, result_rx) =
            std::sync::mpsc::channel::<Result<UnorderedProbeResult, ArchiveWriteError>>();
        let job_rx = std::sync::Arc::new(std::sync::Mutex::new(job_rx));

        let handles = (0..worker_count)
            .map(|_| {
                let job_rx = std::sync::Arc::clone(&job_rx);
                let result_tx = result_tx.clone();
                let subkeys = std::sync::Arc::clone(&subkeys);
                let next_block_index = std::sync::Arc::clone(&next_block_index);
                scope.spawn(move || loop {
                    let job = {
                        let receiver = job_rx.lock().expect("unordered probe receiver poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let is_error = match build_unordered_probe_result(
                        job,
                        &subkeys,
                        &next_block_index,
                        options,
                        archive_uuid,
                        session_id,
                    ) {
                        Ok(result) => result_tx.send(Ok(result)).is_err(),
                        Err(error) => {
                            let _ = result_tx.send(Err(error));
                            true
                        }
                    };
                    if is_error {
                        break;
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(result_tx);

        let mut envelope_index = 0u64;
        let mut batch = Vec::with_capacity(batch_target);
        for file in files {
            let path = normalize_lookup_file_path(file.archive_path(), options.max_path_length)?;
            let prefix = build_regular_file_member_prefix(
                &path,
                file.file_data_size(),
                file.mode(),
                file.mtime(),
            )?;
            let member_group_size = checked_u64_add(
                prefix.len() as u64,
                checked_u64_add(
                    file.file_data_size(),
                    padding_to_512_u64(file.file_data_size()),
                    "tar member",
                )?,
                "tar member",
            )?;
            let mut reader =
                StreamingMemberReader::new(file.open()?, prefix, file.file_data_size());
            let mut member_offset = 0u64;
            while member_offset < member_group_size {
                let remaining = member_group_size - member_offset;
                let available = batch_target.saturating_sub(batch.len()).max(1);
                let read_len = remaining.min(available as u64);
                let mut chunk = vec![0u8; to_usize_writer(read_len, "payload probe batch")?];
                reader
                    .read_exact(&mut chunk)
                    .map_err(ArchiveWriteError::Io)?;
                batch.extend_from_slice(&chunk);
                member_offset = checked_u64_add(member_offset, read_len, "payload probe batch")?;
                if batch.len() >= batch_target {
                    send_unordered_probe_job(
                        &job_tx,
                        &result_rx,
                        &mut jobs_sent,
                        &mut results_received,
                        &mut envelope_index,
                        &mut batch,
                        batch_target,
                        sink,
                        options,
                        &mut state.bytes_written,
                        &mut state.record_counts,
                    )?;
                }
            }
        }
        if !batch.is_empty() {
            send_unordered_probe_job(
                &job_tx,
                &result_rx,
                &mut jobs_sent,
                &mut results_received,
                &mut envelope_index,
                &mut batch,
                batch_target,
                sink,
                options,
                &mut state.bytes_written,
                &mut state.record_counts,
            )?;
        }
        drop(job_tx);

        while results_received < jobs_sent {
            let result = result_rx
                .recv()
                .map_err(|_| FormatError::WriterInvariant("unordered probe worker stopped"))??;
            emit_unordered_probe_result(
                result,
                sink,
                options,
                &mut state.bytes_written,
                &mut state.record_counts,
            )?;
            results_received += 1;
        }

        for handle in handles {
            handle
                .join()
                .map_err(|_| FormatError::WriterInvariant("unordered probe worker panicked"))?;
        }
        Ok(())
    })?;

    state.next_block_index = next_block_index.load(std::sync::atomic::Ordering::SeqCst);
    Ok(WrittenArchiveSummary {
        volume_count: options.stripe_width as usize,
        archive_bytes: state.bytes_written.iter().sum(),
        bootstrap_sidecar_bytes: 0,
        archive_uuid,
        session_id,
        timings: WriterTimings {
            emit_payload: emit_payload_started.elapsed(),
            total: total_started.elapsed(),
            ..WriterTimings::default()
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn write_ordered_parallel_archive_to_sink<S, O>(
    files: &[S],
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let total_started = Instant::now();
    validate_single_pass_writer_options(options)?;
    if let Some(root_auth) = root_auth {
        validate_root_auth_writer_config(root_auth)?;
    }
    let options = plan_single_pass_writer_options(options)?;
    let archive_uuid = options
        .archive_uuid
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let session_id = options
        .session_id
        .unwrap_or_else(|| *Uuid::new_v4().as_bytes());
    let subkeys = Subkeys::derive(master_key, &archive_uuid, &session_id)?;
    let crypto_header = build_crypto_header(
        options,
        false,
        &subkeys,
        &archive_uuid,
        &session_id,
        kdf_params,
    )?;
    let mut emission_state =
        begin_writer_emission_state(sink, options, &crypto_header, archive_uuid, session_id)?;

    let emit_payload_started = Instant::now();
    let mut ordered = OrderedParallelState::new(files.len());
    let worker_count = options.jobs.max(1);
    let frame_job_buffer = worker_count.saturating_mul(4).max(1);
    let envelope_job_buffer = worker_count.saturating_mul(2).max(1);
    let subkeys_for_workers = std::sync::Arc::new(subkeys.clone());

    std::thread::scope(|scope| -> Result<(), ArchiveWriteError> {
        let (frame_job_tx, frame_job_rx) =
            std::sync::mpsc::sync_channel::<OrderedFrameJob>(frame_job_buffer);
        let (frame_result_tx, frame_result_rx) =
            std::sync::mpsc::channel::<Result<OrderedFrameResult, ArchiveWriteError>>();
        let frame_job_rx = std::sync::Arc::new(std::sync::Mutex::new(frame_job_rx));

        let (envelope_job_tx, envelope_job_rx) =
            std::sync::mpsc::sync_channel::<OrderedEnvelopeJob>(envelope_job_buffer);
        let (envelope_result_tx, envelope_result_rx) =
            std::sync::mpsc::channel::<Result<OrderedEnvelopeResult, ArchiveWriteError>>();
        let envelope_job_rx = std::sync::Arc::new(std::sync::Mutex::new(envelope_job_rx));

        let frame_handles = (0..worker_count)
            .map(|_| {
                let frame_job_rx = std::sync::Arc::clone(&frame_job_rx);
                let frame_result_tx = frame_result_tx.clone();
                scope.spawn(move || loop {
                    let job = {
                        let receiver = frame_job_rx
                            .lock()
                            .expect("ordered frame receiver poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let is_error = match build_ordered_frame_result(job, options) {
                        Ok(result) => frame_result_tx.send(Ok(result)).is_err(),
                        Err(error) => {
                            let _ = frame_result_tx.send(Err(error));
                            true
                        }
                    };
                    if is_error {
                        break;
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(frame_result_tx);

        let envelope_handles = (0..worker_count)
            .map(|_| {
                let envelope_job_rx = std::sync::Arc::clone(&envelope_job_rx);
                let envelope_result_tx = envelope_result_tx.clone();
                let subkeys = std::sync::Arc::clone(&subkeys_for_workers);
                scope.spawn(move || loop {
                    let job = {
                        let receiver = envelope_job_rx
                            .lock()
                            .expect("ordered envelope receiver poisoned");
                        receiver.recv()
                    };
                    let Ok(job) = job else {
                        break;
                    };
                    let is_error = match build_ordered_envelope_result(
                        job,
                        &subkeys,
                        options,
                        archive_uuid,
                        session_id,
                    ) {
                        Ok(result) => envelope_result_tx.send(Ok(result)).is_err(),
                        Err(error) => {
                            let _ = envelope_result_tx.send(Err(error));
                            true
                        }
                    };
                    if is_error {
                        break;
                    }
                })
            })
            .collect::<Vec<_>>();
        drop(envelope_result_tx);

        for (member_index, file) in files.iter().enumerate() {
            let path = normalize_lookup_file_path(file.archive_path(), options.max_path_length)?;
            let prefix = build_regular_file_member_prefix(
                &path,
                file.file_data_size(),
                file.mode(),
                file.mtime(),
            )?;
            let member_start = ordered.tar_total_size;
            let member_group_size = checked_u64_add(
                prefix.len() as u64,
                checked_u64_add(
                    file.file_data_size(),
                    padding_to_512_u64(file.file_data_size()),
                    "tar member",
                )?,
                "tar member",
            )?;
            ordered.tar_members.push(TarMember {
                path,
                tar_member_group_start: member_start,
                tar_member_group_size: member_group_size,
                file_data_size: file.file_data_size(),
                mode: file.mode(),
                mtime: file.mtime(),
            });
            let mut reader =
                StreamingMemberReader::new(file.open()?, prefix, file.file_data_size());
            let mut member_offset = 0u64;
            while member_offset < member_group_size {
                let remaining = member_group_size - member_offset;
                let read_len = remaining.min(options.chunk_size as u64);
                let mut plaintext = vec![0u8; to_usize_writer(read_len, "payload chunk")?];
                reader
                    .read_exact(&mut plaintext)
                    .map_err(ArchiveWriteError::Io)?;
                ordered.hasher.update(&plaintext);
                let frame_index = ordered.next_frame_job_index;
                ordered.next_frame_job_index =
                    checked_u64_add(ordered.next_frame_job_index, 1, "PayloadFrame.frame_index")?;
                send_ordered_frame_job(
                    OrderedFrameJob {
                        frame_index,
                        member_index,
                        member_start,
                        member_offset,
                        member_group_size,
                        plaintext,
                    },
                    &frame_job_tx,
                    &frame_result_rx,
                    &envelope_job_tx,
                    &envelope_result_rx,
                    &mut ordered,
                    sink,
                    options,
                    &mut emission_state,
                )?;
                member_offset = checked_u64_add(member_offset, read_len, "payload chunk")?;
                ordered.tar_total_size =
                    checked_u64_add(ordered.tar_total_size, read_len, "tar stream")?;
            }
        }
        drop(frame_job_tx);

        while ordered.next_frame_result_index < ordered.next_frame_job_index {
            receive_ordered_frame_result(
                &frame_result_rx,
                &envelope_job_tx,
                &envelope_result_rx,
                &mut ordered,
                sink,
                options,
                &mut emission_state,
                true,
            )?;
        }
        flush_ordered_parallel_envelope(
            &envelope_job_tx,
            &envelope_result_rx,
            &mut ordered,
            sink,
            options,
            &mut emission_state,
        )?;
        drop(envelope_job_tx);
        while ordered.next_envelope_result_index < ordered.envelope.envelope_index {
            receive_ordered_envelope_result(
                &envelope_result_rx,
                &mut ordered,
                sink,
                options,
                &mut emission_state,
                true,
            )?;
        }

        for handle in frame_handles {
            handle
                .join()
                .map_err(|_| FormatError::WriterInvariant("ordered frame worker panicked"))?;
        }
        for handle in envelope_handles {
            handle
                .join()
                .map_err(|_| FormatError::WriterInvariant("ordered envelope worker panicked"))?;
        }
        Ok(())
    })?;
    let emit_payload = emit_payload_started.elapsed();

    emission_state.next_block_index = ordered.next_payload_block_index;
    let digest = ordered.hasher.finalize();
    let mut content_sha256 = [0u8; 32];
    content_sha256.copy_from_slice(&digest);
    let payload = PayloadPlanning {
        tar_members: ordered.tar_members,
        frames: ordered.frames,
        payload_objects: ordered.payload_objects,
        payload_block_count: ordered.payload_block_count,
        tar_total_size: ordered.tar_total_size,
        content_sha256,
    };
    let plan = build_writer_plan_from_payload(
        payload,
        emission_state.next_block_index,
        master_key,
        options,
        None,
        kdf_params,
        archive_uuid,
        session_id,
        root_auth,
    )?;
    if plan.options != options || plan.crypto_header != crypto_header {
        return Err(FormatError::WriterUnsupported(
            "ordered parallel metadata exceeded the predeclared header class",
        )
        .into());
    }
    let mut summary = emit_writer_plan_suffix(
        &subkeys,
        root_auth,
        authenticator,
        plan,
        sink,
        emission_state,
    )?;
    summary.timings.emit_payload += emit_payload;
    summary.timings.total = total_started.elapsed();
    Ok(summary)
}

#[allow(clippy::too_many_arguments)]
fn send_ordered_frame_job<O: ArchiveWriteSink>(
    mut job: OrderedFrameJob,
    frame_job_tx: &std::sync::mpsc::SyncSender<OrderedFrameJob>,
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    loop {
        match frame_job_tx.try_send(job) {
            Ok(()) => {
                drain_ordered_frame_results(
                    frame_result_rx,
                    envelope_job_tx,
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                )?;
                return Ok(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                job = returned;
                receive_ordered_frame_result(
                    frame_result_rx,
                    envelope_job_tx,
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                    true,
                )?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(FormatError::WriterInvariant("ordered frame worker stopped").into());
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn drain_ordered_frame_results<O: ArchiveWriteSink>(
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    while receive_ordered_frame_result(
        frame_result_rx,
        envelope_job_tx,
        envelope_result_rx,
        ordered,
        sink,
        options,
        emission_state,
        false,
    )? {}
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn receive_ordered_frame_result<O: ArchiveWriteSink>(
    frame_result_rx: &std::sync::mpsc::Receiver<Result<OrderedFrameResult, ArchiveWriteError>>,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
    wait: bool,
) -> Result<bool, ArchiveWriteError> {
    let result = if wait {
        match frame_result_rx.recv() {
            Ok(result) => result?,
            Err(_) => {
                return Err(FormatError::WriterInvariant("ordered frame worker stopped").into())
            }
        }
    } else {
        match frame_result_rx.try_recv() {
            Ok(result) => result?,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(false),
        }
    };
    ordered.frame_buffer.insert(result.frame_index, result);
    while let Some(result) = ordered
        .frame_buffer
        .remove(&ordered.next_frame_result_index)
    {
        append_ordered_frame_result(
            result,
            envelope_job_tx,
            envelope_result_rx,
            ordered,
            sink,
            options,
            emission_state,
        )?;
        ordered.next_frame_result_index = checked_u64_add(
            ordered.next_frame_result_index,
            1,
            "PayloadFrame.frame_index",
        )?;
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn append_ordered_frame_result<O: ArchiveWriteSink>(
    result: OrderedFrameResult,
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    let next_len = checked_usize_add(
        ordered.envelope.plaintext.len(),
        result.frame.len(),
        "payload",
    )?;
    if !ordered.envelope.plaintext.is_empty()
        && (next_len > options.envelope_target_size as usize
            || !payload_object_can_fit(next_len, options)?)
    {
        flush_ordered_parallel_envelope(
            envelope_job_tx,
            envelope_result_rx,
            ordered,
            sink,
            options,
            emission_state,
        )?;
    }
    if ordered.envelope.plaintext.is_empty()
        && !payload_object_can_fit(result.frame.len(), options)?
    {
        return Err(
            FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into(),
        );
    }
    let offset = u32_len(
        ordered.envelope.plaintext.len(),
        "FrameEntry.offset_in_envelope",
    )?;
    ordered.envelope.plaintext.extend_from_slice(&result.frame);
    let mut flags = 0u32;
    if result.member_offset == 0 {
        flags |= 0x0000_0001;
    }
    if checked_u64_add(
        result.member_offset,
        result.decompressed_size as u64,
        "payload chunk",
    )? == result.member_group_size
    {
        flags |= 0x0000_0002;
    }
    ordered.frames.push(PayloadFrame {
        frame_index: ordered.next_frame_metadata_index,
        envelope_index: ordered.envelope.envelope_index,
        member_index: result.member_index,
        offset_in_envelope: offset,
        compressed_size: u32_len(result.frame.len(), "FrameEntry.compressed_size")?,
        decompressed_size: u32_len(result.decompressed_size, "FrameEntry.decompressed_size")?,
        flags,
        tar_stream_offset: checked_u64_add(
            result.member_start,
            result.member_offset,
            "PayloadFrame.tar_stream_offset",
        )?,
    });
    ordered.next_frame_metadata_index = checked_u64_add(
        ordered.next_frame_metadata_index,
        1,
        "PayloadFrame.frame_index",
    )?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flush_ordered_parallel_envelope<O: ArchiveWriteSink>(
    envelope_job_tx: &std::sync::mpsc::SyncSender<OrderedEnvelopeJob>,
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    if ordered.envelope.plaintext.is_empty() {
        return Ok(());
    }
    let plaintext_size = u32_len(
        ordered.envelope.plaintext.len(),
        "EnvelopeEntry.plaintext_size",
    )?;
    let object_plan = plan_encrypted_object(
        ordered.envelope.plaintext.len(),
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )?;
    let extent = ObjectExtent::new(ordered.next_payload_block_index, object_plan)?;
    ordered.next_payload_block_index = extent.next_block_index()?;
    ordered.payload_block_count = checked_u64_add(
        ordered.payload_block_count,
        extent.data_block_count as u64,
        "payload",
    )?;
    ordered.payload_objects.push(PayloadObject {
        envelope_index: ordered.envelope.envelope_index,
        plaintext_size,
        object: extent,
    });
    let mut job = OrderedEnvelopeJob {
        envelope_index: ordered.envelope.envelope_index,
        plaintext: std::mem::take(&mut ordered.envelope.plaintext),
        extent,
    };
    ordered.envelope.envelope_index =
        checked_u64_add(ordered.envelope.envelope_index, 1, "EnvelopeEntry")?;
    loop {
        match envelope_job_tx.try_send(job) {
            Ok(()) => {
                drain_ordered_envelope_results(
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                )?;
                return Ok(());
            }
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                job = returned;
                receive_ordered_envelope_result(
                    envelope_result_rx,
                    ordered,
                    sink,
                    options,
                    emission_state,
                    true,
                )?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(FormatError::WriterInvariant("ordered envelope worker stopped").into());
            }
        }
    }
}

fn drain_ordered_envelope_results<O: ArchiveWriteSink>(
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    while receive_ordered_envelope_result(
        envelope_result_rx,
        ordered,
        sink,
        options,
        emission_state,
        false,
    )? {}
    Ok(())
}

fn receive_ordered_envelope_result<O: ArchiveWriteSink>(
    envelope_result_rx: &std::sync::mpsc::Receiver<
        Result<OrderedEnvelopeResult, ArchiveWriteError>,
    >,
    ordered: &mut OrderedParallelState,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
    wait: bool,
) -> Result<bool, ArchiveWriteError> {
    let result = if wait {
        match envelope_result_rx.recv() {
            Ok(result) => result?,
            Err(_) => {
                return Err(FormatError::WriterInvariant("ordered envelope worker stopped").into());
            }
        }
    } else {
        match envelope_result_rx.try_recv() {
            Ok(result) => result?,
            Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Ok(false),
        }
    };
    ordered
        .envelope_buffer
        .insert(result.envelope_index, result);
    while let Some(result) = ordered
        .envelope_buffer
        .remove(&ordered.next_envelope_result_index)
    {
        emit_ordered_envelope_result(result, sink, options, emission_state)?;
        ordered.next_envelope_result_index =
            checked_u64_add(ordered.next_envelope_result_index, 1, "EnvelopeEntry")?;
    }
    Ok(true)
}

fn build_ordered_frame_result(
    job: OrderedFrameJob,
    options: WriterOptions,
) -> Result<OrderedFrameResult, ArchiveWriteError> {
    let frame = compress_zstd_frame_with_jobs(&job.plaintext, options.zstd_level, 1)?;
    Ok(OrderedFrameResult {
        frame_index: job.frame_index,
        member_index: job.member_index,
        member_start: job.member_start,
        member_offset: job.member_offset,
        member_group_size: job.member_group_size,
        decompressed_size: job.plaintext.len(),
        frame,
    })
}

fn build_ordered_envelope_result(
    job: OrderedEnvelopeJob,
    subkeys: &Subkeys,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
) -> Result<OrderedEnvelopeResult, ArchiveWriteError> {
    let mut local_next_block_index = job.extent.first_block_index;
    let object = encrypt_object(
        &job.plaintext,
        ObjectEncryptionContext {
            key: &subkeys.enc_key,
            nonce_seed: &subkeys.nonce_seed,
            domain: b"envelope",
            counter: job.envelope_index,
            data_kind: BlockKind::PayloadData,
            parity_kind: BlockKind::PayloadParity,
            data_shard_max: options.fec_data_shards,
            class_parity_shard_max: options.fec_parity_shards,
            archive_uuid: &archive_uuid,
            session_id: &session_id,
        },
        &mut local_next_block_index,
        options,
    )?;
    validate_planned_extent(&object, job.extent)?;
    Ok(OrderedEnvelopeResult {
        envelope_index: job.envelope_index,
        records: object.records,
    })
}

fn emit_ordered_envelope_result<O: ArchiveWriteSink>(
    result: OrderedEnvelopeResult,
    sink: &mut O,
    options: WriterOptions,
    emission_state: &mut WriterEmissionState,
) -> Result<(), ArchiveWriteError> {
    for record in &result.records {
        emit_block_record(
            sink,
            options,
            &mut emission_state.bytes_written,
            &mut emission_state.record_counts,
            &mut emission_state.data_leaf_hashes,
            record,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn send_unordered_probe_job<O: ArchiveWriteSink>(
    job_tx: &std::sync::mpsc::SyncSender<UnorderedProbeJob>,
    result_rx: &std::sync::mpsc::Receiver<Result<UnorderedProbeResult, ArchiveWriteError>>,
    jobs_sent: &mut usize,
    results_received: &mut usize,
    envelope_index: &mut u64,
    batch: &mut Vec<u8>,
    batch_target: usize,
    sink: &mut O,
    options: WriterOptions,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
) -> Result<(), ArchiveWriteError> {
    let plaintext = std::mem::replace(batch, Vec::with_capacity(batch_target));
    job_tx
        .send(UnorderedProbeJob {
            envelope_index: *envelope_index,
            plaintext,
        })
        .map_err(|_| FormatError::WriterInvariant("unordered probe worker stopped"))?;
    *envelope_index = checked_u64_add(*envelope_index, 1, "EnvelopeEntry")?;
    *jobs_sent = jobs_sent
        .checked_add(1)
        .ok_or(FormatError::WriterInvariant(
            "unordered probe job count overflow",
        ))?;
    while let Ok(result) = result_rx.try_recv() {
        emit_unordered_probe_result(result?, sink, options, bytes_written, record_counts)?;
        *results_received = results_received
            .checked_add(1)
            .ok_or(FormatError::WriterInvariant(
                "unordered probe result count overflow",
            ))?;
    }
    Ok(())
}

fn build_unordered_probe_result(
    job: UnorderedProbeJob,
    subkeys: &Subkeys,
    next_block_index: &std::sync::atomic::AtomicU64,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
) -> Result<UnorderedProbeResult, ArchiveWriteError> {
    let mut envelope_plaintext = Vec::with_capacity(job.plaintext.len() / 2);
    for chunk in job.plaintext.chunks(options.chunk_size as usize) {
        let frame = compress_zstd_frame_with_jobs(chunk, options.zstd_level, 1)?;
        envelope_plaintext.extend_from_slice(&frame);
    }
    if !payload_object_can_fit(envelope_plaintext.len(), options)? {
        return Err(FormatError::WriterUnsupported(
            "unordered probe payload batch exceeds envelope object limits",
        )
        .into());
    }
    let object_plan = plan_encrypted_object(
        envelope_plaintext.len(),
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )?;
    let block_count = u64::from(object_plan.data_block_count)
        .checked_add(u64::from(object_plan.parity_block_count))
        .ok_or(FormatError::WriterInvariant(
            "unordered probe block count overflow",
        ))?;
    let first_block_index =
        next_block_index.fetch_add(block_count, std::sync::atomic::Ordering::SeqCst);
    let extent = ObjectExtent::new(first_block_index, object_plan)?;
    let mut local_next_block_index = first_block_index;
    let object = encrypt_object(
        &envelope_plaintext,
        ObjectEncryptionContext {
            key: &subkeys.enc_key,
            nonce_seed: &subkeys.nonce_seed,
            domain: b"envelope",
            counter: job.envelope_index,
            data_kind: BlockKind::PayloadData,
            parity_kind: BlockKind::PayloadParity,
            data_shard_max: options.fec_data_shards,
            class_parity_shard_max: options.fec_parity_shards,
            archive_uuid: &archive_uuid,
            session_id: &session_id,
        },
        &mut local_next_block_index,
        options,
    )?;
    validate_planned_extent(&object, extent)?;
    Ok(UnorderedProbeResult {
        records: object.records,
    })
}

fn emit_unordered_probe_result<O: ArchiveWriteSink>(
    result: UnorderedProbeResult,
    sink: &mut O,
    options: WriterOptions,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
) -> Result<(), ArchiveWriteError> {
    for record in &result.records {
        let volume_index = (record.block_index % options.stripe_width as u64) as usize;
        let record_bytes = record.to_bytes();
        sink.write_volume(volume_index, &record_bytes)?;
        bytes_written[volume_index] = checked_u64_add(
            bytes_written[volume_index],
            record_bytes.len() as u64,
            "BlockRecord",
        )?;
        record_counts[volume_index] =
            checked_u64_add(record_counts[volume_index], 1, "BlockRecord count")?;
    }
    Ok(())
}

fn validate_single_pass_writer_options(options: WriterOptions) -> Result<(), FormatError> {
    if options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported(
            "streaming create cannot tolerate volume loss",
        ));
    }
    if options.target_volume_size.is_some() {
        return Err(FormatError::WriterUnsupported(
            "streaming create does not support target volume sizing",
        ));
    }
    Ok(())
}

fn begin_writer_emission_state<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    crypto_header: &[u8],
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
) -> Result<WriterEmissionState, ArchiveWriteError> {
    let volume_count = usize::try_from(options.stripe_width)
        .map_err(|_| FormatError::WriterUnsupported("stripe_width"))?;
    sink.begin_archive(volume_count)?;

    let mut state = WriterEmissionState {
        volume_headers: Vec::with_capacity(volume_count),
        bytes_written: vec![0u64; volume_count],
        record_counts: vec![0u64; volume_count],
        data_leaf_hashes: Vec::new(),
        next_block_index: 0,
    };

    for volume_index in 0..volume_count {
        let volume_index_u32 = u32::try_from(volume_index)
            .map_err(|_| FormatError::WriterUnsupported("volume_index"))?;
        let volume_header = VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index: volume_index_u32,
            stripe_width: options.stripe_width,
            archive_uuid,
            session_id,
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: u32_len(crypto_header.len(), "CryptoHeader")?,
            header_crc32c: 0,
        };
        let volume_header_bytes = volume_header.to_bytes();
        sink.write_volume(volume_index, &volume_header_bytes)?;
        sink.write_volume(volume_index, crypto_header)?;
        state.bytes_written[volume_index] = checked_u64_add(
            VOLUME_HEADER_LEN as u64,
            crypto_header.len() as u64,
            "volume header",
        )?;
        state.volume_headers.push(volume_header_bytes);
    }

    Ok(state)
}

fn plan_single_pass_writer_options(options: WriterOptions) -> Result<WriterOptions, FormatError> {
    let mut options = plan_writer_options(options)?;
    options.index_root_fec_data_shards = max_single_pass_index_root_data_shards(options)?;
    plan_writer_options(options)
}

fn max_single_pass_index_root_data_shards(options: WriterOptions) -> Result<u16, FormatError> {
    let block_size_limit = (u32::MAX as u64 / options.block_size as u64).min(u16::MAX as u64);
    let mut low = MIN_INDEX_ROOT_FEC_DATA_SHARDS as u64;
    let mut high = block_size_limit;
    let mut best = low;
    while low <= high {
        let mid = low + (high - low) / 2;
        match compute_parity(mid, options) {
            Ok(parity)
                if mid + u64::from(parity) <= READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS as u64 =>
            {
                best = mid;
                low = mid + 1;
            }
            _ => {
                if mid == 0 {
                    break;
                }
                high = mid - 1;
            }
        }
    }
    u16::try_from(best).map_err(|_| FormatError::WriterUnsupported("index_root_fec_data_shards"))
}

impl<O: ArchiveWriteSink> StreamingArchiveWriter<'_, O> {
    pub(crate) fn write_regular_member_from_reader(
        &mut self,
        member: StreamingRegularMember,
        payload: &mut dyn Read,
    ) -> Result<(), ArchiveWriteError> {
        let path = member.archive_path;
        validate_file_path_bytes(&path, self.options.max_path_length)?;
        let prefix = build_regular_file_member_prefix(
            &path,
            member.file_data_size,
            member.mode,
            member.mtime,
        )?;
        let member_start = self.tar_total_size;
        let member_group_size = checked_u64_add(
            prefix.len() as u64,
            checked_u64_add(
                member.file_data_size,
                padding_to_512_u64(member.file_data_size),
                "tar member",
            )?,
            "tar member",
        )?;
        let member_index = self.tar_members.len();
        self.tar_members.push(TarMember {
            path,
            tar_member_group_start: member_start,
            tar_member_group_size: member_group_size,
            file_data_size: member.file_data_size,
            mode: member.mode,
            mtime: member.mtime,
        });

        let mut reader =
            StreamingMemberReader::new(Box::new(payload), prefix, member.file_data_size);
        let mut member_offset = 0u64;
        while member_offset < member_group_size {
            let remaining = member_group_size - member_offset;
            let max_chunk = remaining.min(self.options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader
                .read_exact(&mut chunk)
                .map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = compress_zstd_frame_with_jobs(
                    candidate,
                    self.options.zstd_level,
                    self.options.jobs,
                )?;
                if payload_object_can_fit(frame.len(), self.options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    )
                    .into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            let chunk = &chunk[..chunk_len];
            self.hasher.update(chunk);
            self.append_payload_frame(
                &frame,
                chunk_len,
                member_index,
                member_start,
                member_offset,
                member_group_size,
            )?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
            self.tar_total_size =
                checked_u64_add(self.tar_total_size, chunk_len as u64, "tar stream")?;
        }
        Ok(())
    }

    fn append_payload_frame(
        &mut self,
        frame: &[u8],
        decompressed_size: usize,
        member_index: usize,
        member_start: u64,
        member_offset: u64,
        member_group_size: u64,
    ) -> Result<(), ArchiveWriteError> {
        let next_len = checked_usize_add(self.envelope.plaintext.len(), frame.len(), "payload")?;
        if !self.envelope.plaintext.is_empty()
            && (next_len > self.options.envelope_target_size as usize
                || !payload_object_can_fit(next_len, self.options)?)
        {
            self.flush_payload_envelope()?;
        }
        if self.envelope.plaintext.is_empty() && !payload_object_can_fit(frame.len(), self.options)?
        {
            return Err(FormatError::WriterUnsupported(
                "payload frame exceeds envelope object limits",
            )
            .into());
        }
        let offset = u32_len(
            self.envelope.plaintext.len(),
            "FrameEntry.offset_in_envelope",
        )?;
        self.envelope.plaintext.extend_from_slice(frame);
        let mut flags = 0u32;
        if member_offset == 0 {
            flags |= 0x0000_0001;
        }
        if checked_u64_add(member_offset, decompressed_size as u64, "payload chunk")?
            == member_group_size
        {
            flags |= 0x0000_0002;
        }
        self.frames.push(PayloadFrame {
            frame_index: self.next_frame_index,
            envelope_index: self.envelope.envelope_index,
            member_index,
            offset_in_envelope: offset,
            compressed_size: u32_len(frame.len(), "FrameEntry.compressed_size")?,
            decompressed_size: u32_len(decompressed_size, "FrameEntry.decompressed_size")?,
            flags,
            tar_stream_offset: checked_u64_add(
                member_start,
                member_offset,
                "PayloadFrame.tar_stream_offset",
            )?,
        });
        self.next_frame_index =
            checked_u64_add(self.next_frame_index, 1, "PayloadFrame.frame_index")?;
        Ok(())
    }

    fn flush_payload_envelope(&mut self) -> Result<(), ArchiveWriteError> {
        if self.envelope.plaintext.is_empty() {
            return Ok(());
        }
        let plaintext_size = u32_len(
            self.envelope.plaintext.len(),
            "EnvelopeEntry.plaintext_size",
        )?;
        let object_plan = plan_encrypted_object(
            self.envelope.plaintext.len(),
            self.options.fec_data_shards,
            self.options.fec_parity_shards,
            self.options,
        )?;
        let extent = ObjectExtent::new(self.emission_state.next_block_index, object_plan)?;
        let object = encrypt_object(
            &self.envelope.plaintext,
            ObjectEncryptionContext {
                key: &self.subkeys.enc_key,
                nonce_seed: &self.subkeys.nonce_seed,
                domain: b"envelope",
                counter: self.envelope.envelope_index,
                data_kind: BlockKind::PayloadData,
                parity_kind: BlockKind::PayloadParity,
                data_shard_max: self.options.fec_data_shards,
                class_parity_shard_max: self.options.fec_parity_shards,
                archive_uuid: &self.archive_uuid,
                session_id: &self.session_id,
            },
            &mut self.emission_state.next_block_index,
            self.options,
        )?;
        validate_planned_extent(&object, extent)?;
        for record in &object.records {
            emit_block_record(
                self.sink,
                self.options,
                &mut self.emission_state.bytes_written,
                &mut self.emission_state.record_counts,
                &mut self.emission_state.data_leaf_hashes,
                record,
            )?;
        }
        self.payload_block_count = checked_u64_add(
            self.payload_block_count,
            extent.data_block_count as u64,
            "payload",
        )?;
        self.payload_objects.push(PayloadObject {
            envelope_index: self.envelope.envelope_index,
            plaintext_size,
            object: extent,
        });
        self.envelope.envelope_index =
            checked_u64_add(self.envelope.envelope_index, 1, "EnvelopeEntry")?;
        self.envelope.plaintext.clear();
        Ok(())
    }

    fn finish(
        mut self,
        master_key: &MasterKey,
        kdf_params: &KdfParams,
        root_auth: Option<RootAuthWriterConfig<'_>>,
        authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    ) -> Result<WrittenArchiveSummary, ArchiveWriteError> {
        self.flush_payload_envelope()?;
        let digest = self.hasher.finalize();
        let mut content_sha256 = [0u8; 32];
        content_sha256.copy_from_slice(&digest);
        let payload = PayloadPlanning {
            tar_members: self.tar_members,
            frames: self.frames,
            payload_objects: self.payload_objects,
            payload_block_count: self.payload_block_count,
            tar_total_size: self.tar_total_size,
            content_sha256,
        };
        let plan = build_writer_plan_from_payload(
            payload,
            self.emission_state.next_block_index,
            master_key,
            self.options,
            None,
            kdf_params,
            self.archive_uuid,
            self.session_id,
            root_auth,
        )?;
        if plan.options != self.options || plan.crypto_header != self.crypto_header {
            return Err(FormatError::WriterUnsupported(
                "streaming tar stdin metadata exceeded the predeclared header class",
            )
            .into());
        }
        emit_writer_plan_suffix(
            &self.subkeys,
            root_auth,
            authenticator,
            plan,
            self.sink,
            self.emission_state,
        )
    }
}

struct PayloadFramePlanState<'a> {
    envelope: &'a mut PayloadEnvelopeBuilder,
    payload_objects: &'a mut Vec<PayloadObject>,
    payload_block_count: &'a mut u64,
    next_block_index: &'a mut u64,
    frames: &'a mut Vec<PayloadFrame>,
    next_frame_index: &'a mut u64,
    options: WriterOptions,
}

struct PayloadFramePlanInput<'a> {
    frame: &'a [u8],
    decompressed_size: usize,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
}

fn append_payload_frame_to_plan(
    state: PayloadFramePlanState<'_>,
    input: PayloadFramePlanInput<'_>,
) -> Result<(), FormatError> {
    let next_len = checked_usize_add(state.envelope.plaintext.len(), input.frame.len(), "payload")?;
    if !state.envelope.plaintext.is_empty()
        && (next_len > state.options.envelope_target_size as usize
            || !payload_object_can_fit(next_len, state.options)?)
    {
        flush_payload_envelope_plan(
            state.envelope,
            state.payload_objects,
            state.payload_block_count,
            state.next_block_index,
            state.options,
        )?;
    }
    if state.envelope.plaintext.is_empty()
        && !payload_object_can_fit(input.frame.len(), state.options)?
    {
        return Err(FormatError::WriterUnsupported(
            "payload frame exceeds envelope object limits",
        ));
    }
    let offset = u32_len(
        state.envelope.plaintext.len(),
        "FrameEntry.offset_in_envelope",
    )?;
    state.envelope.plaintext.extend_from_slice(input.frame);
    let mut flags = 0u32;
    if input.member_offset == 0 {
        flags |= 0x0000_0001;
    }
    if checked_u64_add(
        input.member_offset,
        input.decompressed_size as u64,
        "payload chunk",
    )? == input.member_group_size
    {
        flags |= 0x0000_0002;
    }
    state.frames.push(PayloadFrame {
        frame_index: *state.next_frame_index,
        envelope_index: state.envelope.envelope_index,
        member_index: input.member_index,
        offset_in_envelope: offset,
        compressed_size: u32_len(input.frame.len(), "FrameEntry.compressed_size")?,
        decompressed_size: u32_len(input.decompressed_size, "FrameEntry.decompressed_size")?,
        flags,
        tar_stream_offset: checked_u64_add(
            input.member_start,
            input.member_offset,
            "PayloadFrame.tar_stream_offset",
        )?,
    });
    *state.next_frame_index =
        checked_u64_add(*state.next_frame_index, 1, "PayloadFrame.frame_index")?;
    Ok(())
}

fn flush_payload_envelope_plan(
    envelope: &mut PayloadEnvelopeBuilder,
    payload_objects: &mut Vec<PayloadObject>,
    payload_block_count: &mut u64,
    next_block_index: &mut u64,
    options: WriterOptions,
) -> Result<(), FormatError> {
    let plaintext_size = u32_len(envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?;
    let object_plan = plan_encrypted_object(
        envelope.plaintext.len(),
        options.fec_data_shards,
        options.fec_parity_shards,
        options,
    )?;
    let extent = ObjectExtent::new(*next_block_index, object_plan)?;
    *next_block_index = extent.next_block_index()?;
    *payload_block_count = checked_u64_add(
        *payload_block_count,
        extent.data_block_count as u64,
        "payload",
    )?;
    payload_objects.push(PayloadObject {
        envelope_index: envelope.envelope_index,
        plaintext_size,
        object: extent,
    });
    envelope.envelope_index = checked_u64_add(envelope.envelope_index, 1, "EnvelopeEntry")?;
    envelope.plaintext.clear();
    Ok(())
}

fn required_stripe_width_for_plan(
    plan: &WriterPlan,
    master_key: &MasterKey,
    target_volume_size: u64,
) -> Result<u32, FormatError> {
    let subkeys = Subkeys::derive(master_key, &plan.archive_uuid, &plan.session_id)?;
    let mut max_volume_size = 0u64;
    let mut max_overhead = 0u64;
    let block_record_len = plan.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    for volume_index in 0..plan.options.stripe_width {
        let block_count = striped_block_count(
            plan.total_block_count,
            plan.options.stripe_width,
            volume_index,
        );
        let volume_size = planned_v41_volume_size(plan, &subkeys, volume_index, block_count)?;
        max_volume_size = max_volume_size.max(volume_size);
        let record_bytes = checked_u64_mul(block_count, block_record_len, "volume records")?;
        let overhead =
            volume_size
                .checked_sub(record_bytes)
                .ok_or(FormatError::WriterInvariant(
                    "planned volume record overflow",
                ))?;
        max_overhead = max_overhead.max(overhead);
    }
    if max_volume_size <= target_volume_size {
        return Ok(plan.options.stripe_width);
    }
    if target_volume_size <= max_overhead {
        return Err(FormatError::WriterUnsupported(
            "volume-size is too small for per-volume metadata",
        ));
    }

    let records_per_volume = (target_volume_size - max_overhead) / block_record_len;
    if records_per_volume == 0 {
        return Err(FormatError::WriterUnsupported(
            "volume-size is too small for the configured block-size",
        ));
    }

    let required = ceil_div(plan.total_block_count, records_per_volume)?
        .max(plan.options.volume_loss_tolerance as u64 + 1)
        .max(1);
    u32::try_from(required).map_err(|_| FormatError::WriterUnsupported("volume count"))
}

fn planned_v41_volume_size(
    plan: &WriterPlan,
    subkeys: &Subkeys,
    volume_index: u32,
    block_count: u64,
) -> Result<u64, FormatError> {
    let volume_header = VolumeHeader {
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        volume_index,
        stripe_width: plan.options.stripe_width,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        crypto_header_offset: VOLUME_HEADER_LEN as u32,
        crypto_header_length: u32_len(plan.crypto_header.len(), "CryptoHeader")?,
        header_crc32c: 0,
    };
    let volume_header_bytes = volume_header.to_bytes();
    let block_record_len = plan.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let block_record_bytes = checked_u64_mul(block_count, block_record_len, "volume records")?;
    let manifest_footer_offset = checked_u64_add(
        VOLUME_HEADER_LEN as u64 + plan.crypto_header.len() as u64,
        block_record_bytes,
        "volume records",
    )?;
    let manifest_footer = build_manifest_footer(
        subkeys,
        plan.archive_uuid,
        plan.session_id,
        volume_index,
        plan.options.stripe_width,
        &plan.index_root_extent,
        plan.index_root_plaintext.len(),
    )?;
    let root_auth_footer = plan
        .root_auth_footer_length
        .map(|length| vec![0u8; length as usize]);
    let root_auth_footer_offset = root_auth_footer
        .as_ref()
        .map(|_| {
            checked_u64_add(
                manifest_footer_offset,
                MANIFEST_FOOTER_LEN as u64,
                "RootAuthFooterV1",
            )
        })
        .transpose()?;
    let trailer_offset = checked_u64_add(
        manifest_footer_offset,
        MANIFEST_FOOTER_LEN as u64 + u64::from(plan.root_auth_footer_length.unwrap_or(0)),
        "VolumeTrailer",
    )?;
    let trailer = build_volume_trailer(VolumeTrailerBuildInput {
        subkeys,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        volume_index,
        block_count,
        bytes_written: trailer_offset,
        manifest_footer_offset,
        closed_at_ns: plan.options.closed_at_ns,
        root_auth_footer: root_auth_footer_offset.zip(plan.root_auth_footer_length),
    });
    let cmra_offset = checked_u64_add(trailer_offset, VOLUME_TRAILER_LEN as u64, "CMRA")?;
    let cmra = build_v41_cmra(CmraBuildInput {
        volume_header_bytes: &volume_header_bytes,
        crypto_header: &plan.crypto_header,
        block_count,
        manifest_footer_offset,
        manifest_footer: &manifest_footer,
        root_auth_footer_offset,
        root_auth_footer: root_auth_footer.as_deref(),
        trailer_offset,
        trailer: &trailer,
        cmra_offset,
        options: plan.options,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        volume_index,
    })?;
    checked_u64_add(
        checked_u64_add(cmra_offset, cmra.bytes.len() as u64, "CMRA")?,
        (CRITICAL_RECOVERY_LOCATOR_LEN * 2) as u64,
        "critical recovery locators",
    )
}

fn striped_block_count(total_block_count: u64, stripe_width: u32, volume_index: u32) -> u64 {
    let volume_index = volume_index as u64;
    let stripe_width = stripe_width as u64;
    if total_block_count <= volume_index {
        0
    } else {
        (total_block_count - 1 - volume_index) / stripe_width + 1
    }
}

fn emit_writer_plan<S, O>(
    files: &[S],
    master_key: &MasterKey,
    dictionary: Option<&[u8]>,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    plan: WriterPlan,
    sink: &mut O,
) -> Result<WrittenArchiveSummary, ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let subkeys = Subkeys::derive(master_key, &plan.archive_uuid, &plan.session_id)?;
    let mut state = begin_writer_emission_state(
        sink,
        plan.options,
        &plan.crypto_header,
        plan.archive_uuid,
        plan.session_id,
    )?;

    let emit_payload_started = Instant::now();
    emit_payload_stream(
        files,
        dictionary,
        &subkeys,
        &plan,
        &mut state.next_block_index,
        sink,
        &mut state.bytes_written,
        &mut state.record_counts,
        &mut state.data_leaf_hashes,
    )?;
    let emit_payload = emit_payload_started.elapsed();

    let mut summary =
        emit_writer_plan_suffix(&subkeys, root_auth, authenticator, plan, sink, state)?;
    summary.timings.emit_payload += emit_payload;
    Ok(summary)
}

fn emit_writer_plan_suffix<O: ArchiveWriteSink>(
    subkeys: &Subkeys,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    plan: WriterPlan,
    sink: &mut O,
    mut state: WriterEmissionState,
) -> Result<WrittenArchiveSummary, ArchiveWriteError> {
    let emit_metadata_started = Instant::now();
    let volume_count = plan.options.stripe_width as usize;

    for planned in &plan.index_shard_objects {
        emit_encrypted_object(
            &planned.compressed,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            planned.shard_index,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            plan.options.index_fec_data_shards,
            plan.options.index_fec_parity_shards,
            &mut state.next_block_index,
            plan.options,
            &plan.archive_uuid,
            &plan.session_id,
            planned.extent,
            None,
            sink,
            &mut state.bytes_written,
            &mut state.record_counts,
            &mut state.data_leaf_hashes,
        )?;
    }

    let dictionary_records = if let (Some(compressed), Some((extent, _))) =
        (plan.compressed_dictionary.as_ref(), plan.dictionary_extent)
    {
        let object = emit_encrypted_object(
            compressed,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            BlockKind::DictionaryParity,
            plan.options.index_root_fec_data_shards,
            plan.options.index_root_fec_parity_shards,
            &mut state.next_block_index,
            plan.options,
            &plan.archive_uuid,
            &plan.session_id,
            extent,
            Some(MetadataObjectKind::Dictionary),
            sink,
            &mut state.bytes_written,
            &mut state.record_counts,
            &mut state.data_leaf_hashes,
        )?;
        Some(object.records)
    } else {
        None
    };

    for planned in &plan.directory_hint_objects {
        emit_encrypted_object(
            &planned.compressed,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            planned.hint_shard_index,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            plan.options.index_fec_data_shards,
            plan.options.index_fec_parity_shards,
            &mut state.next_block_index,
            plan.options,
            &plan.archive_uuid,
            &plan.session_id,
            planned.extent,
            None,
            sink,
            &mut state.bytes_written,
            &mut state.record_counts,
            &mut state.data_leaf_hashes,
        )?;
    }

    let index_root_object = emit_encrypted_object(
        &plan.compressed_index_root,
        &subkeys.index_root_key,
        &subkeys.index_nonce_seed,
        b"idxroot",
        0,
        BlockKind::IndexRootData,
        BlockKind::IndexRootParity,
        plan.options.index_root_fec_data_shards,
        plan.options.index_root_fec_parity_shards,
        &mut state.next_block_index,
        plan.options,
        &plan.archive_uuid,
        &plan.session_id,
        plan.index_root_extent,
        Some(MetadataObjectKind::IndexRoot),
        sink,
        &mut state.bytes_written,
        &mut state.record_counts,
        &mut state.data_leaf_hashes,
    )?;
    if state.next_block_index != plan.total_block_count {
        return Err(FormatError::WriterInvariant("streaming writer block plan mismatch").into());
    }

    let volume_zero_manifest = build_manifest_footer(
        subkeys,
        plan.archive_uuid,
        plan.session_id,
        0,
        plan.options.stripe_width,
        &plan.index_root_extent,
        plan.index_root_plaintext.len(),
    )?;
    let root_auth_footer = match root_auth {
        Some(config) => {
            let signer = authenticator.ok_or(FormatError::WriterInvariant(
                "missing root-auth authenticator",
            ))?;
            Some(build_root_auth_footer_from_leaf_hashes(
                config,
                signer,
                RootAuthFooterBuildInput {
                    archive_uuid: plan.archive_uuid,
                    session_id: plan.session_id,
                    options: plan.options,
                    crypto_header: &plan.crypto_header,
                    volume_zero_manifest: &volume_zero_manifest,
                    index_root_plaintext: &plan.index_root_plaintext,
                    index_root_extent: plan.index_root_extent,
                    dictionary_extent: plan.dictionary_extent,
                    shard_entries: &plan.shard_entries,
                    payload_objects: &plan.payload_objects,
                    directory_hint_entries: &plan.directory_hint_entries,
                    data_leaf_hashes: &state.data_leaf_hashes,
                },
            )?)
        }
        None => None,
    };
    let root_auth_footer_length = root_auth_footer
        .as_ref()
        .map(|footer| u32_len(footer.len(), "RootAuthFooterV1"))
        .transpose()?;

    for volume_index in 0..volume_count {
        let volume_index_u32 = u32::try_from(volume_index)
            .map_err(|_| FormatError::WriterUnsupported("volume_index"))?;
        let manifest_footer_offset = state.bytes_written[volume_index];
        let manifest_footer = build_manifest_footer(
            subkeys,
            plan.archive_uuid,
            plan.session_id,
            volume_index_u32,
            plan.options.stripe_width,
            &plan.index_root_extent,
            plan.index_root_plaintext.len(),
        )?;
        sink.write_volume(volume_index, &manifest_footer)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            MANIFEST_FOOTER_LEN as u64,
            "ManifestFooter",
        )?;

        let root_auth_footer_offset = if let Some(root_auth_footer) = root_auth_footer.as_ref() {
            let offset = state.bytes_written[volume_index];
            sink.write_volume(volume_index, root_auth_footer)?;
            state.bytes_written[volume_index] = checked_u64_add(
                state.bytes_written[volume_index],
                root_auth_footer.len() as u64,
                "RootAuthFooterV1",
            )?;
            Some(offset)
        } else {
            None
        };

        let trailer_offset = state.bytes_written[volume_index];
        let trailer = build_volume_trailer(VolumeTrailerBuildInput {
            subkeys,
            archive_uuid: plan.archive_uuid,
            session_id: plan.session_id,
            volume_index: volume_index_u32,
            block_count: state.record_counts[volume_index],
            bytes_written: trailer_offset,
            manifest_footer_offset,
            closed_at_ns: plan.options.closed_at_ns,
            root_auth_footer: root_auth_footer_offset.zip(root_auth_footer_length),
        });
        sink.write_volume(volume_index, &trailer)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            VOLUME_TRAILER_LEN as u64,
            "VolumeTrailer",
        )?;

        let cmra_offset = state.bytes_written[volume_index];
        let cmra = build_v41_cmra(CmraBuildInput {
            volume_header_bytes: &state.volume_headers[volume_index],
            crypto_header: &plan.crypto_header,
            block_count: state.record_counts[volume_index],
            manifest_footer_offset,
            manifest_footer: &manifest_footer,
            root_auth_footer_offset,
            root_auth_footer: root_auth_footer.as_deref(),
            trailer_offset,
            trailer: &trailer,
            cmra_offset,
            options: plan.options,
            archive_uuid: plan.archive_uuid,
            session_id: plan.session_id,
            volume_index: volume_index_u32,
        })?;
        sink.write_volume(volume_index, &cmra.bytes)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            cmra.bytes.len() as u64,
            "CMRA",
        )?;
        let locator_base = CriticalRecoveryLocator {
            cmra_offset,
            cmra_length: u32_len(cmra.bytes.len(), "CMRA")?,
            volume_trailer_offset: trailer_offset,
            body_bytes_before_cmra: cmra_offset,
            archive_uuid_hint: plan.archive_uuid,
            session_id_hint: plan.session_id,
            volume_index_hint: volume_index_u32,
            locator_sequence: 1,
            cmra_shard_size: cmra.shard_size,
            cmra_data_shard_count: cmra.data_shard_count,
            cmra_parity_shard_count: cmra.parity_shard_count,
            cmra_image_length: cmra.image_length,
            cmra_image_sha256: cmra.image_sha256,
            locator_crc32c: 0,
        };
        let mirror = locator_base.to_bytes();
        sink.write_volume(volume_index, &mirror)?;
        let final_locator = CriticalRecoveryLocator {
            locator_sequence: 0,
            ..locator_base
        }
        .to_bytes();
        sink.write_volume(volume_index, &final_locator)?;
        state.bytes_written[volume_index] = checked_u64_add(
            state.bytes_written[volume_index],
            (CRITICAL_RECOVERY_LOCATOR_LEN * 2) as u64,
            "critical recovery locators",
        )?;

        if volume_index == 0 {
            debug_assert_eq!(volume_zero_manifest, manifest_footer);
        }
    }

    let bootstrap_sidecar_bytes = if plan.options.stripe_width == 1 {
        let sidecar = build_bootstrap_sidecar(
            subkeys,
            plan.archive_uuid,
            plan.session_id,
            &volume_zero_manifest,
            &index_root_object.records,
            dictionary_records.as_deref(),
        )?;
        let sidecar_len = sidecar.len() as u64;
        sink.write_bootstrap_sidecar(&sidecar)?;
        sidecar_len
    } else {
        0
    };

    Ok(WrittenArchiveSummary {
        volume_count,
        archive_bytes: state.bytes_written.iter().sum(),
        bootstrap_sidecar_bytes,
        archive_uuid: plan.archive_uuid,
        session_id: plan.session_id,
        timings: WriterTimings {
            emit_metadata: emit_metadata_started.elapsed(),
            ..WriterTimings::default()
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn emit_encrypted_object<O: ArchiveWriteSink>(
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
    expected_extent: ObjectExtent,
    metadata_kind: Option<MetadataObjectKind>,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Vec<(u64, [u8; 32])>,
) -> Result<EncryptedObject, ArchiveWriteError> {
    let object = encrypt_object(
        payload,
        ObjectEncryptionContext {
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            parity_kind,
            data_shard_max,
            class_parity_shard_max,
            archive_uuid,
            session_id,
        },
        next_block_index,
        options,
    )
    .map_err(|error| match metadata_kind {
        Some(kind) => map_metadata_encrypt_error(error, kind),
        None => error,
    })?;
    validate_planned_extent(&object, expected_extent)?;
    for record in &object.records {
        emit_block_record(
            sink,
            options,
            bytes_written,
            record_counts,
            data_leaf_hashes,
            record,
        )?;
    }
    Ok(object)
}

fn emit_block_record<O: ArchiveWriteSink>(
    sink: &mut O,
    options: WriterOptions,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Vec<(u64, [u8; 32])>,
    record: &BlockRecord,
) -> Result<(), ArchiveWriteError> {
    let volume_index = (record.block_index % options.stripe_width as u64) as usize;
    let record_bytes = record.to_bytes();
    sink.write_volume(volume_index, &record_bytes)?;
    bytes_written[volume_index] = checked_u64_add(
        bytes_written[volume_index],
        record_bytes.len() as u64,
        "BlockRecord",
    )?;
    record_counts[volume_index] =
        checked_u64_add(record_counts[volume_index], 1, "BlockRecord count")?;
    if record.kind.is_data() {
        data_leaf_hashes.push((
            record.block_index,
            data_block_merkle_leaf_hash(
                record.block_index,
                record.kind,
                record.flags,
                &record.payload,
            ),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn emit_payload_stream<S, O>(
    files: &[S],
    dictionary: Option<&[u8]>,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Vec<(u64, [u8; 32])>,
) -> Result<(), ArchiveWriteError>
where
    S: RegularFileSource,
    O: ArchiveWriteSink,
{
    let mut envelope = PayloadEnvelopeBuilder {
        envelope_index: 0,
        plaintext: Vec::new(),
    };
    let mut next_frame_index = 0u64;

    for (member_index, file) in files.iter().enumerate() {
        let member = plan
            .tar_members
            .get(member_index)
            .ok_or(FormatError::WriterInvariant(
                "planned tar member is missing",
            ))?;
        let current_path =
            normalize_lookup_file_path(file.archive_path(), plan.options.max_path_length)?;
        if current_path != member.path
            || file.file_data_size() != member.file_data_size
            || file.mode() != member.mode
            || file.mtime() != member.mtime
        {
            return Err(FormatError::WriterInvariant(
                "file source changed between planning and emission",
            )
            .into());
        }
        let prefix = build_regular_file_member_prefix(
            &member.path,
            member.file_data_size,
            member.mode,
            member.mtime,
        )?;
        let mut reader = StreamingMemberReader::new(file.open()?, prefix, member.file_data_size);
        let mut member_offset = 0u64;
        while member_offset < member.tar_member_group_size {
            let remaining = member.tar_member_group_size - member_offset;
            let max_chunk = remaining.min(plan.options.chunk_size as u64);
            let mut chunk = vec![0u8; to_usize_writer(max_chunk, "payload chunk")?];
            reader
                .read_exact(&mut chunk)
                .map_err(ArchiveWriteError::Io)?;
            let mut chunk_len = chunk.len();
            let frame = loop {
                let candidate = &chunk[..chunk_len];
                let frame = if let Some(dictionary) = dictionary {
                    compress_zstd_frame_with_dictionary_and_jobs(
                        candidate,
                        plan.options.zstd_level,
                        dictionary,
                        plan.options.jobs,
                    )?
                } else {
                    compress_zstd_frame_with_jobs(
                        candidate,
                        plan.options.zstd_level,
                        plan.options.jobs,
                    )?
                };
                if payload_object_can_fit(frame.len(), plan.options)? {
                    break frame;
                }
                if chunk_len == 1 {
                    return Err(FormatError::WriterUnsupported(
                        "single-byte payload frame exceeds envelope object limits",
                    )
                    .into());
                }
                chunk_len = (chunk_len / 2).max(1);
            };
            if chunk_len < chunk.len() {
                reader.push_back(chunk[chunk_len..].to_vec());
            }
            append_payload_frame_to_emit(
                &mut envelope,
                &frame,
                chunk_len,
                member_index,
                member.tar_member_group_start,
                member_offset,
                member.tar_member_group_size,
                &mut next_frame_index,
                subkeys,
                plan,
                next_block_index,
                sink,
                bytes_written,
                record_counts,
                data_leaf_hashes,
            )?;
            member_offset = checked_u64_add(member_offset, chunk_len as u64, "payload chunk")?;
        }
    }

    if !envelope.plaintext.is_empty() {
        flush_payload_envelope_emit(
            &mut envelope,
            subkeys,
            plan,
            next_block_index,
            sink,
            bytes_written,
            record_counts,
            data_leaf_hashes,
        )?;
    }
    if next_frame_index != plan.frames.len() as u64
        || envelope.envelope_index != plan.payload_objects.len() as u64
    {
        return Err(FormatError::WriterInvariant("streaming payload plan mismatch").into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn append_payload_frame_to_emit<O: ArchiveWriteSink>(
    envelope: &mut PayloadEnvelopeBuilder,
    frame: &[u8],
    decompressed_size: usize,
    member_index: usize,
    member_start: u64,
    member_offset: u64,
    member_group_size: u64,
    next_frame_index: &mut u64,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Vec<(u64, [u8; 32])>,
) -> Result<(), ArchiveWriteError> {
    let next_len = checked_usize_add(envelope.plaintext.len(), frame.len(), "payload")?;
    if !envelope.plaintext.is_empty()
        && (next_len > plan.options.envelope_target_size as usize
            || !payload_object_can_fit(next_len, plan.options)?)
    {
        flush_payload_envelope_emit(
            envelope,
            subkeys,
            plan,
            next_block_index,
            sink,
            bytes_written,
            record_counts,
            data_leaf_hashes,
        )?;
    }
    if envelope.plaintext.is_empty() && !payload_object_can_fit(frame.len(), plan.options)? {
        return Err(
            FormatError::WriterUnsupported("payload frame exceeds envelope object limits").into(),
        );
    }
    let offset = u32_len(envelope.plaintext.len(), "FrameEntry.offset_in_envelope")?;
    let mut flags = 0u32;
    if member_offset == 0 {
        flags |= 0x0000_0001;
    }
    if checked_u64_add(member_offset, decompressed_size as u64, "payload chunk")?
        == member_group_size
    {
        flags |= 0x0000_0002;
    }
    let expected =
        plan.frames
            .get(*next_frame_index as usize)
            .ok_or(FormatError::WriterInvariant(
                "planned payload frame is missing",
            ))?;
    let tar_stream_offset = checked_u64_add(
        member_start,
        member_offset,
        "PayloadFrame.tar_stream_offset",
    )?;
    if expected.envelope_index != envelope.envelope_index
        || expected.member_index != member_index
        || expected.offset_in_envelope != offset
        || expected.compressed_size != u32_len(frame.len(), "FrameEntry.compressed_size")?
        || expected.decompressed_size != u32_len(decompressed_size, "FrameEntry.decompressed_size")?
        || expected.flags != flags
        || expected.tar_stream_offset != tar_stream_offset
    {
        return Err(
            FormatError::WriterInvariant("emitted payload frame does not match plan").into(),
        );
    }
    envelope.plaintext.extend_from_slice(frame);
    *next_frame_index = checked_u64_add(*next_frame_index, 1, "PayloadFrame.frame_index")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn flush_payload_envelope_emit<O: ArchiveWriteSink>(
    envelope: &mut PayloadEnvelopeBuilder,
    subkeys: &Subkeys,
    plan: &WriterPlan,
    next_block_index: &mut u64,
    sink: &mut O,
    bytes_written: &mut [u64],
    record_counts: &mut [u64],
    data_leaf_hashes: &mut Vec<(u64, [u8; 32])>,
) -> Result<(), ArchiveWriteError> {
    let expected = plan
        .payload_objects
        .get(envelope.envelope_index as usize)
        .ok_or(FormatError::WriterInvariant(
            "planned payload envelope is missing",
        ))?;
    if expected.envelope_index != envelope.envelope_index
        || expected.plaintext_size
            != u32_len(envelope.plaintext.len(), "EnvelopeEntry.plaintext_size")?
    {
        return Err(
            FormatError::WriterInvariant("emitted payload envelope does not match plan").into(),
        );
    }
    emit_encrypted_object(
        &envelope.plaintext,
        &subkeys.enc_key,
        &subkeys.nonce_seed,
        b"envelope",
        envelope.envelope_index,
        BlockKind::PayloadData,
        BlockKind::PayloadParity,
        plan.options.fec_data_shards,
        plan.options.fec_parity_shards,
        next_block_index,
        plan.options,
        &plan.archive_uuid,
        &plan.session_id,
        expected.object,
        None,
        sink,
        bytes_written,
        record_counts,
        data_leaf_hashes,
    )?;
    envelope.envelope_index = checked_u64_add(envelope.envelope_index, 1, "EnvelopeEntry")?;
    envelope.plaintext.clear();
    Ok(())
}

pub fn write_empty_archive(master_key: &MasterKey) -> Result<WrittenArchive, FormatError> {
    write_archive(&[], master_key, WriterOptions::default())
}

fn plan_writer_options(mut options: WriterOptions) -> Result<WriterOptions, FormatError> {
    if options.jobs == 0 {
        return Err(FormatError::WriterUnsupported("jobs must be at least 1"));
    }
    if options.block_size < MIN_BLOCK_SIZE || options.block_size % 2 != 0 {
        return Err(FormatError::WriterUnsupported(
            "writer requires an even block size of at least 4096",
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
    options.fec_parity_shards =
        compute_parity_u16(options.fec_data_shards as u64, options, "fec_parity_shards")?;
    options.index_fec_parity_shards = compute_parity_u16(
        options.index_fec_data_shards as u64,
        options,
        "index_fec_parity_shards",
    )?;
    options.index_root_fec_parity_shards = compute_parity_u16(
        options.index_root_fec_data_shards as u64,
        options,
        "index_root_fec_parity_shards",
    )?;
    validate_writer_options_match_reader_caps(options)?;
    Ok(options)
}

fn validate_writer_options_match_reader_caps(options: WriterOptions) -> Result<(), FormatError> {
    CryptoHeaderFixed {
        length: CRYPTO_HEADER_FIXED_LEN as u32,
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
        stripe_width: options.stripe_width,
        volume_loss_tolerance: options.volume_loss_tolerance,
        bit_rot_buffer_pct: options.bit_rot_buffer_pct,
        has_dictionary: 0,
        max_path_length: options.max_path_length,
        expected_volume_size: options.target_volume_size.unwrap_or(0),
    }
    .validate_supported_profile()
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

#[cfg(test)]
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
            mode: file.mode,
            mtime: file.mtime,
        });
    }
    Ok((stream, members))
}

#[cfg(test)]
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
                    compress_zstd_frame_with_dictionary_and_jobs(
                        chunk,
                        options.zstd_level,
                        dictionary,
                        options.jobs,
                    )?
                } else {
                    compress_zstd_frame_with_jobs(chunk, options.zstd_level, options.jobs)?
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
    let compressed =
        compress_zstd_frame_with_jobs(&candidate.plaintext, options.zstd_level, options.jobs)?;
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
    let compressed =
        compress_zstd_frame_with_jobs(&candidate.plaintext, options.zstd_level, options.jobs)?;
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

#[derive(Debug, Clone, Copy)]
struct IndexRootPlaintextInput<'a> {
    shard_entries: &'a [ShardEntry],
    frame_count: u64,
    envelope_count: u64,
    file_count: u64,
    payload_block_count: u64,
    tar_total_size: u64,
    content_sha256: [u8; 32],
    directory_hint_entries: &'a [DirectoryHintShardEntry],
    dictionary_extent: Option<(ObjectExtent, u32)>,
}

fn build_index_root_plaintext(input: IndexRootPlaintextInput<'_>) -> Vec<u8> {
    let mut header = IndexRootHeader::empty();
    header.frame_count = input.frame_count;
    header.envelope_count = input.envelope_count;
    header.file_count = input.file_count;
    header.payload_block_count = input.payload_block_count;
    header.tar_total_size = input.tar_total_size;
    header.content_sha256 = input.content_sha256;
    if let Some((dictionary, decompressed_size)) = input.dictionary_extent {
        header.dictionary_first_block = dictionary.first_block_index;
        header.dictionary_data_block_count = dictionary.data_block_count;
        header.dictionary_parity_block_count = dictionary.parity_block_count;
        header.dictionary_encrypted_size = dictionary.encrypted_size;
        header.dictionary_decompressed_size = decompressed_size;
    }
    let root = IndexRoot {
        header,
        shards: input.shard_entries.to_vec(),
        directory_hint_shards: input.directory_hint_entries.to_vec(),
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

#[derive(Debug, Clone, Copy)]
struct ObjectEncryptionContext<'a> {
    key: &'a [u8; 32],
    nonce_seed: &'a [u8; 32],
    domain: &'a [u8],
    counter: u64,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    data_shard_max: u16,
    class_parity_shard_max: u16,
    archive_uuid: &'a [u8; 16],
    session_id: &'a [u8; 16],
}

fn encrypt_object(
    payload: &[u8],
    context: ObjectEncryptionContext<'_>,
    next_block_index: &mut u64,
    options: WriterOptions,
) -> Result<EncryptedObject, FormatError> {
    let block_size = options.block_size as usize;
    let padded = suffix_pad_for_aead(payload, options.aead_algo.tag_len(), block_size)?;
    let nonce = derive_nonce(
        context.nonce_seed,
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
        options.aead_algo.nonce_len(),
    )?;
    let aad = build_aad(
        context.domain,
        context.archive_uuid,
        context.session_id,
        context.counter,
    )?;
    let encrypted = aead_encrypt(options.aead_algo, context.key, &nonce, &aad, &padded)?;
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
    if data_block_count > context.data_shard_max as u32 {
        return Err(FormatError::WriterUnsupported(
            "encrypted object exceeds its data shard class maximum",
        ));
    }
    let required_parity = compute_object_parity(
        data_block_count as u64,
        options,
        context.class_parity_shard_max as u32,
    )?;
    if required_parity > context.class_parity_shard_max as u32 {
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
            kind: context.data_kind,
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
            kind: context.parity_kind,
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

#[derive(Debug, Clone, Copy)]
struct RootAuthFooterBuildInput<'a> {
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    options: WriterOptions,
    crypto_header: &'a [u8],
    volume_zero_manifest: &'a [u8; MANIFEST_FOOTER_LEN],
    index_root_plaintext: &'a [u8],
    index_root_extent: ObjectExtent,
    dictionary_extent: Option<(ObjectExtent, u32)>,
    shard_entries: &'a [ShardEntry],
    payload_objects: &'a [PayloadObject],
    directory_hint_entries: &'a [DirectoryHintShardEntry],
    data_leaf_hashes: &'a [(u64, [u8; 32])],
}

fn build_root_auth_footer_from_leaf_hashes(
    config: RootAuthWriterConfig<'_>,
    authenticator: &mut RootAuthAuthenticator<'_>,
    input: RootAuthFooterBuildInput<'_>,
) -> Result<Vec<u8>, FormatError> {
    let mut sorted_leaf_hashes = input.data_leaf_hashes.to_vec();
    sorted_leaf_hashes.sort_by_key(|(block_index, _)| *block_index);
    let leaf_hashes = sorted_leaf_hashes
        .iter()
        .map(|(_, leaf_hash)| *leaf_hash)
        .collect::<Vec<_>>();
    let total_data_block_count = u64::try_from(leaf_hashes.len())
        .map_err(|_| FormatError::WriterUnsupported("root-auth data block count"))?;
    let data_block_merkle_root = data_block_merkle_root_from_leaf_hashes(&leaf_hashes);

    let parsed_crypto = CryptoHeader::parse(
        input.crypto_header,
        u32_len(input.crypto_header.len(), "CryptoHeader")?,
    )?;
    let footer_length = root_auth_footer_wire_length(
        config.signer_identity.len(),
        config.authenticator_value_length as usize,
    )?;
    let root_auth_descriptor_digest = root_auth_descriptor_digest(
        config.authenticator_id,
        config.signer_identity_type,
        config.signer_identity,
        config.authenticator_value_length,
        footer_length,
    )?;
    let signer_identity_digest =
        signer_identity_digest(config.signer_identity_type, config.signer_identity)?;
    let manifest_pre_hmac = manifest_footer_global_pre_hmac_bytes(input.volume_zero_manifest);
    let critical_metadata_digest = critical_metadata_digest(CriticalMetadataDigestInputs {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        stripe_width: input.options.stripe_width,
        total_volumes: input.options.stripe_width,
        compression_algo: parsed_crypto.fixed.compression_algo,
        aead_algo: parsed_crypto.fixed.aead_algo,
        fec_algo: parsed_crypto.fixed.fec_algo,
        kdf_algo: parsed_crypto.fixed.kdf_algo,
        crypto_header_pre_hmac_bytes: parsed_crypto.hmac_covered_bytes,
        chunk_size: parsed_crypto.fixed.chunk_size,
        envelope_target_size: parsed_crypto.fixed.envelope_target_size,
        block_size: parsed_crypto.fixed.block_size,
        fec_data_shards: parsed_crypto.fixed.fec_data_shards,
        fec_parity_shards: parsed_crypto.fixed.fec_parity_shards,
        index_fec_data_shards: parsed_crypto.fixed.index_fec_data_shards,
        index_fec_parity_shards: parsed_crypto.fixed.index_fec_parity_shards,
        index_root_fec_data_shards: parsed_crypto.fixed.index_root_fec_data_shards,
        index_root_fec_parity_shards: parsed_crypto.fixed.index_root_fec_parity_shards,
        volume_loss_tolerance: parsed_crypto.fixed.volume_loss_tolerance,
        bit_rot_buffer_pct: parsed_crypto.fixed.bit_rot_buffer_pct,
        has_dictionary: parsed_crypto.fixed.has_dictionary,
        manifest_footer_global_pre_hmac_bytes: &manifest_pre_hmac,
        index_root_first_block: input.index_root_extent.first_block_index,
        index_root_data_block_count: input.index_root_extent.data_block_count,
        index_root_parity_block_count: input.index_root_extent.parity_block_count,
        index_root_encrypted_size: input.index_root_extent.encrypted_size,
        index_root_decompressed_size: u32_len(input.index_root_plaintext.len(), "IndexRoot")?,
        root_auth_descriptor_digest,
    })?;
    let index_digest = index_digest(input.index_root_plaintext);
    let fec_layout_rows = writer_fec_layout_rows_from_extents(
        input.index_root_extent,
        u32_len(input.index_root_plaintext.len(), "IndexRoot")?,
        input.dictionary_extent,
        input.shard_entries,
        input.payload_objects,
        input.directory_hint_entries,
    );
    let expected_data_block_count = fec_layout_rows.iter().try_fold(0u64, |total, row| {
        if row.present {
            checked_u64_add(
                total,
                row.data_block_count as u64,
                "root-auth data block count",
            )
        } else {
            Ok(total)
        }
    })?;
    if expected_data_block_count != total_data_block_count {
        return Err(FormatError::WriterInvariant(
            "root-auth data block count does not match FEC layout",
        ));
    }
    let fec_layout_digest = fec_layout_digest(&fec_layout_rows)?;
    let archive_root = archive_root(ArchiveRootInputs {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        compression_algo: parsed_crypto.fixed.compression_algo,
        aead_algo: parsed_crypto.fixed.aead_algo,
        fec_algo: parsed_crypto.fixed.fec_algo,
        kdf_algo: parsed_crypto.fixed.kdf_algo,
        critical_metadata_digest,
        index_digest,
        fec_layout_digest,
        total_data_block_count,
        data_block_merkle_root,
        root_auth_descriptor_digest,
        signer_identity_digest,
    });
    let authenticator_value = authenticator(&RootAuthSigningRequest {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        archive_root,
    })?;
    if authenticator_value.len() != config.authenticator_value_length as usize {
        return Err(FormatError::WriterUnsupported(
            "root-auth authenticator length mismatch",
        ));
    }

    RootAuthFooterV1 {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        authenticator_id: config.authenticator_id,
        signer_identity_type: config.signer_identity_type,
        signer_identity_bytes: config.signer_identity.to_vec(),
        authenticator_value,
        total_data_block_count,
        critical_metadata_digest,
        index_digest,
        fec_layout_digest,
        data_block_merkle_root,
        signer_identity_digest,
        archive_root,
        footer_crc32c: 0,
    }
    .to_bytes()
}

fn writer_fec_layout_rows_from_extents(
    index_root_extent: ObjectExtent,
    index_root_plain_size: u32,
    dictionary_extent: Option<(ObjectExtent, u32)>,
    shard_entries: &[ShardEntry],
    payload_objects: &[PayloadObject],
    directory_hint_entries: &[DirectoryHintShardEntry],
) -> Vec<FecLayoutObjectRow> {
    let mut rows = Vec::new();
    rows.push(FecLayoutObjectRow {
        object_class: 1,
        present: true,
        object_id: 0,
        first_block_index: index_root_extent.first_block_index,
        data_block_count: index_root_extent.data_block_count,
        parity_block_count: index_root_extent.parity_block_count,
        encrypted_size: index_root_extent.encrypted_size,
        plain_size: index_root_plain_size,
    });
    if let Some((dictionary, decompressed_size)) = dictionary_extent {
        rows.push(FecLayoutObjectRow {
            object_class: 2,
            present: true,
            object_id: 0,
            first_block_index: dictionary.first_block_index,
            data_block_count: dictionary.data_block_count,
            parity_block_count: dictionary.parity_block_count,
            encrypted_size: dictionary.encrypted_size,
            plain_size: decompressed_size,
        });
    } else {
        rows.push(FecLayoutObjectRow {
            object_class: 2,
            present: false,
            object_id: 0,
            first_block_index: 0,
            data_block_count: 0,
            parity_block_count: 0,
            encrypted_size: 0,
            plain_size: 0,
        });
    }
    for entry in shard_entries {
        rows.push(FecLayoutObjectRow {
            object_class: 3,
            present: true,
            object_id: entry.shard_index,
            first_block_index: entry.first_block_index,
            data_block_count: entry.data_block_count,
            parity_block_count: entry.parity_block_count,
            encrypted_size: entry.encrypted_size,
            plain_size: entry.decompressed_size,
        });
    }
    for payload in payload_objects {
        rows.push(FecLayoutObjectRow {
            object_class: 4,
            present: true,
            object_id: payload.envelope_index,
            first_block_index: payload.object.first_block_index,
            data_block_count: payload.object.data_block_count,
            parity_block_count: payload.object.parity_block_count,
            encrypted_size: payload.object.encrypted_size,
            plain_size: payload.plaintext_size,
        });
    }
    for entry in directory_hint_entries {
        rows.push(FecLayoutObjectRow {
            object_class: 5,
            present: true,
            object_id: entry.hint_shard_index,
            first_block_index: entry.first_block_index,
            data_block_count: entry.data_block_count,
            parity_block_count: entry.parity_block_count,
            encrypted_size: entry.encrypted_size,
            plain_size: entry.decompressed_size,
        });
    }
    rows
}

fn manifest_footer_global_pre_hmac_bytes(manifest_footer: &[u8; MANIFEST_FOOTER_LEN]) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes.copy_from_slice(&manifest_footer[..104]);
    bytes[36..40].fill(0);
    bytes
}

fn root_auth_footer_wire_length(
    signer_identity_len: usize,
    authenticator_value_len: usize,
) -> Result<u32, FormatError> {
    validate_root_auth_variable_lengths_for_writer(signer_identity_len, authenticator_value_len)?;
    let len = crate::format::ROOT_AUTH_FOOTER_FIXED_LEN
        .checked_add(signer_identity_len)
        .and_then(|value| value.checked_add(authenticator_value_len))
        .and_then(|value| value.checked_add(4))
        .ok_or(FormatError::WriterUnsupported(
            "RootAuthFooterV1 length overflow",
        ))?;
    if len > READER_MAX_ROOT_AUTH_FOOTER_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 length",
            cap: READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
            actual: len as u64,
        });
    }
    u32::try_from(len).map_err(|_| FormatError::WriterUnsupported("RootAuthFooterV1 length"))
}

fn validate_root_auth_writer_config(config: RootAuthWriterConfig<'_>) -> Result<(), FormatError> {
    root_auth_footer_wire_length(
        config.signer_identity.len(),
        config.authenticator_value_length as usize,
    )?;
    Ok(())
}

fn validate_root_auth_variable_lengths_for_writer(
    signer_identity_len: usize,
    authenticator_value_len: usize,
) -> Result<(), FormatError> {
    if signer_identity_len > READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 signer identity length",
            cap: READER_MAX_ROOT_AUTH_SIGNER_IDENTITY_LEN as u64,
            actual: signer_identity_len as u64,
        });
    }
    if authenticator_value_len > READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as usize {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "RootAuthFooterV1 authenticator value length",
            cap: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64,
            actual: authenticator_value_len as u64,
        });
    }
    Ok(())
}

fn build_manifest_footer(
    subkeys: &Subkeys,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
    total_volumes: u32,
    index_root_extent: &ObjectExtent,
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

#[derive(Debug, Clone, Copy)]
struct VolumeTrailerBuildInput<'a> {
    subkeys: &'a Subkeys,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
    block_count: u64,
    bytes_written: u64,
    manifest_footer_offset: u64,
    closed_at_ns: i64,
    root_auth_footer: Option<(u64, u32)>,
}

fn build_volume_trailer(input: VolumeTrailerBuildInput<'_>) -> [u8; VOLUME_TRAILER_LEN] {
    let (root_auth_footer_offset, root_auth_footer_length, root_auth_flags) =
        match input.root_auth_footer {
            Some((offset, length)) => (offset, length, 0x0000_0001),
            None => (0, 0, 0),
        };
    let mut trailer = VolumeTrailer {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        volume_index: input.volume_index,
        block_count: input.block_count,
        bytes_written: input.bytes_written,
        manifest_footer_offset: input.manifest_footer_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        closed_at_ns: input.closed_at_ns,
        root_auth_footer_offset,
        root_auth_footer_length,
        root_auth_flags,
        trailer_hmac: [0u8; 32],
    };
    let mut bytes = trailer.to_bytes();
    trailer.trailer_hmac = compute_hmac(
        HmacDomain::VolumeTrailer,
        &input.subkeys.mac_key,
        &input.archive_uuid,
        &input.session_id,
        &bytes[..96],
    );
    bytes = trailer.to_bytes();
    bytes
}

struct BuiltCmra {
    bytes: Vec<u8>,
    shard_size: u32,
    data_shard_count: u16,
    parity_shard_count: u16,
    image_length: u32,
    image_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct CmraBuildInput<'a> {
    volume_header_bytes: &'a [u8; VOLUME_HEADER_LEN],
    crypto_header: &'a [u8],
    block_count: u64,
    manifest_footer_offset: u64,
    manifest_footer: &'a [u8; MANIFEST_FOOTER_LEN],
    root_auth_footer_offset: Option<u64>,
    root_auth_footer: Option<&'a [u8]>,
    trailer_offset: u64,
    trailer: &'a [u8; VOLUME_TRAILER_LEN],
    cmra_offset: u64,
    options: WriterOptions,
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
}

fn build_v41_cmra(input: CmraBuildInput<'_>) -> Result<BuiltCmra, FormatError> {
    let block_record_len = input.options.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
    let block_records_offset = VOLUME_HEADER_LEN as u64 + input.crypto_header.len() as u64;
    let block_records_length = checked_u64_mul(
        input.block_count,
        block_record_len,
        "CMRA BlockRecord length overflow",
    )?;
    let manifest_end = input
        .manifest_footer_offset
        .checked_add(MANIFEST_FOOTER_LEN as u64)
        .ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?;
    let root_auth_footer_length = input
        .root_auth_footer
        .map(|footer| u32_len(footer.len(), "RootAuthFooterV1"))
        .transpose()?;
    match (input.root_auth_footer_offset, root_auth_footer_length) {
        (Some(offset), Some(length)) => {
            if manifest_end != offset
                || offset
                    .checked_add(length as u64)
                    .ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?
                    != input.trailer_offset
            {
                return Err(FormatError::WriterInvariant(
                    "RootAuthFooter does not sit between ManifestFooter and VolumeTrailer",
                ));
            }
        }
        (None, None) => {
            if manifest_end != input.trailer_offset {
                return Err(FormatError::WriterInvariant(
                    "ManifestFooter does not end at VolumeTrailer",
                ));
            }
        }
        _ => {
            return Err(FormatError::WriterInvariant(
                "RootAuthFooter offset/bytes mismatch",
            ));
        }
    }
    let body_bytes_before_cmra = input
        .trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::WriterUnsupported("CMRA terminal overflow"))?;
    if body_bytes_before_cmra != input.cmra_offset {
        return Err(FormatError::WriterInvariant(
            "CMRA does not start after VolumeTrailer",
        ));
    }

    let mut regions = vec![
        SerializedRegion {
            region_type: 1,
            offset: 0,
            bytes: input.volume_header_bytes.to_vec(),
        },
        SerializedRegion {
            region_type: 2,
            offset: VOLUME_HEADER_LEN as u64,
            bytes: input.crypto_header.to_vec(),
        },
        SerializedRegion {
            region_type: 3,
            offset: input.manifest_footer_offset,
            bytes: input.manifest_footer.to_vec(),
        },
    ];
    if let (Some(offset), Some(footer)) = (input.root_auth_footer_offset, input.root_auth_footer) {
        regions.push(SerializedRegion {
            region_type: 4,
            offset,
            bytes: footer.to_vec(),
        });
    }
    regions.push(SerializedRegion {
        region_type: 5,
        offset: input.trailer_offset,
        bytes: input.trailer.to_vec(),
    });
    let image = CriticalMetadataImage {
        archive_uuid: input.archive_uuid,
        session_id: input.session_id,
        volume_index: input.volume_index,
        stripe_width: input.options.stripe_width,
        layout_flags: if input.root_auth_footer.is_some() {
            0x0000_0001
        } else {
            0
        },
        volume_header_offset: 0,
        volume_header_length: VOLUME_HEADER_LEN as u32,
        crypto_header_offset: VOLUME_HEADER_LEN as u64,
        crypto_header_length: u32_len(input.crypto_header.len(), "CryptoHeader")?,
        block_records_offset,
        block_records_length,
        block_count: input.block_count,
        manifest_footer_offset: input.manifest_footer_offset,
        manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
        root_auth_footer_offset: input.root_auth_footer_offset.unwrap_or(0),
        root_auth_footer_length: root_auth_footer_length.unwrap_or(0),
        volume_trailer_offset: input.trailer_offset,
        volume_trailer_length: VOLUME_TRAILER_LEN as u32,
        body_bytes_before_cmra,
        volume_header_sha256: sha256_bytes(input.volume_header_bytes),
        crypto_header_sha256: sha256_bytes(input.crypto_header),
        manifest_footer_sha256: sha256_bytes(input.manifest_footer),
        root_auth_footer_sha256: input
            .root_auth_footer
            .map(sha256_bytes)
            .unwrap_or([0u8; 32]),
        volume_trailer_sha256: sha256_bytes(input.trailer),
        regions,
    };
    let image_bytes = image.to_bytes()?;
    let image_sha256 = sha256_bytes(&image_bytes);
    let data_shard_count = ceil_div(image_bytes.len() as u64, CMRA_SHARD_SIZE as u64)?;
    let data_shard_count_u16 = u16::try_from(data_shard_count)
        .map_err(|_| FormatError::WriterUnsupported("CMRA data shard count"))?;
    let parity_lower = cmra_min_parity_shards(data_shard_count, input.options.bit_rot_buffer_pct)?;
    let parity_upper = cmra_min_parity_shards(data_shard_count, READER_MAX_CMRA_PARITY_PCT as u8)?;
    if parity_lower > parity_upper {
        return Err(FormatError::WriterUnsupported("CMRA parity bounds"));
    }
    let parity_shard_count_u16 = u16::try_from(parity_lower)
        .map_err(|_| FormatError::WriterUnsupported("CMRA parity shard count"))?;

    let mut data_shards = Vec::with_capacity(data_shard_count as usize);
    for idx in 0..data_shard_count as usize {
        let start = idx * CMRA_SHARD_SIZE;
        let end = (start + CMRA_SHARD_SIZE).min(image_bytes.len());
        let mut shard = vec![0u8; CMRA_SHARD_SIZE];
        if start < image_bytes.len() {
            shard[..end - start].copy_from_slice(&image_bytes[start..end]);
        }
        data_shards.push(shard);
    }
    let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count_u16 as usize)?;

    let header = CriticalMetadataRecoveryHeader {
        shard_size: CMRA_SHARD_SIZE as u32,
        data_shard_count: data_shard_count_u16,
        parity_shard_count: parity_shard_count_u16,
        image_length: u32_len(image_bytes.len(), "CriticalMetadataImageV1")?,
        archive_uuid_hint: input.archive_uuid,
        session_id_hint: input.session_id,
        volume_index_hint: input.volume_index,
        image_sha256,
        header_crc32c: 0,
    };
    let mut cmra = Vec::new();
    cmra.extend_from_slice(&header.to_bytes());
    for (idx, payload) in data_shards.into_iter().enumerate() {
        let payload_len = if idx + 1 == data_shard_count as usize {
            let final_len = image_bytes.len() - idx * CMRA_SHARD_SIZE;
            if final_len == 0 {
                CMRA_SHARD_SIZE
            } else {
                final_len
            }
        } else {
            CMRA_SHARD_SIZE
        };
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: u16::try_from(idx)
                    .map_err(|_| FormatError::WriterUnsupported("CMRA shard index"))?,
                shard_role: 0,
                shard_payload_length: u32_len(payload_len, "CMRA shard payload")?,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(CMRA_SHARD_SIZE)?,
        );
    }
    for (idx, payload) in parity_shards.into_iter().enumerate() {
        let shard_index = data_shard_count
            .checked_add(idx as u64)
            .ok_or(FormatError::WriterUnsupported("CMRA shard index overflow"))?;
        cmra.extend_from_slice(
            &CriticalMetadataRecoveryShard {
                shard_index: u16::try_from(shard_index)
                    .map_err(|_| FormatError::WriterUnsupported("CMRA shard index"))?,
                shard_role: 1,
                shard_payload_length: CMRA_SHARD_SIZE as u32,
                payload,
                shard_crc32c: 0,
            }
            .to_bytes(CMRA_SHARD_SIZE)?,
        );
    }

    Ok(BuiltCmra {
        bytes: cmra,
        shard_size: CMRA_SHARD_SIZE as u32,
        data_shard_count: data_shard_count_u16,
        parity_shard_count: parity_shard_count_u16,
        image_length: u32_len(image_bytes.len(), "CriticalMetadataImageV1")?,
        image_sha256,
    })
}

fn cmra_min_parity_shards(data_shard_count: u64, pct: u8) -> Result<u64, FormatError> {
    let by_pct = ceil_div(
        checked_u64_mul(data_shard_count, pct as u64, "CMRA parity overflow")?,
        100,
    )?;
    Ok(2u64.max(by_pct))
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

struct StreamingMemberReader<'a> {
    prefix: Cursor<Vec<u8>>,
    file: Box<dyn Read + 'a>,
    remaining_file_bytes: u64,
    remaining_padding_bytes: usize,
    pushback: Vec<u8>,
}

impl<'a> StreamingMemberReader<'a> {
    fn new(file: Box<dyn Read + 'a>, prefix: Vec<u8>, file_size: u64) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            file,
            remaining_file_bytes: file_size,
            remaining_padding_bytes: padding_to_512_u64(file_size) as usize,
            pushback: Vec::new(),
        }
    }

    fn push_back(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if self.pushback.is_empty() {
            self.pushback = bytes;
        } else {
            let mut merged = bytes;
            merged.extend_from_slice(&self.pushback);
            self.pushback = merged;
        }
    }
}

impl Read for StreamingMemberReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        if !self.pushback.is_empty() {
            let count = out.len().min(self.pushback.len());
            out[..count].copy_from_slice(&self.pushback[..count]);
            self.pushback.drain(..count);
            written += count;
            if written == out.len() {
                return Ok(written);
            }
        }

        let prefix_count = self.prefix.read(&mut out[written..])?;
        written += prefix_count;
        if written == out.len() {
            return Ok(written);
        }

        if self.remaining_file_bytes > 0 {
            let max_file_read = (out.len() - written)
                .min(usize::try_from(self.remaining_file_bytes).unwrap_or(usize::MAX));
            let count = self.file.read(&mut out[written..written + max_file_read])?;
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "file source ended before declared size",
                ));
            }
            self.remaining_file_bytes -= count as u64;
            written += count;
            if written == out.len() {
                return Ok(written);
            }
            if self.remaining_file_bytes > 0 {
                return Ok(written);
            }
        }

        if self.remaining_padding_bytes > 0 {
            let count = (out.len() - written).min(self.remaining_padding_bytes);
            out[written..written + count].fill(0);
            self.remaining_padding_bytes -= count;
            written += count;
        }

        Ok(written)
    }
}

fn build_regular_file_member_prefix(
    path: &[u8],
    file_size: u64,
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

    let header = build_ustar_header(&header_path, file_size, mode, mtime, b'0')?;
    out.extend_from_slice(&header);
    Ok(out)
}

#[cfg(test)]
fn build_regular_file_member_group(
    path: &[u8],
    contents: &[u8],
    mode: u32,
    mtime: u64,
) -> Result<Vec<u8>, FormatError> {
    let mut out = build_regular_file_member_prefix(path, contents.len() as u64, mode, mtime)?;
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

fn padding_to_512_u64(len: u64) -> u64 {
    let remainder = len % TAR_BLOCK_LEN as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - remainder
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

fn to_usize_writer(value: u64, field: &'static str) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::WriterUnsupported(field))
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
    use crate::wire::{CriticalRecoveryLocator, CryptoHeader};
    use std::cell::RefCell;
    use std::io::{self, Read};
    use std::rc::Rc;

    #[test]
    fn writer_defaults_use_v41_sizing_and_parallel_mode() {
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
        assert_eq!(options.jobs, default_jobs());
        assert!(options.jobs >= 1);
    }

    #[test]
    fn writer_options_reject_zero_jobs() {
        let err = plan_writer_options(WriterOptions {
            jobs: 0,
            ..WriterOptions::default()
        })
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("jobs must be at least 1")
        );
    }

    #[test]
    fn production_writer_defaults_generate_distinct_v4_identities() {
        let master_key = MasterKey::from_raw_key(&[9u8; 32]).unwrap();
        let first = write_archive(&[], &master_key, WriterOptions::default()).unwrap();
        let second = write_archive(&[], &master_key, WriterOptions::default()).unwrap();

        assert_ne!(first.archive_uuid, [0u8; 16]);
        assert_ne!(first.session_id, [0u8; 16]);
        assert_ne!(second.archive_uuid, [0u8; 16]);
        assert_ne!(second.session_id, [0u8; 16]);
        assert_ne!(first.archive_uuid, first.session_id);
        assert_ne!(first.archive_uuid, second.archive_uuid);
        assert_ne!(first.session_id, second.session_id);

        for raw in [
            first.archive_uuid,
            first.session_id,
            second.archive_uuid,
            second.session_id,
        ] {
            let id = Uuid::from_bytes(raw);
            assert_eq!(id.get_version_num(), 4);
        }

        let deterministic = WriterOptions {
            archive_uuid: Some([0x44; 16]),
            session_id: Some([0x55; 16]),
            ..WriterOptions::default()
        };
        let fixture = write_archive(&[], &master_key, deterministic).unwrap();
        assert_eq!(fixture.archive_uuid, [0x44; 16]);
        assert_eq!(fixture.session_id, [0x55; 16]);
    }

    #[test]
    fn writer_partitions_multiple_default_sized_index_shards() {
        let members = (0..=DEFAULT_FILES_PER_INDEX_SHARD)
            .map(|idx| TarMember {
                path: format!("file-{idx:05}.txt").into_bytes(),
                tar_member_group_start: idx as u64 * 512,
                tar_member_group_size: 512,
                file_data_size: 0,
                mode: 0o644,
                mtime: 0,
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
                    mode: 0o644,
                    mtime: 0,
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
                    mode: 0o644,
                    mtime: 0,
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
    fn directory_hints_are_required_only_above_v41_threshold() {
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
    fn regular_file_writer_emits_no_global_metadata_or_tar_eof() {
        let long_path = format!("dir/{}.txt", "a".repeat(120));
        let files = [
            RegularFile::new("plain.txt", b"plain contents"),
            RegularFile::new(&long_path, b"long path contents"),
        ];

        let (tar_stream, members) = build_tar_stream(&files, 4096).unwrap();

        let member_bytes = members
            .iter()
            .map(|member| member.tar_member_group_size)
            .sum::<u64>();
        assert_eq!(tar_stream.len() as u64, member_bytes);
        assert!(!tar_stream[tar_stream.len() - TAR_BLOCK_LEN * 2..]
            .chunks(TAR_BLOCK_LEN)
            .all(|block| block.iter().all(|byte| *byte == 0)));

        for member in members {
            let start = member.tar_member_group_start as usize;
            let end = start + member.tar_member_group_size as usize;
            assert_path_specific_member_group(&tar_stream[start..end]);
        }
    }

    #[test]
    fn regular_file_writer_round_trips_mode_and_mtime() {
        let group =
            build_regular_file_member_group(b"script.sh", b"#!/bin/sh\n", 0o755, 1_700_000_000)
                .unwrap();

        let parsed = parse_tar_member_group(&group, 4096).unwrap();

        assert_eq!(parsed.mode, 0o755);
        assert_eq!(parsed.mtime, 1_700_000_000);
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

        let locator =
            CriticalRecoveryLocator::parse(&bytes[bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN..])
                .unwrap();
        let trailer_offset = locator.volume_trailer_offset as usize;
        let trailer =
            VolumeTrailer::parse(&bytes[trailer_offset..trailer_offset + VOLUME_TRAILER_LEN])
                .unwrap();
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
    fn parity_auto_scaling_matches_v41_examples() {
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
    fn parity_auto_scaling_rejects_non_convergent_budget() {
        let err = compute_parity(
            1,
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 1,
                bit_rot_buffer_pct: 50,
                ..WriterOptions::default()
            },
        )
        .unwrap_err();

        assert_eq!(
            err,
            FormatError::WriterUnsupported("parity calculation did not converge")
        );
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
    fn index_root_data_shard_maximum_obeys_v41_minimum() {
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
    fn single_pass_writer_predeclares_metadata_class_before_payload_streaming() {
        let planned = plan_single_pass_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();

        assert!(planned.index_root_fec_data_shards > DEFAULT_INDEX_ROOT_FEC_DATA_SHARDS);
        let index_root_payload_len = payload_len_for_encrypted_data_blocks(
            u32::from(planned.index_root_fec_data_shards - 1),
            planned,
        );
        let metadata_class =
            plan_index_root_metadata_class(planned, index_root_payload_len, None).unwrap();

        assert_eq!(metadata_class.options, planned);
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

    #[test]
    fn writer_options_reject_reader_resource_cap_excesses() {
        assert_eq!(
            plan_writer_options(WriterOptions {
                stripe_width: crate::format::READER_MAX_STRIPE_WIDTH + 1,
                volume_loss_tolerance: 0,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "stripe_width",
                cap: crate::format::READER_MAX_STRIPE_WIDTH as u64,
                actual: crate::format::READER_MAX_STRIPE_WIDTH as u64 + 1,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                block_size: crate::format::READER_MAX_BLOCK_SIZE + 2,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "block_size",
                cap: crate::format::READER_MAX_BLOCK_SIZE as u64,
                actual: crate::format::READER_MAX_BLOCK_SIZE as u64 + 2,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                chunk_size: crate::format::READER_MAX_CHUNK_SIZE + 1,
                envelope_target_size: crate::format::READER_MAX_CHUNK_SIZE + 1,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "chunk_size",
                cap: crate::format::READER_MAX_CHUNK_SIZE as u64,
                actual: crate::format::READER_MAX_CHUNK_SIZE as u64 + 1,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                max_path_length: crate::format::READER_MAX_PATH_LENGTH + 1,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "max_path_length",
                cap: crate::format::READER_MAX_PATH_LENGTH as u64,
                actual: crate::format::READER_MAX_PATH_LENGTH as u64 + 1,
            }
        );
        assert_eq!(
            plan_writer_options(WriterOptions {
                bit_rot_buffer_pct: 0,
                stripe_width: 1,
                volume_loss_tolerance: 0,
                fec_data_shards: crate::format::READER_MAX_FEC_CLASS_SHARDS as u16 + 1,
                ..WriterOptions::default()
            })
            .unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "fec_data_shards + fec_parity_shards",
                cap: crate::format::READER_MAX_FEC_CLASS_SHARDS as u64,
                actual: crate::format::READER_MAX_FEC_CLASS_SHARDS as u64 + 1,
            }
        );
    }

    #[test]
    fn root_auth_writer_config_rejects_reader_cap_excess_before_authenticator() {
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let mut authenticator_called = false;
        let err = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"payload")],
            &master_key,
            single_volume_metadata_test_options(),
            RootAuthWriterConfig {
                authenticator_id: 1,
                signer_identity_type: 1,
                signer_identity: b"signer",
                authenticator_value_length: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN + 1,
            },
            |_| {
                authenticator_called = true;
                Ok(Vec::new())
            },
        )
        .unwrap_err();

        assert!(!authenticator_called);
        assert_eq!(
            err,
            FormatError::ReaderResourceLimitExceeded {
                field: "RootAuthFooterV1 authenticator value length",
                cap: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64,
                actual: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as u64 + 1,
            }
        );
    }

    #[test]
    fn root_auth_writer_accepts_128_kib_authenticator_value() {
        let master_key = MasterKey::from_raw_key(&[8u8; 32]).unwrap();
        let authenticator_value = vec![0x5a; READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN as usize];
        let expected_value = authenticator_value.clone();
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"payload")],
            &master_key,
            single_volume_metadata_test_options(),
            RootAuthWriterConfig {
                authenticator_id: 0xcafe,
                signer_identity_type: 1,
                signer_identity: b"certificate-profile-signer",
                authenticator_value_length: READER_MAX_ROOT_AUTH_AUTHENTICATOR_VALUE_LEN,
            },
            |_| Ok(authenticator_value.clone()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key).unwrap();
        let footer = opened.root_auth_footer.as_ref().unwrap();
        assert_eq!(footer.authenticator_id, 0xcafe);
        assert_eq!(
            footer.authenticator_value.as_slice(),
            expected_value.as_slice()
        );

        let verification = opened
            .verify_root_auth_with(|footer, _| {
                Ok(footer.authenticator_id == 0xcafe
                    && footer.authenticator_value.as_slice() == expected_value.as_slice())
            })
            .unwrap();
        assert_eq!(verification.authenticator_id, 0xcafe);
    }

    #[test]
    fn streaming_writer_sink_round_trips_archive() {
        let files = [
            RegularFile::new("alpha.txt", b"alpha"),
            RegularFile::new("nested/beta.txt", b"beta payload"),
        ];
        let master_key = MasterKey::from_raw_key(&[7u8; 32]).unwrap();
        let mut sink = MemoryArchiveSink::default();

        let summary = write_archive_sources_to_sink(
            &files,
            &master_key,
            single_volume_metadata_test_options(),
            None,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.volume_count, 1);
        let opened = crate::reader::open_archive(&sink.volumes[0], &master_key).unwrap();
        assert_eq!(
            opened.extract_file("nested/beta.txt").unwrap(),
            Some(b"beta payload".to_vec())
        );
    }

    #[test]
    fn streaming_writer_bounds_source_reads_and_sink_writes_for_large_file() {
        let file_size = 3 * 1024 * 1024;
        let stats = Rc::new(RefCell::new(GeneratedSourceStats::default()));
        let file = GeneratedFileSource {
            path: "large/generated.bin",
            len: file_size,
            stats: Rc::clone(&stats),
        };
        let master_key = MasterKey::from_raw_key(&[3u8; 32]).unwrap();
        let options = plan_writer_options(WriterOptions {
            block_size: MIN_BLOCK_SIZE,
            chunk_size: 16 * 1024,
            envelope_target_size: 64 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            fec_parity_shards: 0,
            index_fec_parity_shards: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        })
        .unwrap();
        let mut sink = TrackingArchiveSink::default();

        let summary = write_archive_sources_to_sink_single_pass(
            &[file],
            &master_key,
            options,
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        let stats = stats.borrow();
        assert_eq!(stats.open_count, 1);
        assert_eq!(stats.total_read, file_size as u64);
        assert!(stats.max_read_request <= options.chunk_size as usize);
        assert_eq!(summary.volume_count, 1);
        assert_eq!(summary.archive_bytes, sink.volume_bytes.iter().sum());
        assert_eq!(
            summary.bootstrap_sidecar_bytes,
            sink.bootstrap_sidecar_bytes
        );
        assert!(sink.max_write_len <= 128 * 1024);
    }

    #[derive(Default)]
    struct GeneratedSourceStats {
        open_count: usize,
        total_read: u64,
        max_read_request: usize,
    }

    struct GeneratedFileSource {
        path: &'static str,
        len: usize,
        stats: Rc<RefCell<GeneratedSourceStats>>,
    }

    impl RegularFileSource for GeneratedFileSource {
        fn archive_path(&self) -> &str {
            self.path
        }

        fn file_data_size(&self) -> u64 {
            self.len as u64
        }

        fn mode(&self) -> u32 {
            0o644
        }

        fn mtime(&self) -> u64 {
            0
        }

        fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
            self.stats.borrow_mut().open_count += 1;
            Ok(Box::new(GeneratedReader {
                remaining: self.len,
                position: 0,
                stats: Rc::clone(&self.stats),
            }))
        }
    }

    struct GeneratedReader {
        remaining: usize,
        position: usize,
        stats: Rc<RefCell<GeneratedSourceStats>>,
    }

    impl Read for GeneratedReader {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Ok(0);
            }
            let count = out.len().min(self.remaining);
            for (offset, byte) in out[..count].iter_mut().enumerate() {
                let position = self.position + offset;
                *byte = position.wrapping_mul(31).wrapping_add(17) as u8;
            }
            self.position += count;
            self.remaining -= count;
            let mut stats = self.stats.borrow_mut();
            stats.total_read += count as u64;
            stats.max_read_request = stats.max_read_request.max(out.len());
            Ok(count)
        }
    }

    #[derive(Default)]
    struct TrackingArchiveSink {
        volume_bytes: Vec<u64>,
        bootstrap_sidecar_bytes: u64,
        max_write_len: usize,
    }

    impl ArchiveWriteSink for TrackingArchiveSink {
        fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
            self.volume_bytes = vec![0; volume_count];
            self.bootstrap_sidecar_bytes = 0;
            self.max_write_len = 0;
            Ok(())
        }

        fn write_volume(
            &mut self,
            volume_index: usize,
            bytes: &[u8],
        ) -> Result<(), ArchiveWriteError> {
            let volume =
                self.volume_bytes
                    .get_mut(volume_index)
                    .ok_or(FormatError::WriterInvariant(
                        "tracking sink volume index is out of bounds",
                    ))?;
            *volume += bytes.len() as u64;
            self.max_write_len = self.max_write_len.max(bytes.len());
            Ok(())
        }

        fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
            self.bootstrap_sidecar_bytes += bytes.len() as u64;
            self.max_write_len = self.max_write_len.max(bytes.len());
            Ok(())
        }
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

    fn assert_path_specific_member_group(group: &[u8]) {
        let mut cursor = 0usize;
        let mut saw_main = false;
        while cursor < group.len() {
            let header = &group[cursor..cursor + TAR_BLOCK_LEN];
            assert!(
                header.iter().any(|byte| *byte != 0),
                "writer emitted tar zero block inside member group"
            );
            let typeflag = header[156];
            assert_ne!(typeflag, b'g', "writer emitted global PAX metadata");
            assert!(
                !matches!(typeflag, b'V' | b'M' | b'N'),
                "writer emitted global GNU metadata"
            );
            assert!(
                matches!(typeflag, b'x' | b'0'),
                "writer emitted unexpected tar record type {typeflag:?}"
            );
            if typeflag == b'0' {
                saw_main = true;
            }
            let size = read_test_tar_octal(&header[124..136]);
            cursor += TAR_BLOCK_LEN + size + padding_to_512(size);
        }
        assert_eq!(cursor, group.len());
        assert!(saw_main);
    }

    fn read_test_tar_octal(field: &[u8]) -> usize {
        let mut value = 0usize;
        for byte in field {
            match *byte {
                0 | b' ' => break,
                b'0'..=b'7' => {
                    value = value * 8 + usize::from(*byte - b'0');
                }
                other => panic!("malformed test tar octal byte {other:?}"),
            }
        }
        value
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
                mode: 0o644,
                mtime: 0,
            },
        }
    }
}
