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
    CRITICAL_METADATA_IMAGE_FIXED_LEN, CRITICAL_METADATA_RECOVERY_HEADER_LEN,
    CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN, CRITICAL_RECOVERY_LOCATOR_LEN,
    CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, IMAGE_CRC_LEN, LOCATOR_PAIR_LEN, MANIFEST_FOOTER_LEN,
    READER_MAX_CMRA_PARITY_PCT, READER_MAX_CRYPTO_HEADER_LEN, READER_MAX_ROOT_AUTH_FOOTER_LEN,
    SERIALIZED_REGION_HEADER_LEN, VOLUME_FORMAT_REV, VOLUME_HEADER_LEN, VOLUME_TRAILER_LEN,
};
use crate::metadata::{
    hash_prefix, normalize_lookup_file_path, DirectoryHintShardEntry, DirectoryHintTable,
    EnvelopeEntry, FileEntry, FrameEntry, IndexRoot, IndexShard, MetadataLimits, ShardEntry,
};
use crate::root_auth::{
    archive_root, critical_metadata_digest, data_block_merkle_root, fec_layout_digest,
    index_digest, root_auth_descriptor_digest, signer_identity_digest, ArchiveRootInputs,
    CriticalMetadataDigestInputs, DataBlockMerkleLeaf, FecLayoutObjectRow,
};
use crate::tar_model::{
    parse_tar_member_group, restore_tar_member, validate_tar_stream_total_extraction_size,
    MetadataDiagnostic, OwnedTarMember, SafeExtractionOptions, TarEntryKind,
};
use crate::wire::{
    BlockRecord, BootstrapSidecarHeader, CriticalMetadataImage, CriticalMetadataRecoveryHeader,
    CriticalMetadataRecoveryShard, CriticalRecoveryLocator, CryptoHeader, CryptoHeaderFixed,
    ManifestFooter, RootAuthFooterV1, VolumeHeader, VolumeTrailer,
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
    crypto_header_bytes: Vec<u8>,
    pub volume_header: VolumeHeader,
    pub crypto_header: CryptoHeaderFixed,
    pub manifest_footer: ManifestFooter,
    pub volume_trailer: Option<VolumeTrailer>,
    pub root_auth_footer: Option<RootAuthFooterV1>,
    pub index_root: IndexRoot,
    payload_dictionary: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootAuthVerification {
    pub archive_root: [u8; 32],
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: Vec<u8>,
    pub total_data_block_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicNoKeyVerification {
    pub archive_root: [u8; 32],
    pub authenticator_id: u16,
    pub signer_identity_type: u16,
    pub signer_identity_bytes: Vec<u8>,
    pub total_data_block_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootAuthMaterial {
    critical_metadata_digest: [u8; 32],
    index_digest: [u8; 32],
    fec_layout_digest: [u8; 32],
    data_block_merkle_root: [u8; 32],
    signer_identity_digest: [u8; 32],
    archive_root: [u8; 32],
    total_data_block_count: u64,
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
        Some(sidecar) => OpenedArchive::open_with_bootstrap_sidecar_options_for_mode(
            bytes,
            sidecar,
            master_key,
            ReaderOptions::default(),
            BootstrapSidecarUse::NonSeekableRandomAccess,
        ),
        None => Err(FormatError::ReaderUnsupported(
            "non-seekable random access requires a bootstrap sidecar",
        )),
    }
}

pub fn public_no_key_verify_archive_with<F>(
    bytes: &[u8],
    verifier: F,
) -> Result<PublicNoKeyVerification, FormatError>
where
    F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
{
    public_no_key_verify_volumes_with_options(&[bytes], verifier, ReaderOptions::default())
}

pub fn public_no_key_verify_volumes_with<F>(
    volumes: &[&[u8]],
    verifier: F,
) -> Result<PublicNoKeyVerification, FormatError>
where
    F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
{
    public_no_key_verify_volumes_with_options(volumes, verifier, ReaderOptions::default())
}

/// Decode a single-volume, dictionary-free non-seekable archive image into tar
/// bytes after authenticating its terminal ManifestFooter and VolumeTrailer.
///
/// This is a whole-buffer helper, not a live provisional-output API.
/// Callers receive no decoded bytes if terminal authentication fails.
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
        let mut manifest_authority: Option<ManifestFooter> = None;
        let mut manifest_authority_volume_header: Option<VolumeHeader> = None;
        let mut manifest_authority_volume_trailer: Option<VolumeTrailer> = None;
        let mut root_auth_authority: Option<RootAuthFooterV1> = None;
        let mut root_auth_authority_bytes: Option<Vec<u8>> = None;
        let mut saw_root_auth_absent = false;
        let mut first_manifest_footer_error: Option<FormatError> = None;
        let mut seen_volume_indexes = BTreeSet::new();
        let mut blocks = BTreeMap::new();
        let mut erased_block_indices = BTreeSet::new();

        for volume_bytes in volumes {
            let mut parsed = parse_seekable_volume(volume_bytes, master_key, options)?;
            if !seen_volume_indexes.insert(parsed.volume_header.volume_index) {
                return Err(FormatError::InvalidArchive(
                    "duplicate authenticated volume index",
                ));
            }

            if let Some(first) = &first {
                validate_volume_set_member(first, &parsed)?;
            }

            if let Some(footer) = &parsed.manifest_footer {
                if let Some(authority) = &manifest_authority {
                    if !manifest_bootstrap_fields_match(authority, footer) {
                        return Err(FormatError::InvalidArchive(
                            "ManifestFooter bootstrap fields differ",
                        ));
                    }
                } else {
                    manifest_authority = Some(footer.clone());
                    manifest_authority_volume_header = Some(parsed.volume_header.clone());
                    manifest_authority_volume_trailer = Some(parsed.volume_trailer.clone());
                }
            } else if first_manifest_footer_error.is_none() {
                first_manifest_footer_error = parsed.manifest_footer_error.take();
            }

            match (&parsed.root_auth_footer, &parsed.root_auth_footer_bytes) {
                (Some(footer), Some(bytes)) => {
                    if saw_root_auth_absent {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    if let Some(authority_bytes) = &root_auth_authority_bytes {
                        if authority_bytes != bytes {
                            return Err(FormatError::InvalidArchive(
                                "RootAuthFooter copies differ",
                            ));
                        }
                    } else {
                        root_auth_authority = Some(footer.clone());
                        root_auth_authority_bytes = Some(bytes.clone());
                    }
                }
                (None, None) => {
                    if root_auth_authority_bytes.is_some() {
                        return Err(FormatError::InvalidArchive(
                            "root-auth footer presence differs across volumes",
                        ));
                    }
                    saw_root_auth_absent = true;
                }
                _ => {
                    return Err(FormatError::InvalidArchive(
                        "root-auth footer terminal state is inconsistent",
                    ));
                }
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
        let manifest_footer =
            manifest_authority.ok_or_else(|| match first_manifest_footer_error {
                Some(err) => err,
                None => FormatError::InvalidArchive("no authenticated ManifestFooter found"),
            })?;
        let authority_volume_header = manifest_authority_volume_header.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        )?;
        let authority_volume_trailer = manifest_authority_volume_trailer.ok_or(
            FormatError::InvalidArchive("no authenticated ManifestFooter found"),
        )?;
        let observed_volume_count = u32::try_from(seen_volume_indexes.len())
            .map_err(|_| FormatError::InvalidArchive("volume count overflow"))?;
        let missing_volume_count = first
            .crypto_header
            .stripe_width
            .checked_sub(observed_volume_count)
            .ok_or(FormatError::InvalidArchive("volume count overflow"))?;
        if missing_volume_count > first.crypto_header.volume_loss_tolerance as u32 {
            return Err(FormatError::InvalidArchive(
                "missing volume count exceeds volume_loss_tolerance",
            ));
        }
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
                first_block_index: manifest_footer.index_root_first_block,
                data_block_count: manifest_footer.index_root_data_block_count,
                parity_block_count: manifest_footer.index_root_parity_block_count,
                encrypted_size: manifest_footer.index_root_encrypted_size,
            },
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            &first.subkeys.index_root_key,
            &first.subkeys.index_nonce_seed,
            b"idxroot",
            0,
            first.crypto_header.index_root_fec_data_shards,
            first.crypto_header.index_root_fec_parity_shards,
            manifest_footer.index_root_decompressed_size,
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
            crypto_header_bytes: first.crypto_header_bytes,
            volume_header: authority_volume_header,
            crypto_header: first.crypto_header,
            manifest_footer,
            volume_trailer: Some(authority_volume_trailer),
            root_auth_footer: root_auth_authority,
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
        Self::open_with_bootstrap_sidecar_options_for_mode(
            bytes,
            bootstrap_sidecar,
            master_key,
            options,
            BootstrapSidecarUse::SeekableAssist,
        )
    }

    fn open_with_bootstrap_sidecar_options_for_mode(
        bytes: &[u8],
        bootstrap_sidecar: &[u8],
        master_key: &MasterKey,
        options: ReaderOptions,
        sidecar_use: BootstrapSidecarUse,
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
        validate_bootstrap_single_volume_input(&volume_header, &parsed_crypto.fixed)?;
        validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

        let sidecar = parse_bootstrap_sidecar(
            bootstrap_sidecar,
            &volume_header,
            &parsed_crypto.fixed,
            &subkeys,
        )?;
        sidecar.require_sections_for(sidecar_use, &parsed_crypto.fixed)?;

        let (mut blocks, terminal_offset, observed_block_count) = parse_stream_block_prefix(
            bytes,
            crypto_end,
            parsed_crypto.fixed.block_size as usize,
            &volume_header,
        )?;
        let terminal_material = match sidecar_use {
            BootstrapSidecarUse::SeekableAssist => Some(parse_terminal_material(
                bytes,
                terminal_offset,
                observed_block_count,
                &subkeys,
                &volume_header,
                &parsed_crypto.fixed,
                options,
            )?),
            BootstrapSidecarUse::NonSeekableRandomAccess => parse_terminal_material(
                bytes,
                terminal_offset,
                observed_block_count,
                &subkeys,
                &volume_header,
                &parsed_crypto.fixed,
                options,
            )
            .ok(),
        };
        let terminal_manifest = terminal_material.as_ref().map(|(manifest, _, _)| manifest);
        let manifest_authority = match sidecar_use {
            BootstrapSidecarUse::SeekableAssist => {
                let terminal_manifest = terminal_manifest.ok_or(FormatError::InvalidArchive(
                    "terminal ManifestFooter/VolumeTrailer is required",
                ))?;
                if let Some(sidecar_manifest) = &sidecar.manifest_footer {
                    if !manifest_bootstrap_fields_match(terminal_manifest, sidecar_manifest) {
                        return Err(FormatError::InvalidArchive(
                            "bootstrap sidecar conflicts with terminal ManifestFooter",
                        ));
                    }
                }
                terminal_manifest.clone()
            }
            BootstrapSidecarUse::NonSeekableRandomAccess => {
                let sidecar_manifest = sidecar
                    .manifest_footer
                    .as_ref()
                    .ok_or(FormatError::ReaderUnsupported(
                    "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
                ))?;
                if let Some(terminal_manifest) = terminal_manifest {
                    if !manifest_bootstrap_fields_match(terminal_manifest, sidecar_manifest) {
                        return Err(FormatError::InvalidArchive(
                            "bootstrap sidecar conflicts with terminal ManifestFooter",
                        ));
                    }
                }
                sidecar_manifest.clone()
            }
        };
        manifest_authority.validate_index_root_extent(parsed_crypto.fixed.block_size)?;

        if let Some((offset, length)) = sidecar.index_root_records_section {
            let index_root_records = parse_sidecar_block_records(
                bootstrap_sidecar,
                offset,
                length,
                parsed_crypto.fixed.block_size as usize,
                index_root_extent_from_manifest(&manifest_authority),
                BlockKind::IndexRootData,
                BlockKind::IndexRootParity,
                "IndexRoot",
            )?;
            insert_sidecar_records(&mut blocks, index_root_records)?;
        }

        let limits = metadata_limits(&parsed_crypto.fixed);
        let index_root_plaintext = load_metadata_object_from_parts(
            &blocks,
            &subkeys,
            &volume_header,
            &parsed_crypto.fixed,
            index_root_extent_from_manifest(&manifest_authority),
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            parsed_crypto.fixed.index_root_fec_data_shards,
            parsed_crypto.fixed.index_root_fec_parity_shards,
            manifest_authority.index_root_decompressed_size,
        )?;
        let index_root = IndexRoot::parse(
            &index_root_plaintext,
            parsed_crypto.fixed.has_dictionary != 0,
            limits,
        )?;
        if parsed_crypto.fixed.has_dictionary != 0 {
            if let Some((offset, length)) = sidecar.dictionary_records_section {
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
            crypto_header_bytes: crypto_bytes.to_vec(),
            volume_header,
            crypto_header: parsed_crypto.fixed,
            manifest_footer: manifest_authority,
            volume_trailer: terminal_material
                .as_ref()
                .map(|(_, trailer, _)| trailer.clone()),
            root_auth_footer: terminal_material.and_then(|(_, _, root_auth)| root_auth),
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

    /// Return only the regular-file payload bytes for `path`.
    ///
    /// This is a payload-only convenience for callers that do not need tar
    /// metadata fidelity diagnostics. Use [`Self::extract_file_with_diagnostics`]
    /// or [`Self::extract_member`] when unsupported local PAX/GNU metadata must
    /// be reported to users.
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

    /// Return regular-file payload bytes together with parsed tar metadata
    /// diagnostics for `path`.
    pub fn extract_file_with_diagnostics(
        &self,
        path: &str,
    ) -> Result<Option<(Vec<u8>, Vec<MetadataDiagnostic>)>, FormatError> {
        self.extract_member(path)?
            .map(|member| {
                if member.kind != TarEntryKind::Regular {
                    return Err(FormatError::ReaderUnsupported(
                        "extract_file_with_diagnostics returns only regular file payloads",
                    ));
                }
                Ok((member.data, member.diagnostics))
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
        if self.index_root.header.file_count > DIRECTORY_HINT_REQUIRED_FILE_COUNT
            && self.index_root.directory_hint_shards.is_empty()
        {
            return Err(FormatError::InvalidArchive(
                "IndexRoot file_count requires directory hints",
            ));
        }

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
        validate_global_file_table_order(&shards)?;

        if file_count != self.index_root.header.file_count {
            return Err(FormatError::InvalidArchive(
                "IndexRoot file_count does not match decoded shards",
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

    pub fn verify_root_auth_with<F>(
        &self,
        mut verifier: F,
    ) -> Result<RootAuthVerification, FormatError>
    where
        F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
    {
        let footer = self
            .root_auth_footer
            .as_ref()
            .ok_or(FormatError::ReaderUnsupported("root-auth footer is absent"))?;
        self.verify()?;
        let material = self.recompute_root_auth_material(footer)?;
        if material.critical_metadata_digest != footer.critical_metadata_digest
            || material.index_digest != footer.index_digest
            || material.fec_layout_digest != footer.fec_layout_digest
            || material.data_block_merkle_root != footer.data_block_merkle_root
            || material.signer_identity_digest != footer.signer_identity_digest
            || material.archive_root != footer.archive_root
            || material.total_data_block_count != footer.total_data_block_count
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter commitments do not match recomputed archive root",
            ));
        }
        if !verifier(footer, &material.archive_root)? {
            return Err(FormatError::InvalidArchive(
                "root-auth authenticator verification failed",
            ));
        }
        Ok(RootAuthVerification {
            archive_root: material.archive_root,
            authenticator_id: footer.authenticator_id,
            signer_identity_type: footer.signer_identity_type,
            signer_identity_bytes: footer.signer_identity_bytes.clone(),
            total_data_block_count: footer.total_data_block_count,
        })
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

    fn recompute_root_auth_material(
        &self,
        footer: &RootAuthFooterV1,
    ) -> Result<RootAuthMaterial, FormatError> {
        let footer_length = footer.footer_length()?;
        let root_auth_descriptor_digest = root_auth_descriptor_digest(
            footer.authenticator_id,
            footer.signer_identity_type,
            &footer.signer_identity_bytes,
            u32::try_from(footer.authenticator_value.len()).map_err(|_| {
                FormatError::InvalidArchive("RootAuthFooter authenticator length overflow")
            })?,
            footer_length,
        )?;
        let signer_identity_digest =
            signer_identity_digest(footer.signer_identity_type, &footer.signer_identity_bytes)?;
        let manifest_pre_hmac = manifest_footer_global_pre_hmac_bytes(&self.manifest_footer);
        let crypto_pre_hmac_len = self
            .crypto_header_bytes
            .len()
            .checked_sub(CRYPTO_HEADER_HMAC_LEN)
            .ok_or(FormatError::InvalidArchive("CryptoHeader is too short"))?;
        let critical_metadata_digest = critical_metadata_digest(CriticalMetadataDigestInputs {
            archive_uuid: self.volume_header.archive_uuid,
            session_id: self.volume_header.session_id,
            stripe_width: self.crypto_header.stripe_width,
            total_volumes: self.manifest_footer.total_volumes,
            compression_algo: self.crypto_header.compression_algo,
            aead_algo: self.crypto_header.aead_algo,
            fec_algo: self.crypto_header.fec_algo,
            kdf_algo: self.crypto_header.kdf_algo,
            crypto_header_pre_hmac_bytes: &self.crypto_header_bytes[..crypto_pre_hmac_len],
            chunk_size: self.crypto_header.chunk_size,
            envelope_target_size: self.crypto_header.envelope_target_size,
            block_size: self.crypto_header.block_size,
            fec_data_shards: self.crypto_header.fec_data_shards,
            fec_parity_shards: self.crypto_header.fec_parity_shards,
            index_fec_data_shards: self.crypto_header.index_fec_data_shards,
            index_fec_parity_shards: self.crypto_header.index_fec_parity_shards,
            index_root_fec_data_shards: self.crypto_header.index_root_fec_data_shards,
            index_root_fec_parity_shards: self.crypto_header.index_root_fec_parity_shards,
            volume_loss_tolerance: self.crypto_header.volume_loss_tolerance,
            bit_rot_buffer_pct: self.crypto_header.bit_rot_buffer_pct,
            has_dictionary: self.crypto_header.has_dictionary,
            manifest_footer_global_pre_hmac_bytes: &manifest_pre_hmac,
            index_root_first_block: self.manifest_footer.index_root_first_block,
            index_root_data_block_count: self.manifest_footer.index_root_data_block_count,
            index_root_parity_block_count: self.manifest_footer.index_root_parity_block_count,
            index_root_encrypted_size: self.manifest_footer.index_root_encrypted_size,
            index_root_decompressed_size: self.manifest_footer.index_root_decompressed_size,
            root_auth_descriptor_digest,
        })?;
        let index_root_plaintext = self.index_root.to_bytes();
        let index_digest = index_digest(&index_root_plaintext);
        let shards = self.load_all_index_shards()?;
        let fec_layout_rows = self.root_auth_fec_layout_rows(&shards)?;
        let fec_layout_digest = fec_layout_digest(&fec_layout_rows)?;
        let data_leaves = self.root_auth_data_block_leaves(&fec_layout_rows)?;
        let total_data_block_count = u64::try_from(data_leaves.len())
            .map_err(|_| FormatError::InvalidArchive("root-auth data block count overflow"))?;
        let data_block_merkle_root = data_block_merkle_root(&data_leaves);
        let archive_root = archive_root(ArchiveRootInputs {
            archive_uuid: self.volume_header.archive_uuid,
            session_id: self.volume_header.session_id,
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            compression_algo: self.crypto_header.compression_algo,
            aead_algo: self.crypto_header.aead_algo,
            fec_algo: self.crypto_header.fec_algo,
            kdf_algo: self.crypto_header.kdf_algo,
            critical_metadata_digest,
            index_digest,
            fec_layout_digest,
            total_data_block_count,
            data_block_merkle_root,
            root_auth_descriptor_digest,
            signer_identity_digest,
        });
        Ok(RootAuthMaterial {
            critical_metadata_digest,
            index_digest,
            fec_layout_digest,
            data_block_merkle_root,
            signer_identity_digest,
            archive_root,
            total_data_block_count,
        })
    }

    fn root_auth_fec_layout_rows(
        &self,
        shards: &[IndexShard],
    ) -> Result<Vec<FecLayoutObjectRow>, FormatError> {
        let mut rows = Vec::new();
        rows.push(FecLayoutObjectRow {
            object_class: 1,
            present: true,
            object_id: 0,
            first_block_index: self.manifest_footer.index_root_first_block,
            data_block_count: self.manifest_footer.index_root_data_block_count,
            parity_block_count: self.manifest_footer.index_root_parity_block_count,
            encrypted_size: self.manifest_footer.index_root_encrypted_size,
            plain_size: self.manifest_footer.index_root_decompressed_size,
        });
        if self.crypto_header.has_dictionary != 0 {
            rows.push(FecLayoutObjectRow {
                object_class: 2,
                present: true,
                object_id: 0,
                first_block_index: self.index_root.header.dictionary_first_block,
                data_block_count: self.index_root.header.dictionary_data_block_count,
                parity_block_count: self.index_root.header.dictionary_parity_block_count,
                encrypted_size: self.index_root.header.dictionary_encrypted_size,
                plain_size: self.index_root.header.dictionary_decompressed_size,
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
        for entry in &self.index_root.shards {
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
        let mut envelopes = BTreeMap::<u64, EnvelopeEntry>::new();
        for shard in shards {
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
        for envelope in envelopes.values() {
            rows.push(FecLayoutObjectRow {
                object_class: 4,
                present: true,
                object_id: envelope.envelope_index,
                first_block_index: envelope.first_block_index,
                data_block_count: envelope.data_block_count,
                parity_block_count: envelope.parity_block_count,
                encrypted_size: envelope.encrypted_size,
                plain_size: envelope.plaintext_size,
            });
        }
        for entry in &self.index_root.directory_hint_shards {
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
        Ok(rows)
    }

    fn root_auth_data_block_leaves(
        &self,
        rows: &[FecLayoutObjectRow],
    ) -> Result<Vec<DataBlockMerkleLeaf>, FormatError> {
        let mut leaves = Vec::new();
        for row in rows.iter().filter(|row| row.present) {
            let (data_kind, parity_kind, data_max, parity_max) = match row.object_class {
                1 => (
                    BlockKind::IndexRootData,
                    BlockKind::IndexRootParity,
                    self.crypto_header.index_root_fec_data_shards,
                    self.crypto_header.index_root_fec_parity_shards,
                ),
                2 => (
                    BlockKind::DictionaryData,
                    BlockKind::DictionaryParity,
                    self.crypto_header.index_root_fec_data_shards,
                    self.crypto_header.index_root_fec_parity_shards,
                ),
                3 => (
                    BlockKind::IndexShardData,
                    BlockKind::IndexShardParity,
                    self.crypto_header.index_fec_data_shards,
                    self.crypto_header.index_fec_parity_shards,
                ),
                4 => (
                    BlockKind::PayloadData,
                    BlockKind::PayloadParity,
                    self.crypto_header.fec_data_shards,
                    self.crypto_header.fec_parity_shards,
                ),
                5 => (
                    BlockKind::DirectoryHintData,
                    BlockKind::DirectoryHintParity,
                    self.crypto_header.index_fec_data_shards,
                    self.crypto_header.index_fec_parity_shards,
                ),
                _ => {
                    return Err(FormatError::InvalidArchive(
                        "unknown root-auth FEC row class",
                    ))
                }
            };
            let extent = ObjectExtent {
                first_block_index: row.first_block_index,
                data_block_count: row.data_block_count,
                parity_block_count: row.parity_block_count,
                encrypted_size: row.encrypted_size,
            };
            let repaired = load_repaired_object_data_shards_from_parts(
                &self.blocks,
                &self.crypto_header,
                extent,
                data_kind,
                parity_kind,
                data_max,
                parity_max,
            )?;
            for (offset, payload) in repaired.into_iter().enumerate() {
                leaves.push(DataBlockMerkleLeaf {
                    block_index: checked_u64_add(
                        row.first_block_index,
                        offset as u64,
                        "root-auth data block",
                    )?,
                    kind: data_kind,
                    flags: if offset + 1 == row.data_block_count as usize {
                        0x01
                    } else {
                        0
                    },
                    payload,
                });
            }
        }
        leaves.sort_by_key(|leaf| leaf.block_index);
        Ok(leaves)
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
    manifest_footer: Option<ManifestFooter>,
    manifest_footer_error: Option<FormatError>,
    root_auth_footer: Option<RootAuthFooterV1>,
    root_auth_footer_bytes: Option<Vec<u8>>,
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
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

    let terminal = locate_v41_terminal(
        bytes,
        &subkeys,
        &volume_header,
        &parsed_crypto.fixed,
        options,
    )?;
    let trailer_offset = to_usize(terminal.image.volume_trailer_offset, "VolumeTrailer")?;
    let volume_trailer = terminal.volume_trailer.clone();
    validate_trailer_identity(&volume_header, &volume_trailer)?;

    let manifest_offset = to_usize(volume_trailer.manifest_footer_offset, "ManifestFooter")?;
    let manifest_end = checked_add(manifest_offset, MANIFEST_FOOTER_LEN, "ManifestFooter")?;
    if volume_trailer.root_auth_flags & 0x0000_0001 != 0 {
        if to_usize(volume_trailer.root_auth_footer_offset, "RootAuthFooter")? != manifest_end
            || volume_trailer
                .root_auth_footer_offset
                .checked_add(volume_trailer.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter terminal boundary overflow",
                ))?
                != trailer_offset as u64
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter does not sit before selected trailer",
            ));
        }
    } else if manifest_end != trailer_offset {
        return Err(FormatError::InvalidArchive(
            "ManifestFooter does not end at selected trailer",
        ));
    }
    let manifest_bytes = &terminal.manifest_footer_bytes;
    let (manifest_footer, manifest_footer_error) = match parse_valid_manifest_footer(
        &volume_header,
        &subkeys,
        manifest_bytes,
        parsed_crypto.fixed.block_size,
    ) {
        Ok(footer) => (Some(footer), None),
        Err(err) if manifest_footer_copy_error_is_recoverable(&err) => (None, Some(err)),
        Err(err) => return Err(err),
    };

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
        manifest_footer_error,
        root_auth_footer: terminal.root_auth_footer,
        root_auth_footer_bytes: terminal.root_auth_footer_bytes,
        volume_trailer,
        blocks: block_region.blocks,
        erased_block_indices: block_region.erased_block_indices,
    })
}

#[derive(Debug)]
struct ParsedPublicNoKeyVolume {
    volume_header: VolumeHeader,
    crypto_header: CryptoHeaderFixed,
    root_auth_footer: RootAuthFooterV1,
    root_auth_footer_bytes: Vec<u8>,
    blocks: BTreeMap<u64, BlockRecord>,
}

fn public_no_key_verify_volumes_with_options<F>(
    volumes: &[&[u8]],
    mut verifier: F,
    options: ReaderOptions,
) -> Result<PublicNoKeyVerification, FormatError>
where
    F: FnMut(&RootAuthFooterV1, &[u8; 32]) -> Result<bool, FormatError>,
{
    if volumes.is_empty() {
        return Err(FormatError::InvalidArchive("no volumes supplied"));
    }
    let mut parsed = Vec::with_capacity(volumes.len());
    for volume in volumes {
        parsed.push(parse_public_no_key_volume(volume, options)?);
    }
    let first = parsed
        .first()
        .ok_or(FormatError::InvalidArchive("no volumes supplied"))?;
    if parsed.len() != first.crypto_header.stripe_width as usize {
        return Err(FormatError::ReaderUnsupported(
            "public no-key verification requires a complete volume set",
        ));
    }

    let mut seen_volume_indexes = BTreeSet::new();
    let mut blocks = BTreeMap::new();
    for volume in &parsed {
        if volume.volume_header.archive_uuid != first.volume_header.archive_uuid
            || volume.volume_header.session_id != first.volume_header.session_id
            || !public_crypto_headers_agree(&volume.crypto_header, &first.crypto_header)
        {
            return Err(FormatError::InvalidArchive(
                "public no-key volume global metadata differs",
            ));
        }
        if volume.root_auth_footer_bytes != first.root_auth_footer_bytes {
            return Err(FormatError::InvalidArchive(
                "public no-key RootAuthFooter copies differ",
            ));
        }
        if !seen_volume_indexes.insert(volume.volume_header.volume_index) {
            return Err(FormatError::InvalidArchive(
                "duplicate public no-key volume index",
            ));
        }
        for (block_index, record) in &volume.blocks {
            if blocks.insert(*block_index, record.clone()).is_some() {
                return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
            }
        }
    }
    validate_complete_global_block_coverage(&blocks, &BTreeSet::new())?;

    let footer = &first.root_auth_footer;
    let mut data_leaves = blocks
        .values()
        .filter(|record| record.kind.is_data())
        .map(|record| DataBlockMerkleLeaf {
            block_index: record.block_index,
            kind: record.kind,
            flags: record.flags,
            payload: record.payload.clone(),
        })
        .collect::<Vec<_>>();
    data_leaves.sort_by_key(|leaf| leaf.block_index);
    let total_data_block_count = u64::try_from(data_leaves.len())
        .map_err(|_| FormatError::InvalidArchive("public no-key data block count overflow"))?;
    let observed_data_root = data_block_merkle_root(&data_leaves);
    if total_data_block_count != footer.total_data_block_count
        || observed_data_root != footer.data_block_merkle_root
    {
        return Err(FormatError::InvalidArchive(
            "public no-key data-block commitment mismatch",
        ));
    }
    let archive_root = recompute_public_archive_root(footer, &first.crypto_header)?;
    if archive_root != footer.archive_root {
        return Err(FormatError::InvalidArchive(
            "public no-key archive_root mismatch",
        ));
    }
    if !verifier(footer, &archive_root)? {
        return Err(FormatError::InvalidArchive(
            "public no-key authenticator verification failed",
        ));
    }
    Ok(PublicNoKeyVerification {
        archive_root,
        authenticator_id: footer.authenticator_id,
        signer_identity_type: footer.signer_identity_type,
        signer_identity_bytes: footer.signer_identity_bytes.clone(),
        total_data_block_count,
    })
}

fn parse_public_no_key_volume(
    bytes: &[u8],
    options: ReaderOptions,
) -> Result<ParsedPublicNoKeyVolume, FormatError> {
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
    parsed_crypto.validate_extension_semantics()?;
    validate_seekable_supported_volume(&volume_header, &parsed_crypto.fixed)?;
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

    let terminal =
        locate_v41_public_terminal(bytes, &volume_header, &parsed_crypto.fixed, options)?;
    let block_region = parse_public_block_observation(
        bytes,
        crypto_end,
        &terminal.image,
        parsed_crypto.fixed.block_size as usize,
        &volume_header,
    )?;
    Ok(ParsedPublicNoKeyVolume {
        volume_header,
        crypto_header: parsed_crypto.fixed,
        root_auth_footer: terminal.root_auth_footer,
        root_auth_footer_bytes: terminal.root_auth_footer_bytes,
        blocks: block_region,
    })
}

fn public_crypto_headers_agree(left: &CryptoHeaderFixed, right: &CryptoHeaderFixed) -> bool {
    left.length == right.length
        && left.stripe_width == right.stripe_width
        && left.block_size == right.block_size
        && left.compression_algo == right.compression_algo
        && left.aead_algo == right.aead_algo
        && left.fec_algo == right.fec_algo
        && left.kdf_algo == right.kdf_algo
}

fn recompute_public_archive_root(
    footer: &RootAuthFooterV1,
    crypto_header: &CryptoHeaderFixed,
) -> Result<[u8; 32], FormatError> {
    let descriptor_digest = root_auth_descriptor_digest(
        footer.authenticator_id,
        footer.signer_identity_type,
        &footer.signer_identity_bytes,
        u32::try_from(footer.authenticator_value.len()).map_err(|_| {
            FormatError::InvalidArchive("RootAuthFooter authenticator length overflow")
        })?,
        footer.footer_length()?,
    )?;
    let signer_digest =
        signer_identity_digest(footer.signer_identity_type, &footer.signer_identity_bytes)?;
    if signer_digest != footer.signer_identity_digest {
        return Err(FormatError::InvalidArchive(
            "public no-key signer identity digest mismatch",
        ));
    }
    Ok(archive_root(ArchiveRootInputs {
        archive_uuid: footer.archive_uuid,
        session_id: footer.session_id,
        format_version: FORMAT_VERSION,
        volume_format_rev: VOLUME_FORMAT_REV,
        compression_algo: crypto_header.compression_algo,
        aead_algo: crypto_header.aead_algo,
        fec_algo: crypto_header.fec_algo,
        kdf_algo: crypto_header.kdf_algo,
        critical_metadata_digest: footer.critical_metadata_digest,
        index_digest: footer.index_digest,
        fec_layout_digest: footer.fec_layout_digest,
        total_data_block_count: footer.total_data_block_count,
        data_block_merkle_root: footer.data_block_merkle_root,
        root_auth_descriptor_digest: descriptor_digest,
        signer_identity_digest: signer_digest,
    }))
}

fn parse_valid_manifest_footer(
    volume_header: &VolumeHeader,
    subkeys: &Subkeys,
    manifest_bytes: &[u8],
    block_size: u32,
) -> Result<ManifestFooter, FormatError> {
    let manifest_footer = ManifestFooter::parse(manifest_bytes)?;
    validate_manifest_footer(volume_header, &manifest_footer, subkeys, manifest_bytes)?;
    manifest_footer.validate_index_root_extent(block_size)?;
    Ok(manifest_footer)
}

fn manifest_footer_copy_error_is_recoverable(error: &FormatError) -> bool {
    matches!(
        error,
        FormatError::BadMagic {
            structure: "ManifestFooter",
        } | FormatError::NonZeroReserved {
            structure: "ManifestFooter",
        } | FormatError::InvalidAuthoritativeFlag(_)
            | FormatError::HmacMismatch {
                structure: "ManifestFooter",
            }
    )
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

fn validate_crypto_class_parity_exactness(
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    let fec = required_object_parity(crypto_header.fec_data_shards as u64, crypto_header)?;
    if crypto_header.fec_parity_shards as u32 != fec {
        return Err(FormatError::InvalidArchive(
            "fec_parity_shards does not match v41 compute_parity",
        ));
    }
    let index = required_object_parity(crypto_header.index_fec_data_shards as u64, crypto_header)?;
    if crypto_header.index_fec_parity_shards as u32 != index {
        return Err(FormatError::InvalidArchive(
            "index_fec_parity_shards does not match v41 compute_parity",
        ));
    }
    let index_root = required_object_parity(
        crypto_header.index_root_fec_data_shards as u64,
        crypto_header,
    )?;
    if crypto_header.index_root_fec_parity_shards as u32 != index_root {
        return Err(FormatError::InvalidArchive(
            "index_root_fec_parity_shards does not match v41 compute_parity",
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

#[derive(Debug)]
struct V41Terminal {
    image: CriticalMetadataImage,
    manifest_footer_bytes: Vec<u8>,
    root_auth_footer_bytes: Option<Vec<u8>>,
    root_auth_footer: Option<RootAuthFooterV1>,
    volume_trailer: VolumeTrailer,
}

#[derive(Debug)]
struct V41PublicTerminal {
    image: CriticalMetadataImage,
    root_auth_footer_bytes: Vec<u8>,
    root_auth_footer: RootAuthFooterV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CmraDecoderTuple {
    shard_size: u32,
    data_shard_count: u16,
    parity_shard_count: u16,
    image_length: u32,
    image_sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CmraIdentityHints {
    archive_uuid: [u8; 16],
    session_id: [u8; 16],
    volume_index: u32,
}

impl From<CriticalMetadataRecoveryHeader> for CmraDecoderTuple {
    fn from(header: CriticalMetadataRecoveryHeader) -> Self {
        Self {
            shard_size: header.shard_size,
            data_shard_count: header.data_shard_count,
            parity_shard_count: header.parity_shard_count,
            image_length: header.image_length,
            image_sha256: header.image_sha256,
        }
    }
}

impl From<CriticalMetadataRecoveryHeader> for CmraIdentityHints {
    fn from(header: CriticalMetadataRecoveryHeader) -> Self {
        Self {
            archive_uuid: header.archive_uuid_hint,
            session_id: header.session_id_hint,
            volume_index: header.volume_index_hint,
        }
    }
}

impl From<CriticalRecoveryLocator> for CmraDecoderTuple {
    fn from(locator: CriticalRecoveryLocator) -> Self {
        Self {
            shard_size: locator.cmra_shard_size,
            data_shard_count: locator.cmra_data_shard_count,
            parity_shard_count: locator.cmra_parity_shard_count,
            image_length: locator.cmra_image_length,
            image_sha256: locator.cmra_image_sha256,
        }
    }
}

impl From<CriticalRecoveryLocator> for CmraIdentityHints {
    fn from(locator: CriticalRecoveryLocator) -> Self {
        Self {
            archive_uuid: locator.archive_uuid_hint,
            session_id: locator.session_id_hint,
            volume_index: locator.volume_index_hint,
        }
    }
}

#[derive(Debug)]
struct RecoveredCmra {
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    header_hints: Option<CmraIdentityHints>,
    cmra_length: u64,
}

#[derive(Debug)]
struct TerminalCandidate {
    terminal: V41Terminal,
    anchor: usize,
    locator_sequence: Option<u32>,
    cmra_offset: u64,
    cmra_length: u64,
}

#[derive(Debug)]
struct PublicTerminalCandidate {
    terminal: V41PublicTerminal,
    anchor: usize,
    cmra_offset: u64,
    cmra_length: u64,
}

#[derive(Debug, Clone, Copy)]
enum CmraRecoveryMode {
    KeyHolding,
    PublicNoKey,
}

fn locate_v41_terminal(
    bytes: &[u8],
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    options: ReaderOptions,
) -> Result<V41Terminal, FormatError> {
    locate_v41_terminal_candidate(bytes, subkeys, volume_header, crypto_header, options)
        .map(|candidate| candidate.terminal)
}

fn locate_v41_terminal_candidate(
    bytes: &[u8],
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    options: ReaderOptions,
) -> Result<TerminalCandidate, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v41_locator_candidate(
            bytes,
            final_offset,
            0,
            subkeys,
            volume_header,
            crypto_header,
            &mut candidates,
        );
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v41_locator_candidate(
            bytes,
            mirror_offset,
            1,
            subkeys,
            volume_header,
            crypto_header,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_locator_candidate(
                    bytes,
                    offset,
                    2,
                    subkeys,
                    volume_header,
                    crypto_header,
                    &mut candidates,
                );
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_locatorless_cmra_candidate(
                    bytes,
                    offset,
                    subkeys,
                    volume_header,
                    crypto_header,
                ) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_terminal_candidate(candidates)
}

fn locate_v41_public_terminal(
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    options: ReaderOptions,
) -> Result<V41PublicTerminal, FormatError> {
    let mut candidates = Vec::new();
    if bytes.len() >= CRITICAL_RECOVERY_LOCATOR_LEN {
        let final_offset = bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        collect_v41_public_locator_candidate(
            bytes,
            final_offset,
            0,
            volume_header,
            crypto_header,
            &mut candidates,
        );
    }
    if bytes.len() >= LOCATOR_PAIR_LEN {
        let mirror_offset = bytes.len() - LOCATOR_PAIR_LEN;
        collect_v41_public_locator_candidate(
            bytes,
            mirror_offset,
            1,
            volume_header,
            crypto_header,
            &mut candidates,
        );
    }

    if candidates.is_empty() {
        let scan = max_critical_recovery_scan(options)?;
        let scan_start = bytes.len().saturating_sub(scan);
        let mut offset = bytes.len().saturating_sub(4);
        while offset >= scan_start {
            if bytes.get(offset..offset + 4) == Some(b"TZCL") {
                collect_v41_public_locator_candidate(
                    bytes,
                    offset,
                    2,
                    volume_header,
                    crypto_header,
                    &mut candidates,
                );
            } else if bytes.get(offset..offset + 4) == Some(b"TZCR") {
                if let Ok(candidate) = parse_public_locatorless_cmra_candidate(
                    bytes,
                    offset,
                    volume_header,
                    crypto_header,
                ) {
                    candidates.push(candidate);
                }
            }
            if offset == 0 {
                break;
            }
            offset -= 1;
        }
    }

    choose_v41_public_terminal_candidate(candidates).map(|candidate| candidate.terminal)
}

fn collect_v41_locator_candidate(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    candidates: &mut Vec<TerminalCandidate>,
) {
    let Some(raw) = bytes.get(offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) = parse_locator_cmra_candidate(
        bytes,
        offset,
        locator,
        subkeys,
        volume_header,
        crypto_header,
    ) {
        candidates.push(candidate);
    }
}

fn collect_v41_public_locator_candidate(
    bytes: &[u8],
    offset: usize,
    expected_sequence: u32,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    candidates: &mut Vec<PublicTerminalCandidate>,
) {
    let Some(raw) = bytes.get(offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN) else {
        return;
    };
    let Ok(locator) = CriticalRecoveryLocator::parse(raw) else {
        return;
    };
    if expected_sequence <= 1 && locator.locator_sequence != expected_sequence {
        return;
    }
    if let Ok(candidate) =
        parse_public_locator_cmra_candidate(bytes, offset, locator, volume_header, crypto_header)
    {
        candidates.push(candidate);
    }
}

fn choose_v41_terminal_candidate(
    mut candidates: Vec<TerminalCandidate>,
) -> Result<TerminalCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive(
        "no valid v41 CMRA candidate found",
    ))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor
            && (previous.cmra_offset != winner.cmra_offset
                || previous.cmra_length != winner.cmra_length)
        {
            return Err(FormatError::InvalidArchive("ambiguous v41 CMRA candidates"));
        }
    }
    Ok(winner)
}

fn choose_v41_public_terminal_candidate(
    mut candidates: Vec<PublicTerminalCandidate>,
) -> Result<PublicTerminalCandidate, FormatError> {
    candidates.sort_by_key(|candidate| candidate.anchor);
    let winner = candidates.pop().ok_or(FormatError::InvalidArchive(
        "no valid v41 public CMRA candidate found",
    ))?;
    if let Some(previous) = candidates.last() {
        if previous.anchor == winner.anchor
            && (previous.cmra_offset != winner.cmra_offset
                || previous.cmra_length != winner.cmra_length)
        {
            return Err(FormatError::InvalidArchive(
                "ambiguous v41 public CMRA candidates",
            ));
        }
    }
    Ok(winner)
}

fn parse_locator_cmra_candidate(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<TerminalCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(
        bytes,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let terminal = validate_recovered_terminal(
        recovered.image,
        recovered.tuple,
        bytes,
        subkeys,
        volume_header,
        crypto_header,
    )?;
    Ok(TerminalCandidate {
        terminal,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        locator_sequence: Some(locator.locator_sequence),
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_public_locator_cmra_candidate(
    bytes: &[u8],
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<PublicTerminalCandidate, FormatError> {
    let tuple = CmraDecoderTuple::from(locator);
    validate_cmra_decoder_tuple(tuple)?;
    let expected_cmra_length = cmra_serialized_length(tuple)?;
    if locator.cmra_length as u64 != expected_cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_position(locator_offset, locator)?;
    let recovered = recover_cmra(
        bytes,
        locator.cmra_offset,
        Some(tuple),
        CmraRecoveryMode::PublicNoKey,
    )?;
    if recovered.tuple != tuple {
        return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
    }
    if expected_cmra_length != recovered.cmra_length {
        return Err(FormatError::InvalidArchive("locator CMRA length mismatch"));
    }
    validate_locator_image_boundary(locator, &recovered.image)?;
    validate_cmra_identity_hints(
        recovered.header_hints,
        Some(CmraIdentityHints::from(locator)),
        &recovered.image,
    )?;
    let terminal =
        validate_recovered_public_terminal(recovered.image, bytes, volume_header, crypto_header)?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: locator_offset
            .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
            .ok_or(FormatError::InvalidArchive("locator anchor overflow"))?,
        cmra_offset: locator.cmra_offset,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_locatorless_cmra_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<TerminalCandidate, FormatError> {
    let recovered = recover_cmra(
        bytes,
        cmra_offset as u64,
        None,
        CmraRecoveryMode::KeyHolding,
    )?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal = validate_recovered_terminal(
        recovered.image,
        recovered.tuple,
        bytes,
        subkeys,
        volume_header,
        crypto_header,
    )?;
    Ok(TerminalCandidate {
        terminal,
        anchor: cmra_offset
            .checked_add(to_usize(recovered.cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        locator_sequence: None,
        cmra_offset: cmra_offset as u64,
        cmra_length: recovered.cmra_length,
    })
}

fn parse_public_locatorless_cmra_candidate(
    bytes: &[u8],
    cmra_offset: usize,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<PublicTerminalCandidate, FormatError> {
    let recovered = recover_cmra(
        bytes,
        cmra_offset as u64,
        None,
        CmraRecoveryMode::PublicNoKey,
    )?;
    if recovered.image.body_bytes_before_cmra != cmra_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locatorless CMRA boundary mismatch",
        ));
    }
    if recovered
        .image
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA boundary overflow"))?
        != cmra_offset as u64
    {
        return Err(FormatError::InvalidArchive(
            "locatorless trailer boundary mismatch",
        ));
    }
    validate_cmra_identity_hints(recovered.header_hints, None, &recovered.image)?;
    let terminal =
        validate_recovered_public_terminal(recovered.image, bytes, volume_header, crypto_header)?;
    Ok(PublicTerminalCandidate {
        terminal,
        anchor: cmra_offset
            .checked_add(to_usize(recovered.cmra_length, "CMRA")?)
            .ok_or(FormatError::InvalidArchive("CMRA anchor overflow"))?,
        cmra_offset: cmra_offset as u64,
        cmra_length: recovered.cmra_length,
    })
}

fn validate_locator_position(
    locator_offset: usize,
    locator: CriticalRecoveryLocator,
) -> Result<(), FormatError> {
    if locator.cmra_offset != locator.body_bytes_before_cmra {
        return Err(FormatError::InvalidArchive(
            "locator CMRA boundary mismatch",
        ));
    }
    if locator
        .volume_trailer_offset
        .checked_add(VOLUME_TRAILER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("locator trailer overflow"))?
        != locator.cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locator trailer boundary mismatch",
        ));
    }
    let expected_offset = match locator.locator_sequence {
        1 => locator.cmra_offset.checked_add(locator.cmra_length as u64),
        0 => locator
            .cmra_offset
            .checked_add(locator.cmra_length as u64)
            .and_then(|value| value.checked_add(CRITICAL_RECOVERY_LOCATOR_LEN as u64)),
        _ => None,
    }
    .ok_or(FormatError::InvalidArchive("locator position overflow"))?;
    if expected_offset != locator_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "locator position does not match sequence",
        ));
    }
    Ok(())
}

fn validate_locator_image_boundary(
    locator: CriticalRecoveryLocator,
    image: &CriticalMetadataImage,
) -> Result<(), FormatError> {
    if locator.volume_trailer_offset != image.volume_trailer_offset
        || locator.body_bytes_before_cmra != image.body_bytes_before_cmra
        || image
            .volume_trailer_offset
            .checked_add(VOLUME_TRAILER_LEN as u64)
            .ok_or(FormatError::InvalidArchive("CMRA image boundary overflow"))?
            != locator.cmra_offset
    {
        return Err(FormatError::InvalidArchive(
            "locator and CMRA image boundaries differ",
        ));
    }
    Ok(())
}

fn validate_cmra_identity_hints(
    header_hints: Option<CmraIdentityHints>,
    locator_hints: Option<CmraIdentityHints>,
    image: &CriticalMetadataImage,
) -> Result<(), FormatError> {
    if let (Some(header), Some(locator)) = (header_hints, locator_hints) {
        if header != locator {
            return Err(FormatError::InvalidArchive(
                "CMRA header and locator identity hints differ",
            ));
        }
    }
    for hints in [header_hints, locator_hints].into_iter().flatten() {
        if hints.archive_uuid != image.archive_uuid
            || hints.session_id != image.session_id
            || hints.volume_index != image.volume_index
        {
            return Err(FormatError::InvalidArchive(
                "CMRA identity hints do not match recovered image",
            ));
        }
    }
    Ok(())
}

fn recover_cmra(
    bytes: &[u8],
    cmra_offset: u64,
    locator_tuple: Option<CmraDecoderTuple>,
    mode: CmraRecoveryMode,
) -> Result<RecoveredCmra, FormatError> {
    let offset = to_usize(cmra_offset, "CMRA")?;
    let header_bytes = slice(
        bytes,
        offset,
        CRITICAL_METADATA_RECOVERY_HEADER_LEN,
        "CriticalMetadataRecoveryHeader",
    )?;
    let parsed_header = CriticalMetadataRecoveryHeader::parse(header_bytes);
    let (tuple, header_hints) = match (parsed_header, locator_tuple) {
        (Ok(header), Some(locator_tuple)) => {
            let header_tuple = CmraDecoderTuple::from(header);
            if header_tuple != locator_tuple {
                return Err(FormatError::InvalidArchive("CMRA decoder tuple mismatch"));
            }
            (locator_tuple, Some(CmraIdentityHints::from(header)))
        }
        (Ok(header), None) => (
            CmraDecoderTuple::from(header),
            Some(CmraIdentityHints::from(header)),
        ),
        (
            Err(FormatError::BadCrc {
                structure: "CriticalMetadataRecoveryHeader",
            }),
            Some(tuple),
        ) => (tuple, None),
        (Err(err), _) => return Err(err),
    };
    validate_cmra_decoder_tuple(tuple)?;
    let cmra_length = cmra_serialized_length(tuple)?;
    let cmra_len = to_usize(cmra_length, "CMRA")?;
    let cmra_bytes = slice(bytes, offset, cmra_len, "CMRA")?;
    let shard_size = tuple.shard_size as usize;
    let mut data_shards = vec![None; tuple.data_shard_count as usize];
    let mut parity_shards = vec![None; tuple.parity_shard_count as usize];
    let mut cursor = CRITICAL_METADATA_RECOVERY_HEADER_LEN;
    for idx in 0..(tuple.data_shard_count as usize + tuple.parity_shard_count as usize) {
        let raw = slice(
            cmra_bytes,
            cursor,
            CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size,
            "CriticalMetadataRecoveryShard",
        )?;
        let shard = match CriticalMetadataRecoveryShard::parse(raw, shard_size) {
            Ok(shard) => Some(shard),
            Err(FormatError::BadCrc {
                structure: "CriticalMetadataRecoveryShard",
            }) => None,
            Err(err) => return Err(err),
        };
        if let Some(shard) = shard {
            validate_cmra_shard(&shard, idx, tuple)?;
            if shard.shard_role == 0 {
                data_shards[idx] = Some(shard.payload);
            } else {
                let parity_idx = idx - tuple.data_shard_count as usize;
                parity_shards[parity_idx] = Some(shard.payload);
            }
        }
        cursor = checked_add(
            cursor,
            CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size,
            "CriticalMetadataRecoveryShard",
        )?;
    }
    let repaired = repair_data_gf16(&data_shards, &parity_shards, shard_size)?;
    let mut image_bytes = Vec::with_capacity(tuple.image_length as usize);
    for shard in repaired {
        image_bytes.extend_from_slice(&shard);
    }
    image_bytes.truncate(tuple.image_length as usize);
    if sha256_bytes(&image_bytes) != tuple.image_sha256 {
        return Err(FormatError::InvalidArchive("CMRA image SHA-256 mismatch"));
    }
    let image = CriticalMetadataImage::parse(&image_bytes)?;
    validate_critical_metadata_image(&image, tuple, mode)?;
    Ok(RecoveredCmra {
        image,
        tuple,
        header_hints,
        cmra_length,
    })
}

fn validate_cmra_decoder_tuple(tuple: CmraDecoderTuple) -> Result<(), FormatError> {
    let shard_size = tuple.shard_size as u64;
    if !(512..=4096).contains(&shard_size) || shard_size % 2 != 0 {
        return Err(FormatError::InvalidArchive("CMRA shard_size is invalid"));
    }
    let image_length = tuple.image_length as u64;
    let min = critical_image_min();
    let cap = critical_image_cap()?;
    if image_length < min || image_length > cap {
        return Err(FormatError::InvalidArchive(
            "CMRA image_length is outside bounds",
        ));
    }
    let expected_data_shards = ceil_div_u64(image_length, shard_size)?;
    if expected_data_shards == 0 || expected_data_shards != tuple.data_shard_count as u64 {
        return Err(FormatError::InvalidArchive(
            "CMRA data_shard_count does not match image length",
        ));
    }
    let max_parity = 2u64.max(ceil_div_u64(
        checked_u64_mul(
            expected_data_shards,
            READER_MAX_CMRA_PARITY_PCT as u64,
            "CMRA parity overflow",
        )?,
        100,
    )?);
    if tuple.parity_shard_count as u64 > max_parity {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field: "CMRA parity shard count",
            cap: max_parity,
            actual: tuple.parity_shard_count as u64,
        });
    }
    let total = expected_data_shards
        .checked_add(tuple.parity_shard_count as u64)
        .ok_or(FormatError::InvalidArchive("CMRA shard count overflow"))?;
    if total > 65_535 {
        return Err(FormatError::FecTooManyShards(total as usize));
    }
    Ok(())
}

fn validate_cmra_writer_parity_lower_bound(
    tuple: CmraDecoderTuple,
    bit_rot_buffer_pct: u8,
) -> Result<(), FormatError> {
    let min_parity = 2u64.max(ceil_div_u64(
        checked_u64_mul(
            tuple.data_shard_count as u64,
            bit_rot_buffer_pct as u64,
            "CMRA parity lower-bound overflow",
        )?,
        100,
    )?);
    if (tuple.parity_shard_count as u64) < min_parity {
        return Err(FormatError::InvalidArchive(
            "CMRA parity shard count is below authenticated bit-rot lower bound",
        ));
    }
    Ok(())
}

fn validate_cmra_shard(
    shard: &CriticalMetadataRecoveryShard,
    serialized_idx: usize,
    tuple: CmraDecoderTuple,
) -> Result<(), FormatError> {
    if shard.shard_index as usize != serialized_idx {
        return Err(FormatError::InvalidArchive(
            "CMRA shards are not in canonical order",
        ));
    }
    let data_count = tuple.data_shard_count as usize;
    let shard_size = tuple.shard_size as usize;
    if serialized_idx < data_count {
        if shard.shard_role != 0 {
            return Err(FormatError::InvalidArchive(
                "CMRA data shard has wrong role",
            ));
        }
        let expected_len = if serialized_idx + 1 == data_count {
            let used = tuple.image_length as usize - serialized_idx * shard_size;
            if used == 0 {
                shard_size
            } else {
                used
            }
        } else {
            shard_size
        };
        if shard.shard_payload_length as usize != expected_len {
            return Err(FormatError::InvalidArchive(
                "CMRA data shard payload length is non-canonical",
            ));
        }
        if serialized_idx + 1 == data_count
            && shard.payload[expected_len..].iter().any(|byte| *byte != 0)
        {
            return Err(FormatError::InvalidArchive(
                "CMRA final data shard padding is non-zero",
            ));
        }
    } else {
        if shard.shard_role != 1 {
            return Err(FormatError::InvalidArchive(
                "CMRA parity shard has wrong role",
            ));
        }
        if shard.shard_payload_length as usize != shard_size {
            return Err(FormatError::InvalidArchive(
                "CMRA parity shard payload length is non-canonical",
            ));
        }
    }
    Ok(())
}

fn validate_critical_metadata_image(
    image: &CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    mode: CmraRecoveryMode,
) -> Result<(), FormatError> {
    let root_auth_present = image.layout_flags & 0x0000_0001 != 0;
    if image.volume_header_offset != 0
        || image.volume_header_length != VOLUME_HEADER_LEN as u32
        || image.crypto_header_offset != VOLUME_HEADER_LEN as u64
        || image.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
        || image.volume_trailer_length != VOLUME_TRAILER_LEN as u32
        || image.body_bytes_before_cmra
            != image
                .volume_trailer_offset
                .checked_add(VOLUME_TRAILER_LEN as u64)
                .ok_or(FormatError::InvalidArchive("CMRA image boundary overflow"))?
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage fixed layout is invalid",
        ));
    }
    if root_auth_present {
        if image.root_auth_footer_offset == 0
            || image.root_auth_footer_length == 0
            || image.root_auth_footer_length > READER_MAX_ROOT_AUTH_FOOTER_LEN
        {
            return Err(FormatError::InvalidArchive(
                "CriticalMetadataImage root-auth range is invalid",
            ));
        }
    } else if image.root_auth_footer_offset != 0
        || image.root_auth_footer_length != 0
        || image.root_auth_footer_sha256 != [0u8; 32]
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage root-auth fields must be zero when absent",
        ));
    }
    let block_record_len = image_block_record_len_from_region(image)?;
    let block_record_len_u64 = u64::try_from(block_record_len)
        .map_err(|_| FormatError::InvalidArchive("BlockRecord length overflow"))?;
    match mode {
        CmraRecoveryMode::KeyHolding => {
            let expected_len = image.block_count.checked_mul(block_record_len_u64).ok_or(
                FormatError::InvalidArchive("BlockRecord region length overflow"),
            )?;
            if image.block_records_length != expected_len {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage terminal equations are invalid",
                ));
            }
        }
        CmraRecoveryMode::PublicNoKey => {
            if image.block_records_length % block_record_len_u64 != 0 {
                return Err(FormatError::InvalidArchive(
                    "CriticalMetadataImage BlockRecord region is not aligned",
                ));
            }
        }
    }
    if image.block_records_offset
        != image
            .crypto_header_offset
            .checked_add(image.crypto_header_length as u64)
            .ok_or(FormatError::InvalidArchive(
                "CryptoHeader boundary overflow",
            ))?
        || image.manifest_footer_offset
            != image
                .block_records_offset
                .checked_add(image.block_records_length)
                .ok_or(FormatError::InvalidArchive(
                    "ManifestFooter boundary overflow",
                ))?
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage terminal equations are invalid",
        ));
    }
    let manifest_end = image
        .manifest_footer_offset
        .checked_add(MANIFEST_FOOTER_LEN as u64)
        .ok_or(FormatError::InvalidArchive(
            "RootAuthFooter boundary overflow",
        ))?;
    if root_auth_present {
        if image.root_auth_footer_offset != manifest_end
            || image
                .root_auth_footer_offset
                .checked_add(image.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "VolumeTrailer boundary overflow",
                ))?
                != image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive(
                "CriticalMetadataImage root-auth terminal equations are invalid",
            ));
        }
    } else if image.volume_trailer_offset != manifest_end {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage unsigned terminal equations are invalid",
        ));
    }
    let expected_types: &[u16] = if root_auth_present {
        &[1, 2, 3, 4, 5]
    } else {
        &[1, 2, 3, 5]
    };
    if image.regions.len() != expected_types.len()
        || image
            .regions
            .iter()
            .map(|region| region.region_type)
            .ne(expected_types.iter().copied())
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage regions are not canonical",
        ));
    }
    validate_image_region(
        image,
        1,
        image.volume_header_offset,
        image.volume_header_length,
    )?;
    validate_image_region(
        image,
        2,
        image.crypto_header_offset,
        image.crypto_header_length,
    )?;
    validate_image_region(
        image,
        3,
        image.manifest_footer_offset,
        image.manifest_footer_length,
    )?;
    if root_auth_present {
        validate_image_region(
            image,
            4,
            image.root_auth_footer_offset,
            image.root_auth_footer_length,
        )?;
    }
    validate_image_region(
        image,
        5,
        image.volume_trailer_offset,
        image.volume_trailer_length,
    )?;
    if sha256_region(image, 1)? != image.volume_header_sha256
        || sha256_region(image, 2)? != image.crypto_header_sha256
        || sha256_region(image, 3)? != image.manifest_footer_sha256
        || (root_auth_present && sha256_region(image, 4)? != image.root_auth_footer_sha256)
        || (!root_auth_present && image.root_auth_footer_sha256 != [0u8; 32])
        || sha256_region(image, 5)? != image.volume_trailer_sha256
        || sha256_bytes_from_tuple(tuple) != tuple.image_sha256
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage region digest mismatch",
        ));
    }
    Ok(())
}

fn sha256_bytes_from_tuple(tuple: CmraDecoderTuple) -> [u8; 32] {
    tuple.image_sha256
}

fn image_block_record_len_from_region(image: &CriticalMetadataImage) -> Result<usize, FormatError> {
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    crypto.fixed.validate_v36()?;
    Ok(crypto.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN)
}

fn validate_image_region(
    image: &CriticalMetadataImage,
    region_type: u16,
    offset: u64,
    length: u32,
) -> Result<(), FormatError> {
    let region = image
        .region(region_type)
        .ok_or(FormatError::InvalidArchive(
            "missing CriticalMetadataImage region",
        ))?;
    if region.offset != offset || region.bytes.len() != length as usize {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage region range mismatch",
        ));
    }
    Ok(())
}

fn validate_image_identity(
    image: &CriticalMetadataImage,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if image.archive_uuid != volume_header.archive_uuid
        || image.session_id != volume_header.session_id
        || image.volume_index != volume_header.volume_index
        || image.stripe_width != volume_header.stripe_width
        || image.stripe_width != crypto_header.stripe_width
    {
        return Err(FormatError::InvalidArchive(
            "CriticalMetadataImage identity does not match selected volume",
        ));
    }
    Ok(())
}

fn sha256_region(image: &CriticalMetadataImage, region_type: u16) -> Result<[u8; 32], FormatError> {
    Ok(sha256_bytes(
        &image
            .region(region_type)
            .ok_or(FormatError::InvalidArchive(
                "missing CriticalMetadataImage region",
            ))?
            .bytes,
    ))
}

fn validate_recovered_terminal(
    image: CriticalMetadataImage,
    tuple: CmraDecoderTuple,
    bytes: &[u8],
    subkeys: &Subkeys,
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<V41Terminal, FormatError> {
    let volume_header_region = image
        .region(1)
        .ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let recovered_volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    if &recovered_volume_header != volume_header {
        return Err(FormatError::InvalidArchive(
            "CMRA VolumeHeader differs from parsed VolumeHeader",
        ));
    }
    validate_image_identity(&image, volume_header, crypto_header)?;
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let recovered_crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    if recovered_crypto.fixed != *crypto_header {
        return Err(FormatError::InvalidArchive(
            "CMRA CryptoHeader differs from parsed CryptoHeader",
        ));
    }
    verify_hmac(
        HmacDomain::CryptoHeader,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        recovered_crypto.hmac_covered_bytes,
        &recovered_crypto.header_hmac,
    )?;
    validate_cmra_writer_parity_lower_bound(tuple, recovered_crypto.fixed.bit_rot_buffer_pct)?;
    recovered_crypto.validate_extension_semantics()?;

    let manifest_region = image
        .region(3)
        .ok_or(FormatError::InvalidArchive("missing ManifestFooter region"))?;
    let manifest_footer = ManifestFooter::parse(&manifest_region.bytes)?;
    validate_manifest_footer(
        volume_header,
        &manifest_footer,
        subkeys,
        &manifest_region.bytes,
    )?;
    manifest_footer.validate_index_root_extent(crypto_header.block_size)?;

    let root_auth_footer = if image.layout_flags & 0x0000_0001 != 0 {
        let root_auth_region = image
            .region(4)
            .ok_or(FormatError::InvalidArchive("missing RootAuthFooter region"))?;
        let footer = RootAuthFooterV1::parse(&root_auth_region.bytes)?;
        if footer.archive_uuid != volume_header.archive_uuid
            || footer.session_id != volume_header.session_id
            || footer.footer_length()? != image.root_auth_footer_length
        {
            return Err(FormatError::InvalidArchive(
                "RootAuthFooter identity or length does not match terminal image",
            ));
        }
        Some(footer)
    } else {
        None
    };

    let trailer_region = image
        .region(5)
        .ok_or(FormatError::InvalidArchive("missing VolumeTrailer region"))?;
    let trailer = VolumeTrailer::parse(&trailer_region.bytes)?;
    verify_hmac(
        HmacDomain::VolumeTrailer,
        &subkeys.mac_key,
        &volume_header.archive_uuid,
        &volume_header.session_id,
        &trailer_region.bytes[..TRAILER_HMAC_COVERED_LEN],
        &trailer.trailer_hmac,
    )?;
    validate_trailer_identity(volume_header, &trailer)?;
    validate_v41_trailer_equations(&image, &trailer)?;

    let cmra_offset = to_usize(image.body_bytes_before_cmra, "CMRA")?;
    if bytes.get(cmra_offset..cmra_offset + 4) != Some(b"TZCR") {
        return Err(FormatError::InvalidArchive("CMRA is not at image boundary"));
    }

    let manifest_footer_bytes = manifest_region.bytes.clone();
    let root_auth_footer_bytes = image.region(4).map(|region| region.bytes.clone());
    Ok(V41Terminal {
        image,
        manifest_footer_bytes,
        root_auth_footer_bytes,
        root_auth_footer,
        volume_trailer: trailer,
    })
}

fn validate_recovered_public_terminal(
    image: CriticalMetadataImage,
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<V41PublicTerminal, FormatError> {
    if image.layout_flags & 0x0000_0001 == 0 {
        return Err(FormatError::ReaderUnsupported(
            "public no-key verification requires root-auth",
        ));
    }
    let volume_header_region = image
        .region(1)
        .ok_or(FormatError::InvalidArchive("missing VolumeHeader region"))?;
    let recovered_volume_header = VolumeHeader::parse(&volume_header_region.bytes)?;
    if &recovered_volume_header != volume_header {
        return Err(FormatError::InvalidArchive(
            "CMRA VolumeHeader differs from parsed VolumeHeader",
        ));
    }
    validate_image_identity(&image, volume_header, crypto_header)?;
    let crypto_region = image
        .region(2)
        .ok_or(FormatError::InvalidArchive("missing CryptoHeader region"))?;
    let recovered_crypto = CryptoHeader::parse(&crypto_region.bytes, image.crypto_header_length)?;
    if recovered_crypto.fixed != *crypto_header {
        return Err(FormatError::InvalidArchive(
            "CMRA CryptoHeader differs from parsed CryptoHeader",
        ));
    }
    recovered_crypto.validate_extension_semantics()?;

    image
        .region(3)
        .ok_or(FormatError::InvalidArchive("missing ManifestFooter region"))?;

    let root_auth_region = image
        .region(4)
        .ok_or(FormatError::InvalidArchive("missing RootAuthFooter region"))?;
    let root_auth_footer = RootAuthFooterV1::parse(&root_auth_region.bytes)?;
    if root_auth_footer.archive_uuid != volume_header.archive_uuid
        || root_auth_footer.session_id != volume_header.session_id
        || root_auth_footer.footer_length()? != image.root_auth_footer_length
    {
        return Err(FormatError::InvalidArchive(
            "public RootAuthFooter identity or length does not match terminal image",
        ));
    }

    let trailer_region = image
        .region(5)
        .ok_or(FormatError::InvalidArchive("missing VolumeTrailer region"))?;
    let trailer = VolumeTrailer::parse(&trailer_region.bytes)?;
    validate_trailer_identity(volume_header, &trailer)?;
    validate_v41_public_trailer_profile(&image, &trailer)?;

    let cmra_offset = to_usize(image.body_bytes_before_cmra, "CMRA")?;
    if bytes.get(cmra_offset..cmra_offset + 4) != Some(b"TZCR") {
        return Err(FormatError::InvalidArchive("CMRA is not at image boundary"));
    }

    let root_auth_footer_bytes = root_auth_region.bytes.clone();
    Ok(V41PublicTerminal {
        image,
        root_auth_footer_bytes,
        root_auth_footer,
    })
}

fn validate_v41_trailer_equations(
    image: &CriticalMetadataImage,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    let root_auth_present = image.layout_flags & 0x0000_0001 != 0;
    if trailer.bytes_written != image.volume_trailer_offset
        || trailer.manifest_footer_offset != image.manifest_footer_offset
        || trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
        || trailer.block_count != image.block_count
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer does not match v41 terminal layout",
        ));
    }
    if root_auth_present {
        if trailer.root_auth_flags != 0x0000_0001
            || trailer.root_auth_footer_offset != image.root_auth_footer_offset
            || trailer.root_auth_footer_length != image.root_auth_footer_length
            || image.root_auth_footer_offset
                != image
                    .manifest_footer_offset
                    .checked_add(MANIFEST_FOOTER_LEN as u64)
                    .ok_or(FormatError::InvalidArchive(
                        "RootAuthFooter trailer boundary overflow",
                    ))?
            || image
                .root_auth_footer_offset
                .checked_add(image.root_auth_footer_length as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter trailer boundary overflow",
                ))?
                != image.volume_trailer_offset
        {
            return Err(FormatError::InvalidArchive(
                "VolumeTrailer root-auth fields do not match v41 terminal layout",
            ));
        }
    } else if trailer.root_auth_footer_offset != 0
        || trailer.root_auth_footer_length != 0
        || trailer.root_auth_flags != 0
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer root-auth fields must be zero when absent",
        ));
    }
    Ok(())
}

fn validate_v41_public_trailer_profile(
    image: &CriticalMetadataImage,
    trailer: &VolumeTrailer,
) -> Result<(), FormatError> {
    if trailer.bytes_written != image.volume_trailer_offset
        || trailer.manifest_footer_offset != image.manifest_footer_offset
        || trailer.manifest_footer_length != MANIFEST_FOOTER_LEN as u32
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer does not match v41 public terminal layout",
        ));
    }
    if trailer.root_auth_flags != 0x0000_0001
        || trailer.root_auth_footer_offset == 0
        || trailer.root_auth_footer_length == 0
        || trailer.root_auth_footer_length > READER_MAX_ROOT_AUTH_FOOTER_LEN
        || trailer.root_auth_footer_offset != image.root_auth_footer_offset
        || trailer.root_auth_footer_length != image.root_auth_footer_length
        || image.root_auth_footer_offset
            != image
                .manifest_footer_offset
                .checked_add(MANIFEST_FOOTER_LEN as u64)
                .ok_or(FormatError::InvalidArchive(
                    "RootAuthFooter trailer boundary overflow",
                ))?
        || image
            .root_auth_footer_offset
            .checked_add(image.root_auth_footer_length as u64)
            .ok_or(FormatError::InvalidArchive(
                "RootAuthFooter trailer boundary overflow",
            ))?
            != image.volume_trailer_offset
    {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer root-auth fields do not match v41 public terminal layout",
        ));
    }
    Ok(())
}

fn critical_image_min() -> u64 {
    const MIN_CRYPTO_HEADER_LEN: u64 = 116;
    CRITICAL_METADATA_IMAGE_FIXED_LEN as u64
        + 4 * SERIALIZED_REGION_HEADER_LEN as u64
        + VOLUME_HEADER_LEN as u64
        + MIN_CRYPTO_HEADER_LEN
        + MANIFEST_FOOTER_LEN as u64
        + VOLUME_TRAILER_LEN as u64
        + IMAGE_CRC_LEN as u64
}

fn critical_image_cap() -> Result<u64, FormatError> {
    [
        CRITICAL_METADATA_IMAGE_FIXED_LEN as u64,
        5 * SERIALIZED_REGION_HEADER_LEN as u64,
        VOLUME_HEADER_LEN as u64,
        READER_MAX_CRYPTO_HEADER_LEN as u64,
        MANIFEST_FOOTER_LEN as u64,
        READER_MAX_ROOT_AUTH_FOOTER_LEN as u64,
        VOLUME_TRAILER_LEN as u64,
        IMAGE_CRC_LEN as u64,
    ]
    .into_iter()
    .try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or(FormatError::InvalidArchive("critical image cap overflow"))
    })
}

fn cmra_serialized_length(tuple: CmraDecoderTuple) -> Result<u64, FormatError> {
    let shard_total = (tuple.data_shard_count as u64)
        .checked_add(tuple.parity_shard_count as u64)
        .ok_or(FormatError::InvalidArchive("CMRA shard count overflow"))?;
    let row_len = (CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN as u64)
        .checked_add(tuple.shard_size as u64)
        .ok_or(FormatError::InvalidArchive("CMRA row length overflow"))?;
    checked_u64_mul(shard_total, row_len, "CMRA length overflow")?
        .checked_add(CRITICAL_METADATA_RECOVERY_HEADER_LEN as u64)
        .ok_or(FormatError::InvalidArchive("CMRA length overflow"))
}

fn max_critical_recovery_scan(options: ReaderOptions) -> Result<usize, FormatError> {
    let cap = critical_image_cap()?;
    let mut worst = 0u64;
    let mut shard_size = 512u64;
    while shard_size <= 4096 {
        let data = ceil_div_u64(cap, shard_size)?;
        let parity = 2u64.max(ceil_div_u64(
            checked_u64_mul(data, READER_MAX_CMRA_PARITY_PCT as u64, "CMRA cap overflow")?,
            100,
        )?);
        let tuple = CmraDecoderTuple {
            shard_size: shard_size as u32,
            data_shard_count: u16::try_from(data)
                .map_err(|_| FormatError::InvalidArchive("CMRA cap data shard overflow"))?,
            parity_shard_count: u16::try_from(parity)
                .map_err(|_| FormatError::InvalidArchive("CMRA cap parity shard overflow"))?,
            image_length: u32::try_from(cap)
                .map_err(|_| FormatError::InvalidArchive("CMRA cap image overflow"))?,
            image_sha256: [0u8; 32],
        };
        worst = worst.max(cmra_serialized_length(tuple)?);
        shard_size += 2;
    }
    let total = options
        .max_trailing_garbage_scan
        .try_into()
        .map_err(|_| FormatError::InvalidArchive("scan cap overflow"))
        .and_then(|scan: u64| {
            scan.checked_add(worst)
                .and_then(|value| value.checked_add(LOCATOR_PAIR_LEN as u64))
                .ok_or(FormatError::InvalidArchive("scan cap overflow"))
        })?;
    usize::try_from(total).map_err(|_| FormatError::InvalidArchive("scan cap overflow"))
}

fn validate_bootstrap_single_volume_input(
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
) -> Result<(), FormatError> {
    if volume_header.stripe_width != 1 || volume_header.volume_index != 0 {
        return Err(FormatError::ReaderUnsupported(
            "bootstrap sidecar reader supports only single-volume archive input",
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
struct ParsedBootstrapSidecar {
    manifest_footer: Option<ManifestFooter>,
    index_root_records_section: Option<(u64, u64)>,
    dictionary_records_section: Option<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapSidecarUse {
    SeekableAssist,
    NonSeekableRandomAccess,
}

impl ParsedBootstrapSidecar {
    fn require_sections_for(
        &self,
        sidecar_use: BootstrapSidecarUse,
        crypto_header: &CryptoHeaderFixed,
    ) -> Result<(), FormatError> {
        if sidecar_use == BootstrapSidecarUse::NonSeekableRandomAccess {
            if self.manifest_footer.is_none() || self.index_root_records_section.is_none() {
                return Err(FormatError::ReaderUnsupported(
                    "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections",
                ));
            }
            if crypto_header.has_dictionary != 0 && self.dictionary_records_section.is_none() {
                return Err(FormatError::ReaderUnsupported(
                    "dictionary bootstrap required",
                ));
            }
        }
        Ok(())
    }
}

fn parse_bootstrap_sidecar(
    bytes: &[u8],
    volume_header: &VolumeHeader,
    crypto_header: &CryptoHeaderFixed,
    subkeys: &Subkeys,
) -> Result<ParsedBootstrapSidecar, FormatError> {
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

    if header.has_dictionary_records() {
        if crypto_header.has_dictionary == 0 {
            return Err(FormatError::InvalidArchive(
                "bootstrap sidecar has dictionary records while has_dictionary is false",
            ));
        }
    }

    let manifest_footer = if header.has_manifest_footer() {
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
        Some(manifest_footer)
    } else {
        None
    };

    Ok(ParsedBootstrapSidecar {
        manifest_footer,
        index_root_records_section: header.has_index_root_records().then_some((
            header.index_root_records_offset,
            header.index_root_records_length,
        )),
        dictionary_records_section: header.has_dictionary_records().then_some((
            header.dictionary_records_offset,
            header.dictionary_records_length,
        )),
    })
}

fn index_root_extent_from_manifest(manifest_footer: &ManifestFooter) -> ObjectExtent {
    ObjectExtent {
        first_block_index: manifest_footer.index_root_first_block,
        data_block_count: manifest_footer.index_root_data_block_count,
        parity_block_count: manifest_footer.index_root_parity_block_count,
        encrypted_size: manifest_footer.index_root_encrypted_size,
    }
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

fn parse_public_block_observation(
    bytes: &[u8],
    start: usize,
    image: &CriticalMetadataImage,
    block_size: usize,
    volume_header: &VolumeHeader,
) -> Result<BTreeMap<u64, BlockRecord>, FormatError> {
    let image_start = to_usize(image.block_records_offset, "BlockRecord")?;
    if start != image_start {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation start mismatch",
        ));
    }
    let scan_limit_u64 = image
        .block_records_offset
        .checked_add(image.block_records_length)
        .ok_or(FormatError::InvalidArchive(
            "public BlockRecord observation limit overflow",
        ))?;
    if scan_limit_u64 != image.manifest_footer_offset {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation limit mismatch",
        ));
    }
    let scan_limit = to_usize(scan_limit_u64, "BlockRecord")?;
    if scan_limit < start {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation limit before start",
        ));
    }
    let record_len = block_size
        .checked_add(BLOCK_RECORD_FRAMING_LEN)
        .ok_or(FormatError::InvalidArchive("BlockRecord length overflow"))?;
    let region_len = scan_limit - start;
    if region_len % record_len != 0 {
        return Err(FormatError::InvalidArchive(
            "public BlockRecord observation window is not aligned",
        ));
    }

    let mut blocks = BTreeMap::new();
    let mut offset = start;
    let mut observed_slot = 0u64;
    while offset < scan_limit {
        let magic_end = checked_add(offset, 4, "BlockRecord")?;
        if magic_end > scan_limit || bytes.get(offset..magic_end) != Some(b"TZBK") {
            break;
        }
        let record_end = checked_add(offset, record_len, "BlockRecord")?;
        if record_end > scan_limit {
            return Err(FormatError::InvalidArchive(
                "public BlockRecord observation slot is incomplete",
            ));
        }
        let raw = slice(bytes, offset, record_len, "BlockRecord")?;
        let record = BlockRecord::parse(raw, block_size)?;
        let expected_block_index = checked_u64_add(
            volume_header.volume_index as u64,
            checked_u64_mul(
                observed_slot,
                volume_header.stripe_width as u64,
                "BlockRecord index overflow",
            )?,
            "BlockRecord index overflow",
        )?;
        if record.block_index != expected_block_index {
            return Err(FormatError::InvalidArchive(
                "public BlockRecord index does not match volume position",
            ));
        }
        if blocks.insert(record.block_index, record).is_some() {
            return Err(FormatError::InvalidArchive("duplicate BlockRecord index"));
        }
        offset = record_end;
        observed_slot = observed_slot
            .checked_add(1)
            .ok_or(FormatError::InvalidArchive("BlockRecord count overflow"))?;
    }

    let mut scan = if offset < scan_limit {
        checked_add(offset, record_len, "BlockRecord")?
    } else {
        scan_limit
    };
    while scan < scan_limit {
        let magic_end = checked_add(scan, 4, "BlockRecord")?;
        let record_end = checked_add(scan, record_len, "BlockRecord")?;
        if record_end <= scan_limit && bytes.get(scan..magic_end) == Some(b"TZBK") {
            let raw = slice(bytes, scan, record_len, "BlockRecord")?;
            if BlockRecord::parse(raw, block_size).is_ok() {
                return Err(FormatError::InvalidArchive(
                    "public observation has ambiguous extra BlockRecord",
                ));
            }
        }
        scan = record_end;
    }

    Ok(blocks)
}

fn block_record_error_is_recoverable_erasure(error: &FormatError) -> bool {
    matches!(
        error,
        FormatError::BadCrc {
            structure: "BlockRecord",
        }
    )
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
    crypto_header: &CryptoHeaderFixed,
    options: ReaderOptions,
) -> Result<(ManifestFooter, VolumeTrailer, Option<RootAuthFooterV1>), FormatError> {
    let candidate =
        locate_v41_terminal_candidate(bytes, subkeys, volume_header, crypto_header, options)?;
    if !terminal_candidate_reaches_eof(&candidate, bytes.len())? {
        return Err(FormatError::InvalidArchive(
            "sequential terminal does not end at EOF",
        ));
    }
    let terminal = candidate.terminal;
    if terminal.image.manifest_footer_offset != manifest_offset as u64 {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer ManifestFooter offset does not match observed stream offset",
        ));
    }
    if terminal.volume_trailer.block_count != observed_block_count {
        return Err(FormatError::InvalidArchive(
            "VolumeTrailer block_count does not match observed stream",
        ));
    }
    let manifest_footer = ManifestFooter::parse(&terminal.manifest_footer_bytes)?;
    Ok((
        manifest_footer,
        terminal.volume_trailer,
        terminal.root_auth_footer,
    ))
}

fn terminal_candidate_reaches_eof(
    candidate: &TerminalCandidate,
    input_len: usize,
) -> Result<bool, FormatError> {
    let expected_end =
        match candidate.locator_sequence {
            Some(0) => candidate.anchor,
            Some(1) => candidate
                .anchor
                .checked_add(CRITICAL_RECOVERY_LOCATOR_LEN)
                .ok_or(FormatError::InvalidArchive(
                    "terminal EOF boundary overflow",
                ))?,
            None => candidate.anchor.checked_add(LOCATOR_PAIR_LEN).ok_or(
                FormatError::InvalidArchive("terminal EOF boundary overflow"),
            )?,
            Some(_) => {
                return Err(FormatError::InvalidArchive(
                    "invalid terminal locator sequence",
                ))
            }
        };
    Ok(expected_end == input_len)
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
    validate_crypto_class_parity_exactness(&parsed_crypto.fixed)?;

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
        &parsed_crypto.fixed,
        options,
    )?;
    // This public helper is intentionally whole-buffer: decoded payload bytes
    // stay internal until terminal ManifestFooter and VolumeTrailer HMACs pass.
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
            "sequential reader supports only single-volume archive input",
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
    let repaired = load_repaired_object_data_shards_from_parts(
        blocks,
        crypto_header,
        extent,
        data_kind,
        parity_kind,
        class_data_shard_max,
        class_parity_shard_max,
    )?;
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

fn load_repaired_object_data_shards_from_parts(
    blocks: &BTreeMap<u64, BlockRecord>,
    crypto_header: &CryptoHeaderFixed,
    extent: ObjectExtent,
    data_kind: BlockKind,
    parity_kind: BlockKind,
    class_data_shard_max: u16,
    class_parity_shard_max: u16,
) -> Result<Vec<Vec<u8>>, FormatError> {
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

    repair_data_gf16(&data_shards, &parity_shards, block_size)
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
    if extent.parity_block_count != required_parity {
        return Err(FormatError::InvalidArchive(
            "encrypted object parity does not match v41 compute_parity",
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

fn validate_global_file_table_order(shards: &[IndexShard]) -> Result<(), FormatError> {
    let mut previous_by_path = HashMap::<([u8; 8], Vec<u8>), u64>::new();
    for shard in shards {
        for (idx, file) in shard.files.iter().enumerate() {
            let path = shard
                .file_path(idx)
                .ok_or(FormatError::InvalidArchive("FileEntry path is missing"))?
                .to_vec();
            let start = shard
                .tar_member_group_start(idx)
                .ok_or(FormatError::InvalidArchive(
                    "FileEntry tar member start is missing",
                ))?;
            let key = (file.path_hash, path, start);
            let path_key = (key.0, key.1.clone());
            if let Some(previous_start) = previous_by_path.get(&path_key) {
                let previous_key = (path_key.0, path_key.1.clone(), *previous_start);
                validate_global_file_table_key_step(Some(&previous_key), &key)?;
            }
            previous_by_path.insert(path_key, key.2);
        }
    }
    Ok(())
}

fn validate_global_file_table_key_step(
    previous: Option<&([u8; 8], Vec<u8>, u64)>,
    current: &([u8; 8], Vec<u8>, u64),
) -> Result<(), FormatError> {
    if let Some(previous) = previous {
        let same_path = previous.0 == current.0 && previous.1 == current.1;
        if same_path && previous.2 >= current.2 {
            return Err(FormatError::InvalidArchive(
                "global FileEntry rows are not sorted and unique",
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

fn manifest_footer_global_pre_hmac_bytes(manifest_footer: &ManifestFooter) -> [u8; 104] {
    let mut bytes = [0u8; 104];
    bytes.copy_from_slice(&manifest_footer.to_bytes()[..104]);
    bytes[36..40].fill(0);
    bytes
}

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
    use crate::fec::encode_parity_gf16;
    use crate::format::{
        AeadAlgo, CompressionAlgo, FecAlgo, KdfAlgo, CRYPTO_HEADER_FIXED_LEN, FORMAT_VERSION,
        VOLUME_FORMAT_REV,
    };
    use crate::metadata::{
        DirectoryHintEntry, DirectoryHintTableHeader, IndexRootHeader, IndexShardHeader,
        ENVELOPE_ENTRY_LEN, FILE_ENTRY_LEN, FRAME_ENTRY_LEN, INDEX_SHARD_HEADER_LEN,
    };
    use crate::signing::{
        ed25519_authenticator_value, verify_ed25519_root_auth, Ed25519RootAuthOutcome,
        Ed25519VerificationMode, ED25519_AUTHENTICATOR_ID, ED25519_AUTHENTICATOR_VALUE_LEN,
    };
    use crate::writer::{
        write_archive, write_archive_with_dictionary, write_archive_with_root_auth, RegularFile,
        RootAuthWriterConfig, WriterOptions,
    };
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

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

    fn small_block_recovery_options() -> WriterOptions {
        WriterOptions {
            block_size: 4096,
            chunk_size: 32 * 1024,
            envelope_target_size: 32 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 1,
            fec_data_shards: 16,
            fec_parity_shards: 1,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 1,
            ..WriterOptions::default()
        }
    }

    fn parity_rich_recovery_options() -> WriterOptions {
        WriterOptions {
            block_size: 4096,
            chunk_size: 32 * 1024,
            envelope_target_size: 32 * 1024,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 40,
            fec_data_shards: 16,
            fec_parity_shards: 16,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 4,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 16,
            ..WriterOptions::default()
        }
    }

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x1234_5678u32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect()
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
    fn root_auth_archive_round_trips_and_verifies_with_callback() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"root-auth payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x7777,
                signer_identity_type: 1,
                signer_identity: b"test signer",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        opened.verify().unwrap();
        let verified = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(footer.authenticator_value == archive_root.as_slice())
            })
            .unwrap();

        assert_eq!(verified.authenticator_id, 0x7777);
        assert_eq!(verified.signer_identity_type, 1);
        assert_eq!(verified.signer_identity_bytes, b"test signer");
        assert_eq!(
            verified.archive_root,
            opened.root_auth_footer.as_ref().unwrap().archive_root
        );
    }

    #[test]
    fn root_auth_verification_requires_authenticator_success() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"root-auth payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 9,
                signer_identity_type: 1,
                signer_identity: b"test signer",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.verify_root_auth_with(|_, _| Ok(false)).unwrap_err(),
            FormatError::InvalidArchive("root-auth authenticator verification failed")
        );
    }

    #[test]
    fn public_no_key_verifies_encrypted_data_block_commitment_with_callback() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("public.txt", b"public commitment")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();

        let verified = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();

        assert_eq!(verified.authenticator_id, 0x2222);
        assert_eq!(verified.signer_identity_bytes, b"public verifier");
        assert!(verified.total_data_block_count > 0);
    }

    #[test]
    fn public_no_key_ignores_untrusted_manifest_and_trailer_block_count_fields() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new(
                "public-fields.txt",
                b"public source authority",
            )],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x2222,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut bytes = archive.bytes.clone();

        rewrite_public_cmra_image(&mut bytes, |image| {
            let manifest_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 3)
                .unwrap();
            manifest_region.bytes[44..48].copy_from_slice(&99u32.to_le_bytes());

            let trailer_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 5)
                .unwrap();
            let mut trailer = VolumeTrailer::parse(&trailer_region.bytes).unwrap();
            trailer.block_count += 7;
            trailer_region.bytes = trailer.to_bytes().to_vec();
        });

        public_no_key_verify_archive_with(&bytes, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();
    }

    #[test]
    fn public_no_key_compares_only_public_crypto_profile_across_volumes() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new(
                "public-crypto.txt",
                b"cross-volume public profile",
            )],
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 0,
                ..WriterOptions::default()
            },
            RootAuthWriterConfig {
                authenticator_id: 0x3333,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let mut volumes = archive.volumes.clone();
        let volume_header = VolumeHeader::parse(&volumes[1][..VOLUME_HEADER_LEN]).unwrap();
        let crypto_offset = volume_header.crypto_header_offset as usize;
        let expected_volume_size = 123_456_789u64;
        volumes[1][crypto_offset + 52..crypto_offset + 60]
            .copy_from_slice(&expected_volume_size.to_le_bytes());
        rewrite_public_cmra_image(&mut volumes[1], |image| {
            let crypto_region = image
                .regions
                .iter_mut()
                .find(|region| region.region_type == 2)
                .unwrap();
            crypto_region.bytes[52..60].copy_from_slice(&expected_volume_size.to_le_bytes());
        });

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        public_no_key_verify_volumes_with(&volume_refs, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();
    }

    #[test]
    fn locator_based_cmra_recovery_only_ignores_header_crc_failures() {
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("cmra-header.txt", b"header fallback")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: 0x4444,
                signer_identity_type: 1,
                signer_identity: b"public verifier",
                authenticator_value_length: 32,
            },
            |request| Ok(request.archive_root.to_vec()),
        )
        .unwrap();
        let final_locator = final_recovery_locator(&archive.bytes);

        let mut bad_crc = archive.bytes.clone();
        let crc_offset =
            final_locator.cmra_offset as usize + CRITICAL_METADATA_RECOVERY_HEADER_LEN - 1;
        bad_crc[crc_offset] ^= 0x55;
        public_no_key_verify_archive_with(&bad_crc, |footer, archive_root| {
            Ok(footer.authenticator_value == archive_root.as_slice())
        })
        .unwrap();

        let mut bad_magic = archive.bytes.clone();
        bad_magic[final_locator.cmra_offset as usize] ^= 0x55;
        assert_eq!(
            public_no_key_verify_archive_with(&bad_magic, |_, _| Ok(true)).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );

        let mut bad_hint = archive.bytes.clone();
        bad_hint[crc_offset] ^= 0xAA;
        for offset in [
            bad_hint.len() - LOCATOR_PAIR_LEN,
            bad_hint.len() - CRITICAL_RECOVERY_LOCATOR_LEN,
        ] {
            let mut locator = CriticalRecoveryLocator::parse(
                &bad_hint[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN],
            )
            .unwrap();
            locator.volume_index_hint += 1;
            bad_hint[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN]
                .copy_from_slice(&locator.to_bytes());
        }
        assert_eq!(
            public_no_key_verify_archive_with(&bad_hint, |_, _| Ok(true)).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn key_holding_rejects_cmra_below_authenticated_parity_floor() {
        let archive = write_archive(
            &[RegularFile::new(
                "cmra-floor.txt",
                b"authenticated CMRA floor",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let malformed = rewrite_cmra_parity_count(&archive.bytes, 1);
        let final_offset = malformed.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let locator = CriticalRecoveryLocator::parse(
            &malformed[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap();
        let volume_header = VolumeHeader::parse(&malformed[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &malformed[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();

        assert_eq!(
            parse_locator_cmra_candidate(
                &malformed,
                final_offset,
                locator,
                &subkeys,
                &volume_header,
                &crypto_header.fixed,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "CMRA parity shard count is below authenticated bit-rot lower bound"
            )
        );
        assert!(open_archive(&malformed, &master_key()).is_err());
    }

    #[test]
    fn locator_tuple_bounds_are_checked_before_locator_position_fields() {
        let archive = write_archive(
            &[RegularFile::new(
                "locator-order.txt",
                b"locator tuple first",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let final_offset = archive.bytes.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let mut locator = final_recovery_locator(&archive.bytes);
        locator.cmra_shard_size = 513;
        locator.body_bytes_before_cmra = locator.cmra_offset + 1;
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();

        assert_eq!(
            parse_locator_cmra_candidate(
                &archive.bytes,
                final_offset,
                locator,
                &subkeys,
                &volume_header,
                &crypto_header.fixed,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("CMRA shard_size is invalid")
        );
    }

    #[test]
    fn sequential_extract_rejects_bytes_after_terminal_locator() {
        let archive = write_archive(
            &[RegularFile::new("seq.txt", b"sequential EOF")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut appended = archive.bytes.clone();
        appended.extend_from_slice(&[0xAA; 32]);

        assert_eq!(
            sequential_extract_tar_stream(&appended, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("sequential terminal does not end at EOF")
        );
    }

    #[test]
    fn global_file_table_order_rejects_cross_shard_duplicate_reversal() {
        let first = (hash_prefix(b"dup.txt"), b"dup.txt".to_vec(), 2048);
        let second = (hash_prefix(b"dup.txt"), b"dup.txt".to_vec(), 1024);

        assert_eq!(
            validate_global_file_table_key_step(Some(&first), &second).unwrap_err(),
            FormatError::InvalidArchive("global FileEntry rows are not sorted and unique")
        );
    }

    #[test]
    fn ed25519_root_auth_verifies_key_holding_and_public_no_key_modes() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("signed.txt", b"ed25519 payload")],
            &master_key(),
            single_stream_options(),
            RootAuthWriterConfig {
                authenticator_id: ED25519_AUTHENTICATOR_ID,
                signer_identity_type: 1,
                signer_identity: &public_key,
                authenticator_value_length: ED25519_AUTHENTICATOR_VALUE_LEN,
            },
            |request| Ok(ed25519_authenticator_value(&signing_key, request).to_vec()),
        )
        .unwrap();

        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let root_auth = opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(matches!(
                    verify_ed25519_root_auth(
                        footer,
                        archive_root,
                        Some(public_key),
                        Ed25519VerificationMode::KeyHoldingRootAuth,
                    )?,
                    Ed25519RootAuthOutcome::RootAuthContentVerified { .. }
                ))
            })
            .unwrap();
        assert_eq!(
            root_auth.archive_root,
            opened.root_auth_footer.as_ref().unwrap().archive_root
        );

        let public = public_no_key_verify_archive_with(&archive.bytes, |footer, archive_root| {
            Ok(matches!(
                verify_ed25519_root_auth(
                    footer,
                    archive_root,
                    Some(public_key),
                    Ed25519VerificationMode::PublicNoKey,
                )?,
                Ed25519RootAuthOutcome::PublicDataBlockCommitmentVerified { .. }
            ))
        })
        .unwrap();
        assert_eq!(public.archive_root, root_auth.archive_root);
    }

    #[test]
    fn root_auth_verifies_with_tolerated_missing_volume_after_fec_repair() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key = signing_key.verifying_key().to_bytes();
        let options = WriterOptions {
            block_size: 4096,
            chunk_size: 16 * 1024,
            envelope_target_size: 16 * 1024,
            stripe_width: 2,
            volume_loss_tolerance: 1,
            bit_rot_buffer_pct: 0,
            fec_data_shards: 16,
            fec_parity_shards: 1,
            index_fec_data_shards: 4,
            index_fec_parity_shards: 1,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 1,
            ..WriterOptions::default()
        };
        let archive = write_archive_with_root_auth(
            &[RegularFile::new("missing-volume.txt", b"recover me")],
            &master_key(),
            options,
            RootAuthWriterConfig {
                authenticator_id: ED25519_AUTHENTICATOR_ID,
                signer_identity_type: 1,
                signer_identity: &public_key,
                authenticator_value_length: ED25519_AUTHENTICATOR_VALUE_LEN,
            },
            |request| Ok(ed25519_authenticator_value(&signing_key, request).to_vec()),
        )
        .unwrap();

        let opened = open_archive_volumes(&[archive.volumes[0].as_slice()], &master_key()).unwrap();
        opened
            .verify_root_auth_with(|footer, archive_root| {
                Ok(matches!(
                    verify_ed25519_root_auth(
                        footer,
                        archive_root,
                        Some(public_key),
                        Ed25519VerificationMode::KeyHoldingRootAuth,
                    )?,
                    Ed25519RootAuthOutcome::RootAuthContentVerified { .. }
                ))
            })
            .unwrap();
    }

    #[test]
    fn public_no_key_rejects_unsigned_archives() {
        let archive = write_archive(
            &[RegularFile::new("plain.txt", b"unsigned")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        assert_eq!(
            public_no_key_verify_archive_with(&archive.bytes, |_, _| Ok(true)).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 public CMRA candidate found")
        );
    }

    #[test]
    fn unsigned_archive_reports_root_auth_absent() {
        let archive = write_archive(
            &[RegularFile::new("plain.txt", b"unsigned")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.verify_root_auth_with(|_, _| Ok(true)).unwrap_err(),
            FormatError::ReaderUnsupported("root-auth footer is absent")
        );
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
    fn seekable_open_rejects_too_small_and_unavailable_header_crypto_bytes() {
        assert_eq!(
            open_archive(
                &[0u8; VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN - 1],
                &master_key()
            )
            .unwrap_err(),
            FormatError::InvalidLength {
                structure: "archive",
                expected: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
                actual: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN - 1,
            }
        );

        let mut header = test_volume_header();
        header.crypto_header_length = 512;
        let mut unavailable_crypto = header.to_bytes().to_vec();
        unavailable_crypto.resize(VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN, 0);

        assert_eq!(
            open_archive(&unavailable_crypto, &master_key()).unwrap_err(),
            FormatError::InvalidLength {
                structure: "CryptoHeader",
                expected: VOLUME_HEADER_LEN + 512,
                actual: VOLUME_HEADER_LEN + VOLUME_TRAILER_LEN,
            }
        );
    }

    #[test]
    fn seekable_open_rejects_in_bounds_noncanonical_crypto_header_offset() {
        let archive = write_archive(
            &[RegularFile::new("offset.txt", b"offset")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut mutated = archive.bytes;
        let mut header = VolumeHeader::parse(&mutated[..VOLUME_HEADER_LEN]).unwrap();
        header.crypto_header_offset = VOLUME_HEADER_LEN as u32 + 1;
        mutated[..VOLUME_HEADER_LEN].copy_from_slice(&header.to_bytes());

        assert_eq!(
            open_archive(&mutated, &master_key()).unwrap_err(),
            FormatError::NonCanonicalCryptoHeaderOffset(VOLUME_HEADER_LEN as u32 + 1)
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
    fn non_seekable_full_sidecar_bootstraps_when_terminal_trailer_is_corrupt() {
        let archive = write_archive(
            &[RegularFile::new(
                "sidecar-terminal.txt",
                b"sidecar authority",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_v41_terminal_recovery(&mut corrupted);
        assert!(open_archive(&corrupted, &master_key()).is_err());

        let opened =
            open_non_seekable_archive(&corrupted, &master_key(), Some(&archive.bootstrap_sidecar))
                .unwrap();

        assert!(opened.volume_trailer.is_none());
        assert_eq!(
            opened.extract_file("sidecar-terminal.txt").unwrap(),
            Some(b"sidecar authority".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn dictionary_full_sidecar_bootstraps_when_terminal_material_is_absent() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "dict-no-terminal.txt",
                b"common words common words without terminal",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let terminal_offset = terminal_material_offset(&archive.bytes);
        let truncated = archive.bytes[..terminal_offset].to_vec();
        assert!(open_archive(&truncated, &master_key()).is_err());

        let opened =
            open_non_seekable_archive(&truncated, &master_key(), Some(&archive.bootstrap_sidecar))
                .unwrap();

        assert!(opened.volume_trailer.is_none());
        assert_eq!(
            opened.extract_file("dict-no-terminal.txt").unwrap(),
            Some(b"common words common words without terminal".to_vec())
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
            open_non_seekable_archive(&archive.bytes, &master_key(), Some(&missing_dictionary))
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
    fn non_seekable_bootstrap_rejects_index_root_only_sidecar() {
        let archive = write_archive(
            &[RegularFile::new("sparse.txt", b"sparse sidecar")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let index_root_only = sparse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &master_key(),
            false,
            true,
            false,
        );

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), Some(&index_root_only))
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections"
            )
        );
    }

    #[test]
    fn seekable_sidecar_uses_index_root_records_after_terminal_manifest_authority() {
        let archive = write_archive(
            &[RegularFile::new("sparse-index.txt", b"recover index root")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_object_extent_records(
            &mut corrupted,
            index_root_extent_from_manifest(&opened.manifest_footer),
        );
        assert!(open_archive(&corrupted, &master_key()).is_err());

        let index_root_only = sparse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &master_key(),
            false,
            true,
            false,
        );
        let recovered =
            open_archive_with_bootstrap_sidecar(&corrupted, &index_root_only, &master_key())
                .unwrap();

        assert_eq!(
            recovered.extract_file("sparse-index.txt").unwrap(),
            Some(b"recover index root".to_vec())
        );
        recovered.verify().unwrap();
    }

    #[test]
    fn seekable_sidecar_uses_dictionary_records_after_index_root_authority() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "sparse-dict.txt",
                b"common words common words sparse dictionary",
            )],
            &master_key(),
            single_stream_options(),
            dictionary(),
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        let mut corrupted = archive.bytes.clone();
        corrupt_object_extent_records(
            &mut corrupted,
            dictionary_extent_from_index_root(&opened.index_root).unwrap(),
        );
        assert!(open_archive(&corrupted, &master_key()).is_err());

        let dictionary_only = sparse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &master_key(),
            false,
            false,
            true,
        );
        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), Some(&dictionary_only))
                .unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable bootstrap sidecar requires ManifestFooter and IndexRoot sections"
            )
        );

        let recovered =
            open_archive_with_bootstrap_sidecar(&corrupted, &dictionary_only, &master_key())
                .unwrap();
        assert_eq!(
            recovered.extract_file("sparse-dict.txt").unwrap(),
            Some(b"common words common words sparse dictionary".to_vec())
        );
        recovered.verify().unwrap();
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
    fn sequential_rejects_when_terminal_authentication_fails_without_returning_bytes() {
        let archive = write_archive(
            &[RegularFile::new(
                "seq.txt",
                b"payload must not be returned after terminal auth failure",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut corrupted = archive.bytes;
        corrupt_v41_terminal_recovery(&mut corrupted);

        match sequential_extract_tar_stream(&corrupted, &master_key()) {
            Ok(bytes) => panic!(
                "sequential helper returned {} decoded byte(s) despite terminal HMAC failure",
                bytes.len()
            ),
            Err(err) => assert_eq!(
                err,
                FormatError::InvalidArchive("no valid v41 CMRA candidate found")
            ),
        }
    }

    #[test]
    fn sequential_rejects_dictionary_archive_without_bootstrap_before_payload_release() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "seq-dict.txt",
                b"common words common words dictionary payload",
            )],
            &master_key(),
            single_stream_options(),
            b"common words dictionary",
        )
        .unwrap();

        match sequential_extract_tar_stream(&archive.bytes, &master_key()) {
            Ok(bytes) => panic!(
                "sequential helper returned {} decoded byte(s) for dictionary archive without bootstrap",
                bytes.len()
            ),
            Err(err) => assert_eq!(
                err,
                FormatError::ReaderUnsupported(
                    "dictionary bootstrap required for non-seekable sequential extraction"
                )
            ),
        }
    }

    #[test]
    fn non_seekable_dictionary_error_keeps_missing_bootstrap_wording() {
        let archive = write_archive_with_dictionary(
            &[RegularFile::new(
                "seq-dict-open.txt",
                b"common words common words bootstrap required",
            )],
            &master_key(),
            single_stream_options(),
            b"common words bootstrap",
        )
        .unwrap();

        assert_eq!(
            open_non_seekable_archive(&archive.bytes, &master_key(), None).unwrap_err(),
            FormatError::ReaderUnsupported(
                "non-seekable random access requires a bootstrap sidecar"
            )
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
    fn sidecar_manifest_validation_does_not_compare_opened_volume_index() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &archive.bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut opened_header = volume_header;
        opened_header.volume_index = 1;

        let parsed = parse_bootstrap_sidecar(
            &archive.bootstrap_sidecar,
            &opened_header,
            &crypto_header.fixed,
            &subkeys,
        )
        .unwrap();

        assert_eq!(parsed.manifest_footer.unwrap().volume_index, 0);
    }

    #[test]
    fn bootstrap_sidecar_rejects_conflicting_manifest_bootstrap_fields() {
        let archive = write_archive(&[], &master_key(), single_stream_options()).unwrap();
        let mut conflicting = archive.bootstrap_sidecar.clone();
        mutate_sidecar_manifest(&mut conflicting, &master_key(), |footer| {
            footer.index_root_first_block += 1;
        });

        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &conflicting, &master_key())
                .unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar conflicts with terminal ManifestFooter")
        );
    }

    #[test]
    fn sidecar_size_cap_counts_only_present_sparse_sections() {
        let mut crypto_header = test_crypto_header();
        crypto_header.has_dictionary = 1;
        crypto_header.index_root_fec_data_shards = 1;
        crypto_header.index_root_fec_parity_shards = 0;
        let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
        let header = BootstrapSidecarHeader {
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            flags: 0x04,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            index_root_records_offset: 0,
            index_root_records_length: 0,
            dictionary_records_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            dictionary_records_length: record_len,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        validate_sidecar_size_cap(
            &header,
            &crypto_header,
            BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len,
        )
        .unwrap();
        assert_eq!(
            validate_sidecar_size_cap(
                &header,
                &crypto_header,
                BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len + 1,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar exceeds resource cap")
        );
    }

    #[test]
    fn sidecar_size_cap_rejects_sparse_section_above_class_max() {
        let mut crypto_header = test_crypto_header();
        crypto_header.index_root_fec_data_shards = 1;
        crypto_header.index_root_fec_parity_shards = 0;
        let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
        let header = BootstrapSidecarHeader {
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            flags: 0x02,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            index_root_records_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            index_root_records_length: record_len * 2,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        assert_eq!(
            validate_sidecar_size_cap(
                &header,
                &crypto_header,
                BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + record_len * 2,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar IndexRoot records exceed resource cap")
        );
    }

    #[test]
    fn sidecar_size_cap_uses_wide_arithmetic_for_large_record_classes() {
        let mut crypto_header = test_crypto_header();
        crypto_header.block_size = u32::MAX;
        crypto_header.index_root_fec_data_shards = u16::MAX;
        crypto_header.index_root_fec_parity_shards = u16::MAX;
        let record_len = crypto_header.block_size as u64 + BLOCK_RECORD_FRAMING_LEN as u64;
        let max_records = crypto_header.index_root_fec_data_shards as u64
            + crypto_header.index_root_fec_parity_shards as u64;
        let max_section_len = max_records * record_len;
        let cap = BOOTSTRAP_SIDECAR_HEADER_LEN as u64
            + MANIFEST_FOOTER_LEN as u64
            + max_section_len
            + max_section_len;
        let header = BootstrapSidecarHeader {
            archive_uuid: [0x31; 16],
            session_id: [0x42; 16],
            flags: 0x01 | 0x02 | 0x04,
            manifest_footer_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            index_root_records_offset: 0,
            index_root_records_length: max_section_len,
            dictionary_records_offset: 0,
            dictionary_records_length: max_section_len,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        validate_sidecar_size_cap(&header, &crypto_header, cap).unwrap();
        assert_eq!(
            validate_sidecar_size_cap(&header, &crypto_header, cap + 1).unwrap_err(),
            FormatError::InvalidArchive("bootstrap sidecar exceeds resource cap")
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
    fn verify_rejects_authenticated_content_hash_mismatch() {
        let options = WriterOptions {
            index_root_fec_parity_shards: 0,
            ..single_stream_options()
        };
        let archive = write_archive(
            &[RegularFile::new("content-hash.txt", b"hash covered")],
            &master_key(),
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        let mut root = opened.index_root.clone();
        root.header.content_sha256 = [0xa5; 32];
        let root_plaintext = root.to_bytes();
        IndexRoot::parse(
            &root_plaintext,
            false,
            metadata_limits(&opened.crypto_header),
        )
        .unwrap();
        assert_eq!(
            root_plaintext.len() as u32,
            opened.manifest_footer.index_root_decompressed_size
        );

        let compressed_root = compress_zstd_frame(&root_plaintext, options.zstd_level).unwrap();
        let mut next_block_index = opened.manifest_footer.index_root_first_block;
        let replacement = encrypt_test_object(
            &compressed_root,
            &opened.subkeys.index_root_key,
            &opened.subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        assert_eq!(
            replacement.extent.data_block_count,
            opened.manifest_footer.index_root_data_block_count
        );
        assert_eq!(
            replacement.extent.encrypted_size,
            opened.manifest_footer.index_root_encrypted_size
        );

        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = volume_header.crypto_header_offset as usize
            + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let mut malformed = archive.bytes.clone();
        for record in replacement.records {
            let offset = crypto_end + record.block_index as usize * record_len;
            malformed[offset..offset + record_len].copy_from_slice(&record.to_bytes());
        }

        let reopened = open_archive(&malformed, &master_key()).unwrap();
        assert_eq!(
            reopened.verify().unwrap_err(),
            FormatError::InvalidArchive(
                "IndexRoot content_sha256 does not match decoded tar stream"
            )
        );
    }

    #[test]
    fn verify_rejects_file_entry_tar_path_and_size_mismatches() {
        let (mut path_mismatch, _) = multi_envelope_reader_fixture();
        rewrite_as_single_healthy_file(&mut path_mismatch, |_file, path| {
            path[0] = b'x';
        });
        assert_eq!(
            path_mismatch.verify().unwrap_err(),
            FormatError::InvalidArchive("tar member path does not match FileEntry path")
        );

        let (mut size_mismatch, _) = multi_envelope_reader_fixture();
        rewrite_as_single_healthy_file(&mut size_mismatch, |file, _path| {
            file.file_data_size += 1;
        });
        assert_eq!(
            size_mismatch.verify().unwrap_err(),
            FormatError::InvalidArchive("tar member size does not match FileEntry file_data_size")
        );
    }

    #[test]
    fn verify_rejects_inconsistent_duplicate_local_frame_rows_across_shards() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        let locating = opened.index_root.shards[0].clone();
        let mut duplicate = opened.load_index_shard(&locating).unwrap();
        duplicate.header.shard_index = 1;
        duplicate.frames[0].flags ^= 0x0000_0001;
        let duplicate_plaintext = duplicate.to_bytes();
        let mut next_block_index = opened
            .blocks
            .keys()
            .last()
            .copied()
            .map(|index| index + 1)
            .unwrap_or(0);
        let duplicate_object = encrypt_test_object(
            &compress_zstd_frame(&duplicate_plaintext, 1).unwrap(),
            &opened.subkeys.index_shard_key,
            &opened.subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        insert_records(&mut opened.blocks, &duplicate_object.records);
        opened.index_root.shards.push(ShardEntry {
            shard_index: 1,
            first_block_index: duplicate_object.extent.first_block_index,
            data_block_count: duplicate_object.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: duplicate_object.extent.encrypted_size,
            decompressed_size: duplicate_plaintext.len() as u32,
            file_count: locating.file_count,
            first_path_hash: locating.first_path_hash,
            last_path_hash: locating.last_path_hash,
        });
        opened.index_root.header.file_count += locating.file_count as u64;

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidArchive("duplicate FrameEntry rows do not match")
        );
    }

    #[test]
    fn verify_rejects_inconsistent_duplicate_local_envelope_rows_across_shards() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        let locating = opened.index_root.shards[0].clone();
        let mut duplicate = opened.load_index_shard(&locating).unwrap();
        duplicate.header.shard_index = 1;
        duplicate.envelopes[0].first_block_index += 1;
        let duplicate_plaintext = duplicate.to_bytes();
        let mut next_block_index = opened
            .blocks
            .keys()
            .last()
            .copied()
            .map(|index| index + 1)
            .unwrap_or(0);
        let duplicate_object = encrypt_test_object(
            &compress_zstd_frame(&duplicate_plaintext, 1).unwrap(),
            &opened.subkeys.index_shard_key,
            &opened.subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        insert_records(&mut opened.blocks, &duplicate_object.records);
        opened.index_root.shards.push(ShardEntry {
            shard_index: 1,
            first_block_index: duplicate_object.extent.first_block_index,
            data_block_count: duplicate_object.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: duplicate_object.extent.encrypted_size,
            decompressed_size: duplicate_plaintext.len() as u32,
            file_count: locating.file_count,
            first_path_hash: locating.first_path_hash,
            last_path_hash: locating.last_path_hash,
        });
        opened.index_root.header.file_count += locating.file_count as u64;

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidArchive("duplicate EnvelopeEntry rows do not match")
        );
    }

    #[test]
    fn verify_rejects_non_contiguous_global_envelope_indexes() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        replace_first_index_shard(&mut opened, |shard| {
            let frame = shard
                .frames
                .iter_mut()
                .find(|entry| entry.frame_index == 1)
                .unwrap();
            frame.envelope_index = 2;

            let envelope = shard
                .envelopes
                .iter_mut()
                .find(|entry| entry.envelope_index == 1)
                .unwrap();
            envelope.envelope_index = 2;
        });

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidMetadata {
                structure: "EnvelopeEntry",
                reason: "global index coverage has a gap",
            }
        );
    }

    #[test]
    fn verify_rejects_payload_object_extent_overlap() {
        let (mut opened, _) = multi_envelope_reader_fixture();
        replace_first_index_shard(&mut opened, |shard| {
            let first_block_index = shard.envelopes[0].first_block_index;
            shard.envelopes[1].first_block_index = first_block_index;
        });

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::InvalidArchive("encrypted object block ranges overlap")
        );
    }

    #[test]
    fn verify_accepts_cross_shard_shared_envelope_frame_union() {
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

        let alpha = test_member(b"alpha.txt", b"alpha cross shard\n");
        let zulu = test_member(b"zulu.txt", b"zulu cross shard\n");
        let tar_stream = [alpha.as_slice(), zulu.as_slice()].concat();
        let frame0_plaintext = compress_zstd_frame(&alpha, 1).unwrap();
        let frame1_plaintext = compress_zstd_frame(&zulu, 1).unwrap();
        let envelope_plaintext =
            [frame0_plaintext.as_slice(), frame1_plaintext.as_slice()].concat();
        let payload = encrypt_test_object(
            &envelope_plaintext,
            &subkeys.enc_key,
            &subkeys.nonce_seed,
            b"envelope",
            0,
            BlockKind::PayloadData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &payload.records);

        let envelope = EnvelopeEntry {
            envelope_index: 0,
            first_block_index: payload.extent.first_block_index,
            data_block_count: payload.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: payload.extent.encrypted_size,
            plaintext_size: envelope_plaintext.len() as u32,
            first_frame_index: 0,
            frame_count: 2,
        };
        let frame0 = FrameEntry {
            frame_index: 0,
            envelope_index: 0,
            offset_in_envelope: 0,
            compressed_size: frame0_plaintext.len() as u32,
            decompressed_size: alpha.len() as u32,
            flags: 0x0000_0003,
            tar_stream_offset: 0,
        };
        let frame1 = FrameEntry {
            frame_index: 1,
            envelope_index: 0,
            offset_in_envelope: frame0_plaintext.len() as u32,
            compressed_size: frame1_plaintext.len() as u32,
            decompressed_size: zulu.len() as u32,
            flags: 0x0000_0003,
            tar_stream_offset: alpha.len() as u64,
        };

        let (shard0_plaintext, first0, last0) = build_test_index_shard(
            &[TestFileMeta {
                path: b"alpha.txt".to_vec(),
                frame_index: 0,
                tar_stream_offset: 0,
                member_group_size: alpha.len() as u64,
                file_data_size: b"alpha cross shard\n".len() as u64,
            }],
            &[frame0],
            std::slice::from_ref(&envelope),
        );
        let (mut shard1_plaintext, first1, last1) = build_test_index_shard(
            &[TestFileMeta {
                path: b"zulu.txt".to_vec(),
                frame_index: 1,
                tar_stream_offset: alpha.len() as u64,
                member_group_size: zulu.len() as u64,
                file_data_size: b"zulu cross shard\n".len() as u64,
            }],
            &[frame1],
            std::slice::from_ref(&envelope),
        );
        shard1_plaintext[8..16].copy_from_slice(&1u64.to_le_bytes());

        let shard0 = encrypt_test_object(
            &compress_zstd_frame(&shard0_plaintext, 1).unwrap(),
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            0,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        let shard1 = encrypt_test_object(
            &compress_zstd_frame(&shard1_plaintext, 1).unwrap(),
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &crypto_header,
            &volume_header,
        );
        insert_records(&mut blocks, &shard0.records);
        insert_records(&mut blocks, &shard1.records);

        let index_root = IndexRoot {
            header: IndexRootHeader {
                frame_count: 2,
                envelope_count: 1,
                file_count: 2,
                payload_block_count: payload.extent.data_block_count as u64,
                tar_total_size: tar_stream.len() as u64,
                content_sha256: sha256_bytes(&tar_stream),
                ..IndexRootHeader::empty()
            },
            shards: vec![
                ShardEntry {
                    shard_index: 0,
                    first_block_index: shard0.extent.first_block_index,
                    data_block_count: shard0.extent.data_block_count,
                    parity_block_count: 0,
                    encrypted_size: shard0.extent.encrypted_size,
                    decompressed_size: shard0_plaintext.len() as u32,
                    file_count: 1,
                    first_path_hash: first0,
                    last_path_hash: last0,
                },
                ShardEntry {
                    shard_index: 1,
                    first_block_index: shard1.extent.first_block_index,
                    data_block_count: shard1.extent.data_block_count,
                    parity_block_count: 0,
                    encrypted_size: shard1.extent.encrypted_size,
                    decompressed_size: shard1_plaintext.len() as u32,
                    file_count: 1,
                    first_path_hash: first1,
                    last_path_hash: last1,
                },
            ],
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
            crypto_header_bytes: Vec::new(),
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
            volume_trailer: Some(VolumeTrailer {
                archive_uuid,
                session_id,
                volume_index: 0,
                block_count: next_block_index,
                bytes_written: 0,
                manifest_footer_offset: 0,
                manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
                closed_at_ns: 0,
                root_auth_footer_offset: 0,
                root_auth_footer_length: 0,
                root_auth_flags: 0,
                trailer_hmac: [0u8; 32],
            }),
            root_auth_footer: None,
            index_root,
            payload_dictionary: None,
        };

        opened.verify().unwrap();
    }

    #[test]
    fn verify_rejects_authenticated_archive_missing_required_directory_hints() {
        let options = WriterOptions {
            index_root_fec_parity_shards: 0,
            ..single_stream_options()
        };
        let archive = write_archive(
            &[RegularFile::new("only.txt", b"only payload")],
            &master_key(),
            options,
        )
        .unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        assert!(opened.index_root.directory_hint_shards.is_empty());

        let mut root = opened.index_root.clone();
        root.header.file_count = DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1;
        root.shards[0].file_count = (DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1) as u32;
        let root_plaintext = root.to_bytes();
        IndexRoot::parse(
            &root_plaintext,
            false,
            metadata_limits(&opened.crypto_header),
        )
        .unwrap();
        assert_eq!(
            root_plaintext.len() as u32,
            opened.manifest_footer.index_root_decompressed_size
        );

        let compressed_root = compress_zstd_frame(&root_plaintext, options.zstd_level).unwrap();
        let mut next_block_index = opened.manifest_footer.index_root_first_block;
        let replacement = encrypt_test_object(
            &compressed_root,
            &opened.subkeys.index_root_key,
            &opened.subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        assert_eq!(
            replacement.extent.first_block_index,
            opened.manifest_footer.index_root_first_block
        );
        assert_eq!(
            replacement.extent.data_block_count,
            opened.manifest_footer.index_root_data_block_count
        );
        assert_eq!(
            replacement.extent.encrypted_size,
            opened.manifest_footer.index_root_encrypted_size
        );

        let volume_header = VolumeHeader::parse(&archive.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = volume_header.crypto_header_offset as usize
            + volume_header.crypto_header_length as usize;
        let record_len = opened.crypto_header.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let mut malformed = archive.bytes.clone();
        for record in replacement.records {
            let offset = crypto_end + record.block_index as usize * record_len;
            malformed[offset..offset + record_len].copy_from_slice(&record.to_bytes());
        }

        let reopened = open_archive(&malformed, &master_key()).unwrap();
        assert_eq!(
            reopened.index_root.header.file_count,
            DIRECTORY_HINT_REQUIRED_FILE_COUNT + 1
        );
        assert!(reopened.index_root.directory_hint_shards.is_empty());

        assert_eq!(
            reopened.verify().unwrap_err(),
            FormatError::InvalidArchive("IndexRoot file_count requires directory hints")
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

        let mut missing_root = expected.clone();
        missing_root.remove(&Vec::new());
        let missing_root_rows = sorted_directory_hint_rows(&missing_root);
        let missing_root_table = directory_hint_table_from_rows(8, &missing_root_rows, 2);
        assert_eq!(
            validate_directory_hint_tables_against_expected(&[missing_root_table], &expected)
                .unwrap_err(),
            FormatError::InvalidArchive("directory hint map does not match decoded files")
        );

        let mut expected_missing_directory_entry = expected.clone();
        expected_missing_directory_entry
            .get_mut(&b"foo".to_vec())
            .unwrap()
            .remove(&1);
        assert_eq!(
            validate_directory_hint_tables_against_expected(
                &[table.clone()],
                &expected_missing_directory_entry,
            )
            .unwrap_err(),
            FormatError::InvalidArchive("directory hint map does not match decoded files")
        );

        let mut extra = expected.clone();
        extra.insert(b"foo/extra".to_vec(), BTreeSet::from([0]));
        let extra_rows = sorted_directory_hint_rows(&extra);
        let extra_table = directory_hint_table_from_rows(9, &extra_rows, 2);
        assert_eq!(
            validate_directory_hint_tables_against_expected(&[extra_table], &expected).unwrap_err(),
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
                "encrypted object parity does not match v41 compute_parity"
            )
        );
    }

    #[test]
    fn encrypted_object_extent_matrix_rejects_overlaps() {
        let (opened, _) = multi_envelope_reader_fixture();
        let loaded_shard = opened
            .load_index_shard(&opened.index_root.shards[0])
            .unwrap();
        let base_envelopes = loaded_shard
            .envelopes
            .iter()
            .map(|entry| (entry.envelope_index, entry.clone()))
            .collect::<BTreeMap<_, _>>();
        let payload_start = loaded_shard.envelopes[0].first_block_index;
        let overlap = FormatError::InvalidArchive("encrypted object block ranges overlap");

        let mut payload_overlap = base_envelopes.clone();
        payload_overlap
            .get_mut(&loaded_shard.envelopes[1].envelope_index)
            .unwrap()
            .first_block_index = payload_start;
        assert_eq!(
            opened
                .validate_encrypted_object_block_ranges(&payload_overlap)
                .unwrap_err(),
            overlap
        );

        let mut shard_overlap = opened.clone();
        let shard = shard_overlap.index_root.shards[0].clone();
        shard_overlap.index_root.shards.push(ShardEntry {
            shard_index: 1,
            ..shard
        });
        assert_eq!(
            shard_overlap
                .validate_encrypted_object_block_ranges(&base_envelopes)
                .unwrap_err(),
            overlap
        );

        let mut dictionary_overlap = opened.clone();
        dictionary_overlap.crypto_header.has_dictionary = 1;
        dictionary_overlap.index_root.header.dictionary_first_block = payload_start;
        dictionary_overlap
            .index_root
            .header
            .dictionary_data_block_count = 1;
        dictionary_overlap
            .index_root
            .header
            .dictionary_parity_block_count = 0;
        dictionary_overlap
            .index_root
            .header
            .dictionary_encrypted_size = 4096;
        dictionary_overlap
            .index_root
            .header
            .dictionary_decompressed_size = 128;
        assert_eq!(
            dictionary_overlap
                .validate_encrypted_object_block_ranges(&base_envelopes)
                .unwrap_err(),
            overlap
        );

        let mut hint_overlap = opened.clone();
        hint_overlap
            .index_root
            .directory_hint_shards
            .push(DirectoryHintShardEntry {
                hint_shard_index: 0,
                first_dir_hash: [0; 8],
                last_dir_hash: [0; 8],
                first_block_index: payload_start,
                data_block_count: 1,
                parity_block_count: 0,
                encrypted_size: 4096,
                decompressed_size: 128,
                entry_count: 1,
            });
        assert_eq!(
            hint_overlap
                .validate_encrypted_object_block_ranges(&base_envelopes)
                .unwrap_err(),
            overlap
        );
    }

    #[test]
    fn load_metadata_object_rejects_per_object_zstd_frame_exactness_mutations() {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;

        let index_root_payload = b"index root metadata object";
        let index_root_compressed = compress_zstd_frame(index_root_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = index_root_compressed.clone();
                bytes.push(0);
                bytes
            },
            index_root_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &index_root_compressed,
            index_root_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            BlockKind::IndexRootParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: index_root_payload.len() + 1,
                actual: index_root_payload.len(),
            },
        );

        let index_shard_payload = b"index shard metadata object";
        let index_shard_compressed = compress_zstd_frame(index_shard_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = index_shard_compressed.clone();
                bytes.push(0);
                bytes
            },
            index_shard_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &index_shard_compressed,
            index_shard_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            BlockKind::IndexShardParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: index_shard_payload.len() + 1,
                actual: index_shard_payload.len(),
            },
        );

        let directory_hint_payload = b"directory hint metadata object";
        let directory_hint_compressed = compress_zstd_frame(directory_hint_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = directory_hint_compressed.clone();
                bytes.push(0);
                bytes
            },
            directory_hint_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            0,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &directory_hint_compressed,
            directory_hint_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            0,
            BlockKind::DirectoryHintData,
            BlockKind::DirectoryHintParity,
            crypto_header.index_fec_data_shards,
            crypto_header.index_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: directory_hint_payload.len() + 1,
                actual: directory_hint_payload.len(),
            },
        );

        let dictionary_payload = b"dictionary metadata object";
        let dictionary_compressed = compress_zstd_frame(dictionary_payload, 1).unwrap();
        assert_metadata_object_from_compressed(
            &{
                let mut bytes = dictionary_compressed.clone();
                bytes.push(0);
                bytes
            },
            dictionary_payload.len(),
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            BlockKind::DictionaryParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::TrailingBytesAfterZstdFrame,
        );
        assert_metadata_object_from_compressed(
            &dictionary_compressed,
            dictionary_payload.len() + 1,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            BlockKind::DictionaryParity,
            crypto_header.index_root_fec_data_shards,
            crypto_header.index_root_fec_parity_shards,
            &mut next_block_index,
            FormatError::ZstdDecompressedSizeMismatch {
                expected: dictionary_payload.len() + 1,
                actual: dictionary_payload.len(),
            },
        );
    }

    #[test]
    fn load_metadata_object_extent_rejects_encrypted_size_not_data_block_count_times_block_size() {
        let volume_header = test_volume_header();
        let crypto_header = test_crypto_header();
        let subkeys = Subkeys::derive(
            &master_key(),
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        let mut next_block_index = 0u64;

        let index_root_payload = b"index root metadata object";
        let (index_root_extent, index_root_records) = build_metadata_object_from_payload(
            index_root_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_root_key,
            &subkeys.index_nonce_seed,
            b"idxroot",
            0,
            BlockKind::IndexRootData,
            &mut next_block_index,
        );
        let mut index_root_extent = index_root_extent;
        index_root_extent.encrypted_size = index_root_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &index_root_records,
                &subkeys,
                &volume_header,
                &crypto_header,
                index_root_extent,
                BlockKind::IndexRootData,
                BlockKind::IndexRootParity,
                &subkeys.index_root_key,
                &subkeys.index_nonce_seed,
                b"idxroot",
                0,
                crypto_header.index_root_fec_data_shards,
                crypto_header.index_root_fec_parity_shards,
                index_root_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );

        let index_shard_payload = b"index shard metadata object";
        let (index_shard_extent, index_shard_records) = build_metadata_object_from_payload(
            index_shard_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.index_shard_key,
            &subkeys.index_nonce_seed,
            b"idxshard",
            1,
            BlockKind::IndexShardData,
            &mut next_block_index,
        );
        let mut index_shard_extent = index_shard_extent;
        index_shard_extent.encrypted_size = index_shard_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &index_shard_records,
                &subkeys,
                &volume_header,
                &crypto_header,
                index_shard_extent,
                BlockKind::IndexShardData,
                BlockKind::IndexShardParity,
                &subkeys.index_shard_key,
                &subkeys.index_nonce_seed,
                b"idxshard",
                1,
                crypto_header.index_fec_data_shards,
                crypto_header.index_fec_parity_shards,
                index_shard_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );

        let directory_hint_payload = b"directory hint metadata object";
        let (directory_hint_extent, directory_hint_records) = build_metadata_object_from_payload(
            directory_hint_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dir_hint_key,
            &subkeys.index_nonce_seed,
            b"dirhint",
            0,
            BlockKind::DirectoryHintData,
            &mut next_block_index,
        );
        let mut directory_hint_extent = directory_hint_extent;
        directory_hint_extent.encrypted_size = directory_hint_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &directory_hint_records,
                &subkeys,
                &volume_header,
                &crypto_header,
                directory_hint_extent,
                BlockKind::DirectoryHintData,
                BlockKind::DirectoryHintParity,
                &subkeys.dir_hint_key,
                &subkeys.index_nonce_seed,
                b"dirhint",
                0,
                crypto_header.index_fec_data_shards,
                crypto_header.index_fec_parity_shards,
                directory_hint_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
            )
        );

        let dictionary_payload = b"dictionary metadata object";
        let (dictionary_extent, dictionary_records) = build_metadata_object_from_payload(
            dictionary_payload,
            &subkeys,
            &volume_header,
            &crypto_header,
            &subkeys.dictionary_key,
            &subkeys.index_nonce_seed,
            b"dict",
            0,
            BlockKind::DictionaryData,
            &mut next_block_index,
        );
        let mut dictionary_extent = dictionary_extent;
        dictionary_extent.encrypted_size = dictionary_extent
            .encrypted_size
            .saturating_add(crypto_header.block_size);
        assert_eq!(
            load_metadata_object_from_parts(
                &dictionary_records,
                &subkeys,
                &volume_header,
                &crypto_header,
                dictionary_extent,
                BlockKind::DictionaryData,
                BlockKind::DictionaryParity,
                &subkeys.dictionary_key,
                &subkeys.index_nonce_seed,
                b"dict",
                0,
                crypto_header.index_root_fec_data_shards,
                crypto_header.index_root_fec_parity_shards,
                dictionary_payload.len() as u32,
            )
            .unwrap_err(),
            FormatError::InvalidArchive(
                "encrypted object size is not data_block_count * block_size"
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
    fn rejects_multi_volume_count_mismatch_without_tolerance() {
        let files = [RegularFile::new("alpha.txt", b"count check")];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 3,
                volume_loss_tolerance: 0,
                ..single_stream_options()
            },
        )
        .unwrap();

        assert_eq!(
            open_archive_volumes(&[archive.volumes[0].as_slice()], &master_key()).unwrap_err(),
            FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance")
        );
    }

    #[test]
    fn rejects_multi_volume_manifest_bootstrap_field_mismatch() {
        let files = [RegularFile::new("alpha.txt", b"footer mismatch")];
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

        let mut bad_first = archive.volumes[0].clone();
        rewrite_manifest_footer(&mut bad_first, &master_key(), |footer| {
            footer.index_root_first_block = footer.index_root_first_block.wrapping_add(1);
        });

        open_archive_volumes(
            &[bad_first.as_slice(), archive.volumes[1].as_slice()],
            &master_key(),
        )
        .unwrap();
    }

    #[test]
    fn repairs_corrupted_index_root_block_in_multi_volume_archive() {
        let files = [RegularFile::new("alpha.txt", b"repair meta root")];
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

        let mut corrupted = false;
        for volume in &mut volumes {
            if let Some(slot) =
                block_record_slots_with_kind(volume, BlockKind::IndexRootData).first()
            {
                corrupt_block_record_payload_at_slot(volume, *slot);
                corrupted = true;
                break;
            }
        }
        assert!(corrupted, "expected an IndexRootData record");

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"repair meta root".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn repairs_corrupted_index_shard_block_in_multi_volume_archive() {
        let files = [RegularFile::new("alpha.txt", b"repair meta shard")];
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

        let mut corrupted = false;
        for volume in &mut volumes {
            if let Some(slot) =
                block_record_slots_with_kind(volume, BlockKind::IndexShardData).first()
            {
                corrupt_block_record_payload_at_slot(volume, *slot);
                corrupted = true;
                break;
            }
        }
        assert!(corrupted, "expected an IndexShardData record");

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"repair meta shard".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_missing_volume_when_loss_tolerance_zero_even_with_bitrot_parity() {
        let files = [RegularFile::new(
            "alpha.txt",
            b"bitrot parity is not volume loss",
        )];
        let archive = write_archive(
            &files,
            &master_key(),
            WriterOptions {
                stripe_width: 2,
                volume_loss_tolerance: 0,
                bit_rot_buffer_pct: 1,
                ..single_stream_options()
            },
        )
        .unwrap();

        assert_eq!(
            open_archive_volumes(&[archive.volumes[1].as_slice()], &master_key()).unwrap_err(),
            FormatError::InvalidArchive("missing volume count exceeds volume_loss_tolerance")
        );
    }

    #[test]
    fn repairs_crc_erasure_only_within_parity_budget() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("rot.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slots = first_payload_data_run_slots(&archive.bytes);
        assert!(
            payload_slots.len() >= 2,
            "fixture must contain a multi-block payload object"
        );

        let mut one_erasure = archive.bytes.clone();
        corrupt_block_record_payload_at_slot(&mut one_erasure, payload_slots[0]);
        let repaired = open_archive(&one_erasure, &master_key()).unwrap();
        assert_eq!(
            repaired.extract_file("rot.bin").unwrap(),
            Some(payload.clone())
        );

        let mut two_erasures = archive.bytes.clone();
        corrupt_block_record_payload_at_slot(&mut two_erasures, payload_slots[0]);
        corrupt_block_record_payload_at_slot(&mut two_erasures, payload_slots[1]);
        let unrepaired = open_archive(&two_erasures, &master_key()).unwrap();
        assert_eq!(
            unrepaired.extract_file("rot.bin").unwrap_err(),
            FormatError::FecTooFewAvailableShards
        );
    }

    #[test]
    fn verify_rejects_missing_required_object_block_extent() {
        let (mut opened, missing_block) = multi_envelope_reader_fixture();
        assert!(opened.blocks.remove(&missing_block).is_some());

        assert_eq!(
            opened.verify().unwrap_err(),
            FormatError::FecTooFewAvailableShards
        );
    }

    #[test]
    fn parity_crc_erasure_does_not_hide_authenticated_data() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("parity-erasure.bin", &payload)],
            &master_key(),
            parity_rich_recovery_options(),
        )
        .unwrap();
        let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];
        let parity_slots = block_record_slots_with_kind(&archive.bytes, BlockKind::PayloadParity);
        assert!(
            parity_slots.len() >= 2,
            "fixture must contain redundant parity shards"
        );
        let mut corrupted = archive.bytes;
        corrupt_block_record_payload_at_slot(&mut corrupted, payload_slot);
        corrupt_block_record_payload_at_slot(&mut corrupted, parity_slots[0]);

        let opened = open_archive(&corrupted, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("parity-erasure.bin").unwrap(),
            Some(payload)
        );
        opened.verify().unwrap();
    }

    #[test]
    fn rejects_odd_block_size_before_fec_repair() {
        let archive = write_archive(
            &[RegularFile::new("odd-block.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let mut malformed = archive.bytes;
        let volume_header = VolumeHeader::parse(&malformed[..VOLUME_HEADER_LEN]).unwrap();
        let block_size_offset = volume_header.crypto_header_offset as usize + 24;
        malformed[block_size_offset..block_size_offset + 4].copy_from_slice(&4097u32.to_le_bytes());

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
            FormatError::OddBlockSize(4097)
        );
    }

    #[test]
    fn rejects_structurally_malformed_block_records_instead_of_repairing() {
        let archive = write_archive(
            &[RegularFile::new("structural-block.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slot = first_payload_data_run_slots(&archive.bytes)[0];

        let mut bad_magic = archive.bytes.clone();
        corrupt_block_record_magic_at_slot(&mut bad_magic, payload_slot);
        assert_eq!(
            open_archive(&bad_magic, &master_key()).unwrap_err(),
            FormatError::BadMagic {
                structure: "BlockRecord"
            }
        );

        let mut bad_reserved = archive.bytes;
        corrupt_block_record_reserved_at_slot(&mut bad_reserved, payload_slot);
        assert_eq!(
            open_archive(&bad_reserved, &master_key()).unwrap_err(),
            FormatError::NonZeroReserved {
                structure: "BlockRecord"
            }
        );
    }

    #[test]
    fn rejects_parity_block_with_last_data_flag() {
        let archive = write_archive(
            &[RegularFile::new("parity-flag.txt", b"payload")],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let parity_slot =
            first_block_record_slot_with_kind(&archive.bytes, BlockKind::PayloadParity).unwrap();
        let mut malformed = archive.bytes;
        mutate_block_record_at_slot(&mut malformed, parity_slot, |record| {
            record.flags = 0x01;
        });

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
            FormatError::ParityBlockHasLastDataFlag
        );
    }

    #[test]
    fn rejects_missing_and_duplicate_payload_last_data_flags() {
        let payload = pseudo_random_bytes(12_000);
        let archive = write_archive(
            &[RegularFile::new("flags.bin", &payload)],
            &master_key(),
            small_block_recovery_options(),
        )
        .unwrap();
        let payload_slots = first_payload_data_run_slots(&archive.bytes);
        assert!(
            payload_slots.len() >= 2,
            "fixture must contain a multi-block payload object"
        );

        let mut duplicate_last = archive.bytes.clone();
        mutate_block_record_at_slot(&mut duplicate_last, payload_slots[0], |record| {
            record.flags = 0x01;
        });
        let opened = open_archive(&duplicate_last, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("flags.bin").unwrap_err(),
            FormatError::InvalidArchive("object last-data flag is not on the final data block")
        );

        let mut missing_last = archive.bytes;
        mutate_block_record_at_slot(
            &mut missing_last,
            *payload_slots.last().unwrap(),
            |record| {
                record.flags = 0;
            },
        );
        let opened = open_archive(&missing_last, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("flags.bin").unwrap_err(),
            FormatError::InvalidArchive("object last-data flag is not on the final data block")
        );
    }

    #[test]
    fn recovers_from_one_corrupt_manifest_footer_copy_when_another_volume_authenticates() {
        let files = [RegularFile::new(
            "footer-copy.txt",
            b"survives one bad footer",
        )];
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
        corrupt_manifest_footer_hmac(&mut volumes[0]);

        let volume_refs = volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&volume_refs, &master_key()).unwrap();
        assert_eq!(opened.manifest_footer.volume_index, 0);
        assert_eq!(opened.volume_header.volume_index, 0);
        assert_eq!(opened.volume_trailer.as_ref().unwrap().volume_index, 0);
        assert_eq!(
            opened.extract_file("footer-copy.txt").unwrap(),
            Some(b"survives one bad footer".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn manifest_footer_corruption_requires_trusted_sidecar() {
        let archive = write_archive(
            &[RegularFile::new("footer.txt", b"sidecar authority")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let manifest_offset = terminal_material_offset(&archive.bytes);
        let mut corrupted = archive.bytes.clone();
        corrupted[manifest_offset + MANIFEST_HMAC_COVERED_LEN] ^= 0x01;
        corrupt_v41_terminal_recovery(&mut corrupted);

        assert!(open_archive(&corrupted, &master_key()).is_err());

        let opened =
            open_non_seekable_archive(&corrupted, &master_key(), Some(&archive.bootstrap_sidecar))
                .unwrap();
        assert!(opened.volume_trailer.is_none());
        assert_eq!(
            opened.extract_file("footer.txt").unwrap(),
            Some(b"sidecar authority".to_vec())
        );
        opened.verify().unwrap();
    }

    #[test]
    fn authenticated_footer_trailer_and_sidecar_hmac_boundaries_are_enforced() {
        let archive = write_archive(
            &[RegularFile::new("hmac-boundary.txt", b"boundary bytes")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut strict_options = ReaderOptions::default();
        strict_options.max_trailing_garbage_scan = 0;

        let manifest_offset = terminal_material_offset(&archive.bytes);
        for offset in [
            manifest_offset + 71,
            manifest_offset + MANIFEST_HMAC_COVERED_LEN,
        ] {
            let mut corrupted = archive.bytes.clone();
            corrupted[offset] ^= 0x01;
            open_archive(&corrupted, &master_key()).unwrap();
        }

        let trailer_offset = manifest_offset + MANIFEST_FOOTER_LEN;
        for offset in [
            trailer_offset + 75,
            trailer_offset + TRAILER_HMAC_COVERED_LEN,
        ] {
            let mut corrupted = archive.bytes.clone();
            corrupted[offset] ^= 0x01;
            OpenedArchive::open_with_options(&corrupted, &master_key(), strict_options).unwrap();
        }

        let mut covered_sidecar = archive.bootstrap_sidecar.clone();
        let mut header =
            BootstrapSidecarHeader::parse(&covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN])
                .unwrap();
        header.manifest_footer_offset += 1;
        covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header.to_bytes());
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &covered_sidecar, &master_key())
                .unwrap_err(),
            FormatError::HmacMismatch {
                structure: "BootstrapSidecarHeader"
            }
        );

        let mut tag_sidecar = archive.bootstrap_sidecar.clone();
        let mut header =
            BootstrapSidecarHeader::parse(&tag_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        header.sidecar_hmac[0] ^= 1;
        tag_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header.to_bytes());
        assert_eq!(
            open_archive_with_bootstrap_sidecar(&archive.bytes, &tag_sidecar, &master_key())
                .unwrap_err(),
            FormatError::HmacMismatch {
                structure: "BootstrapSidecarHeader"
            }
        );

        let mut non_covered_sidecar = archive.bootstrap_sidecar.clone();
        let header =
            BootstrapSidecarHeader::parse(&non_covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN])
                .unwrap();
        let mut header_bytes = header.to_bytes();
        header_bytes[124] ^= 0x01;
        let crc = crc32c::crc32c(&header_bytes[..124]);
        header_bytes[124..128].copy_from_slice(&crc.to_le_bytes());
        non_covered_sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN].copy_from_slice(&header_bytes);
        let opened = open_archive_with_bootstrap_sidecar(
            &archive.bytes,
            &non_covered_sidecar,
            &master_key(),
        )
        .unwrap();
        assert_eq!(
            opened.extract_file("hmac-boundary.txt").unwrap(),
            Some(b"boundary bytes".to_vec())
        );
    }

    #[test]
    fn rejects_authenticated_footer_and_trailer_volume_index_mismatches() {
        let archive = write_archive(
            &[RegularFile::new("volume-index.txt", b"identity")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();

        let mut bad_trailer = archive.bytes.clone();
        rewrite_volume_trailer(&mut bad_trailer, &master_key(), |trailer| {
            trailer.volume_index = 1;
        });
        open_archive(&bad_trailer, &master_key()).unwrap();

        let mut bad_manifest = archive.bytes;
        rewrite_manifest_footer(&mut bad_manifest, &master_key(), |footer| {
            footer.volume_index = 1;
        });
        open_archive(&bad_manifest, &master_key()).unwrap();
    }

    #[test]
    fn rejects_same_key_header_terminal_material_splice() {
        let first = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let second = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        assert_ne!(first.archive_uuid, second.archive_uuid);
        assert_eq!(
            terminal_material_offset(&first.bytes),
            terminal_material_offset(&second.bytes)
        );
        assert_eq!(first.bytes.len(), second.bytes.len());

        let terminal_offset = terminal_material_offset(&first.bytes);
        let mut spliced = first.bytes.clone();
        spliced[terminal_offset..].copy_from_slice(&second.bytes[terminal_offset..]);

        assert_eq!(
            open_archive(&spliced, &master_key()).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 CMRA candidate found")
        );
    }

    #[test]
    fn rejects_same_key_crypto_header_splice_with_session_mismatch() {
        let base = WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x22; 16]),
            ..single_stream_options()
        };
        let same_archive = WriterOptions {
            archive_uuid: Some([0x11; 16]),
            session_id: Some([0x33; 16]),
            ..single_stream_options()
        };

        let first = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            base,
        )
        .unwrap();
        let second = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            same_archive,
        )
        .unwrap();

        let volume_header = VolumeHeader::parse(&first.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let second_volume_header = VolumeHeader::parse(&second.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let second_crypto_end = second_volume_header.crypto_header_offset as usize
            + second_volume_header.crypto_header_length as usize;
        assert_eq!(crypto_end, second_crypto_end);

        let mut spliced = first.bytes.clone();
        spliced[crypto_start..crypto_end].copy_from_slice(&second.bytes[crypto_start..crypto_end]);

        assert_eq!(
            open_archive(&spliced, &master_key()).unwrap_err(),
            FormatError::HmacMismatch {
                structure: "CryptoHeader"
            }
        );
    }

    #[test]
    fn rejects_same_key_object_splice_with_session_mismatch() {
        let first = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            WriterOptions {
                archive_uuid: Some([0x11; 16]),
                session_id: Some([0x22; 16]),
                ..single_stream_options()
            },
        )
        .unwrap();
        let second = write_archive(
            &[RegularFile::new("splice.txt", b"same shape")],
            &master_key(),
            WriterOptions {
                archive_uuid: Some([0x11; 16]),
                session_id: Some([0x33; 16]),
                ..single_stream_options()
            },
        )
        .unwrap();

        let volume_header = VolumeHeader::parse(&first.bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_end = volume_header.crypto_header_offset as usize
            + volume_header.crypto_header_length as usize;
        let terminal_offset = terminal_material_offset(&first.bytes);
        let second_terminal_offset = terminal_material_offset(&second.bytes);
        assert_eq!(terminal_offset, second_terminal_offset);

        let mut spliced = first.bytes.clone();
        spliced[crypto_end..terminal_offset]
            .copy_from_slice(&second.bytes[crypto_end..terminal_offset]);

        assert_eq!(
            open_archive(&spliced, &master_key()).unwrap_err(),
            FormatError::AeadFailure
        );
    }

    #[test]
    fn rejects_authenticated_trailer_pointer_and_count_mutations() {
        let archive = write_archive(
            &[RegularFile::new(
                "trailer-range.txt",
                b"authenticated ranges",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let strict_options = {
            let mut options = ReaderOptions::default();
            options.max_trailing_garbage_scan = 0;
            options
        };
        let bytes = archive.bytes;
        let manifest_offset = terminal_material_offset(&bytes);
        let trailer_offset = manifest_offset + MANIFEST_FOOTER_LEN;

        let mut wrong_footer_length = bytes.clone();
        rewrite_volume_trailer(&mut wrong_footer_length, &master_key(), |trailer| {
            trailer.manifest_footer_length = 42;
        });
        OpenedArchive::open_with_options(&wrong_footer_length, &master_key(), strict_options)
            .unwrap();

        for (label, offset) in [
            (
                "offset before trailer by 1",
                manifest_offset.saturating_sub(1),
            ),
            ("offset after trailer", manifest_offset + 1),
            ("offset at stream start", 0),
            ("offset at trailer", trailer_offset),
            ("offset beyond trailer", trailer_offset + 4),
        ] {
            let mut wrong_footer_offset = bytes.clone();
            rewrite_volume_trailer(&mut wrong_footer_offset, &master_key(), |trailer| {
                trailer.manifest_footer_offset = offset as u64;
            });
            open_archive(&wrong_footer_offset, &master_key())
                .unwrap_or_else(|err| panic!("manifest offset case {label}: {err:?}"));
        }

        let mut wrong_bytes_written = bytes.clone();
        rewrite_volume_trailer(&mut wrong_bytes_written, &master_key(), |trailer| {
            trailer.bytes_written += 1;
        });
        open_archive(&wrong_bytes_written, &master_key()).unwrap();

        let mut wrong_block_count = bytes.clone();
        rewrite_volume_trailer(&mut wrong_block_count, &master_key(), |trailer| {
            trailer.block_count += 1;
        });
        open_archive(&wrong_block_count, &master_key()).unwrap();

        let mut wrong_footer_offset = bytes.clone();
        rewrite_volume_trailer(&mut wrong_footer_offset, &master_key(), |trailer| {
            trailer.manifest_footer_offset = bytes.len() as u64 + 1024;
        });
        open_archive(&wrong_footer_offset, &master_key()).unwrap();
    }

    #[test]
    fn rejects_authenticated_trailer_outside_trailing_scan_cap() {
        let archive = write_archive(
            &[RegularFile::new(
                "trailer-trailing-scan.txt",
                b"trailer scan boundaries",
            )],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut options = ReaderOptions::default();
        options.max_trailing_garbage_scan = 8;

        let mut within_scan = archive.bytes.clone();
        within_scan.resize(within_scan.len() + options.max_trailing_garbage_scan, 0xAA);
        let opened =
            OpenedArchive::open_with_options(&within_scan, &master_key(), options).unwrap();
        assert_eq!(
            opened.extract_file("trailer-trailing-scan.txt").unwrap(),
            Some(b"trailer scan boundaries".to_vec())
        );

        let mut beyond_scan = within_scan;
        beyond_scan.resize(beyond_scan.len() + 300_000, 0xAA);
        assert_eq!(
            OpenedArchive::open_with_options(&beyond_scan, &master_key(), options).unwrap_err(),
            FormatError::InvalidArchive("no valid v41 CMRA candidate found")
        );
    }

    #[test]
    fn rejects_authenticated_index_root_extent_size_mismatch_at_open() {
        let archive = write_archive(
            &[RegularFile::new("index-root-size.txt", b"extent size")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        let mut malformed = archive.bytes;
        let slot = first_block_record_slot_with_kind(&malformed, BlockKind::IndexRootData)
            .expect("archive should contain IndexRootData");
        mutate_block_record_at_slot(&mut malformed, slot, |record| {
            record.payload[0] ^= 0x55;
        });

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
            FormatError::AeadFailure
        );
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
    fn rejects_decreasing_block_record_index_in_required_region() {
        let archive = write_archive(
            &[RegularFile::new("alpha.txt", b"decreasing block index")],
            &master_key(),
            single_stream_options(),
        )
        .unwrap();
        assert!(block_record_slots(&archive.bytes).len() >= 2);

        let mut malformed = archive.bytes;
        mutate_block_record_at_slot(&mut malformed, 1, |record| {
            record.block_index = 0;
        });

        assert_eq!(
            open_archive(&malformed, &master_key()).unwrap_err(),
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

    #[test]
    fn rejects_conflicting_duplicate_authenticated_volume_indexes_by_default() {
        let files = [RegularFile::new("alpha.txt", b"conflicting duplicates")];
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
        let mut conflicting = archive.volumes[0].clone();
        corrupt_first_block_record_payload(&mut conflicting);

        assert_eq!(
            open_archive_volumes(
                &[archive.volumes[0].as_slice(), conflicting.as_slice()],
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

    fn corrupt_block_record_payload_at_slot(volume: &mut [u8], slot: usize) {
        let (record_offset, _) = block_record_at_slot(volume, slot);
        volume[record_offset + 16] ^= 0x55;
    }

    fn corrupt_block_record_magic_at_slot(volume: &mut [u8], slot: usize) {
        let (record_offset, _) = block_record_at_slot(volume, slot);
        volume[record_offset] ^= 0x55;
    }

    fn corrupt_block_record_reserved_at_slot(volume: &mut [u8], slot: usize) {
        let (record_offset, _) = block_record_at_slot(volume, slot);
        volume[record_offset + 14] = 0x01;
    }

    fn corrupt_manifest_footer_hmac(volume: &mut [u8]) {
        let manifest_offset = terminal_material_offset(volume);
        volume[manifest_offset + MANIFEST_HMAC_COVERED_LEN] ^= 0x01;
    }

    fn final_recovery_locator(volume: &[u8]) -> CriticalRecoveryLocator {
        let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        CriticalRecoveryLocator::parse(
            &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap()
    }

    fn rewrite_cmra_parity_count(volume: &[u8], parity_shard_count: u16) -> Vec<u8> {
        let locator = final_recovery_locator(volume);
        let tuple = CmraDecoderTuple::from(locator);
        assert!(parity_shard_count < tuple.parity_shard_count);
        let cmra_offset = locator.cmra_offset as usize;
        let shard_size = tuple.shard_size as usize;
        let row_len = CRITICAL_METADATA_RECOVERY_SHARD_HEADER_LEN + shard_size;
        let kept_rows = tuple.data_shard_count as usize + parity_shard_count as usize;
        let mut header = CriticalMetadataRecoveryHeader::parse(
            &volume[cmra_offset..cmra_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN],
        )
        .unwrap();
        header.parity_shard_count = parity_shard_count;

        let mut cmra =
            Vec::with_capacity(CRITICAL_METADATA_RECOVERY_HEADER_LEN + kept_rows * row_len);
        cmra.extend_from_slice(&header.to_bytes());
        let rows_start = cmra_offset + CRITICAL_METADATA_RECOVERY_HEADER_LEN;
        for row in 0..kept_rows {
            let start = rows_start + row * row_len;
            cmra.extend_from_slice(&volume[start..start + row_len]);
        }

        let mut out = Vec::with_capacity(cmra_offset + cmra.len() + LOCATOR_PAIR_LEN);
        out.extend_from_slice(&volume[..cmra_offset]);
        out.extend_from_slice(&cmra);
        let mut mirror = locator;
        mirror.locator_sequence = 1;
        mirror.cmra_length = cmra.len() as u32;
        mirror.cmra_parity_shard_count = parity_shard_count;
        out.extend_from_slice(&mirror.to_bytes());
        let final_locator = CriticalRecoveryLocator {
            locator_sequence: 0,
            ..mirror
        };
        out.extend_from_slice(&final_locator.to_bytes());
        out
    }

    fn rewrite_public_cmra_image(
        volume: &mut [u8],
        mutate: impl FnOnce(&mut CriticalMetadataImage),
    ) {
        let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let locator = final_recovery_locator(volume);
        let tuple = CmraDecoderTuple::from(locator);
        let recovered = recover_cmra(
            volume,
            locator.cmra_offset,
            Some(tuple),
            CmraRecoveryMode::PublicNoKey,
        )
        .unwrap();
        let mut image = recovered.image;
        mutate(&mut image);
        refresh_critical_image_region_digests(&mut image);
        let image_bytes = image.to_bytes().unwrap();
        assert_eq!(image_bytes.len(), tuple.image_length as usize);

        let shard_size = tuple.shard_size as usize;
        let data_shard_count = tuple.data_shard_count as usize;
        let parity_shard_count = tuple.parity_shard_count as usize;
        assert!(image_bytes.len() <= data_shard_count * shard_size);

        let mut data_shards = Vec::with_capacity(data_shard_count);
        for idx in 0..data_shard_count {
            let start = idx * shard_size;
            let end = (start + shard_size).min(image_bytes.len());
            let mut payload = vec![0u8; shard_size];
            if start < image_bytes.len() {
                payload[..end - start].copy_from_slice(&image_bytes[start..end]);
            }
            data_shards.push(payload);
        }
        let parity_shards = encode_parity_gf16(&data_shards, parity_shard_count).unwrap();
        let image_sha256 = sha256_bytes(&image_bytes);

        let header = CriticalMetadataRecoveryHeader {
            shard_size: tuple.shard_size,
            data_shard_count: tuple.data_shard_count,
            parity_shard_count: tuple.parity_shard_count,
            image_length: tuple.image_length,
            archive_uuid_hint: locator.archive_uuid_hint,
            session_id_hint: locator.session_id_hint,
            volume_index_hint: locator.volume_index_hint,
            image_sha256,
            header_crc32c: 0,
        };
        let mut cmra = Vec::new();
        cmra.extend_from_slice(&header.to_bytes());
        for (idx, payload) in data_shards.into_iter().enumerate() {
            let payload_len = if idx + 1 == data_shard_count {
                image_bytes.len() - idx * shard_size
            } else {
                shard_size
            };
            cmra.extend_from_slice(
                &CriticalMetadataRecoveryShard {
                    shard_index: idx as u16,
                    shard_role: 0,
                    shard_payload_length: payload_len as u32,
                    payload,
                    shard_crc32c: 0,
                }
                .to_bytes(shard_size)
                .unwrap(),
            );
        }
        for (idx, payload) in parity_shards.into_iter().enumerate() {
            cmra.extend_from_slice(
                &CriticalMetadataRecoveryShard {
                    shard_index: (data_shard_count + idx) as u16,
                    shard_role: 1,
                    shard_payload_length: shard_size as u32,
                    payload,
                    shard_crc32c: 0,
                }
                .to_bytes(shard_size)
                .unwrap(),
            );
        }
        assert_eq!(cmra.len() as u64, recovered.cmra_length);
        let cmra_offset = locator.cmra_offset as usize;
        volume[cmra_offset..cmra_offset + cmra.len()].copy_from_slice(&cmra);

        rewrite_locator_image_sha(volume, final_offset, image_sha256);
        let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
        rewrite_locator_image_sha(volume, mirror_offset, image_sha256);
    }

    fn refresh_critical_image_region_digests(image: &mut CriticalMetadataImage) {
        image.volume_header_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 1)
                .unwrap()
                .bytes,
        );
        image.crypto_header_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 2)
                .unwrap()
                .bytes,
        );
        image.manifest_footer_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 3)
                .unwrap()
                .bytes,
        );
        image.root_auth_footer_sha256 = image
            .regions
            .iter()
            .find(|region| region.region_type == 4)
            .map(|region| sha256_bytes(&region.bytes))
            .unwrap_or([0u8; 32]);
        image.volume_trailer_sha256 = sha256_bytes(
            &image
                .regions
                .iter()
                .find(|region| region.region_type == 5)
                .unwrap()
                .bytes,
        );
    }

    fn rewrite_locator_image_sha(volume: &mut [u8], offset: usize, image_sha256: [u8; 32]) {
        let mut locator =
            CriticalRecoveryLocator::parse(&volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN])
                .unwrap();
        locator.cmra_image_sha256 = image_sha256;
        volume[offset..offset + CRITICAL_RECOVERY_LOCATOR_LEN].copy_from_slice(&locator.to_bytes());
    }

    fn corrupt_v41_terminal_recovery(volume: &mut [u8]) {
        let final_offset = volume.len() - CRITICAL_RECOVERY_LOCATOR_LEN;
        let final_locator = CriticalRecoveryLocator::parse(
            &volume[final_offset..final_offset + CRITICAL_RECOVERY_LOCATOR_LEN],
        )
        .unwrap();
        let mirror_offset = final_offset - CRITICAL_RECOVERY_LOCATOR_LEN;
        volume[final_locator.cmra_offset as usize] ^= 0x55;
        volume[mirror_offset] ^= 0x55;
        volume[final_offset] ^= 0x55;
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

    fn mutate_block_record_at_slot(
        volume: &mut [u8],
        slot: usize,
        mutate: impl FnOnce(&mut BlockRecord),
    ) {
        let (record_offset, record_len) = block_record_at_slot(volume, slot);
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
        block_record_at_slot(volume, 0)
    }

    fn block_record_at_slot(volume: &[u8], slot: usize) -> (usize, usize) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let record_offset = crypto_end + slot * record_len;
        assert!(volume.len() >= record_offset + record_len);
        (record_offset, record_len)
    }

    fn first_block_record_slot_with_kind(volume: &[u8], kind: BlockKind) -> Option<usize> {
        block_record_slots(volume)
            .into_iter()
            .enumerate()
            .find_map(|(slot, (_, _, record))| (record.kind == kind).then_some(slot))
    }

    fn block_record_slots_with_kind(volume: &[u8], kind: BlockKind) -> Vec<usize> {
        block_record_slots(volume)
            .into_iter()
            .enumerate()
            .filter_map(|(slot, (_, _, record))| (record.kind == kind).then_some(slot))
            .collect()
    }

    fn first_payload_data_run_slots(volume: &[u8]) -> Vec<usize> {
        let mut slots = Vec::new();
        for (slot, (_, _, record)) in block_record_slots(volume).into_iter().enumerate() {
            if record.kind == BlockKind::PayloadData {
                slots.push(slot);
            } else if !slots.is_empty() {
                break;
            }
        }
        slots
    }

    fn block_record_slots(volume: &[u8]) -> Vec<(usize, usize, BlockRecord)> {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let manifest_offset = terminal_material_offset(volume);
        assert_eq!((manifest_offset - crypto_end) % record_len, 0);
        let record_count = (manifest_offset - crypto_end) / record_len;
        (0..record_count)
            .map(|slot| {
                let offset = crypto_end + slot * record_len;
                let record = BlockRecord::parse(
                    &volume[offset..offset + record_len],
                    record_len - BLOCK_RECORD_FRAMING_LEN,
                )
                .unwrap();
                (offset, record_len, record)
            })
            .collect()
    }

    fn rewrite_manifest_footer(
        volume: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut ManifestFooter),
    ) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let offset = terminal_material_offset(volume);
        let mut footer =
            ManifestFooter::parse(&volume[offset..offset + MANIFEST_FOOTER_LEN]).unwrap();
        mutate(&mut footer);
        footer.manifest_hmac = [0u8; 32];
        let mut footer_bytes = footer.to_bytes();
        let subkeys = Subkeys::derive(
            master_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        footer.manifest_hmac = compute_hmac(
            HmacDomain::ManifestFooter,
            &subkeys.mac_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            &footer_bytes[..MANIFEST_HMAC_COVERED_LEN],
        );
        footer_bytes = footer.to_bytes();
        volume[offset..offset + MANIFEST_FOOTER_LEN].copy_from_slice(&footer_bytes);
    }

    fn rewrite_volume_trailer(
        volume: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut VolumeTrailer),
    ) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let offset = terminal_material_offset(volume) + MANIFEST_FOOTER_LEN;
        let mut trailer =
            VolumeTrailer::parse(&volume[offset..offset + VOLUME_TRAILER_LEN]).unwrap();
        mutate(&mut trailer);
        trailer.trailer_hmac = [0u8; 32];
        let mut trailer_bytes = trailer.to_bytes();
        let subkeys = Subkeys::derive(
            master_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
        )
        .unwrap();
        trailer.trailer_hmac = compute_hmac(
            HmacDomain::VolumeTrailer,
            &subkeys.mac_key,
            &volume_header.archive_uuid,
            &volume_header.session_id,
            &trailer_bytes[..TRAILER_HMAC_COVERED_LEN],
        );
        trailer_bytes = trailer.to_bytes();
        volume[offset..offset + VOLUME_TRAILER_LEN].copy_from_slice(&trailer_bytes);
    }

    fn rewrite_sidecar_header(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        mutate: impl FnOnce(&mut BootstrapSidecarHeader),
    ) {
        let mut header =
            BootstrapSidecarHeader::parse(&sidecar[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        mutate(&mut header);
        write_signed_sidecar_header(sidecar, master_key, &mut header);
    }

    fn write_signed_sidecar_header(
        sidecar: &mut [u8],
        master_key: &MasterKey,
        header: &mut BootstrapSidecarHeader,
    ) {
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

    fn sparse_bootstrap_sidecar(
        source: &[u8],
        master_key: &MasterKey,
        include_manifest: bool,
        include_index_root: bool,
        include_dictionary: bool,
    ) -> Vec<u8> {
        let source_header =
            BootstrapSidecarHeader::parse(&source[..BOOTSTRAP_SIDECAR_HEADER_LEN]).unwrap();
        let mut sidecar = vec![0u8; BOOTSTRAP_SIDECAR_HEADER_LEN];
        let mut header = BootstrapSidecarHeader {
            archive_uuid: source_header.archive_uuid,
            session_id: source_header.session_id,
            flags: 0,
            manifest_footer_offset: 0,
            manifest_footer_length: 0,
            index_root_records_offset: 0,
            index_root_records_length: 0,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0u8; 32],
            header_crc32c: 0,
        };

        if include_manifest {
            assert!(source_header.has_manifest_footer());
            let (offset, length) = append_sidecar_section(
                source,
                &mut sidecar,
                source_header.manifest_footer_offset,
                source_header.manifest_footer_length as u64,
            );
            header.flags |= 0x01;
            header.manifest_footer_offset = offset;
            header.manifest_footer_length = length as u32;
        }
        if include_index_root {
            assert!(source_header.has_index_root_records());
            let (offset, length) = append_sidecar_section(
                source,
                &mut sidecar,
                source_header.index_root_records_offset,
                source_header.index_root_records_length,
            );
            header.flags |= 0x02;
            header.index_root_records_offset = offset;
            header.index_root_records_length = length;
        }
        if include_dictionary {
            assert!(source_header.has_dictionary_records());
            let (offset, length) = append_sidecar_section(
                source,
                &mut sidecar,
                source_header.dictionary_records_offset,
                source_header.dictionary_records_length,
            );
            header.flags |= 0x04;
            header.dictionary_records_offset = offset;
            header.dictionary_records_length = length;
        }

        write_signed_sidecar_header(&mut sidecar, master_key, &mut header);
        sidecar
    }

    fn append_sidecar_section(
        source: &[u8],
        sidecar: &mut Vec<u8>,
        source_offset: u64,
        length: u64,
    ) -> (u64, u64) {
        let source_offset = source_offset as usize;
        let length = length as usize;
        let offset = sidecar.len() as u64;
        sidecar.extend_from_slice(&source[source_offset..source_offset + length]);
        (offset, length as u64)
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

    fn corrupt_object_extent_records(volume: &mut [u8], extent: ObjectExtent) {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        assert_eq!(volume_header.volume_index, 0);
        assert_eq!(volume_header.stripe_width, 1);
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let record_len = crypto_header.fixed.block_size as usize + BLOCK_RECORD_FRAMING_LEN;
        let record_count = extent.data_block_count as u64 + extent.parity_block_count as u64;
        for offset in 0..record_count {
            let block_index = extent.first_block_index + offset;
            let record_offset = crypto_end + block_index as usize * record_len;
            volume[record_offset + 16] ^= 0x55;
        }
    }

    fn terminal_material_offset(volume: &[u8]) -> usize {
        let volume_header = VolumeHeader::parse(&volume[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &volume[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let (_, offset, _) = parse_stream_block_prefix(
            volume,
            crypto_end,
            crypto_header.fixed.block_size as usize,
            &volume_header,
        )
        .unwrap();
        offset
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
            crypto_header_bytes: Vec::new(),
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
            volume_trailer: Some(VolumeTrailer {
                archive_uuid,
                session_id,
                volume_index: 0,
                block_count: next_block_index,
                bytes_written: 0,
                manifest_footer_offset: 0,
                manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
                closed_at_ns: 0,
                root_auth_footer_offset: 0,
                root_auth_footer_length: 0,
                root_auth_flags: 0,
                trailer_hmac: [0u8; 32],
            }),
            root_auth_footer: None,
            index_root,
            payload_dictionary: None,
        };
        (opened, broken_payload_block)
    }

    fn replace_first_index_shard(opened: &mut OpenedArchive, mutate: impl FnOnce(&mut IndexShard)) {
        let locating = opened.index_root.shards[0].clone();
        let mut shard = opened.load_index_shard(&locating).unwrap();
        mutate(&mut shard);
        let plaintext = shard.to_bytes();
        let mut next_block_index = opened
            .blocks
            .keys()
            .last()
            .copied()
            .map(|index| index + 1)
            .unwrap_or(0);
        let replacement = encrypt_test_object(
            &compress_zstd_frame(&plaintext, 1).unwrap(),
            &opened.subkeys.index_shard_key,
            &opened.subkeys.index_nonce_seed,
            b"idxshard",
            locating.shard_index,
            BlockKind::IndexShardData,
            &mut next_block_index,
            &opened.crypto_header,
            &opened.volume_header,
        );
        insert_records(&mut opened.blocks, &replacement.records);
        opened.index_root.shards[0] = ShardEntry {
            shard_index: locating.shard_index,
            first_block_index: replacement.extent.first_block_index,
            data_block_count: replacement.extent.data_block_count,
            parity_block_count: 0,
            encrypted_size: replacement.extent.encrypted_size,
            decompressed_size: plaintext.len() as u32,
            file_count: shard.files.len() as u32,
            first_path_hash: shard.files.first().unwrap().path_hash,
            last_path_hash: shard.files.last().unwrap().path_hash,
        };
    }

    fn rewrite_as_single_healthy_file(
        opened: &mut OpenedArchive,
        mutate: impl FnOnce(&mut FileEntry, &mut Vec<u8>),
    ) {
        let healthy_path = b"healthy.txt";
        let healthy_payload = b"healthy payload\n";
        let healthy_member = test_member(healthy_path, healthy_payload);
        replace_first_index_shard(opened, |shard| {
            let file_index = (0..shard.files.len())
                .find(|idx| shard.file_path(*idx) == Some(healthy_path.as_slice()))
                .unwrap();
            let mut file = shard.files[file_index].clone();
            let frame = shard
                .frames
                .iter()
                .find(|entry| entry.frame_index == 0)
                .unwrap()
                .clone();
            let envelope = shard
                .envelopes
                .iter()
                .find(|entry| entry.envelope_index == 0)
                .unwrap()
                .clone();
            let mut path = healthy_path.to_vec();

            file.path_offset = 0;
            file.path_length = path.len() as u32;
            file.first_frame_index = 0;
            file.frame_count = 1;
            file.offset_in_first_frame_plaintext = 0;
            file.tar_member_group_size = healthy_member.len() as u64;
            file.file_data_size = healthy_payload.len() as u64;
            file.flags = 0;
            mutate(&mut file, &mut path);
            file.path_offset = 0;
            file.path_length = path.len() as u32;
            file.path_hash = hash_prefix(&path);

            shard.files = vec![file];
            shard.frames = vec![frame];
            shard.envelopes = vec![envelope];
            shard.string_pool = path;
        });

        opened.index_root.header.file_count = 1;
        opened.index_root.header.frame_count = 1;
        opened.index_root.header.envelope_count = 1;
        opened.index_root.header.payload_block_count = 1;
        opened.index_root.header.tar_total_size = healthy_member.len() as u64;
        opened.index_root.header.content_sha256 = sha256_bytes(&healthy_member);
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

    fn build_metadata_object_from_payload(
        payload: &[u8],
        _subkeys: &Subkeys,
        volume_header: &VolumeHeader,
        crypto_header: &CryptoHeaderFixed,
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        next_block_index: &mut u64,
    ) -> (ObjectExtent, BTreeMap<u64, BlockRecord>) {
        let compressed = compress_zstd_frame(payload, 1).unwrap();
        build_metadata_object_from_compressed(
            &compressed,
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            next_block_index,
            crypto_header,
            volume_header,
        )
    }

    fn build_metadata_object_from_compressed(
        compressed: &[u8],
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        next_block_index: &mut u64,
        crypto_header: &CryptoHeaderFixed,
        volume_header: &VolumeHeader,
    ) -> (ObjectExtent, BTreeMap<u64, BlockRecord>) {
        let object = encrypt_test_object(
            compressed,
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            next_block_index,
            crypto_header,
            volume_header,
        );

        let mut blocks = BTreeMap::new();
        for record in object.records {
            blocks.insert(record.block_index, record);
        }
        (object.extent, blocks)
    }

    fn assert_metadata_object_from_compressed(
        compressed: &[u8],
        decompressed_size: usize,
        subkeys: &Subkeys,
        volume_header: &VolumeHeader,
        crypto_header: &CryptoHeaderFixed,
        key: &[u8; 32],
        nonce_seed: &[u8; 32],
        domain: &[u8],
        counter: u64,
        data_kind: BlockKind,
        parity_kind: BlockKind,
        class_data_shards: u16,
        class_parity_shards: u16,
        next_block_index: &mut u64,
        expected: FormatError,
    ) {
        let (extent, blocks) = build_metadata_object_from_compressed(
            compressed,
            key,
            nonce_seed,
            domain,
            counter,
            data_kind,
            next_block_index,
            crypto_header,
            volume_header,
        );
        let error = load_metadata_object_from_parts(
            &blocks,
            subkeys,
            volume_header,
            crypto_header,
            extent,
            data_kind,
            parity_kind,
            key,
            nonce_seed,
            domain,
            counter,
            class_data_shards,
            class_parity_shards,
            decompressed_size as u32,
        )
        .unwrap_err();
        assert_eq!(error, expected);
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
