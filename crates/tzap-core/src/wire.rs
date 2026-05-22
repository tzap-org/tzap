use crc32c::crc32c;

use crate::crypto::KdfParams;
use crate::format::{
    AeadAlgo, BlockKind, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, BLOCK_RECORD_FRAMING_LEN,
    BOOTSTRAP_SIDECAR_HEADER_LEN, CRYPTO_EXTENSION_HEADER_LEN, CRYPTO_EXTENSION_MAX_VALUE_LEN,
    CRYPTO_HEADER_FIXED_LEN, CRYPTO_HEADER_HMAC_LEN, FORMAT_VERSION, MANIFEST_FOOTER_LEN,
    READER_MAX_BLOCK_SIZE, READER_MAX_CHUNK_SIZE, READER_MAX_CRYPTO_HEADER_LEN,
    READER_MAX_ENVELOPE_TARGET_SIZE, READER_MAX_FEC_CLASS_SHARDS,
    READER_MAX_INDEX_FEC_CLASS_SHARDS, READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS,
    READER_MAX_PATH_LENGTH, READER_MAX_STRIPE_WIDTH, VOLUME_FORMAT_REV, VOLUME_HEADER_LEN,
    VOLUME_TRAILER_LEN,
};

const TZAP_MAGIC: [u8; 4] = *b"TZAP";
const TZCH_MAGIC: [u8; 4] = *b"TZCH";
const TZBK_MAGIC: [u8; 4] = *b"TZBK";
const TZMF_MAGIC: [u8; 4] = *b"TZMF";
const TZVT_MAGIC: [u8; 4] = *b"TZVT";
const TZBS_MAGIC: [u8; 4] = *b"TZBS";

const BLOCK_LAST_DATA_FLAG: u8 = 0x01;
const BLOCK_RESERVED_FLAGS: u8 = !BLOCK_LAST_DATA_FLAG;

const SIDECAR_MANIFEST_PRESENT: u32 = 0x01;
const SIDECAR_INDEX_ROOT_PRESENT: u32 = 0x02;
const SIDECAR_DICTIONARY_PRESENT: u32 = 0x04;
const SIDECAR_KNOWN_FLAGS: u32 =
    SIDECAR_MANIFEST_PRESENT | SIDECAR_INDEX_ROOT_PRESENT | SIDECAR_DICTIONARY_PRESENT;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHeader {
    pub format_version: u16,
    pub volume_format_rev: u16,
    pub volume_index: u32,
    pub stripe_width: u32,
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub crypto_header_offset: u32,
    pub crypto_header_length: u32,
    pub header_crc32c: u32,
}

impl VolumeHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("VolumeHeader", VOLUME_HEADER_LEN, bytes.len())?;
        expect_magic("VolumeHeader", TZAP_MAGIC, &bytes[0..4])?;
        expect_crc("VolumeHeader", &bytes[..124], read_u32(bytes, 124)?)?;
        expect_zero("VolumeHeader", &bytes[56..124])?;

        let header = Self {
            format_version: read_u16(bytes, 4)?,
            volume_format_rev: read_u16(bytes, 6)?,
            volume_index: read_u32(bytes, 8)?,
            stripe_width: read_u32(bytes, 12)?,
            archive_uuid: read_array_16(bytes, 16)?,
            session_id: read_array_16(bytes, 32)?,
            crypto_header_offset: read_u32(bytes, 48)?,
            crypto_header_length: read_u32(bytes, 52)?,
            header_crc32c: read_u32(bytes, 124)?,
        };
        header.validate()?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<(), FormatError> {
        if self.format_version != FORMAT_VERSION {
            return Err(FormatError::UnsupportedFormatVersion(self.format_version));
        }
        if self.volume_format_rev != VOLUME_FORMAT_REV {
            return Err(FormatError::UnsupportedVolumeFormatRevision(
                self.volume_format_rev,
            ));
        }
        if self.stripe_width == 0 {
            return Err(FormatError::ZeroStripeWidth);
        }
        if self.volume_index >= self.stripe_width {
            return Err(FormatError::VolumeIndexOutOfRange {
                volume_index: self.volume_index,
                stripe_width: self.stripe_width,
            });
        }
        if self.crypto_header_offset != VOLUME_HEADER_LEN as u32 {
            return Err(FormatError::NonCanonicalCryptoHeaderOffset(
                self.crypto_header_offset,
            ));
        }
        if self.crypto_header_length > READER_MAX_CRYPTO_HEADER_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: self.crypto_header_length as u64,
            });
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; VOLUME_HEADER_LEN] {
        let mut bytes = [0u8; VOLUME_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZAP_MAGIC);
        write_u16(&mut bytes, 4, self.format_version);
        write_u16(&mut bytes, 6, self.volume_format_rev);
        write_u32(&mut bytes, 8, self.volume_index);
        write_u32(&mut bytes, 12, self.stripe_width);
        bytes[16..32].copy_from_slice(&self.archive_uuid);
        bytes[32..48].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 48, self.crypto_header_offset);
        write_u32(&mut bytes, 52, self.crypto_header_length);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoHeaderFixed {
    pub length: u32,
    pub compression_algo: CompressionAlgo,
    pub aead_algo: AeadAlgo,
    pub fec_algo: FecAlgo,
    pub kdf_algo: KdfAlgo,
    pub chunk_size: u32,
    pub envelope_target_size: u32,
    pub block_size: u32,
    pub fec_data_shards: u16,
    pub fec_parity_shards: u16,
    pub index_fec_data_shards: u16,
    pub index_fec_parity_shards: u16,
    pub index_root_fec_data_shards: u16,
    pub index_root_fec_parity_shards: u16,
    pub stripe_width: u32,
    pub volume_loss_tolerance: u8,
    pub bit_rot_buffer_pct: u8,
    pub has_dictionary: u8,
    pub max_path_length: u32,
    pub expected_volume_size: u64,
}

impl CryptoHeaderFixed {
    pub fn parse(bytes: &[u8], volume_crypto_header_length: u32) -> Result<Self, FormatError> {
        expect_len("CryptoHeaderFixed", CRYPTO_HEADER_FIXED_LEN, bytes.len())?;
        expect_magic("CryptoHeaderFixed", TZCH_MAGIC, &bytes[0..4])?;
        expect_zero("CryptoHeaderFixed", &bytes[59..60])?;
        expect_zero("CryptoHeaderFixed", &bytes[60..76])?;

        let length = read_u32(bytes, 4)?;
        if length != volume_crypto_header_length {
            return Err(FormatError::CryptoHeaderLengthMismatch {
                fixed: length,
                volume: volume_crypto_header_length,
            });
        }
        if length > READER_MAX_CRYPTO_HEADER_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: length as u64,
            });
        }

        let header = Self {
            length,
            compression_algo: CompressionAlgo::try_from(read_u16(bytes, 8)?)?,
            aead_algo: AeadAlgo::try_from(read_u16(bytes, 10)?)?,
            fec_algo: FecAlgo::try_from(read_u16(bytes, 12)?)?,
            kdf_algo: KdfAlgo::try_from(read_u16(bytes, 14)?)?,
            chunk_size: read_u32(bytes, 16)?,
            envelope_target_size: read_u32(bytes, 20)?,
            block_size: read_u32(bytes, 24)?,
            fec_data_shards: read_u16(bytes, 28)?,
            fec_parity_shards: read_u16(bytes, 30)?,
            index_fec_data_shards: read_u16(bytes, 32)?,
            index_fec_parity_shards: read_u16(bytes, 34)?,
            index_root_fec_data_shards: read_u16(bytes, 36)?,
            index_root_fec_parity_shards: read_u16(bytes, 38)?,
            stripe_width: read_u32(bytes, 40)?,
            volume_loss_tolerance: bytes[44],
            bit_rot_buffer_pct: bytes[45],
            has_dictionary: bytes[46],
            max_path_length: read_u32(bytes, 48)?,
            expected_volume_size: read_u64(bytes, 52)?,
        };
        header.validate_v36()?;
        Ok(header)
    }

    pub fn validate_v36(&self) -> Result<(), FormatError> {
        if self.compression_algo != CompressionAlgo::ZstdFramed {
            return Err(FormatError::UnsupportedCompressionForV36(
                self.compression_algo,
            ));
        }
        if self.fec_algo != FecAlgo::ReedSolomonGF16 {
            return Err(FormatError::UnsupportedFecForV36(self.fec_algo));
        }
        if self.has_dictionary > 1 {
            return Err(FormatError::InvalidBoolean {
                field: "has_dictionary",
                value: self.has_dictionary,
            });
        }
        if self.stripe_width == 0 {
            return Err(FormatError::ZeroStripeWidth);
        }
        if self.stripe_width > READER_MAX_STRIPE_WIDTH {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "stripe_width",
                cap: READER_MAX_STRIPE_WIDTH as u64,
                actual: self.stripe_width as u64,
            });
        }
        if self.volume_loss_tolerance as u32 >= self.stripe_width {
            return Err(FormatError::VolumeLossToleranceOutOfRange {
                volume_loss_tolerance: self.volume_loss_tolerance,
                stripe_width: self.stripe_width,
            });
        }
        if self.bit_rot_buffer_pct > 100 {
            return Err(FormatError::BitRotBufferPctTooLarge(
                self.bit_rot_buffer_pct,
            ));
        }
        if self.fec_data_shards == 0 {
            return Err(FormatError::ZeroDataShardMaximum {
                field: "fec_data_shards",
            });
        }
        if self.index_fec_data_shards == 0 {
            return Err(FormatError::ZeroDataShardMaximum {
                field: "index_fec_data_shards",
            });
        }
        if self.index_root_fec_data_shards == 0 {
            return Err(FormatError::ZeroDataShardMaximum {
                field: "index_root_fec_data_shards",
            });
        }
        validate_fec_class_shards(
            "fec_data_shards + fec_parity_shards",
            self.fec_data_shards,
            self.fec_parity_shards,
            READER_MAX_FEC_CLASS_SHARDS,
        )?;
        validate_fec_class_shards(
            "index_fec_data_shards + index_fec_parity_shards",
            self.index_fec_data_shards,
            self.index_fec_parity_shards,
            READER_MAX_INDEX_FEC_CLASS_SHARDS,
        )?;
        validate_fec_class_shards(
            "index_root_fec_data_shards + index_root_fec_parity_shards",
            self.index_root_fec_data_shards,
            self.index_root_fec_parity_shards,
            READER_MAX_INDEX_ROOT_FEC_CLASS_SHARDS,
        )?;
        if self.chunk_size == 0 {
            return Err(FormatError::ZeroChunkSize);
        }
        if self.envelope_target_size == 0 {
            return Err(FormatError::ZeroEnvelopeTargetSize);
        }
        if self.chunk_size > self.envelope_target_size {
            return Err(FormatError::ChunkSizeExceedsEnvelopeTarget {
                chunk_size: self.chunk_size,
                envelope_target_size: self.envelope_target_size,
            });
        }
        if self.chunk_size > READER_MAX_CHUNK_SIZE {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "chunk_size",
                cap: READER_MAX_CHUNK_SIZE as u64,
                actual: self.chunk_size as u64,
            });
        }
        if self.envelope_target_size > READER_MAX_ENVELOPE_TARGET_SIZE {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "envelope_target_size",
                cap: READER_MAX_ENVELOPE_TARGET_SIZE as u64,
                actual: self.envelope_target_size as u64,
            });
        }
        if self.block_size < 4096 {
            return Err(FormatError::BlockSizeTooSmall(self.block_size));
        }
        if self.block_size % 2 != 0 {
            return Err(FormatError::OddBlockSize(self.block_size));
        }
        if self.block_size > READER_MAX_BLOCK_SIZE {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "block_size",
                cap: READER_MAX_BLOCK_SIZE as u64,
                actual: self.block_size as u64,
            });
        }
        if self.max_path_length > READER_MAX_PATH_LENGTH {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "max_path_length",
                cap: READER_MAX_PATH_LENGTH as u64,
                actual: self.max_path_length as u64,
            });
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; CRYPTO_HEADER_FIXED_LEN] {
        let mut bytes = [0u8; CRYPTO_HEADER_FIXED_LEN];
        bytes[0..4].copy_from_slice(&TZCH_MAGIC);
        write_u32(&mut bytes, 4, self.length);
        write_u16(&mut bytes, 8, self.compression_algo as u16);
        write_u16(&mut bytes, 10, self.aead_algo as u16);
        write_u16(&mut bytes, 12, self.fec_algo as u16);
        write_u16(&mut bytes, 14, self.kdf_algo as u16);
        write_u32(&mut bytes, 16, self.chunk_size);
        write_u32(&mut bytes, 20, self.envelope_target_size);
        write_u32(&mut bytes, 24, self.block_size);
        write_u16(&mut bytes, 28, self.fec_data_shards);
        write_u16(&mut bytes, 30, self.fec_parity_shards);
        write_u16(&mut bytes, 32, self.index_fec_data_shards);
        write_u16(&mut bytes, 34, self.index_fec_parity_shards);
        write_u16(&mut bytes, 36, self.index_root_fec_data_shards);
        write_u16(&mut bytes, 38, self.index_root_fec_parity_shards);
        write_u32(&mut bytes, 40, self.stripe_width);
        bytes[44] = self.volume_loss_tolerance;
        bytes[45] = self.bit_rot_buffer_pct;
        bytes[46] = self.has_dictionary;
        write_u32(&mut bytes, 48, self.max_path_length);
        write_u64(&mut bytes, 52, self.expected_volume_size);
        bytes
    }
}

fn validate_fec_class_shards(
    field: &'static str,
    data_shards: u16,
    parity_shards: u16,
    cap: u32,
) -> Result<(), FormatError> {
    let total = data_shards as u32 + parity_shards as u32;
    if total > cap {
        return Err(FormatError::ReaderResourceLimitExceeded {
            field,
            cap: cap as u64,
            actual: total as u64,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionTlv<'a> {
    pub tag: u16,
    pub value: &'a [u8],
}

pub fn scan_crypto_extension_tlvs(bytes: &[u8]) -> Result<Vec<ExtensionTlv<'_>>, FormatError> {
    let mut offset = 0usize;
    let mut extensions = Vec::new();
    loop {
        if offset == bytes.len() {
            return Err(FormatError::MissingExtensionTerminator);
        }
        if bytes.len() - offset < CRYPTO_EXTENSION_HEADER_LEN {
            return Err(FormatError::TruncatedExtensionHeader);
        }
        let tag = read_u16(bytes, offset)?;
        let length = read_u32(bytes, offset + 2)?;
        offset += CRYPTO_EXTENSION_HEADER_LEN;
        if tag == 0 {
            if length != 0 {
                return Err(FormatError::MalformedExtensionTerminator);
            }
            if offset != bytes.len() {
                return Err(FormatError::BytesAfterExtensionTerminator);
            }
            return Ok(extensions);
        }
        if length > CRYPTO_EXTENSION_MAX_VALUE_LEN {
            return Err(FormatError::ExtensionPayloadTooLarge(length));
        }
        let length = length as usize;
        if bytes.len() - offset < length {
            return Err(FormatError::TruncatedExtensionPayload);
        }
        extensions.push(ExtensionTlv {
            tag,
            value: &bytes[offset..offset + length],
        });
        offset += length;
    }
}

pub fn validate_crypto_extension_semantics(
    extensions: &[ExtensionTlv<'_>],
) -> Result<(), FormatError> {
    let mut seen_known = Vec::new();
    for extension in extensions {
        let ext_tag = extension.tag & 0x7fff;
        let is_critical = extension.tag & 0x8000 != 0;
        if matches!(ext_tag, 0x0004 | 0x0006) {
            return Err(FormatError::ForbiddenExtensionTag(ext_tag));
        }
        if is_known_extension(ext_tag) {
            if seen_known.contains(&ext_tag) {
                return Err(FormatError::DuplicateKnownExtension(ext_tag));
            }
            validate_known_extension(ext_tag, extension.value)?;
            seen_known.push(ext_tag);
        } else if is_critical {
            return Err(FormatError::UnknownCriticalExtension(ext_tag));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoHeader<'a> {
    pub fixed: CryptoHeaderFixed,
    pub kdf_params: KdfParams,
    pub extensions: Vec<ExtensionTlv<'a>>,
    pub header_hmac: [u8; 32],
    pub hmac_covered_bytes: &'a [u8],
}

impl<'a> CryptoHeader<'a> {
    pub fn parse(bytes: &'a [u8], volume_crypto_header_length: u32) -> Result<Self, FormatError> {
        let declared_len = volume_crypto_header_length as usize;
        if volume_crypto_header_length > READER_MAX_CRYPTO_HEADER_LEN {
            return Err(FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: volume_crypto_header_length as u64,
            });
        }
        if bytes.len() != declared_len {
            return Err(FormatError::InvalidLength {
                structure: "CryptoHeader",
                expected: declared_len,
                actual: bytes.len(),
            });
        }
        let min_len =
            CRYPTO_HEADER_FIXED_LEN + 2 + CRYPTO_EXTENSION_HEADER_LEN + CRYPTO_HEADER_HMAC_LEN;
        if bytes.len() < min_len {
            return Err(FormatError::CryptoHeaderTooShort {
                min: min_len,
                actual: bytes.len(),
            });
        }

        let fixed = CryptoHeaderFixed::parse(
            &bytes[..CRYPTO_HEADER_FIXED_LEN],
            volume_crypto_header_length,
        )?;
        let hmac_offset = bytes.len() - CRYPTO_HEADER_HMAC_LEN;
        let (kdf_params, kdf_len) =
            KdfParams::parse(fixed.kdf_algo, &bytes[CRYPTO_HEADER_FIXED_LEN..hmac_offset])?;
        let extension_bytes = &bytes[CRYPTO_HEADER_FIXED_LEN + kdf_len..hmac_offset];
        let extensions = scan_crypto_extension_tlvs(extension_bytes)?;
        let header_hmac = read_array_32(bytes, hmac_offset)?;

        Ok(Self {
            fixed,
            kdf_params,
            extensions,
            header_hmac,
            hmac_covered_bytes: &bytes[..hmac_offset],
        })
    }

    pub fn validate_extension_semantics(&self) -> Result<(), FormatError> {
        validate_crypto_extension_semantics(&self.extensions)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRecord {
    pub block_index: u64,
    pub kind: BlockKind,
    pub flags: u8,
    pub payload: Vec<u8>,
    pub record_crc32c: u32,
}

impl BlockRecord {
    pub fn parse(bytes: &[u8], block_size: usize) -> Result<Self, FormatError> {
        let expected = block_size + BLOCK_RECORD_FRAMING_LEN;
        expect_len("BlockRecord", expected, bytes.len())?;
        expect_magic("BlockRecord", TZBK_MAGIC, &bytes[0..4])?;
        expect_zero("BlockRecord", &bytes[14..16])?;
        expect_crc(
            "BlockRecord",
            &bytes[..16 + block_size],
            read_u32(bytes, 16 + block_size)?,
        )?;

        let kind = BlockKind::try_from(bytes[12])?;
        let flags = bytes[13];
        if flags & BLOCK_RESERVED_FLAGS != 0 {
            return Err(FormatError::InvalidBlockFlags(flags));
        }
        if kind.is_parity() && flags & BLOCK_LAST_DATA_FLAG != 0 {
            return Err(FormatError::ParityBlockHasLastDataFlag);
        }

        Ok(Self {
            block_index: read_u64(bytes, 4)?,
            kind,
            flags,
            payload: bytes[16..16 + block_size].to_vec(),
            record_crc32c: read_u32(bytes, 16 + block_size)?,
        })
    }

    pub fn is_last_data(&self) -> bool {
        self.flags & BLOCK_LAST_DATA_FLAG != 0
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; self.payload.len() + BLOCK_RECORD_FRAMING_LEN];
        bytes[0..4].copy_from_slice(&TZBK_MAGIC);
        write_u64(&mut bytes, 4, self.block_index);
        bytes[12] = self.kind as u8;
        bytes[13] = self.flags;
        bytes[16..16 + self.payload.len()].copy_from_slice(&self.payload);
        let crc = crc32c(&bytes[..16 + self.payload.len()]);
        let crc_offset = 16 + self.payload.len();
        write_u32(&mut bytes, crc_offset, crc);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFooter {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
    pub is_authoritative: u8,
    pub total_volumes: u32,
    pub index_root_first_block: u64,
    pub index_root_data_block_count: u32,
    pub index_root_parity_block_count: u32,
    pub index_root_encrypted_size: u32,
    pub index_root_decompressed_size: u32,
    pub manifest_hmac: [u8; 32],
}

impl ManifestFooter {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("ManifestFooter", MANIFEST_FOOTER_LEN, bytes.len())?;
        expect_magic("ManifestFooter", TZMF_MAGIC, &bytes[0..4])?;
        expect_zero("ManifestFooter", &bytes[41..44])?;
        expect_zero("ManifestFooter", &bytes[72..104])?;
        let is_authoritative = bytes[40];
        if is_authoritative > 1 {
            return Err(FormatError::InvalidAuthoritativeFlag(is_authoritative));
        }

        Ok(Self {
            archive_uuid: read_array_16(bytes, 4)?,
            session_id: read_array_16(bytes, 20)?,
            volume_index: read_u32(bytes, 36)?,
            is_authoritative,
            total_volumes: read_u32(bytes, 44)?,
            index_root_first_block: read_u64(bytes, 48)?,
            index_root_data_block_count: read_u32(bytes, 56)?,
            index_root_parity_block_count: read_u32(bytes, 60)?,
            index_root_encrypted_size: read_u32(bytes, 64)?,
            index_root_decompressed_size: read_u32(bytes, 68)?,
            manifest_hmac: read_array_32(bytes, 104)?,
        })
    }

    pub fn validate_index_root_extent(&self, block_size: u32) -> Result<(), FormatError> {
        if self.index_root_data_block_count == 0 || self.index_root_encrypted_size == 0 {
            return Err(FormatError::EmptyIndexRootExtent);
        }
        let expected = self
            .index_root_data_block_count
            .checked_mul(block_size)
            .ok_or(FormatError::IndexRootSizeMismatch)?;
        if expected != self.index_root_encrypted_size {
            return Err(FormatError::IndexRootSizeMismatch);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> [u8; MANIFEST_FOOTER_LEN] {
        let mut bytes = [0u8; MANIFEST_FOOTER_LEN];
        bytes[0..4].copy_from_slice(&TZMF_MAGIC);
        bytes[4..20].copy_from_slice(&self.archive_uuid);
        bytes[20..36].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 36, self.volume_index);
        bytes[40] = self.is_authoritative;
        write_u32(&mut bytes, 44, self.total_volumes);
        write_u64(&mut bytes, 48, self.index_root_first_block);
        write_u32(&mut bytes, 56, self.index_root_data_block_count);
        write_u32(&mut bytes, 60, self.index_root_parity_block_count);
        write_u32(&mut bytes, 64, self.index_root_encrypted_size);
        write_u32(&mut bytes, 68, self.index_root_decompressed_size);
        bytes[104..136].copy_from_slice(&self.manifest_hmac);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeTrailer {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub volume_index: u32,
    pub block_count: u64,
    pub bytes_written: u64,
    pub manifest_footer_offset: u64,
    pub manifest_footer_length: u32,
    pub closed_at_ns: i64,
    pub trailer_hmac: [u8; 32],
}

impl VolumeTrailer {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len("VolumeTrailer", VOLUME_TRAILER_LEN, bytes.len())?;
        expect_magic("VolumeTrailer", TZVT_MAGIC, &bytes[0..4])?;
        expect_zero("VolumeTrailer", &bytes[76..96])?;
        let manifest_footer_length = read_u32(bytes, 64)?;
        if manifest_footer_length != MANIFEST_FOOTER_LEN as u32 {
            return Err(FormatError::InvalidManifestFooterLength(
                manifest_footer_length,
            ));
        }

        Ok(Self {
            archive_uuid: read_array_16(bytes, 4)?,
            session_id: read_array_16(bytes, 20)?,
            volume_index: read_u32(bytes, 36)?,
            block_count: read_u64(bytes, 40)?,
            bytes_written: read_u64(bytes, 48)?,
            manifest_footer_offset: read_u64(bytes, 56)?,
            manifest_footer_length,
            closed_at_ns: read_i64(bytes, 68)?,
            trailer_hmac: read_array_32(bytes, 96)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; VOLUME_TRAILER_LEN] {
        let mut bytes = [0u8; VOLUME_TRAILER_LEN];
        bytes[0..4].copy_from_slice(&TZVT_MAGIC);
        bytes[4..20].copy_from_slice(&self.archive_uuid);
        bytes[20..36].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 36, self.volume_index);
        write_u64(&mut bytes, 40, self.block_count);
        write_u64(&mut bytes, 48, self.bytes_written);
        write_u64(&mut bytes, 56, self.manifest_footer_offset);
        write_u32(&mut bytes, 64, self.manifest_footer_length);
        write_i64(&mut bytes, 68, self.closed_at_ns);
        bytes[96..128].copy_from_slice(&self.trailer_hmac);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapSidecarHeader {
    pub archive_uuid: [u8; 16],
    pub session_id: [u8; 16],
    pub flags: u32,
    pub manifest_footer_offset: u64,
    pub manifest_footer_length: u32,
    pub index_root_records_offset: u64,
    pub index_root_records_length: u64,
    pub dictionary_records_offset: u64,
    pub dictionary_records_length: u64,
    pub sidecar_hmac: [u8; 32],
    pub header_crc32c: u32,
}

impl BootstrapSidecarHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        expect_len(
            "BootstrapSidecarHeader",
            BOOTSTRAP_SIDECAR_HEADER_LEN,
            bytes.len(),
        )?;
        expect_magic("BootstrapSidecarHeader", TZBS_MAGIC, &bytes[0..4])?;
        let version = read_u32(bytes, 4)?;
        if version != 1 {
            return Err(FormatError::UnsupportedBootstrapSidecarVersion(version));
        }
        expect_zero("BootstrapSidecarHeader", &bytes[88..92])?;
        expect_crc(
            "BootstrapSidecarHeader",
            &bytes[..124],
            read_u32(bytes, 124)?,
        )?;

        let header = Self {
            archive_uuid: read_array_16(bytes, 8)?,
            session_id: read_array_16(bytes, 24)?,
            flags: read_u32(bytes, 40)?,
            manifest_footer_offset: read_u64(bytes, 44)?,
            manifest_footer_length: read_u32(bytes, 52)?,
            index_root_records_offset: read_u64(bytes, 56)?,
            index_root_records_length: read_u64(bytes, 64)?,
            dictionary_records_offset: read_u64(bytes, 72)?,
            dictionary_records_length: read_u64(bytes, 80)?,
            sidecar_hmac: read_array_32(bytes, 92)?,
            header_crc32c: read_u32(bytes, 124)?,
        };
        header.validate_sections()?;
        Ok(header)
    }

    pub fn validate_packed_layout(&self, file_size: u64) -> Result<(), FormatError> {
        let mut cursor = BOOTSTRAP_SIDECAR_HEADER_LEN as u64;
        cursor = self.validate_section_cursor(
            self.has_manifest_footer(),
            self.manifest_footer_offset,
            self.manifest_footer_length as u64,
            cursor,
        )?;
        cursor = self.validate_section_cursor(
            self.has_index_root_records(),
            self.index_root_records_offset,
            self.index_root_records_length,
            cursor,
        )?;
        cursor = self.validate_section_cursor(
            self.has_dictionary_records(),
            self.dictionary_records_offset,
            self.dictionary_records_length,
            cursor,
        )?;
        if cursor != file_size {
            return Err(FormatError::NonCanonicalBootstrapSidecarLayout);
        }
        Ok(())
    }

    pub fn has_manifest_footer(&self) -> bool {
        self.flags & SIDECAR_MANIFEST_PRESENT != 0
    }

    pub fn has_index_root_records(&self) -> bool {
        self.flags & SIDECAR_INDEX_ROOT_PRESENT != 0
    }

    pub fn has_dictionary_records(&self) -> bool {
        self.flags & SIDECAR_DICTIONARY_PRESENT != 0
    }

    pub fn to_bytes(&self) -> [u8; BOOTSTRAP_SIDECAR_HEADER_LEN] {
        let mut bytes = [0u8; BOOTSTRAP_SIDECAR_HEADER_LEN];
        bytes[0..4].copy_from_slice(&TZBS_MAGIC);
        write_u32(&mut bytes, 4, 1);
        bytes[8..24].copy_from_slice(&self.archive_uuid);
        bytes[24..40].copy_from_slice(&self.session_id);
        write_u32(&mut bytes, 40, self.flags);
        write_u64(&mut bytes, 44, self.manifest_footer_offset);
        write_u32(&mut bytes, 52, self.manifest_footer_length);
        write_u64(&mut bytes, 56, self.index_root_records_offset);
        write_u64(&mut bytes, 64, self.index_root_records_length);
        write_u64(&mut bytes, 72, self.dictionary_records_offset);
        write_u64(&mut bytes, 80, self.dictionary_records_length);
        bytes[92..124].copy_from_slice(&self.sidecar_hmac);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        bytes
    }

    fn validate_sections(&self) -> Result<(), FormatError> {
        if self.flags & !SIDECAR_KNOWN_FLAGS != 0 {
            return Err(FormatError::UnknownBootstrapSidecarFlags(self.flags));
        }
        self.validate_presence_fields(
            self.has_manifest_footer(),
            self.manifest_footer_offset,
            self.manifest_footer_length as u64,
        )?;
        if self.has_manifest_footer() && self.manifest_footer_length != MANIFEST_FOOTER_LEN as u32 {
            return Err(FormatError::InvalidManifestFooterLength(
                self.manifest_footer_length,
            ));
        }
        self.validate_presence_fields(
            self.has_index_root_records(),
            self.index_root_records_offset,
            self.index_root_records_length,
        )?;
        self.validate_presence_fields(
            self.has_dictionary_records(),
            self.dictionary_records_offset,
            self.dictionary_records_length,
        )?;
        Ok(())
    }

    fn validate_presence_fields(
        &self,
        present: bool,
        offset: u64,
        length: u64,
    ) -> Result<(), FormatError> {
        match (present, offset, length) {
            (true, 0, _) | (true, _, 0) => Err(FormatError::EmptyBootstrapSidecarSection),
            (false, 0, 0) => Ok(()),
            (false, _, _) => Err(FormatError::NonZeroAbsentBootstrapSidecarSection),
            (true, _, _) => Ok(()),
        }
    }

    fn validate_section_cursor(
        &self,
        present: bool,
        offset: u64,
        length: u64,
        cursor: u64,
    ) -> Result<u64, FormatError> {
        if present {
            if offset != cursor {
                return Err(FormatError::NonCanonicalBootstrapSidecarLayout);
            }
            cursor
                .checked_add(length)
                .ok_or(FormatError::NonCanonicalBootstrapSidecarLayout)
        } else {
            Ok(cursor)
        }
    }
}

fn is_known_extension(ext_tag: u16) -> bool {
    matches!(ext_tag, 0x0001 | 0x0002 | 0x0003 | 0x0005)
}

fn validate_known_extension(ext_tag: u16, value: &[u8]) -> Result<(), FormatError> {
    match ext_tag {
        0x0001 | 0x0002 | 0x0005 => std::str::from_utf8(value)
            .map(|_| ())
            .map_err(|_| FormatError::MalformedKnownExtension(ext_tag)),
        0x0003 => {
            if value.len() == 8 {
                Ok(())
            } else {
                Err(FormatError::MalformedKnownExtension(ext_tag))
            }
        }
        _ => Ok(()),
    }
}

fn expect_len(structure: &'static str, expected: usize, actual: usize) -> Result<(), FormatError> {
    if actual != expected {
        return Err(FormatError::InvalidLength {
            structure,
            expected,
            actual,
        });
    }
    Ok(())
}

fn expect_magic(
    structure: &'static str,
    expected: [u8; 4],
    actual: &[u8],
) -> Result<(), FormatError> {
    if actual != expected {
        return Err(FormatError::BadMagic { structure });
    }
    Ok(())
}

fn expect_zero(structure: &'static str, bytes: &[u8]) -> Result<(), FormatError> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(FormatError::NonZeroReserved { structure });
    }
    Ok(())
}

fn expect_crc(structure: &'static str, covered: &[u8], expected: u32) -> Result<(), FormatError> {
    if crc32c(covered) != expected {
        return Err(FormatError::BadCrc { structure });
    }
    Ok(())
}

fn read_array_16(bytes: &[u8], offset: usize) -> Result<[u8; 16], FormatError> {
    let mut value = [0u8; 16];
    value.copy_from_slice(
        bytes
            .get(offset..offset + 16)
            .ok_or(FormatError::InvalidLength {
                structure: "array16",
                expected: offset + 16,
                actual: bytes.len(),
            })?,
    );
    Ok(value)
}

fn read_array_32(bytes: &[u8], offset: usize) -> Result<[u8; 32], FormatError> {
    let mut value = [0u8; 32];
    value.copy_from_slice(
        bytes
            .get(offset..offset + 32)
            .ok_or(FormatError::InvalidLength {
                structure: "array32",
                expected: offset + 32,
                actual: bytes.len(),
            })?,
    );
    Ok(value)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, FormatError> {
    let array: [u8; 2] = bytes
        .get(offset..offset + 2)
        .ok_or(FormatError::InvalidLength {
            structure: "u16",
            expected: offset + 2,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("slice length checked");
    Ok(u16::from_le_bytes(array))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, FormatError> {
    let array: [u8; 4] = bytes
        .get(offset..offset + 4)
        .ok_or(FormatError::InvalidLength {
            structure: "u32",
            expected: offset + 4,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("slice length checked");
    Ok(u32::from_le_bytes(array))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, FormatError> {
    let array: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(FormatError::InvalidLength {
            structure: "u64",
            expected: offset + 8,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("slice length checked");
    Ok(u64::from_le_bytes(array))
}

fn read_i64(bytes: &[u8], offset: usize) -> Result<i64, FormatError> {
    let array: [u8; 8] = bytes
        .get(offset..offset + 8)
        .ok_or(FormatError::InvalidLength {
            structure: "i64",
            expected: offset + 8,
            actual: bytes.len(),
        })?
        .try_into()
        .expect("slice length checked");
    Ok(i64::from_le_bytes(array))
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_i64(bytes: &mut [u8], offset: usize, value: i64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::CRYPTO_HEADER_HMAC_LEN;

    fn uuid() -> [u8; 16] {
        [0x11; 16]
    }

    fn session() -> [u8; 16] {
        [0x22; 16]
    }

    fn volume_header() -> VolumeHeader {
        VolumeHeader {
            format_version: FORMAT_VERSION,
            volume_format_rev: VOLUME_FORMAT_REV,
            volume_index: 0,
            stripe_width: 1,
            archive_uuid: uuid(),
            session_id: session(),
            crypto_header_offset: VOLUME_HEADER_LEN as u32,
            crypto_header_length: 128,
            header_crc32c: 0,
        }
    }

    fn crypto_fixed() -> CryptoHeaderFixed {
        CryptoHeaderFixed {
            length: (CRYPTO_HEADER_FIXED_LEN + 2 + 6 + CRYPTO_HEADER_HMAC_LEN) as u32,
            compression_algo: CompressionAlgo::ZstdFramed,
            aead_algo: AeadAlgo::AesGcmSiv256,
            fec_algo: FecAlgo::ReedSolomonGF16,
            kdf_algo: KdfAlgo::Raw,
            chunk_size: 262_144,
            envelope_target_size: 4 * 1024 * 1024,
            block_size: 4096,
            fec_data_shards: 16,
            fec_parity_shards: 2,
            index_fec_data_shards: 16,
            index_fec_parity_shards: 2,
            index_root_fec_data_shards: 16,
            index_root_fec_parity_shards: 2,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 5,
            has_dictionary: 0,
            max_path_length: 4096,
            expected_volume_size: 0,
        }
    }

    fn raw_crypto_header_bytes() -> Vec<u8> {
        let fixed = crypto_fixed();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&fixed.to_bytes());
        bytes.extend_from_slice(&(KdfAlgo::Raw as u16).to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&[0xab; CRYPTO_HEADER_HMAC_LEN]);
        bytes
    }

    #[test]
    fn volume_header_round_trips_and_validates() {
        let bytes = volume_header().to_bytes();
        let parsed = VolumeHeader::parse(&bytes).unwrap();
        assert_eq!(parsed.format_version, FORMAT_VERSION);
        assert_eq!(parsed.volume_format_rev, VOLUME_FORMAT_REV);
        assert_eq!(parsed.crypto_header_offset, VOLUME_HEADER_LEN as u32);
    }

    #[test]
    fn volume_header_rejects_mutations() {
        let mut bytes = volume_header().to_bytes();
        bytes[0] = b'X';
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap_err(),
            FormatError::BadMagic {
                structure: "VolumeHeader"
            }
        );

        let mut bytes = volume_header().to_bytes();
        write_u16(&mut bytes, 6, 35);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap_err(),
            FormatError::UnsupportedVolumeFormatRevision(35)
        );

        let mut bytes = volume_header().to_bytes();
        bytes[124] ^= 1;
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap_err(),
            FormatError::BadCrc {
                structure: "VolumeHeader"
            }
        );

        let mut bytes = volume_header().to_bytes();
        write_u32(&mut bytes, 48, 129);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap_err(),
            FormatError::NonCanonicalCryptoHeaderOffset(129)
        );

        let mut bytes = volume_header().to_bytes();
        write_u32(&mut bytes, 52, READER_MAX_CRYPTO_HEADER_LEN + 1);
        let crc = crc32c(&bytes[..124]);
        write_u32(&mut bytes, 124, crc);
        assert_eq!(
            VolumeHeader::parse(&bytes).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "CryptoHeader length",
                cap: READER_MAX_CRYPTO_HEADER_LEN as u64,
                actual: (READER_MAX_CRYPTO_HEADER_LEN + 1) as u64,
            }
        );
    }

    #[test]
    fn crypto_header_fixed_round_trips_and_validates() {
        let header = crypto_fixed();
        let bytes = header.to_bytes();
        let parsed = CryptoHeaderFixed::parse(&bytes, header.length).unwrap();
        assert_eq!(parsed.compression_algo, CompressionAlgo::ZstdFramed);
        assert_eq!(parsed.fec_algo, FecAlgo::ReedSolomonGF16);
    }

    #[test]
    fn crypto_header_fixed_rejects_v36_incompatible_values() {
        let mut header = crypto_fixed();
        header.compression_algo = CompressionAlgo::None;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::UnsupportedCompressionForV36(CompressionAlgo::None)
        );

        let mut header = crypto_fixed();
        header.block_size = 4097;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::OddBlockSize(4097)
        );

        let mut bytes = crypto_fixed().to_bytes();
        bytes[59] = 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&bytes, crypto_fixed().length).unwrap_err(),
            FormatError::NonZeroReserved {
                structure: "CryptoHeaderFixed"
            }
        );
    }

    #[test]
    fn crypto_header_fixed_rejects_reader_cap_excesses() {
        let mut header = crypto_fixed();
        header.chunk_size = READER_MAX_CHUNK_SIZE + 1;
        header.envelope_target_size = header.chunk_size;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "chunk_size",
                cap: READER_MAX_CHUNK_SIZE as u64,
                actual: (READER_MAX_CHUNK_SIZE + 1) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.block_size = READER_MAX_BLOCK_SIZE + 2;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "block_size",
                cap: READER_MAX_BLOCK_SIZE as u64,
                actual: (READER_MAX_BLOCK_SIZE + 2) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.max_path_length = READER_MAX_PATH_LENGTH + 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "max_path_length",
                cap: READER_MAX_PATH_LENGTH as u64,
                actual: (READER_MAX_PATH_LENGTH + 1) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.fec_data_shards = READER_MAX_FEC_CLASS_SHARDS as u16;
        header.fec_parity_shards = 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "fec_data_shards + fec_parity_shards",
                cap: READER_MAX_FEC_CLASS_SHARDS as u64,
                actual: (READER_MAX_FEC_CLASS_SHARDS + 1) as u64,
            }
        );

        let mut header = crypto_fixed();
        header.index_fec_data_shards = READER_MAX_INDEX_FEC_CLASS_SHARDS as u16;
        header.index_fec_parity_shards = 1;
        assert_eq!(
            CryptoHeaderFixed::parse(&header.to_bytes(), header.length).unwrap_err(),
            FormatError::ReaderResourceLimitExceeded {
                field: "index_fec_data_shards + index_fec_parity_shards",
                cap: READER_MAX_INDEX_FEC_CLASS_SHARDS as u64,
                actual: (READER_MAX_INDEX_FEC_CLASS_SHARDS + 1) as u64,
            }
        );
    }

    #[test]
    fn crypto_extension_scanner_enforces_terminator_and_caps() {
        let bytes = [0u8; CRYPTO_EXTENSION_HEADER_LEN];
        assert!(scan_crypto_extension_tlvs(&bytes).unwrap().is_empty());

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0001u16.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(b"hey");
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        let tlvs = scan_crypto_extension_tlvs(&bytes).unwrap();
        assert_eq!(tlvs[0].tag, 1);
        assert_eq!(tlvs[0].value, b"hey");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0001u16.to_le_bytes());
        bytes.extend_from_slice(&257u32.to_le_bytes());
        assert_eq!(
            scan_crypto_extension_tlvs(&bytes).unwrap_err(),
            FormatError::ExtensionPayloadTooLarge(257)
        );

        assert_eq!(
            scan_crypto_extension_tlvs(&[]).unwrap_err(),
            FormatError::MissingExtensionTerminator
        );
    }

    #[test]
    fn crypto_header_parse_splits_fixed_kdf_extensions_and_hmac() {
        let bytes = raw_crypto_header_bytes();
        let header = CryptoHeader::parse(&bytes, bytes.len() as u32).unwrap();
        assert_eq!(header.fixed.kdf_algo, KdfAlgo::Raw);
        assert_eq!(header.kdf_params, KdfParams::Raw);
        assert!(header.extensions.is_empty());
        assert_eq!(header.header_hmac, [0xab; CRYPTO_HEADER_HMAC_LEN]);
        assert_eq!(
            header.hmac_covered_bytes.len(),
            bytes.len() - CRYPTO_HEADER_HMAC_LEN
        );
    }

    #[test]
    fn crypto_header_parse_rejects_truncated_and_bad_kdf_params() {
        let mut bytes = raw_crypto_header_bytes();
        bytes.truncate(CRYPTO_HEADER_FIXED_LEN + 1);
        assert_eq!(
            CryptoHeader::parse(&bytes, bytes.len() as u32).unwrap_err(),
            FormatError::CryptoHeaderTooShort {
                min: CRYPTO_HEADER_FIXED_LEN
                    + 2
                    + CRYPTO_EXTENSION_HEADER_LEN
                    + CRYPTO_HEADER_HMAC_LEN,
                actual: CRYPTO_HEADER_FIXED_LEN + 1
            }
        );

        let mut bytes = raw_crypto_header_bytes();
        write_u16(
            &mut bytes,
            CRYPTO_HEADER_FIXED_LEN,
            KdfAlgo::Argon2id as u16,
        );
        assert_eq!(
            CryptoHeader::parse(&bytes, bytes.len() as u32).unwrap_err(),
            FormatError::KdfAlgoTagMismatch {
                expected: 0,
                actual: 1
            }
        );
    }

    #[test]
    fn crypto_extension_semantics_reject_forbidden_duplicate_and_critical() {
        let duplicate = vec![
            ExtensionTlv {
                tag: 0x0001,
                value: b"one",
            },
            ExtensionTlv {
                tag: 0x0001,
                value: b"two",
            },
        ];
        assert_eq!(
            validate_crypto_extension_semantics(&duplicate).unwrap_err(),
            FormatError::DuplicateKnownExtension(0x0001)
        );

        let forbidden = vec![ExtensionTlv {
            tag: 0x8004,
            value: b"",
        }];
        assert_eq!(
            validate_crypto_extension_semantics(&forbidden).unwrap_err(),
            FormatError::ForbiddenExtensionTag(0x0004)
        );

        let unknown_critical = vec![ExtensionTlv {
            tag: 0x8123,
            value: b"",
        }];
        assert_eq!(
            validate_crypto_extension_semantics(&unknown_critical).unwrap_err(),
            FormatError::UnknownCriticalExtension(0x0123)
        );

        let malformed_known = vec![ExtensionTlv {
            tag: 0x0003,
            value: b"short",
        }];
        assert_eq!(
            validate_crypto_extension_semantics(&malformed_known).unwrap_err(),
            FormatError::MalformedKnownExtension(0x0003)
        );
    }

    #[test]
    fn block_record_round_trips_and_validates_crc() {
        let record = BlockRecord {
            block_index: 0,
            kind: BlockKind::PayloadData,
            flags: BLOCK_LAST_DATA_FLAG,
            payload: vec![7; 4096],
            record_crc32c: 0,
        };
        let bytes = record.to_bytes();
        let parsed = BlockRecord::parse(&bytes, 4096).unwrap();
        assert_eq!(parsed.kind, BlockKind::PayloadData);
        assert!(parsed.is_last_data());

        let mut corrupted = bytes;
        corrupted[20] ^= 1;
        assert_eq!(
            BlockRecord::parse(&corrupted, 4096).unwrap_err(),
            FormatError::BadCrc {
                structure: "BlockRecord"
            }
        );
    }

    #[test]
    fn block_record_rejects_reserved_kind_flags_and_parity_last_flag() {
        let mut record = BlockRecord {
            block_index: 0,
            kind: BlockKind::PayloadData,
            flags: 0x02,
            payload: vec![0; 4096],
            record_crc32c: 0,
        };
        assert_eq!(
            BlockRecord::parse(&record.to_bytes(), 4096).unwrap_err(),
            FormatError::InvalidBlockFlags(0x02)
        );

        record.kind = BlockKind::PayloadParity;
        record.flags = BLOCK_LAST_DATA_FLAG;
        assert_eq!(
            BlockRecord::parse(&record.to_bytes(), 4096).unwrap_err(),
            FormatError::ParityBlockHasLastDataFlag
        );

        let mut bytes = record.to_bytes();
        bytes[12] = 10;
        let crc = crc32c(&bytes[..4112]);
        write_u32(&mut bytes, 4112, crc);
        assert_eq!(
            BlockRecord::parse(&bytes, 4096).unwrap_err(),
            FormatError::UnknownBlockKind(10)
        );
    }

    #[test]
    fn manifest_footer_round_trips_and_validates_index_extent() {
        let footer = ManifestFooter {
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            is_authoritative: 1,
            total_volumes: 1,
            index_root_first_block: 0,
            index_root_data_block_count: 2,
            index_root_parity_block_count: 1,
            index_root_encrypted_size: 8192,
            index_root_decompressed_size: 120,
            manifest_hmac: [0xaa; 32],
        };
        let parsed = ManifestFooter::parse(&footer.to_bytes()).unwrap();
        parsed.validate_index_root_extent(4096).unwrap();

        let mut bad = footer.clone();
        bad.index_root_encrypted_size = 4096;
        assert_eq!(
            ManifestFooter::parse(&bad.to_bytes())
                .unwrap()
                .validate_index_root_extent(4096)
                .unwrap_err(),
            FormatError::IndexRootSizeMismatch
        );
    }

    #[test]
    fn volume_trailer_round_trips_and_requires_manifest_length() {
        let trailer = VolumeTrailer {
            archive_uuid: uuid(),
            session_id: session(),
            volume_index: 0,
            block_count: 3,
            bytes_written: 10_000,
            manifest_footer_offset: 9_864,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            closed_at_ns: 123,
            trailer_hmac: [0xbb; 32],
        };
        let parsed = VolumeTrailer::parse(&trailer.to_bytes()).unwrap();
        assert_eq!(parsed.block_count, 3);

        let mut bad = trailer;
        bad.manifest_footer_length = 100;
        assert_eq!(
            VolumeTrailer::parse(&bad.to_bytes()).unwrap_err(),
            FormatError::InvalidManifestFooterLength(100)
        );
    }

    #[test]
    fn bootstrap_sidecar_header_validates_presence_and_layout() {
        let header = BootstrapSidecarHeader {
            archive_uuid: uuid(),
            session_id: session(),
            flags: SIDECAR_MANIFEST_PRESENT | SIDECAR_INDEX_ROOT_PRESENT,
            manifest_footer_offset: BOOTSTRAP_SIDECAR_HEADER_LEN as u64,
            manifest_footer_length: MANIFEST_FOOTER_LEN as u32,
            index_root_records_offset: (BOOTSTRAP_SIDECAR_HEADER_LEN + MANIFEST_FOOTER_LEN) as u64,
            index_root_records_length: 40,
            dictionary_records_offset: 0,
            dictionary_records_length: 0,
            sidecar_hmac: [0xcc; 32],
            header_crc32c: 0,
        };
        let parsed = BootstrapSidecarHeader::parse(&header.to_bytes()).unwrap();
        parsed
            .validate_packed_layout(
                BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + MANIFEST_FOOTER_LEN as u64 + 40,
            )
            .unwrap();

        let mut bad = header.clone();
        bad.flags |= 0x08;
        assert_eq!(
            BootstrapSidecarHeader::parse(&bad.to_bytes()).unwrap_err(),
            FormatError::UnknownBootstrapSidecarFlags(0x0b)
        );

        let mut bad = header;
        bad.index_root_records_offset += 1;
        let parsed = BootstrapSidecarHeader::parse(&bad.to_bytes()).unwrap();
        assert_eq!(
            parsed
                .validate_packed_layout(
                    BOOTSTRAP_SIDECAR_HEADER_LEN as u64 + MANIFEST_FOOTER_LEN as u64 + 40
                )
                .unwrap_err(),
            FormatError::NonCanonicalBootstrapSidecarLayout
        );
    }
}
