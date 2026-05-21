use thiserror::Error;

pub const FORMAT_VERSION: u16 = 1;
pub const VOLUME_FORMAT_REV: u16 = 36;

pub const VOLUME_HEADER_LEN: usize = 128;
pub const CRYPTO_HEADER_FIXED_LEN: usize = 76;
pub const MANIFEST_FOOTER_LEN: usize = 136;
pub const VOLUME_TRAILER_LEN: usize = 128;
pub const BOOTSTRAP_SIDECAR_HEADER_LEN: usize = 128;
pub const BLOCK_RECORD_FRAMING_LEN: usize = 20;
pub const CRYPTO_HEADER_HMAC_LEN: usize = 32;
pub const CRYPTO_EXTENSION_HEADER_LEN: usize = 6;
pub const CRYPTO_EXTENSION_MAX_VALUE_LEN: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CompressionAlgo {
    None = 0,
    ZstdFramed = 1,
}

impl TryFrom<u16> for CompressionAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ZstdFramed),
            other => Err(FormatError::UnknownCompressionAlgo(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AeadAlgo {
    AesGcmSiv256 = 1,
    XChaCha20Poly1305 = 2,
    AesGcm256 = 3,
}

impl TryFrom<u16> for AeadAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::AesGcmSiv256),
            2 => Ok(Self::XChaCha20Poly1305),
            3 => Ok(Self::AesGcm256),
            other => Err(FormatError::UnknownAeadAlgo(other)),
        }
    }
}

impl AeadAlgo {
    pub const fn nonce_len(self) -> usize {
        match self {
            Self::AesGcmSiv256 | Self::AesGcm256 => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }

    pub const fn tag_len(self) -> usize {
        16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum FecAlgo {
    None = 0,
    ReedSolomonGF16 = 1,
    Wirehair = 2,
}

impl TryFrom<u16> for FecAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ReedSolomonGF16),
            2 => Ok(Self::Wirehair),
            other => Err(FormatError::UnknownFecAlgo(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum KdfAlgo {
    Raw = 0,
    Argon2id = 1,
}

impl TryFrom<u16> for KdfAlgo {
    type Error = FormatError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Raw),
            1 => Ok(Self::Argon2id),
            other => Err(FormatError::UnknownKdfAlgo(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BlockKind {
    PayloadData = 0,
    PayloadParity = 1,
    IndexRootData = 2,
    IndexRootParity = 3,
    IndexShardData = 4,
    IndexShardParity = 5,
    DictionaryData = 6,
    DictionaryParity = 7,
    DirectoryHintData = 8,
    DirectoryHintParity = 9,
}

impl TryFrom<u8> for BlockKind {
    type Error = FormatError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::PayloadData),
            1 => Ok(Self::PayloadParity),
            2 => Ok(Self::IndexRootData),
            3 => Ok(Self::IndexRootParity),
            4 => Ok(Self::IndexShardData),
            5 => Ok(Self::IndexShardParity),
            6 => Ok(Self::DictionaryData),
            7 => Ok(Self::DictionaryParity),
            8 => Ok(Self::DirectoryHintData),
            9 => Ok(Self::DirectoryHintParity),
            other => Err(FormatError::UnknownBlockKind(other)),
        }
    }
}

impl BlockKind {
    pub const fn is_data(self) -> bool {
        matches!(
            self,
            Self::PayloadData
                | Self::IndexRootData
                | Self::IndexShardData
                | Self::DictionaryData
                | Self::DirectoryHintData
        )
    }

    pub const fn is_parity(self) -> bool {
        !self.is_data()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FormatError {
    #[error("unknown compression algorithm id {0}")]
    UnknownCompressionAlgo(u16),

    #[error("unknown AEAD algorithm id {0}")]
    UnknownAeadAlgo(u16),

    #[error("unknown FEC algorithm id {0}")]
    UnknownFecAlgo(u16),

    #[error("unknown KDF algorithm id {0}")]
    UnknownKdfAlgo(u16),

    #[error("unknown block kind {0}")]
    UnknownBlockKind(u8),

    #[error("invalid length for {structure}: expected {expected}, actual {actual}")]
    InvalidLength {
        structure: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("bad magic for {structure}")]
    BadMagic { structure: &'static str },

    #[error("bad CRC32C for {structure}")]
    BadCrc { structure: &'static str },

    #[error("unsupported format version {0}")]
    UnsupportedFormatVersion(u16),

    #[error("unsupported volume format revision {0}")]
    UnsupportedVolumeFormatRevision(u16),

    #[error("non-zero reserved bytes in {structure}")]
    NonZeroReserved { structure: &'static str },

    #[error("non-canonical CryptoHeader offset {0}")]
    NonCanonicalCryptoHeaderOffset(u32),

    #[error("stripe width must be non-zero")]
    ZeroStripeWidth,

    #[error("volume index {volume_index} is outside stripe width {stripe_width}")]
    VolumeIndexOutOfRange {
        volume_index: u32,
        stripe_width: u32,
    },

    #[error(
        "CryptoHeader length mismatch: fixed header says {fixed}, volume header says {volume}"
    )]
    CryptoHeaderLengthMismatch { fixed: u32, volume: u32 },

    #[error("compression algorithm {0:?} is not valid for v0.36")]
    UnsupportedCompressionForV36(CompressionAlgo),

    #[error("FEC algorithm {0:?} is not valid for v0.36")]
    UnsupportedFecForV36(FecAlgo),

    #[error("invalid boolean field {field}={value}")]
    InvalidBoolean { field: &'static str, value: u8 },

    #[error("volume loss tolerance {volume_loss_tolerance} must be less than stripe width {stripe_width}")]
    VolumeLossToleranceOutOfRange {
        volume_loss_tolerance: u8,
        stripe_width: u32,
    },

    #[error("bit rot buffer pct {0} exceeds 100")]
    BitRotBufferPctTooLarge(u8),

    #[error("data shard maximum {field} must be non-zero")]
    ZeroDataShardMaximum { field: &'static str },

    #[error("chunk_size must be non-zero")]
    ZeroChunkSize,

    #[error("envelope_target_size must be non-zero")]
    ZeroEnvelopeTargetSize,

    #[error("chunk_size {chunk_size} exceeds envelope_target_size {envelope_target_size}")]
    ChunkSizeExceedsEnvelopeTarget {
        chunk_size: u32,
        envelope_target_size: u32,
    },

    #[error("block_size {0} is below the v0.36 minimum")]
    BlockSizeTooSmall(u32),

    #[error("block_size {0} must be even")]
    OddBlockSize(u32),

    #[error("invalid block flags 0x{0:02x}")]
    InvalidBlockFlags(u8),

    #[error("parity block must not set the last-data flag")]
    ParityBlockHasLastDataFlag,

    #[error("invalid authoritative flag {0}")]
    InvalidAuthoritativeFlag(u8),

    #[error("invalid ManifestFooter length {0}")]
    InvalidManifestFooterLength(u32),

    #[error("IndexRoot encrypted size is not data_block_count * block_size")]
    IndexRootSizeMismatch,

    #[error("IndexRoot data block count and encrypted size must be non-zero")]
    EmptyIndexRootExtent,

    #[error("bootstrap sidecar version {0} is unsupported")]
    UnsupportedBootstrapSidecarVersion(u32),

    #[error("bootstrap sidecar has unknown flags 0x{0:08x}")]
    UnknownBootstrapSidecarFlags(u32),

    #[error("bootstrap sidecar present section has zero offset or length")]
    EmptyBootstrapSidecarSection,

    #[error("bootstrap sidecar absent section has non-zero offset or length")]
    NonZeroAbsentBootstrapSidecarSection,

    #[error("bootstrap sidecar sections are not packed canonically")]
    NonCanonicalBootstrapSidecarLayout,

    #[error("extension TLV header is truncated")]
    TruncatedExtensionHeader,

    #[error("extension TLV payload is truncated")]
    TruncatedExtensionPayload,

    #[error("extension TLV payload length {0} exceeds 256")]
    ExtensionPayloadTooLarge(u32),

    #[error("extension terminator is malformed")]
    MalformedExtensionTerminator,

    #[error("extension terminator is missing")]
    MissingExtensionTerminator,

    #[error("bytes follow extension terminator")]
    BytesAfterExtensionTerminator,
}
