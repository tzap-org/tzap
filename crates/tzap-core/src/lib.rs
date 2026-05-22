//! Core implementation surface for the tzap v0.36 archive format.
//!
//! This crate owns wire-format parsing, validation, crypto, compression, FEC,
//! and archive read/write primitives. The CLI stays intentionally thin.

pub mod compression;
pub mod crypto;
pub mod fec;
pub mod format;
pub mod metadata;
pub mod padding;
pub mod reader;
pub mod tar_model;
pub mod wire;
pub mod writer;

pub use crypto::{HmacDomain, KdfParams, MasterKey, Subkeys};
pub use format::{
    AeadAlgo, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, FORMAT_VERSION, VOLUME_FORMAT_REV,
};
pub use reader::{
    open_archive, open_archive_with_bootstrap_sidecar, open_non_seekable_archive,
    sequential_extract_tar_stream, ArchiveEntry, OpenedArchive, ReaderOptions,
};
pub use tar_model::{MetadataDiagnostic, SafeExtractionOptions, TarEntryKind};
pub use writer::{
    write_archive, write_archive_with_dictionary, write_empty_archive, RegularFile, WriterOptions,
};
