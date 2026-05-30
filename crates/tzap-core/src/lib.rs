//! Core implementation surface for the tzap v0.41 archive format.
//!
//! This crate owns wire-format parsing, validation, crypto, compression, FEC,
//! and archive read/write primitives. The CLI stays intentionally thin.

pub mod compression;
pub mod crypto;
pub mod fec;
pub mod format;
pub mod metadata;
pub mod non_seekable_reader;
pub mod padding;
pub mod reader;
pub mod root_auth;
pub mod tar_model;
pub mod wire;
pub mod writer;

mod raw_stream_profile;
#[cfg(test)]
mod streaming_volume_distributor;
mod streaming_writer;

pub use crypto::{HmacDomain, KdfParams, MasterKey, Subkeys};
pub use format::{
    AeadAlgo, ArchiveWriteError, CompressionAlgo, ExtractError, FecAlgo, FormatError, KdfAlgo,
    FORMAT_VERSION, VOLUME_FORMAT_REV,
};
pub use non_seekable_reader::{
    extract_non_seekable_stream_to_dir, extract_non_seekable_stream_to_dir_with_bootstrap_sidecar,
    list_non_seekable_stream, list_non_seekable_stream_with_bootstrap_sidecar,
    verify_non_seekable_stream, verify_non_seekable_stream_with_bootstrap_sidecar,
    verify_non_seekable_stream_with_options, NonSeekableReaderOptions, SequentialExtractReport,
    SequentialListReport, SequentialRootAuthStatus, SequentialVerifyReport,
};
pub use reader::{
    open_archive, open_archive_volumes, open_archive_with_bootstrap_sidecar,
    open_non_seekable_archive, open_seekable_archive, open_seekable_archive_volumes,
    open_seekable_archive_with_bootstrap_sidecar,
    open_seekable_archive_with_bootstrap_sidecar_options, public_no_key_verify_archive_with,
    public_no_key_verify_volumes_with, public_no_key_verify_volumes_with_options,
    sequential_extract_tar_stream, ArchiveContentVerification, ArchiveEntry, ArchiveIndexEntry,
    ArchiveReadAt, OpenedArchive, PublicNoKeyDiagnostic, PublicNoKeyVerification, ReaderOptions,
    RootAuthDiagnostic, RootAuthVerification,
};
pub use streaming_writer::{
    write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth, write_tar_stream_archive,
    write_tar_stream_archive_to_sink, write_tar_stream_archive_to_sink_with_kdf_and_root_auth,
    StreamingRawWriterSummary, StreamingTarWriterSummary,
};
pub use tar_model::{MetadataDiagnostic, SafeExtractionOptions, TarEntryKind};
pub use writer::{
    write_archive, write_archive_sources_to_sink, write_archive_with_dictionary,
    write_archive_with_dictionary_and_kdf, write_archive_with_dictionary_and_root_auth,
    write_archive_with_dictionary_kdf_and_root_auth, write_archive_with_kdf,
    write_archive_with_root_auth, write_archive_with_root_auth_and_kdf, write_empty_archive,
    ArchiveWriteSink, MemoryArchiveSink, RegularFile, RegularFileSource, RootAuthSigningRequest,
    RootAuthWriterConfig, WriterOptions, WrittenArchiveSummary,
};
