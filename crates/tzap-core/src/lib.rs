//! Core implementation surface for the tzap v0.41 archive format.
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
pub mod root_auth;
pub mod signing;
pub mod tar_model;
pub mod wire;
pub mod writer;

pub use crypto::{HmacDomain, KdfParams, MasterKey, Subkeys};
pub use format::{
    AeadAlgo, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, FORMAT_VERSION, VOLUME_FORMAT_REV,
};
pub use reader::{
    open_archive, open_archive_volumes, open_archive_with_bootstrap_sidecar,
    open_non_seekable_archive, public_no_key_verify_archive_with,
    public_no_key_verify_volumes_with, sequential_extract_tar_stream, ArchiveEntry, OpenedArchive,
    PublicNoKeyVerification, ReaderOptions, RootAuthVerification,
};
pub use signing::{
    ed25519_authenticator_value, ed25519_signing_input, verify_ed25519_after_root_auth,
    verify_ed25519_root_auth, Ed25519RootAuthOutcome, Ed25519VerificationMode,
    ED25519_AUTHENTICATOR_ID, ED25519_AUTHENTICATOR_VALUE_LEN,
};
pub use tar_model::{MetadataDiagnostic, SafeExtractionOptions, TarEntryKind};
pub use writer::{
    write_archive, write_archive_with_dictionary, write_archive_with_dictionary_and_kdf,
    write_archive_with_dictionary_and_root_auth, write_archive_with_dictionary_kdf_and_root_auth,
    write_archive_with_kdf, write_archive_with_root_auth, write_archive_with_root_auth_and_kdf,
    write_empty_archive, RegularFile, RootAuthSigningRequest, RootAuthWriterConfig, WriterOptions,
};
