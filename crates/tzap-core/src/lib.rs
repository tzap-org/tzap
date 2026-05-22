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
pub mod wire;
pub mod writer;

pub use crypto::{HmacDomain, KdfParams, MasterKey, Subkeys};
pub use format::{
    AeadAlgo, CompressionAlgo, FecAlgo, FormatError, KdfAlgo, FORMAT_VERSION, VOLUME_FORMAT_REV,
};
pub use writer::{RegularFile, WriterOptions};
