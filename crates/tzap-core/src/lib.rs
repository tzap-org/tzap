//! Core implementation surface for the tzap v0.36 archive format.
//!
//! This crate owns wire-format parsing, validation, crypto, compression, FEC,
//! and archive read/write primitives. The CLI stays intentionally thin.

pub mod format;
pub mod wire;

pub use format::{
    AeadAlgo, CompressionAlgo, FecAlgo, FormatError, FORMAT_VERSION, VOLUME_FORMAT_REV,
};
