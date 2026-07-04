//! Signing profiles for tzap RootAuth.
//!
//! The plugin crate owns authenticator-profile behavior. `tzap-core` owns the
//! v44 archive fields and computes the RootAuth signing input that these
//! profiles sign or verify.

#![forbid(unsafe_code)]

pub mod ed25519_raw;
pub mod x509_chain;
