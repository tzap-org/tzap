//! Portable metadata capture: filesystem path to `PortableFileMetadata`.
//!
//! This module closes an asymmetry. The crate already owned every *native*
//! capture path -- `capture_linux_metadata`, `capture_macos_metadata`,
//! `capture_windows_metadata` -- which is the hard, platform-specific, unsafe
//! part. It did not own the small portable wrapper that assembles those results
//! with source OS, mode origin, ownership, attributes, and times, so both the
//! CLI and zmanager wrote that wrapper separately.
//!
//! Two hosts assembling the same struct differently is the failure mode
//! `entry_metadata::projected_posix_mode` documents: the same input produces
//! archives that restore differently. It had already happened more than once --
//! a source-OS label that drifted out of range, and a pre-epoch timestamp
//! conversion that was a full second wrong in one host and right in the other.
//!
//! Hosts still own what is genuinely theirs: error types, cancellation,
//! progress, retry policy, and any change-detection they layer on top.

use std::fs;
use std::io;
use std::path::Path;

use crate::entry_metadata::{archive_timestamp_from_system_time, host_source_os_label, ArchiveTimestamp};
use crate::writer::{NativeFileMetadata, PortableFileMetadata, PortableModeOrigin, PortablePosixOwner};

/// Portable metadata plus anything a host needs to re-open the same object.
pub struct CapturedPortableMetadata {
    pub metadata: PortableFileMetadata,
    /// Identity of the macOS object the native capture read, so a later
    /// resource-fork open can verify it is still the same file.
    #[cfg(target_os = "macos")]
    pub macos_identity: Option<crate::macos_metadata::MacosMetadataIdentity>,
}

/// Assemble a `PortableFileMetadata` from the parts a host has already gathered.
///
/// Pure, no filesystem access. This is the layer that kept drifting: the source
/// OS label, the mode-origin rule, and owner-name resolution were each written
/// twice, once per host, and each copy went wrong in a different place. Hosts
/// still own the `native` capture and any change-detection around it -- they
/// just stop re-deciding the portable rules.
///
/// `owner_ids` is `None` on a host with no POSIX ownership model, which §16.7.1
/// distinguishes from zeroed ids: the PAX owner keys are then absent entirely.
#[must_use]
pub fn assemble_portable_file_metadata(
    native: NativeFileMetadata,
    owner_ids: Option<(u64, u64)>,
    attributes: Option<u32>,
    created: Option<ArchiveTimestamp>,
    accessed: Option<ArchiveTimestamp>,
) -> PortableFileMetadata {
    PortableFileMetadata {
        source_os: host_source_os_label().to_owned(),
        source_filesystem: "unknown".to_owned(),
        // A host with no POSIX mode projects one; see `projected_posix_mode`.
        mode_origin: if cfg!(unix) { PortableModeOrigin::Native } else { PortableModeOrigin::Projected },
        posix_owner: owner_ids.map(|(uid, gid)| {
            let names = match (u32::try_from(uid), u32::try_from(gid)) {
                // Ids beyond u32 cannot be looked up through the POSIX APIs. The
                // numeric identity still travels, which is what carries ownership.
                (Ok(uid), Ok(gid)) => crate::entry_metadata::resolve_posix_owner_names(uid, gid),
                _ => (None, None),
            };
            PortablePosixOwner { uid, gid, uname: names.0, gname: names.1 }
        }),
        attributes,
        created,
        accessed,
        native,
    }
}

/// Capture portable metadata for one filesystem object.
///
/// Never follows a symlink: the object itself is described, not its target.
///
/// Times that the format cannot encode are omitted rather than approximated.
/// §16.7.2 has no representation for the last second before the Unix epoch
/// (`-0` is forbidden), so an `atime` or creation time in that window is
/// dropped; `mtime` is the caller's to supply, because losing it silently is a
/// different decision than losing an optional time.
pub fn capture_portable_file_metadata(input: &Path) -> io::Result<CapturedPortableMetadata> {
    let metadata = fs::symlink_metadata(input)?;
    let symlink = metadata.file_type().is_symlink();

    let created = metadata.created().ok().and_then(|time| archive_timestamp_from_system_time(time).ok());
    // musl cannot expose birth time (statx/STATX_BTIME is unsupported there), so
    // fall back to ctime from the standard stat fields as an approximation.
    #[cfg(target_os = "linux")]
    let created = created.or_else(|| {
        use std::os::unix::fs::MetadataExt as _;
        Some(crate::entry_metadata::ArchiveTimestamp::new(metadata.ctime(), u32::try_from(metadata.ctime_nsec()).unwrap_or(0)))
    });
    let accessed = metadata.accessed().ok().and_then(|time| archive_timestamp_from_system_time(time).ok());

    #[cfg(target_os = "macos")]
    let captured_macos = crate::macos_metadata::capture_macos_metadata(input, symlink)?;
    #[cfg(target_os = "macos")]
    let native = captured_macos.native;
    #[cfg(target_os = "linux")]
    let native = crate::linux_metadata::capture_linux_metadata(input, symlink)?;
    #[cfg(windows)]
    let native = {
        let _ = symlink;
        crate::windows_metadata::capture_windows_metadata(input)?
    };
    #[cfg(all(not(target_os = "macos"), not(target_os = "linux"), not(windows)))]
    let native = {
        let _ = symlink;
        NativeFileMetadata::default()
    };

    Ok(CapturedPortableMetadata {
        metadata: assemble_portable_file_metadata(native, portable_owner_ids(&metadata), portable_attributes(&metadata), created, accessed),
        #[cfg(target_os = "macos")]
        macos_identity: Some(captured_macos.identity),
    })
}

#[cfg(unix)]
fn portable_owner_ids(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;
    Some((u64::from(metadata.uid()), u64::from(metadata.gid())))
}

#[cfg(not(unix))]
fn portable_owner_ids(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    // §16.7.1: with owner kind `none` the PAX owner keys are absent, not zeroed.
    None
}

#[cfg(windows)]
fn portable_attributes(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::windows::fs::MetadataExt as _;
    Some(crate::entry_metadata::windows_portable_attribute_projection(metadata.file_attributes()))
}

#[cfg(not(windows))]
fn portable_attributes(_metadata: &fs::Metadata) -> Option<u32> {
    // The four-bit projection is Windows-specific. macOS carries exact BSD flags
    // in `TZAP.macos.st-flags` instead, which the native capture handles.
    None
}
