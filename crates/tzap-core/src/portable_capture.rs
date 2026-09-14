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
#[derive(Debug)]
pub struct CapturedPortableMetadata {
    pub metadata: PortableFileMetadata,
    /// Identity of the macOS object the native capture read, so a later
    /// resource-fork open can verify it is still the same file.
    ///
    /// Always present: the capture cannot succeed without observing the object,
    /// so an `Option` here only invited callers to handle a case that does not
    /// occur. A host that assembles metadata without a native capture has its own
    /// type for that.
    #[cfg(target_os = "macos")]
    pub macos_identity: crate::macos_metadata::MacosMetadataIdentity,
}

/// Marker shared by every capture site that loses a race with a concurrent
/// writer, so hosts can recognise the condition without guessing at a message
/// they do not own.
///
/// zmanager string-matched this from the outside and documented that "the
/// durable fix is a typed error upstream". This is that fix: the constant lives
/// with the code that produces it, and [`is_transient_capture_race`] is the
/// supported way to ask.
pub const CAPTURE_RACE_MARKER: &str = "changed during metadata capture";

/// The same race observed one step earlier: the object was replaced between the
/// scan that identified it and the open that pins it.
///
/// This is the *more* common shape of the race, not a rarer one -- a capture
/// spends almost all of its window after the open -- and every native capture
/// path reports it. It was not covered by [`CAPTURE_RACE_MARKER`], so the retry
/// that exists precisely for this never fired on it.
pub const CAPTURE_PREOPEN_RACE_MARKER: &str = "changed before metadata capture";

/// Whether an error is the transient mid-capture race worth retrying.
///
/// Matches on a substring: the sites qualify it (`input`, `input kind`, `xattr`,
/// `symlink`, `symlink xattr`), and a host enriching the message with a path
/// must not silently disable the retry.
#[must_use]
pub fn is_transient_capture_race(error: &io::Error) -> bool {
    let message = error.to_string();
    message.contains(CAPTURE_RACE_MARKER) || message.contains(CAPTURE_PREOPEN_RACE_MARKER)
}

/// How many times a capture is attempted before the race is reported.
pub const CAPTURE_ATTEMPTS: usize = 3;

/// Retry a capture that lost a race with a concurrent writer.
///
/// Ported from zmanager's `with_metadata_capture_retry`, added there by "Fix
/// TZAP Unicode archives and metadata capture races" -- a race hit in practice,
/// not a hypothetical. A file changing mid-capture is ordinary during a live
/// backup, and failing the whole archive for it is the wrong response when a
/// re-read almost always succeeds.
///
/// Only the race is retried. Every other error returns on the first attempt.
pub fn with_capture_retry<T>(mut capture: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    for attempt in 0..CAPTURE_ATTEMPTS {
        match capture() {
            Ok(value) => return Ok(value),
            Err(error) if is_transient_capture_race(&error) && attempt + 1 < CAPTURE_ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the retry loop returns from every attempt")
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
            // The lookup is POSIX-only. A non-POSIX host reaches this arm solely
            // when a caller supplies ids explicitly, and has no name database to
            // resolve them against -- so the numeric identity travels alone.
            #[cfg(unix)]
            let names = match (u32::try_from(uid), u32::try_from(gid)) {
                // Ids beyond u32 cannot be looked up through the POSIX APIs. The
                // numeric identity still travels, which is what carries ownership.
                (Ok(uid), Ok(gid)) => crate::entry_metadata::resolve_posix_owner_names(uid, gid),
                _ => (None, None),
            };
            #[cfg(not(unix))]
            let names: (Option<String>, Option<String>) = (None, None);
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
    with_capture_retry(|| capture_portable_file_metadata_once(input))
}

fn capture_portable_file_metadata_once(input: &Path) -> io::Result<CapturedPortableMetadata> {
    let metadata = fs::symlink_metadata(input)?;
    let symlink = metadata.file_type().is_symlink();

    let created = metadata.created().ok().and_then(archive_timestamp_from_system_time);
    // musl cannot expose birth time (statx/STATX_BTIME is unsupported there), so
    // fall back to ctime from the standard stat fields as an approximation.
    //
    // The fallback fires only when the host supplied NO birth time. Filtering for
    // encodability first would also fire it when a real birth time exists but
    // falls in the one second §16.7.2 cannot express -- substituting a different
    // instant for a time the format deliberately drops, which is worse than
    // omitting it.
    #[cfg(target_os = "linux")]
    let created = created.or_else(|| {
        use std::os::unix::fs::MetadataExt as _;
        Some(crate::entry_metadata::ArchiveTimestamp::new(metadata.ctime(), u32::try_from(metadata.ctime_nsec()).unwrap_or(0)))
    });
    let created = created.filter(encodable);
    let accessed = metadata.accessed().ok().and_then(archive_timestamp_from_system_time).filter(encodable);

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
        macos_identity: captured_macos.identity,
    })
}

/// Whether a time survives the §16.7.2 encoding, applied where the contract to
/// drop it is stated rather than left to the writer.
///
/// Only the last second before the epoch fails: its integer part would be `-0`,
/// which the format forbids. The writer propagates that as an error, so without
/// this an optional `atime` or birth time in that window fails the whole archive
/// instead of being omitted -- and `mtime`, which genuinely should fail loudly,
/// is the caller's and is untouched here.
fn encodable(timestamp: &ArchiveTimestamp) -> bool {
    timestamp.canonical_pax_value().is_ok()
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry_metadata::ArchiveTimestamp;

    fn native_with_marker() -> NativeFileMetadata {
        let mut native = NativeFileMetadata::default();
        native.primary_pax_records.insert("TZAP.test.marker".into(), b"1".to_vec());
        native
    }

    #[test]
    fn assembly_sets_the_host_source_os_and_mode_origin() {
        let assembled = assemble_portable_file_metadata(NativeFileMetadata::default(), None, None, None, None);
        assert_eq!(assembled.source_os, host_source_os_label(), "the label must come from the one owner of it");
        assert_eq!(assembled.source_filesystem, "unknown");
        // §16.7.1: a host with a native POSIX mode declares `native`; one that
        // projects a mode declares `projected`. Getting this backwards would make
        // a reader trust a synthesized mode as exact.
        let expected = if cfg!(unix) { PortableModeOrigin::Native } else { PortableModeOrigin::Projected };
        assert_eq!(assembled.mode_origin, expected);
    }

    #[test]
    fn assembly_distinguishes_absent_ownership_from_zeroed_ownership() {
        // §16.7.1: with owner kind `none` the PAX owner keys are absent entirely.
        // A zeroed owner would claim the entry is owned by root.
        let none = assemble_portable_file_metadata(NativeFileMetadata::default(), None, None, None, None);
        assert!(none.posix_owner.is_none(), "no ownership model must mean absent, never uid 0");

        let owned = assemble_portable_file_metadata(NativeFileMetadata::default(), Some((0, 0)), None, None, None);
        let owner = owned.posix_owner.expect("owner ids were supplied");
        assert_eq!((owner.uid, owner.gid), (0, 0));
    }

    #[cfg(unix)]
    #[test]
    fn assembly_resolves_owner_names_and_tolerates_unknown_ids() {
        let owner =
            assemble_portable_file_metadata(NativeFileMetadata::default(), Some((0, 0)), None, None, None).posix_owner.expect("owner ids were supplied");
        assert_eq!(owner.uname.as_deref(), Some("root"), "uid 0 resolves on every POSIX host");

        // An id from another system has no local entry. The numeric identity must
        // still travel -- that is what actually carries ownership on restore.
        let unknown = assemble_portable_file_metadata(NativeFileMetadata::default(), Some((0x7fff_fffe, 0x7fff_fffe)), None, None, None)
            .posix_owner
            .expect("owner ids were supplied");
        assert_eq!((unknown.uid, unknown.gid), (0x7fff_fffe, 0x7fff_fffe));
        assert_eq!(unknown.uname, None);
        assert_eq!(unknown.gname, None);
    }

    #[test]
    fn assembly_passes_through_attributes_times_and_native_untouched() {
        let created = ArchiveTimestamp::new(1_700_000_000, 123_456_789);
        let accessed = ArchiveTimestamp::new(-2, 500_000_000);
        let assembled = assemble_portable_file_metadata(native_with_marker(), None, Some(0b1011), Some(created), Some(accessed));

        assert_eq!(assembled.attributes, Some(0b1011));
        assert_eq!(assembled.created, Some(created));
        assert_eq!(assembled.accessed, Some(accessed));
        assert_eq!(assembled.native.primary_pax_records.get("TZAP.test.marker").map(Vec::as_slice), Some(b"1".as_slice()));
    }

    #[test]
    fn capture_reads_a_regular_file_without_following_anything() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a.bin");
        std::fs::write(&file, b"body").unwrap();

        let captured = capture_portable_file_metadata(&file).unwrap();
        assert_eq!(captured.metadata.source_os, host_source_os_label());
        #[cfg(unix)]
        assert!(captured.metadata.posix_owner.is_some(), "a POSIX host must record ownership");
    }

    #[cfg(unix)]
    #[test]
    fn capture_describes_a_symlink_itself_not_its_target() {
        // The load-bearing safety property. If capture followed the link, the
        // archive would silently carry the target's metadata -- and the target
        // can point anywhere, including outside the tree being archived.
        //
        // Detect it by putting a distinctive xattr on the target only: a capture
        // that followed would pick it up. The paired assertion on the target
        // proves the probe can actually tell the two apart, so a pass here means
        // "did not follow", not "cannot see xattrs at all".
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target.bin");
        let link = temp.path().join("link.sym");
        std::fs::write(&target, b"target body").unwrap();
        std::os::unix::fs::symlink("target.bin", &link).unwrap();

        // Probe on the xattr NAME, not its value: §16.7.3 stores values
        // base64-encoded, so a raw marker never appears verbatim. The name shows
        // up in the PAX key or the auxiliary record name.
        const PROBE: &str = "follow-probe";
        let tagged = xattr::set(&target, "user.tzap.follow-probe", b"target-only").is_ok();

        let mentions_probe = |captured: &CapturedPortableMetadata| {
            let native = &captured.metadata.native;
            native.primary_pax_records.keys().any(|key| key.contains(PROBE))
                || native.auxiliary_records.iter().any(|record| record.name.windows(PROBE.len()).any(|w| w == PROBE.as_bytes()))
        };

        let via_link = capture_portable_file_metadata(&link).unwrap();
        assert!(!mentions_probe(&via_link), "capture followed the symlink and picked up the target's xattr");

        if tagged {
            let via_target = capture_portable_file_metadata(&target).unwrap();
            assert!(mentions_probe(&via_target), "probe is blind -- the link assertion above would pass for the wrong reason");
        }

        // A dangling link is still a capturable object: the link is the entry,
        // and its target need not exist.
        let dangling = temp.path().join("dangling.sym");
        std::os::unix::fs::symlink("does-not-exist.bin", &dangling).unwrap();
        capture_portable_file_metadata(&dangling).expect("a dangling symlink is still a capturable object");
    }

    /// Ported from zmanager's `preserves_all_metadata_in_tzap_round_trip`, which
    /// is the best-exercised metadata fixture across the two projects. That test
    /// drives zmanager's manifest API end to end; this covers the same ground at
    /// the capture layer both hosts now share, so neither host can regress it.
    ///
    /// The resource fork is deliberately larger than the PAX metadata limit --
    /// §16.18.2's corpus names exactly that case, and it had no fixture here.
    #[cfg(target_os = "macos")]
    #[test]
    fn capture_collects_the_full_macos_metadata_set() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("data.bin");
        let directory = temp.path().join("folder");
        std::fs::write(&file, b"round-trip payload").unwrap();
        std::fs::create_dir(&directory).unwrap();

        xattr::set(&file, "com.tzap.test", b"file metadata").unwrap();
        xattr::set(&directory, "com.tzap.test", b"directory metadata").unwrap();
        xattr::set(&file, "com.apple.FinderInfo", &[0x5a; 32]).unwrap();
        // Over the PAX metadata limit, so it must take the streamed auxiliary
        // path rather than an inline record.
        std::fs::write(file.join("..namedfork/rsrc"), vec![0x6b; 2 * 1024 * 1024 + 31]).unwrap();
        let acl_set = std::process::Command::new("/bin/chmod").args(["+a", "everyone deny delete"]).arg(&file).status().is_ok_and(|s| s.success());
        let flags_set = std::process::Command::new("/usr/bin/chflags").arg("hidden").arg(&file).status().is_ok_and(|s| s.success());

        let captured = capture_portable_file_metadata(&file).unwrap();
        let native = &captured.metadata.native;
        let aux_kind = |kind: &str| native.auxiliary_records.iter().any(|record| record.kind == kind);

        // The identity comes back so a later fork open can verify the same object.
        assert_eq!(captured.macos_identity, crate::macos_metadata::MacosMetadataIdentity::from_metadata(&std::fs::symlink_metadata(&file).unwrap()));
        assert!(aux_kind("macos.finder-info"), "FinderInfo must be captured as its own auxiliary kind, not a generic xattr");
        assert!(aux_kind("macos.resource-fork"), "a fork over the PAX limit must still be captured");
        if acl_set {
            assert!(aux_kind("macos.acl-native"), "a native ACL must be captured");
            assert!(native.primary_pax_records.contains_key("TZAP.acl.projection"), "the textual ACL projection must accompany the native blob");
        }
        if flags_set {
            assert!(native.primary_pax_records.contains_key("TZAP.macos.st-flags"), "Darwin flags must be captured exactly");
        }

        // The ordinary xattr survives under some representation -- inline record
        // or auxiliary -- but must not be smuggled in as FinderInfo or a fork.
        let mentions = |needle: &str| {
            native.primary_pax_records.keys().any(|key| key.contains(needle))
                || native.auxiliary_records.iter().any(|record| record.name.windows(needle.len()).any(|w| w == needle.as_bytes()))
        };
        assert!(mentions("com.tzap.test"), "an ordinary xattr must be captured");

        // A directory carries its own metadata, not the file's.
        let directory_capture = capture_portable_file_metadata(&directory).unwrap();
        assert!(
            !directory_capture.metadata.native.auxiliary_records.iter().any(|record| record.kind == "macos.resource-fork"),
            "a directory has no resource fork to capture"
        );
    }

    #[test]
    fn capture_retry_recovers_from_a_race_and_reports_everything_else() {
        use std::cell::Cell;

        let race = || io::Error::other("input changed during metadata capture");
        assert!(is_transient_capture_race(&race()));
        assert!(is_transient_capture_race(&io::Error::other("xattr changed during metadata capture")));
        // A host that enriches the message with a path must keep matching.
        assert!(is_transient_capture_race(&io::Error::other("input changed during metadata capture: /tmp/a.bin")));
        // Losing the race before the open is the same race, and is what every
        // native capture reports when the identity check fails on the handle.
        // Every message the capture paths actually emit must be recognised.
        for emitted in [
            "input changed before metadata capture",
            "input kind changed before metadata capture",
            "symlink changed before metadata capture: /tmp/a.sym",
            "symlink changed during metadata capture",
            "symlink xattr changed during metadata capture",
        ] {
            assert!(is_transient_capture_race(&io::Error::other(emitted)), "{emitted}");
        }
        assert!(!is_transient_capture_race(&io::Error::from(io::ErrorKind::NotFound)));
        assert!(!is_transient_capture_race(&io::Error::other("input changed after scan")));
        assert!(!is_transient_capture_race(&io::Error::other("failed to open /tmp/a.bin for metadata capture")));

        // Succeeds once the writer stops touching the file.
        let attempts = Cell::new(0usize);
        let value = with_capture_retry(|| {
            attempts.set(attempts.get() + 1);
            if attempts.get() < CAPTURE_ATTEMPTS {
                Err(race())
            } else {
                Ok(7)
            }
        })
        .unwrap();
        assert_eq!(value, 7);
        assert_eq!(attempts.get(), CAPTURE_ATTEMPTS);

        // A race that never settles is reported, not retried forever.
        let attempts = Cell::new(0usize);
        let error = with_capture_retry(|| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(race())
        })
        .unwrap_err();
        assert!(is_transient_capture_race(&error));
        assert_eq!(attempts.get(), CAPTURE_ATTEMPTS, "must stop after the attempt budget");

        // Anything else fails on the first attempt -- retrying a missing file
        // just delays the report.
        let attempts = Cell::new(0usize);
        let error = with_capture_retry(|| {
            attempts.set(attempts.get() + 1);
            Err::<(), _>(io::Error::from(io::ErrorKind::PermissionDenied))
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(attempts.get(), 1);
    }

    /// §16.18.1 names "binary, empty, privileged, and non-UTF-8-named xattrs".
    /// Binary values were covered by the base64/percent codecs; an **empty**
    /// value had no fixture, and it is the case most likely to be mishandled --
    /// a zero-length value reads exactly like an absent attribute unless the
    /// capture path distinguishes them.
    #[cfg(target_os = "macos")]
    #[test]
    fn capture_keeps_an_empty_xattr_distinct_from_an_absent_one() {
        let temp = tempfile::tempdir().unwrap();
        let with_empty = temp.path().join("empty-xattr.bin");
        let without = temp.path().join("no-xattr.bin");
        std::fs::write(&with_empty, b"body").unwrap();
        std::fs::write(&without, b"body").unwrap();
        if xattr::set(&with_empty, "com.tzap.empty", b"").is_err() {
            return; // filesystem rejects empty xattr values
        }

        let mentions = |captured: &CapturedPortableMetadata, needle: &str| {
            let native = &captured.metadata.native;
            native.primary_pax_records.keys().any(|key| key.contains(needle))
                || native.auxiliary_records.iter().any(|record| record.name.windows(needle.len()).any(|w| w == needle.as_bytes()))
        };

        let captured = capture_portable_file_metadata(&with_empty).unwrap();
        assert!(mentions(&captured, "com.tzap.empty"), "an empty xattr must still be captured, not treated as absent");

        let bare = capture_portable_file_metadata(&without).unwrap();
        assert!(!mentions(&bare, "com.tzap.empty"), "a file without the xattr must not gain one");
    }

    /// §16.18.2 names "quarantine/provenance xattrs" -- the macOS attributes that
    /// mark a file as downloaded. They are ordinary `com.apple.*` xattrs, so what
    /// matters is that they survive capture rather than being filtered out as
    /// system metadata: losing them silently changes Gatekeeper's view of a
    /// restored file.
    #[cfg(target_os = "macos")]
    #[test]
    fn capture_retains_the_macos_quarantine_xattr() {
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("downloaded.bin");
        std::fs::write(&file, b"downloaded body").unwrap();
        if xattr::set(&file, "com.apple.quarantine", b"0081;00000000;tzap-test;").is_err() {
            return; // not settable here
        }

        let captured = capture_portable_file_metadata(&file).unwrap();
        let native = &captured.metadata.native;
        let retained = native.primary_pax_records.keys().any(|key| key.contains("quarantine"))
            || native.auxiliary_records.iter().any(|record| record.name.windows(10).any(|w| w == b"quarantine"));
        assert!(retained, "the quarantine xattr must be captured, not filtered away");
    }

    /// §16.18.1 names "non-UTF-8-**named**" xattrs. A POSIX xattr name is a byte
    /// string, and §16.7.3 has percent/base64 name encodings precisely because
    /// such names exist -- but no fixture created one, because the `xattr` crate
    /// takes `&str`. This goes through `setxattr` directly.
    ///
    /// The value is what must survive: a name that cannot be expressed as UTF-8
    /// must be carried through an encoded form rather than dropping the whole
    /// attribute.
    ///
    /// Linux-only by necessity. APFS refuses a non-UTF-8 xattr name outright
    /// (`setxattr` returns -1), so the case cannot be created on macOS at all --
    /// a macOS version of this test could only ever skip itself.
    #[cfg(target_os = "linux")]
    #[test]
    fn capture_carries_an_xattr_whose_name_is_not_utf8() {
        use std::os::unix::ffi::OsStrExt as _;

        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("odd-name.bin");
        std::fs::write(&file, b"body").unwrap();

        // Linux requires the `user.` namespace on a regular file; the byte after
        // the stem cannot start a UTF-8 sequence.
        let raw_name = b"user.tzap-odd-\xff\0";
        let path = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
        // SAFETY: both pointers are NUL-terminated and live for the call.
        let status = unsafe { libc::setxattr(path.as_ptr(), raw_name.as_ptr().cast::<libc::c_char>(), c"odd".as_ptr().cast::<libc::c_void>(), 3, 0) };
        if status != 0 {
            return; // filesystem refuses the name; nothing to assert
        }

        let captured = capture_portable_file_metadata(&file).unwrap();
        let native = &captured.metadata.native;
        // The name cannot appear literally, so look for the distinctive stem in
        // either an encoded PAX key or an auxiliary record name.
        let stem = "tzap-odd-";
        let carried = native.primary_pax_records.keys().any(|key| key.contains(stem))
            || native.auxiliary_records.iter().any(|record| record.name.windows(stem.len()).any(|w| w == stem.as_bytes()));
        assert!(carried, "an xattr with a non-UTF-8 name must be carried through an encoded form, not dropped");
    }

    #[test]
    fn capture_reads_a_directory() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("sub");
        std::fs::create_dir(&directory).unwrap();
        let captured = capture_portable_file_metadata(&directory).unwrap();
        assert_eq!(captured.metadata.source_os, host_source_os_label());
    }

    #[test]
    fn capture_reports_a_missing_path_as_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let error = capture_portable_file_metadata(&temp.path().join("absent.bin")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[cfg(not(windows))]
    #[test]
    fn capture_leaves_windows_attributes_absent_on_hosts_without_them() {
        // The four-bit projection is Windows-specific. macOS carries exact BSD
        // flags in `TZAP.macos.st-flags` instead, so a zeroed projection here
        // would claim "no attributes set" rather than "not applicable".
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("a.bin");
        std::fs::write(&file, b"body").unwrap();
        assert_eq!(capture_portable_file_metadata(&file).unwrap().metadata.attributes, None);
    }
}
