//! Integration coverage for the metadata surface hosts actually call.
//!
//! Everything here goes through `tzap-core`'s **public** API, from outside the
//! crate, the way `tzap-cli` and zmanager do. That distinction matters: the unit
//! tests inside `src/` can reach private helpers, so they prove the internals
//! agree with themselves. What went wrong historically is different -- the
//! public surface a second host builds on drifted, and the only thing exercising
//! that surface end to end lived in zmanager. A defect in tzap-core should be
//! caught by tzap-core's own suite, not by a downstream project's.

use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tzap_core::entry_metadata::{archive_timestamp_from_system_time, host_source_os_label, system_time_from_archive_timestamp, ArchiveTimestamp};
use tzap_core::portable_capture::{
    assemble_portable_file_metadata, capture_portable_file_metadata, is_transient_capture_race, with_capture_retry, CAPTURE_ATTEMPTS,
};
use tzap_core::{open_archive, write_archive, MasterKey, NativeFileMetadata, PortableModeOrigin, RegularFile, WriterOptions};

fn key() -> MasterKey {
    MasterKey::from_raw_key(&[0x5a; 32]).unwrap()
}

fn options() -> WriterOptions {
    WriterOptions { stripe_width: 1, volume_loss_tolerance: 0, bit_rot_buffer_pct: 0, ..WriterOptions::default() }
}

/// A writer that keeps changing a file until told to stop.
///
/// Changes size *and* content so the identity a capture samples on open really
/// does move underneath it, rather than only the access time.
struct ConcurrentWriter {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ConcurrentWriter {
    fn hammer(path: &Path) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let path = path.to_path_buf();
        let flag = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            let mut round = 0usize;
            while !flag.load(Ordering::Relaxed) {
                round = round.wrapping_add(1);
                let _ = fs::write(&path, vec![b'a'; 1 + (round % 4096)]);
            }
        });
        Self { stop, handle: Some(handle) }
    }
}

impl Drop for ConcurrentWriter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Every failure from capturing a file under active modification must be
/// recognisable as the transient race.
///
/// This is the contract `is_transient_capture_race` exists to provide, and the
/// one that silently broke: the marker matched only "changed *during* metadata
/// capture", while the identity check on the freshly opened handle reports
/// "changed *before*" -- the far more common outcome. The retry therefore never
/// fired on the case it was written for, and no unit test noticed because they
/// all fed the predicate hand-written strings.
///
/// Asserts against real OS behaviour instead: whatever the platform actually
/// produces when a writer is mid-flight has to be classified correctly.
#[test]
fn capture_under_a_concurrent_writer_only_ever_fails_with_a_recognisable_race() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("contended.bin");
    fs::write(&path, b"initial").unwrap();

    let _writer = ConcurrentWriter::hammer(&path);

    let mut unrecognised = Vec::new();
    let mut succeeded = 0usize;
    for _ in 0..400 {
        match capture_portable_file_metadata(&path) {
            Ok(_) => succeeded += 1,
            // `NotFound` is not a race: the file always exists here. Anything
            // else must be the race, spelled so a host can detect it.
            Err(error) if is_transient_capture_race(&error) => {}
            Err(error) => unrecognised.push(format!("{error}")),
        }
    }

    assert!(unrecognised.is_empty(), "a capture losing a race must report it in a form `is_transient_capture_race` recognises; got: {unrecognised:#?}");
    // The retry exists so that contention degrades into a slower capture, not a
    // failed archive. With 400 attempts against a writer that yields constantly,
    // a total shutout would mean the retry is not working at all.
    assert!(succeeded > 0, "no capture succeeded under contention, so the retry never recovered");
}

/// The pre-open race, triggered deterministically.
///
/// `capture_portable_file_metadata` supplies no expected identity, so it can
/// only ever reach the *final* check and report "changed during". The "changed
/// before" wording comes from the host-identity check, which is exactly the
/// variant `is_transient_capture_race` used to miss -- so a concurrent-writer
/// test against the no-identity entry point cannot catch that regression, and
/// this one has to drive the identity-taking entry point instead.
///
/// Replacing the file outright makes the stale identity certain, with no timing
/// involved.
#[cfg(target_os = "macos")]
#[test]
fn a_stale_host_identity_is_reported_as_a_race_the_retry_recognises() {
    use tzap_core::macos_metadata::{capture_macos_metadata_with, MacosMetadataIdentity};

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("swapped.bin");
    fs::write(&path, b"original").unwrap();
    let stale = MacosMetadataIdentity::from_metadata(&fs::symlink_metadata(&path).unwrap());

    // A different object at the same path: new inode, different length.
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"a replacement of a different length").unwrap();

    let error = capture_macos_metadata_with(&path, false, Some(stale)).expect_err("a replaced object must be refused");
    assert!(is_transient_capture_race(&error), "the pre-open race must be recognised by the predicate hosts retry on; got: {error}");

    // And the retry must actually spend its budget on it rather than giving up
    // on the first attempt, which is what the missed marker caused.
    let attempts = std::cell::Cell::new(0usize);
    let _ = with_capture_retry(|| {
        attempts.set(attempts.get() + 1);
        capture_macos_metadata_with(&path, false, Some(stale))
    });
    assert_eq!(attempts.get(), CAPTURE_ATTEMPTS, "a recognised race must be retried, not reported on the first attempt");
}

/// The same race one step earlier: the object is replaced between the stat that
/// identified it and the open that pins it.
#[test]
fn a_replaced_object_is_reported_as_a_race_not_an_opaque_error() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("swapped.bin");
    let elsewhere = temp.path().join("moved.bin");
    fs::write(&path, b"original").unwrap();

    // Whatever the platform reports, a host must be able to tell a swap apart
    // from a genuine failure; `with_capture_retry` depends on exactly that.
    let observed = with_capture_retry(|| {
        let result = capture_portable_file_metadata(&path);
        if path.exists() && !elsewhere.exists() {
            let _ = fs::rename(&path, &elsewhere);
            let _ = fs::write(&path, b"replacement with a different length");
        }
        result
    });
    if let Err(error) = observed {
        assert!(is_transient_capture_race(&error) || error.kind() == io::ErrorKind::NotFound, "unexpected capture error: {error}");
    }
}

/// The whole host flow, inside tzap-core: capture a real file, assemble the
/// portable record, write an archive, open it, and read the metadata back.
///
/// zmanager has driven this end to end for both projects. tzap-core never did,
/// so a break in its own public surface surfaced first in a downstream repo.
#[test]
fn a_captured_file_round_trips_through_the_writer_and_reader() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("payload.bin");
    let payload = b"captured payload";
    fs::write(&path, payload).unwrap();

    let captured = capture_portable_file_metadata(&path).unwrap();
    assert_eq!(captured.metadata.source_os, host_source_os_label());
    let expected_mode_origin = if cfg!(unix) { PortableModeOrigin::Native } else { PortableModeOrigin::Projected };
    assert_eq!(captured.metadata.mode_origin, expected_mode_origin);

    let metadata = fs::symlink_metadata(&path).unwrap();
    let mtime = archive_timestamp_from_system_time(metadata.modified().unwrap()).expect("mtime is in range");
    let mode = if cfg!(unix) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            metadata.mode() & 0o7777
        }
        #[cfg(not(unix))]
        {
            0o644
        }
    } else {
        0o644
    };

    let archive =
        write_archive(&[RegularFile { path: "payload.bin", contents: payload, mode, mtime, portable_metadata: captured.metadata.clone() }], &key(), options())
            .expect("a freshly captured record must be writable");

    let opened = open_archive(&archive.bytes, &key()).unwrap();
    opened.verify().unwrap();
    opened.verify_content().unwrap();
    assert_eq!(opened.extract_file("payload.bin").unwrap(), Some(payload.to_vec()));

    let entries = opened.list_index_entries().unwrap();
    let entry = entries.iter().find(|entry| entry.path == "payload.bin").expect("the member must be indexed");
    assert_eq!(entry.mtime, mtime, "the stored mtime must be the instant that was captured");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        assert_eq!(entry.uid, Some(u64::from(metadata.uid())), "ownership must survive the writer");
        assert_eq!(entry.gid, Some(u64::from(metadata.gid())));
        // §16.7.1: names are optional but tzap-core resolves them, and a host
        // that stopped getting them would silently lose a corpus requirement.
        assert!(entry.uname.is_some(), "owner name must be resolved and stored");
        assert!(entry.gname.is_some(), "group name must be resolved and stored");
    }
}

/// Capture describes the link, never its target.
///
/// The load-bearing safety property: a followed link would put a file from
/// outside the archived tree into the archive under the link's name.
#[cfg(unix)]
#[test]
fn capturing_a_symlink_never_describes_its_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target.bin");
    let link = temp.path().join("link.bin");
    fs::write(&target, vec![b'x'; 8192]).unwrap();
    std::os::unix::fs::symlink("target.bin", &link).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    }

    let via_link = capture_portable_file_metadata(&link).unwrap();
    let via_target = capture_portable_file_metadata(&target).unwrap();

    // The link and its target are different objects, so their captures must not
    // be interchangeable. Comparing the native records catches a follow that a
    // size or mode check alone would miss.
    assert_ne!(
        format!("{:?}", via_link.metadata.native),
        format!("{:?}", via_target.metadata.native),
        "capturing a symlink must not produce the target's native metadata"
    );

    // A dangling link is still a capturable object, not an error.
    let dangling = temp.path().join("dangling.bin");
    std::os::unix::fs::symlink("no-such-file", &dangling).unwrap();
    capture_portable_file_metadata(&dangling).expect("a dangling symlink describes itself");
}

/// The timestamp contract, exercised the way a host does rather than through
/// crate-private helpers.
#[test]
fn host_times_survive_the_public_conversion_pair() {
    use std::time::{Duration, UNIX_EPOCH};

    // 100ns-aligned: Windows `SystemTime` is FILETIME-backed and rounds finer values.
    for offset in [Duration::new(2, 750_000_000), Duration::new(1, 500_000_000), Duration::new(5, 0), Duration::new(0, 100)] {
        for instant in [UNIX_EPOCH + offset, UNIX_EPOCH - offset] {
            let stamp = archive_timestamp_from_system_time(instant).expect("in range");
            assert_eq!(system_time_from_archive_timestamp(stamp), Some(instant), "round trip for {offset:?}");
        }
    }

    // The encoding a reader sees, for the case that distinguishes a correct
    // conversion from one that folds the fraction into the magnitude.
    let stamp = archive_timestamp_from_system_time(UNIX_EPOCH - Duration::new(1, 250_000_000)).unwrap();
    assert_eq!(stamp, ArchiveTimestamp::new(-2, 750_000_000));
    assert_eq!(stamp.canonical_pax_value().unwrap(), b"-1.25");
}

/// §16.7.1 distinguishes "this host has no ownership model" from "owned by root",
/// and the writer must carry that distinction rather than zeroing it.
#[test]
fn absent_ownership_is_not_the_same_as_uid_zero() {
    let none = assemble_portable_file_metadata(NativeFileMetadata::default(), None, None, None, None);
    assert!(none.posix_owner.is_none(), "no ownership model must mean the PAX owner keys are absent");

    let root = assemble_portable_file_metadata(NativeFileMetadata::default(), Some((0, 0)), None, None, None);
    let owner = root.posix_owner.expect("ids were supplied");
    assert_eq!((owner.uid, owner.gid), (0, 0));
    #[cfg(unix)]
    assert_eq!(owner.uname.as_deref(), Some("root"), "uid 0 resolves on every POSIX host");
}

/// The retry budget is part of the public contract: a race that never settles
/// must be reported rather than retried forever.
#[test]
fn the_retry_budget_is_bounded_and_reports_the_race() {
    use std::cell::Cell;

    let attempts = Cell::new(0usize);
    let error = with_capture_retry(|| {
        attempts.set(attempts.get() + 1);
        Err::<(), _>(io::Error::other("input changed before metadata capture"))
    })
    .unwrap_err();

    assert_eq!(attempts.get(), CAPTURE_ATTEMPTS, "the budget must be spent exactly once");
    assert!(is_transient_capture_race(&error), "the reported error must still say what happened");
}
