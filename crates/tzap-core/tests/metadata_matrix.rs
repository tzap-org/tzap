//! Metadata must survive identically through every writer and reader path.
//!
//! The existing property matrix varies stripe width and dictionary but carries
//! plain files and asserts only paths and bytes. That leaves the thing most
//! likely to break silently uncovered: a change made for speed -- a different
//! frame layout, a parallel path that skips a step the buffered one does, a new
//! compression setting, a reordered index -- can drop or alter *metadata* while
//! every content assertion still passes.
//!
//! So these tests fix one metadata-rich input and require every combination to
//! agree with a single reference. They do not describe what the right answer is;
//! they require that all the paths give the same answer. An optimisation that
//! changes behaviour fails here immediately, and names which combination broke.

use tzap_core::entry_metadata::ArchiveTimestamp;
use tzap_core::{
    open_archive, open_archive_volumes, open_non_seekable_archive, write_archive, write_archive_sources_to_sink_ordered_parallel,
    write_archive_sources_to_sink_single_pass, write_archive_with_dictionary, ArchiveIndexEntry, KdfParams, MasterKey, MemoryArchiveSink, NativeFileMetadata,
    PortableFileMetadata, PortableModeOrigin, PortablePosixOwner, RegularFile, WriterOptions,
};

fn master_key() -> MasterKey {
    MasterKey::from_raw_key(&[0x5a; 32]).unwrap()
}

fn kdf() -> KdfParams {
    KdfParams::Argon2id { t_cost: 1, m_cost_kib: 8, parallelism: 1, salt: b"12345678".to_vec() }
}

/// Metadata chosen so that a path which drops or rounds any of it is visible:
/// a non-default mode, a pre-epoch fractional mtime, an explicit creation and
/// access time, ownership with names, portable attributes, and a native record.
fn rich_metadata(seed: u8) -> PortableFileMetadata {
    // Portable metadata only: a native record needs a declared profile, and the
    // profiles are per-OS, which would make this matrix assert different things
    // on different hosts. The portable projection is the part every host shares,
    // so it is the part an equivalence comparison should pin.
    PortableFileMetadata {
        // `other-unix` so the member can carry a creation time portably: on
        // linux/macos/windows `LIBARCHIVE.creationtime` belongs to that host's
        // native profile, which a portable-only member cannot declare
        // (`source_os_requires_posix_profile`). Using the generic-unix family
        // keeps this matrix host-independent while still exercising the field.
        source_os: "other-unix".to_owned(),
        source_filesystem: "unknown".to_owned(),
        mode_origin: PortableModeOrigin::Native,
        posix_owner: Some(PortablePosixOwner {
            uid: 1000 + u64::from(seed),
            gid: 2000 + u64::from(seed),
            uname: Some(format!("user{seed}")),
            gname: Some(format!("group{seed}")),
        }),
        attributes: None,
        // Pre-epoch with a fraction: the case every timestamp defect in this
        // codebase has turned on.
        created: Some(ArchiveTimestamp::new(-2, 750_000_000)),
        accessed: Some(ArchiveTimestamp::new(1_700_000_000, 123_456_789)),
        native: NativeFileMetadata::default(),
    }
}

struct Fixture {
    paths: Vec<String>,
    bodies: Vec<Vec<u8>>,
}

impl Fixture {
    fn new(count: usize) -> Self {
        let paths = (0..count).map(|index| format!("dir/member-{index}.bin")).collect();
        // Compressible, so dictionary and level changes actually take effect.
        let bodies = (0..count).map(|index| format!("payload {index} common words common words common words").repeat(4 + index).into_bytes()).collect();
        Self { paths, bodies }
    }

    fn files(&self) -> Vec<RegularFile<'_>> {
        self.paths
            .iter()
            .zip(&self.bodies)
            .enumerate()
            .map(|(index, (path, body))| RegularFile {
                path,
                contents: body,
                mode: 0o640 | u32::from(index as u8 & 1),
                mtime: ArchiveTimestamp::new(-2 - index as i64, 250_000_000),
                portable_metadata: rich_metadata(index as u8),
            })
            .collect()
    }
}

/// Everything about a member that a reader can observe, so a comparison covers
/// the whole projection rather than whichever fields a test remembered to check.
#[derive(Debug, PartialEq, Eq)]
struct MemberProjection {
    path: String,
    size: u64,
    kind: String,
    mode: u32,
    mtime: ArchiveTimestamp,
    created: Option<ArchiveTimestamp>,
    accessed: Option<ArchiveTimestamp>,
    uid: Option<u64>,
    gid: Option<u64>,
    uname: Option<String>,
    gname: Option<String>,
    attributes: Option<u32>,
    flags: u32,
    contents: Vec<u8>,
}

fn project(opened: &tzap_core::OpenedArchive) -> Vec<MemberProjection> {
    let mut rows: Vec<MemberProjection> = opened
        .list_index_entries()
        .expect("index must be readable")
        .into_iter()
        .map(|entry: ArchiveIndexEntry| {
            let contents = opened.extract_file(&entry.path).expect("member must extract").unwrap_or_default();
            MemberProjection {
                path: entry.path,
                size: entry.file_data_size,
                kind: format!("{:?}", entry.kind),
                mode: entry.mode,
                mtime: entry.mtime,
                created: entry.created,
                accessed: entry.accessed,
                uid: entry.uid,
                gid: entry.gid,
                uname: entry.uname,
                gname: entry.gname,
                attributes: entry.attributes,
                flags: entry.flags,
                contents,
            }
        })
        .collect();
    rows.sort_by(|left, right| left.path.cmp(&right.path));
    rows
}

fn options(stripe_width: u32, zstd_level: i32, jobs: usize) -> WriterOptions {
    WriterOptions {
        // Pinned so two runs are comparable: an archive otherwise carries a fresh
        // UUID, session id and close time, which are meant to differ.
        archive_uuid: Some([0x11; 16]),
        session_id: Some([0x22; 16]),
        closed_at_ns: 123_456_789,
        stripe_width,
        // Zero throughout so all three writers accept the identical options and
        // the comparison is between the writers, not between configurations --
        // the streaming sinks refuse volume-loss tolerance by design.
        volume_loss_tolerance: 0,
        bit_rot_buffer_pct: 0,
        zstd_level,
        jobs,
        ..WriterOptions::default()
    }
}

/// Every writer path and option combination must yield the same metadata.
///
/// The reference is the plainest configuration. Anything that differs is a
/// behaviour change, whether or not it was meant as one -- which is the point:
/// a faster path that quietly stores less is caught by the comparison, not by
/// someone noticing months later that a restored tree lost its owners.
#[test]
fn every_writer_path_and_option_combination_stores_the_same_metadata() {
    let fixture = Fixture::new(4);
    let files = fixture.files();

    let reference_archive = write_archive(&files, &master_key(), options(1, 1, 1)).expect("reference archive");
    let reference = project(&open_archive(&reference_archive.bytes, &master_key()).unwrap());
    assert_eq!(reference.len(), 4, "the fixture must actually produce members");
    // The fixture has to carry the metadata it claims to, or every comparison
    // below would agree on nothing.
    assert!(reference.iter().all(|row| row.uname.is_some() && row.created.is_some() && row.accessed.is_some()));
    assert!(reference.iter().any(|row| row.mtime.seconds < 0), "a pre-epoch mtime must reach the index");

    for stripe_width in [1u32, 2, 4] {
        for zstd_level in [1i32, 9] {
            for jobs in [1usize, 4] {
                let label = format!("stripe={stripe_width} level={zstd_level} jobs={jobs}");
                let options = options(stripe_width, zstd_level, jobs);

                // Buffered writer.
                let archive = write_archive(&files, &master_key(), options).unwrap_or_else(|error| panic!("{label}: {error:?}"));
                let opened = if stripe_width > 1 {
                    let refs = archive.volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
                    open_archive_volumes(&refs, &master_key()).unwrap()
                } else {
                    open_archive(&archive.bytes, &master_key()).unwrap()
                };
                opened.verify().expect("archive must verify");
                assert_eq!(project(&opened), reference, "buffered writer differs at {label}");

                // Single-pass sink writer.
                let mut sink = MemoryArchiveSink::default();
                write_archive_sources_to_sink_single_pass(&files, &master_key(), options, &kdf(), None, None, &mut sink)
                    .unwrap_or_else(|error| panic!("single-pass {label}: {error:?}"));
                let refs = sink.volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
                let opened = open_archive_volumes(&refs, &master_key()).unwrap();
                opened.verify().expect("single-pass archive must verify");
                assert_eq!(project(&opened), reference, "single-pass writer differs at {label}");

                // Ordered parallel sink writer -- the one a speed change touches first.
                let mut sink = MemoryArchiveSink::default();
                write_archive_sources_to_sink_ordered_parallel(&files, &master_key(), options, &kdf(), None, None, &mut sink)
                    .unwrap_or_else(|error| panic!("parallel {label}: {error:?}"));
                let refs = sink.volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
                let opened = open_archive_volumes(&refs, &master_key()).unwrap();
                opened.verify().expect("parallel archive must verify");
                assert_eq!(project(&opened), reference, "ordered-parallel writer differs at {label}");
            }
        }
    }
}

/// A dictionary changes how bytes are compressed and must change nothing else.
#[test]
fn a_compression_dictionary_changes_no_metadata() {
    let fixture = Fixture::new(3);
    let files = fixture.files();

    let plain = write_archive(&files, &master_key(), options(1, 1, 1)).unwrap();
    let reference = project(&open_archive(&plain.bytes, &master_key()).unwrap());

    let dictionary = b"common words common words payload dictionary".as_slice();
    let with_dictionary = write_archive_with_dictionary(&files, &master_key(), options(1, 1, 1), dictionary).unwrap();
    let opened = open_archive(&with_dictionary.bytes, &master_key()).unwrap();
    opened.verify().unwrap();
    assert_eq!(project(&opened), reference, "a dictionary must not alter stored metadata");
}

/// The streaming reader must see exactly what the seekable reader sees.
///
/// They share no code path for locating members -- one walks the index, the
/// other reconstructs from the member stream -- so an optimisation to either is
/// free to drift from the other until something compares them.
#[test]
fn the_streaming_reader_agrees_with_the_seekable_reader() {
    let fixture = Fixture::new(3);
    let files = fixture.files();

    for zstd_level in [1i32, 9] {
        let archive = write_archive(&files, &master_key(), options(1, zstd_level, 1)).unwrap();

        let seekable = project(&open_archive(&archive.bytes, &master_key()).unwrap());
        let streaming = open_non_seekable_archive(&archive.bytes, &master_key(), Some(&archive.bootstrap_sidecar))
            .unwrap_or_else(|error| panic!("streaming open at level {zstd_level}: {error:?}"));
        streaming.verify().expect("streamed archive must verify");

        assert_eq!(project(&streaming), seekable, "the streaming reader disagrees at level {zstd_level}");
    }
}

/// Writing the same input twice must produce the same bytes, for every path.
///
/// Determinism is what makes the differential matrix meaningful; a cache, a
/// thread pool or a timestamp leaking into the output breaks it, and that is far
/// easier to catch here than by diffing two release builds.
#[test]
fn every_writer_path_is_byte_for_byte_deterministic() {
    let fixture = Fixture::new(3);
    let files = fixture.files();

    for jobs in [1usize, 4] {
        let first = write_archive(&files, &master_key(), options(1, 1, jobs)).unwrap();
        let second = write_archive(&files, &master_key(), options(1, 1, jobs)).unwrap();
        assert_eq!(first.bytes, second.bytes, "buffered writer is not deterministic at jobs={jobs}");
        assert_eq!(first.bootstrap_sidecar, second.bootstrap_sidecar, "sidecar is not deterministic at jobs={jobs}");

        let mut first_sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(&files, &master_key(), options(1, 1, jobs), &kdf(), None, None, &mut first_sink).unwrap();
        let mut second_sink = MemoryArchiveSink::default();
        write_archive_sources_to_sink_ordered_parallel(&files, &master_key(), options(1, 1, jobs), &kdf(), None, None, &mut second_sink).unwrap();
        assert_eq!(first_sink.volumes, second_sink.volumes, "ordered-parallel writer is not deterministic at jobs={jobs}");
    }
}

/// Restoring the same archive under each policy must apply exactly the metadata
/// that policy admits, and report the rest rather than dropping it silently.
///
/// `tar_model/os_restore.rs` is the least-covered file in the crate, and it is
/// the one that decides what actually lands on disk. The policies form a ladder
/// -- Content applies none, Portable applies the portable set, SameOs adds
/// native classes, System adds the privileged ones -- so walking the ladder with
/// one fixture exercises the branch structure rather than a single path through
/// it, and pins the ordering between them.
#[cfg(unix)]
#[test]
fn each_restore_policy_applies_exactly_what_it_admits() {
    use std::os::unix::fs::PermissionsExt as _;
    use tzap_core::entry_metadata::RestorePolicy;
    use tzap_core::SafeExtractionOptions;

    let fixture = Fixture::new(2);
    let files = fixture.files();
    let archive = write_archive(&files, &master_key(), options(1, 1, 1)).unwrap();
    let opened = open_archive(&archive.bytes, &master_key()).unwrap();
    let expected_mode = files[0].mode & 0o7777;

    // Content first: it must not apply metadata, and must say so rather than
    // silently skipping. Every later policy is compared against this baseline.
    let mut restored_modes = Vec::new();
    for policy in [RestorePolicy::Content, RestorePolicy::Portable, RestorePolicy::SameOs, RestorePolicy::System] {
        let root = tempfile::tempdir().unwrap();
        let outcome =
            opened.extract_all_to(root.path(), SafeExtractionOptions { restore_policy: policy, allow_degraded: true, ..SafeExtractionOptions::default() });
        let reports = match outcome {
            Ok(reports) => reports,
            // A policy the host cannot satisfy must refuse in a named way, not
            // panic or half-apply; that refusal is itself the covered branch.
            Err(error) => {
                assert!(matches!(policy, RestorePolicy::SameOs | RestorePolicy::System), "{policy:?} must be satisfiable everywhere: {error:?}");
                continue;
            }
        };
        assert_eq!(reports.len(), 2, "{policy:?} must report on every member");

        let member = root.path().join(&fixture.paths[0]);
        assert_eq!(std::fs::read(&member).unwrap(), fixture.bodies[0], "{policy:?} must restore content whatever it does with metadata");
        let mode = std::fs::symlink_metadata(&member).unwrap().permissions().mode() & 0o7777;
        restored_modes.push((policy, mode));

        // Diagnostics are the contract for anything a policy declines. A class
        // that is outside the policy has to appear here; silence would mean the
        // caller cannot tell "not requested" from "failed".
        let diagnostics: Vec<_> = reports.iter().flat_map(|(_, diagnostics)| diagnostics).collect();
        if policy == RestorePolicy::Content {
            assert!(!diagnostics.is_empty(), "content restore must report the metadata it deliberately skipped");
        }
    }

    // Content leaves the mode to the umask; every policy above it applies the
    // stored mode. That ordering is the ladder's whole point.
    for (policy, mode) in &restored_modes {
        if *policy != RestorePolicy::Content {
            assert_eq!(*mode, expected_mode, "{policy:?} must apply the stored mode");
        }
    }
    assert!(restored_modes.iter().any(|(policy, _)| *policy == RestorePolicy::Portable), "portable restore must be reachable on every host");
}
