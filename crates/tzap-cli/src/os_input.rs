use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::SystemTime;

#[cfg(windows)]
use crate::commands::archive_path_to_string;
#[cfg(windows)]
use crate::commands::create::InputSpec;
#[cfg(target_os = "macos")]
use anyhow::anyhow;
#[cfg(windows)]
use anyhow::bail;
#[cfg(windows)]
use anyhow::Context;
use anyhow::Result;
#[cfg(windows)]
use tzap_core::SourceEntryKind;
use tzap_core::{ArchiveTimestamp, NativeFileMetadata, PortableFileMetadata, SparseExtent};

#[cfg(windows)]
pub(crate) use tzap_core::windows_metadata::{
    add_refs_sparse_layout_omission as add_windows_refs_sparse_layout_omission, open_windows_metadata_handle, query_windows_allocated_ranges,
    query_windows_reparse_data, unsupported_windows_file_attribute_reason, validate_windows_known_reparse_data, windows_file_system_is_refs,
    WindowsKnownReparse,
};

#[cfg(unix)]
pub(crate) fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}
#[cfg(not(unix))]
pub(crate) fn readonly_mode(metadata: &fs::Metadata) -> u32 {
    // Hosts without a POSIX mode project one, and tzap-core owns that convention so
    // the CLI and other hosts cannot drift apart on it. See
    // `entry_metadata::projected_posix_mode` for why a directory ignores the
    // read-only attribute while a regular file keeps it.
    tzap_core::entry_metadata::projected_posix_mode(metadata.is_dir(), metadata.permissions().readonly())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InputIdentity {
    pub(crate) len: u64,
    pub(crate) mtime: ArchiveTimestamp,
    pub(crate) mode: u32,
    pub(crate) attributes: Option<u32>,
    #[cfg(unix)]
    pub(crate) uid: u64,
    #[cfg(unix)]
    pub(crate) gid: u64,
    #[cfg(unix)]
    pub(crate) raw_mode: u32,
    #[cfg(unix)]
    pub(crate) link_count: u64,
    #[cfg(unix)]
    pub(crate) change_time_seconds: i64,
    #[cfg(unix)]
    pub(crate) change_time_nanoseconds: i64,
    #[cfg(unix)]
    pub(crate) creation_time: Option<ArchiveTimestamp>,
    /// What the scan saw, in the form tzap-core's macOS capture compares against
    /// and its resource-fork reader re-checks. Carrying core's own type keeps the
    /// two ends of that check from drifting apart.
    #[cfg(target_os = "macos")]
    pub(crate) macos_identity: Option<tzap_core::macos_metadata::MacosMetadataIdentity>,
    #[cfg(unix)]
    pub(crate) dev: u64,
    #[cfg(unix)]
    pub(crate) ino: u64,
    #[cfg(windows)]
    pub(crate) creation_time_100ns: u64,
    #[cfg(windows)]
    pub(crate) last_access_time_100ns: u64,
    #[cfg(windows)]
    pub(crate) change_time_100ns: u64,
    #[cfg(windows)]
    pub(crate) file_attributes: u32,
    #[cfg(windows)]
    pub(crate) link_count: u64,
    #[cfg(windows)]
    pub(crate) volume_serial: u64,
    #[cfg(windows)]
    pub(crate) file_index: u64,
}

#[cfg(target_os = "linux")]
pub(crate) fn query_linux_sparse_extents(file: &File, logical_size: u64) -> io::Result<Option<Vec<SparseExtent>>> {
    use std::os::fd::AsRawFd;

    if logical_size == 0 {
        return Ok(None);
    }
    let end = libc::off_t::try_from(logical_size).map_err(|_| io::Error::other("file size exceeds Linux off_t"))?;
    let fd = file.as_raw_fd();
    let mut cursor: libc::off_t = 0;
    let mut extents = Vec::new();
    while cursor < end {
        // SAFETY: `fd` is live and SEEK_DATA does not mutate caller memory.
        let data = unsafe { libc::lseek(fd, cursor, libc::SEEK_DATA) };
        if data < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            if cursor == 0 && error.raw_os_error().is_some_and(|code| code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOTSUP) {
                return Ok(None);
            }
            return Err(error);
        }
        // SAFETY: as above, SEEK_HOLE only updates the descriptor offset.
        let hole = unsafe { libc::lseek(fd, data, libc::SEEK_HOLE) };
        if hole < 0 {
            return Err(io::Error::last_os_error());
        }
        let data = u64::try_from(data).map_err(|_| io::Error::other("negative data offset"))?;
        let hole = u64::try_from(hole).map_err(|_| io::Error::other("negative hole offset"))?;
        let hole = hole.min(logical_size);
        if hole <= data {
            return Err(io::Error::other("Linux sparse-range query did not advance"));
        }
        extents.push(SparseExtent { offset: data, length: hole - data });
        cursor = libc::off_t::try_from(hole).map_err(|_| io::Error::other("sparse offset exceeds Linux off_t"))?;
    }

    let allocated =
        extents.iter().try_fold(0u64, |sum, extent| sum.checked_add(extent.length).ok_or_else(|| io::Error::other("sparse extent length overflow")))?;
    Ok((allocated < logical_size).then_some(extents))
}

#[cfg(windows)]
pub(crate) fn collect_windows_known_reparse_input(input: &Path, archive_path: &Path, metadata: fs::Metadata, out: &mut Vec<InputSpec>) -> Result<()> {
    let file = open_windows_metadata_handle(input).with_context(|| format!("failed to open Windows reparse point {}", input.display()))?;
    let mut identity = input_identity(&metadata).with_context(|| format!("failed to identify reparse point {}", input.display()))?;
    augment_windows_input_identity(&mut identity, &file).with_context(|| format!("failed to identify reparse point {}", input.display()))?;
    let reparse_data = query_windows_reparse_data(&file).with_context(|| format!("failed to query reparse point {}", input.display()))?;
    let known = validate_windows_known_reparse_data(&reparse_data).with_context(|| format!("unsupported Windows reparse point {}", input.display()))?;
    let archive_path = archive_path_to_string(archive_path)?;
    let mut portable_metadata = portable_input_metadata(identity, input)?.metadata;
    match known {
        WindowsKnownReparse::RelativeSymlink { portable_target } => {
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: SourceEntryKind::Symlink,
                link_target: Some(portable_target),
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
        WindowsKnownReparse::Junction => {
            portable_metadata.native.primary_pax_records.insert("TZAP.windows.reparse-placeholder".into(), b"1".to_vec());
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: SourceEntryKind::ReparseDirectory,
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
        WindowsKnownReparse::Opaque => {
            portable_metadata.native.primary_pax_records.insert("TZAP.windows.reparse-placeholder".into(), b"1".to_vec());
            out.push(InputSpec {
                source: input.to_owned(),
                archive_path,
                entry_kind: if metadata.is_dir() { SourceEntryKind::ReparseDirectory } else { SourceEntryKind::ReparseRegular },
                link_target: None,
                mode: readonly_mode(&metadata),
                mtime: identity.mtime,
                portable_metadata,
                size: 0,
                sparse_extents: None,
                identity,
            });
        }
    }
    Ok(())
}

pub(crate) fn input_identity(metadata: &fs::Metadata) -> io::Result<InputIdentity> {
    Ok(InputIdentity {
        len: metadata.len(),
        mtime: archive_timestamp(metadata.modified()?)?,
        mode: readonly_mode(metadata),
        attributes: portable_attributes(metadata),
        #[cfg(unix)]
        uid: {
            use std::os::unix::fs::MetadataExt;
            metadata.uid() as u64
        },
        #[cfg(unix)]
        gid: {
            use std::os::unix::fs::MetadataExt;
            metadata.gid() as u64
        },
        #[cfg(unix)]
        raw_mode: {
            use std::os::unix::fs::MetadataExt;
            metadata.mode()
        },
        #[cfg(unix)]
        link_count: {
            use std::os::unix::fs::MetadataExt;
            metadata.nlink()
        },
        #[cfg(unix)]
        change_time_seconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime()
        },
        #[cfg(unix)]
        change_time_nanoseconds: {
            use std::os::unix::fs::MetadataExt;
            metadata.ctime_nsec()
        },
        #[cfg(unix)]
        creation_time: metadata.created().ok().and_then(|time| archive_timestamp(time).ok()),
        #[cfg(target_os = "macos")]
        macos_identity: Some(tzap_core::macos_metadata::MacosMetadataIdentity::from_metadata(metadata)),
        #[cfg(unix)]
        dev: {
            use std::os::unix::fs::MetadataExt;
            metadata.dev()
        },
        #[cfg(unix)]
        ino: {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        },
        #[cfg(windows)]
        creation_time_100ns: {
            use std::os::windows::fs::MetadataExt;
            metadata.creation_time()
        },
        #[cfg(windows)]
        last_access_time_100ns: {
            use std::os::windows::fs::MetadataExt;
            metadata.last_access_time()
        },
        #[cfg(windows)]
        change_time_100ns: 0,
        #[cfg(windows)]
        file_attributes: {
            use std::os::windows::fs::MetadataExt;
            metadata.file_attributes()
        },
        #[cfg(windows)]
        link_count: 0,
        #[cfg(windows)]
        volume_serial: 0,
        #[cfg(windows)]
        file_index: 0,
    })
}

pub(crate) fn validate_opened_input_identity(file: &File, expected: InputIdentity) -> io::Result<()> {
    let actual_metadata = file.metadata()?;
    let actual = input_identity(&actual_metadata)?;
    #[cfg(windows)]
    let actual = {
        let mut actual = actual;
        augment_windows_input_identity(&mut actual, file)?;
        actual
    };
    if !input_identity_matches_after_read(expected, actual) {
        return Err(io::Error::other("input changed after scan"));
    }
    Ok(())
}

pub(crate) fn input_identity_matches_after_read(expected: InputIdentity, actual: InputIdentity) -> bool {
    #[cfg(windows)]
    {
        let mut expected = expected;
        let mut actual = actual;
        // Opening and reading the file may update LastAccessTime. Preserve the pre-read value in
        // the archive, but exclude this self-induced field from the final source identity check.
        expected.last_access_time_100ns = 0;
        actual.last_access_time_100ns = 0;
        expected == actual
    }
    #[cfg(all(unix, not(windows)))]
    {
        expected == actual
    }
    #[cfg(not(any(unix, windows)))]
    {
        expected == actual
    }
}

#[cfg(windows)]
// The CLI only maps core's platform identity into its scan model; Windows API
// queries and metadata policy remain owned by tzap-core.
pub(crate) fn augment_windows_input_identity(identity: &mut InputIdentity, file: &File) -> io::Result<()> {
    let observed = tzap_core::windows_metadata::query_windows_input_identity(file)?;
    identity.creation_time_100ns = observed.creation_time_100ns;
    identity.last_access_time_100ns = observed.last_access_time_100ns;
    identity.change_time_100ns = observed.change_time_100ns;
    identity.file_attributes = observed.file_attributes;
    identity.link_count = observed.link_count;
    identity.volume_serial = observed.volume_serial;
    identity.file_index = observed.file_index;
    Ok(())
}

pub(crate) struct IdentityCheckedInputReader {
    pub(crate) file: File,
    pub(crate) expected: InputIdentity,
    pub(crate) remaining: u64,
    pub(crate) validated: bool,
    /// The archive path, so a note can name what the person recognises.
    pub(crate) path: String,
}

pub(crate) struct SparseExtentInputReader<'a> {
    pub(crate) file: File,
    pub(crate) expected: InputIdentity,
    pub(crate) expected_extents: &'a [SparseExtent],
    pub(crate) extent_index: usize,
    pub(crate) extent_remaining: u64,
    pub(crate) validated: bool,
    /// The archive path, so a note can name what the person recognises.
    pub(crate) path: String,
}

impl SparseExtentInputReader<'_> {
    /// Total bytes this member promised: the allocated extents, not the logical
    /// size. That sum is already in the member header, so it is what must be
    /// delivered however the file behaves from here.
    fn promised(&self) -> u64 {
        self.expected_extents.iter().map(|extent| extent.length).sum()
    }

    /// Bytes still owed once the current extent and every later one are counted.
    fn still_owed(&self) -> u64 {
        self.extent_remaining + self.expected_extents.iter().skip(self.extent_index + 1).map(|extent| extent.length).sum::<u64>()
    }

    /// Note that this member's bytes are as of the moment archiving started.
    ///
    /// The sparse path reaches this for the same reasons the dense one does -- a
    /// live file shortened or rewritten underneath the read -- and owes the same
    /// answer. Failing the whole archive here while the dense path pads and
    /// reports made the outcome depend on whether the file happened to have
    /// holes, which is not something the person chose.
    fn note_changed(&mut self, padded: u64) {
        if self.validated {
            return;
        }
        self.validated = true;
        record_input_changed_during_read(&self.path, self.promised(), padded);
    }

    fn validate_finished(&mut self) {
        if self.validated {
            return;
        }
        if validate_opened_input_identity(&self.file, self.expected).is_err() {
            self.note_changed(0);
            return;
        }
        #[cfg(windows)]
        if query_windows_allocated_ranges(&self.file, self.expected.len).is_ok_and(|ranges| ranges != self.expected_extents) {
            self.note_changed(0);
            return;
        }
        self.validated = true;
    }
}

impl Read for SparseExtentInputReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.extent_remaining == 0 {
                let (offset, length) = match self.expected_extents.get(self.extent_index) {
                    Some(extent) => (extent.offset, extent.length),
                    None => {
                        self.validate_finished();
                        break;
                    }
                };
                // Count the extent as owed before attempting the seek, so a seek
                // failure reports this extent's bytes as well as every later one.
                self.extent_remaining = length;
                if self.file.seek(SeekFrom::Start(offset)).is_err() {
                    let shortfall = self.still_owed();
                    return Ok(self.pad_remaining(out, written, shortfall));
                }
            }
            let count = (out.len() - written).min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                // The file was shortened or rewritten mid-archive. The member's
                // stored length is already promised in its header, so fill the
                // rest with zeros exactly as the dense path does -- a short
                // member would leave every later member unreadable.
                //
                // The shortfall is everything still owed across this extent and
                // all later ones, not just this chunk: the file is at EOF and no
                // further extent can produce bytes either.
                let shortfall = self.still_owed();
                return Ok(self.pad_remaining(out, written, shortfall));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished();
        }
        Ok(written)
    }
}

impl SparseExtentInputReader<'_> {
    /// Zero-fill the rest of this buffer and account for the whole shortfall.
    ///
    /// Advances past every remaining extent so subsequent reads keep supplying
    /// zeros until the promised length is met, then stop.
    fn pad_remaining(&mut self, out: &mut [u8], written: usize, shortfall: u64) -> usize {
        let fill = out.len() - written;
        let fill = usize::try_from(shortfall).unwrap_or(usize::MAX).min(fill);
        out[written..written + fill].fill(0);
        let consumed = fill as u64;
        // Walk the extent cursor forward by what was just emitted, so the next
        // call resumes owing exactly the remainder.
        let mut left = consumed;
        while left > 0 {
            if self.extent_remaining == 0 {
                match self.expected_extents.get(self.extent_index) {
                    Some(extent) => self.extent_remaining = extent.length,
                    None => break,
                }
            }
            let step = left.min(self.extent_remaining);
            self.extent_remaining -= step;
            left -= step;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        self.note_changed(shortfall);
        written + fill
    }
}

impl IdentityCheckedInputReader {
    /// Note that this member's bytes are as of the moment archiving started.
    ///
    /// A file being appended to or truncated while it is archived is ordinary on
    /// a live system -- a log rotating, a database checkpointing, a build still
    /// running -- so the archive is completed and the person is told, rather than
    /// the whole run being refused over a file they do not control. The size was
    /// promised in the member header before its bytes were written, so honouring
    /// that promise exactly is also the only way to keep the archive readable.
    fn note_changed(&mut self, padded: u64) {
        if self.validated {
            return;
        }
        self.validated = true;
        record_input_changed_during_read(&self.path, self.expected.len, padded);
    }
}

impl Read for IdentityCheckedInputReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if !self.validated && validate_opened_input_identity(&self.file, self.expected).is_err() {
                self.note_changed(0);
            }
            self.validated = true;
            return Ok(0);
        }
        let max_read = out.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.file.read(&mut out[..max_read])?;
        if count == 0 {
            // The file was shortened mid-archive. Fill the rest of the promised
            // length with zeros: a short member would leave every later member
            // unreadable. GNU tar and libarchive both pad here.
            //
            // The shortfall is everything still owed, not this one chunk. The file
            // is at EOF and the member's length is already promised, so every byte
            // left will be a zero. Reporting the chunk instead inverted the whole
            // message: a 300 MB file truncated to 1 MB said "kept the 299.9 MB
            // still there and filled the remaining 8.0 KB with zeros" when 276 MB
            // of the member had in fact become zeros.
            let shortfall = self.remaining;
            out[..max_read].fill(0);
            self.remaining -= max_read as u64;
            self.note_changed(shortfall);
            return Ok(max_read);
        }
        self.remaining -= count as u64;
        if self.remaining == 0 {
            if validate_opened_input_identity(&self.file, self.expected).is_err() {
                self.note_changed(0);
            }
            self.validated = true;
        }
        Ok(count)
    }
}

/// Inputs that moved while they were being archived, for the run to report.
///
/// Collected here rather than threaded through every source because the reader
/// is handed to the writer as a `dyn Read` with no channel back, and one archive
/// run is one process.
static CHANGED_DURING_READ: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn record_input_changed_during_read(path: &str, declared: u64, padded: u64) {
    // Substituted bytes are content this archive does not hold. That is the same
    // thing `note_input_vanished_before_read` reports, and it has to reach the
    // exit code the same way -- a backup that silently stored 276 MB of zeros in
    // place of real data must not report success. A file that merely changed
    // underneath the read is still a complete member and stays a note.
    if padded > 0 {
        mark_archive_incomplete();
    }
    let note = if padded > 0 {
        let kept = declared.saturating_sub(padded);
        format!(
            "{path} was shortened while being archived; kept the {} still there and filled the remaining {} with zeros",
            tzap_core::entry_metadata::human_bytes(kept),
            tzap_core::entry_metadata::human_bytes(padded)
        )
    } else {
        format!(
            "{path} was still being written while being archived; stored the {} it had when archiving started",
            tzap_core::entry_metadata::human_bytes(declared)
        )
    };
    if let Ok(mut notes) = CHANGED_DURING_READ.lock() {
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
}

/// One input this run left out, and whether leaving it out took more with it.
pub(crate) struct SkippedInput {
    pub(crate) note: String,
    /// The input was a directory, so its contents were skipped along with it.
    /// The scan never enumerated them, so there is no count to report -- only
    /// the fact, which is what stops the summary claiming the archive holds
    /// everything else.
    pub(crate) took_contents: bool,
}

/// Note an input this run could not archive, so the rest still can be.
///
/// Refusing the whole archive because one file is unreadable is not what an
/// archiver should do, and is not what any of the established ones do: GNU tar
/// warns and exits 2, bsdtar warns and exits 1, 7-Zip warns and exits 1 -- all
/// three still write the archive with everything they could read. A backup that
/// produces nothing because one file had the wrong permissions is worse than a
/// backup that is honest about what it skipped.
///
/// `took_contents` says the skipped input was a directory. Its children are not
/// separately reported -- a directory is usually skipped precisely because it
/// could not be enumerated -- so the summary has to say plainly that more than
/// the named entry is missing.
pub(crate) fn note_input_skipped(path: &Path, reason: &str, took_contents: bool) {
    let note = format!("skipped {}: {reason}", path.display());
    if let Ok(mut notes) = SKIPPED_INPUTS.lock() {
        if !notes.iter().any(|existing| existing.note == note) {
            notes.push(SkippedInput { note, took_contents });
        }
    }
}

/// Whether `path` is a directory, for the skip notes.
///
/// A directory is commonly skipped because it could not be read, but the failure
/// that makes it unreadable is its own -- `symlink_metadata` goes through the
/// parent, so the kind is still knowable. An unknowable kind reports `false`:
/// claiming contents were lost when they were not is its own wrong answer.
pub(crate) fn skipped_input_took_contents(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir())
}

static SKIPPED_INPUTS: std::sync::Mutex<Vec<SkippedInput>> = std::sync::Mutex::new(Vec::new());

/// Whether this run left something out of the archive it produced.
///
/// Separate from the error path because the archive exists and is valid: the
/// caller gets it, and the exit code says it is not the whole story. This is the
/// distinction GNU tar draws with exit 2 and 7-Zip with exit 1.
static ARCHIVE_INCOMPLETE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub(crate) fn mark_archive_incomplete() {
    ARCHIVE_INCOMPLETE.store(true, std::sync::atomic::Ordering::Relaxed);
}

pub(crate) fn archive_was_incomplete() -> bool {
    ARCHIVE_INCOMPLETE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Everything this run could not archive, in the order it was noticed.
pub(crate) fn take_skipped_inputs() -> Vec<SkippedInput> {
    SKIPPED_INPUTS.lock().map(|mut notes| std::mem::take(&mut *notes)).unwrap_or_default()
}

/// How many inputs have been skipped so far, without draining them.
///
/// The dry-run summary reports the count inline and then lets
/// `report_inputs_not_fully_archived` name them, so it must not consume the
/// buffer on the way past.
pub(crate) fn skipped_input_count() -> usize {
    SKIPPED_INPUTS.lock().map(|notes| notes.len()).unwrap_or(0)
}

/// Note an input that became unreadable between the scan and the read.
///
/// Distinct from a file that merely changed: nothing of it could be read at all,
/// so the member is entirely zeros. Worth its own wording -- "stored as zeros"
/// is a materially different thing to be told than "shortened".
pub(crate) fn note_input_vanished_before_read(path: &str, declared: u64, error: &io::Error) {
    let note = format!(
        "{path} could not be read when its contents were archived ({error}); stored {} of zeros in its place",
        tzap_core::entry_metadata::human_bytes(declared)
    );
    if let Ok(mut notes) = CHANGED_DURING_READ.lock() {
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
    mark_archive_incomplete();
}

/// Directories archived without their platform-native metadata.
///
/// Kept apart from `CHANGED_DURING_READ` because these are recorded during the
/// scan, which can still abandon the directory afterwards, while that buffer is
/// filled by the writer's threads during the read. Separating them makes
/// [`rollback_degraded_directories`] provably safe: nothing else writes here
/// while the scan runs, so a mark taken before an input still describes the same
/// buffer when that input is abandoned.
static DEGRADED_DIRECTORIES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Note a directory archived without its platform-native metadata.
///
/// Reported, not fatal, and not an incomplete archive: the directory and
/// everything inside it are present, with mode, ownership and times intact. Only
/// the native layer -- xattrs, ACL, flags -- is missing, because the directory
/// would not hold still long enough to read it.
///
/// The claim is only true if the directory is still archived when the scan ends.
/// The same permission failure that hides a directory's xattrs usually also
/// fails the `read_dir` that follows, and the note was emitted first: an
/// unreadable directory announced "archived it and everything inside it" and was
/// then skipped entirely, two lines apart. [`rollback_degraded_directories`] is
/// how the scan retracts it.
pub(crate) fn note_directory_metadata_degraded(path: &Path, reason: &str) {
    let note =
        format!("{}: could not read the directory's own extended metadata ({reason}); archived it and everything inside it without that layer", path.display());
    if let Ok(mut notes) = DEGRADED_DIRECTORIES.lock() {
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
}

/// How many degraded-directory notes stand, for a caller about to try an input
/// it may have to abandon.
pub(crate) fn degraded_directory_mark() -> usize {
    DEGRADED_DIRECTORIES.lock().map(|notes| notes.len()).unwrap_or(0)
}

/// Drop every degraded-directory note recorded since `mark`.
///
/// The scan is sequential -- `collect_input_specs` walks inputs one at a time,
/// and the writer has not started -- so the notes above `mark` are exactly the
/// ones the abandoned input produced.
pub(crate) fn rollback_degraded_directories(mark: usize) {
    if let Ok(mut notes) = DEGRADED_DIRECTORIES.lock() {
        if mark <= notes.len() {
            notes.truncate(mark);
        }
    }
}

/// Every directory archived with degraded metadata, in the order it was noticed.
pub(crate) fn take_degraded_directories() -> Vec<String> {
    DEGRADED_DIRECTORIES.lock().map(|mut notes| std::mem::take(&mut *notes)).unwrap_or_default()
}

/// Note a regular input that moved between the scan and the read of its bytes.
/// Open a regular input for archiving, denying writers while it is read.
///
/// This is 7-Zip's default (`CArchiveUpdateCallback::GetStream2` opens with
/// `ShareForWrite = false`; `-ssw` opts back in). Windows share modes make the
/// race preventable rather than something to detect and paper over, which is
/// why it is the first thing to reach for there.
///
/// POSIX has no equivalent -- its locks are advisory -- so on those hosts this
/// is an ordinary open and the reader's clamp-and-pad still carries the load.
pub(crate) fn open_input_for_archiving(path: &Path) -> io::Result<File> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // FILE_SHARE_READ only: another reader is fine, a writer is not. Rust's
        // `File::open` would also permit FILE_SHARE_WRITE and FILE_SHARE_DELETE.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).open(path)
    }
    #[cfg(not(windows))]
    {
        File::open(path)
    }
}

pub(crate) fn note_input_changed_before_read(path: &str, declared: u64) {
    record_input_changed_during_read(path, declared, 0);
}

/// Note a hardlink alias stored as a full copy instead of a link.
///
/// The two names for one inode stopped agreeing between the two stats that saw
/// them, so the topology cannot be recorded from a settled observation. Storing
/// the entry in full is always correct -- only larger -- whereas writing an alias
/// from a stale observation points a link at a file that may have changed.
///
/// Not an incomplete archive: every byte of the entry is present. It is a note
/// because the restored tree will have two independent files where the source had
/// two names for one, and that is worth knowing.
pub(crate) fn note_hardlink_not_grouped(path: &str) {
    let note =
        format!("{path} shares an inode with another input, but the inode changed while they were being scanned; stored it in full instead of as a hardlink");
    if let Ok(mut notes) = CHANGED_DURING_READ.lock() {
        if !notes.contains(&note) {
            notes.push(note);
        }
    }
}

/// Everything that moved during this run, in the order it was noticed.
pub(crate) fn take_inputs_changed_during_read() -> Vec<String> {
    CHANGED_DURING_READ.lock().map(|mut notes| std::mem::take(&mut *notes)).unwrap_or_default()
}

pub(crate) fn archive_timestamp(time: SystemTime) -> io::Result<ArchiveTimestamp> {
    // tzap-core owns this conversion, so this host and zmanager cannot disagree
    // about it. `ArchiveTimestamp` is a timespec (`tv_sec` plus an always-positive
    // `tv_nsec`), which is what the restore paths feed straight into
    // `libc::timespec`, `fsetattrlist`, and the FILETIME math; the §16.7.2
    // sign-and-magnitude form is produced only by `canonical_pax_value`.
    tzap_core::entry_metadata::archive_timestamp_from_system_time(time).ok_or_else(|| io::Error::other("input mtime exceeds revision-45 i64 range"))
}

#[cfg(windows)]
pub(crate) fn reject_unsupported_windows_regular_file(metadata: &fs::Metadata, input: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    let attributes = metadata.file_attributes();
    if let Some(reason) = unsupported_windows_file_attribute_reason(attributes) {
        bail!("Windows metadata capture does not support {}: {reason}", input.display());
    }
    Ok(())
}

/// A native capture plus whatever the host needs to re-open the same object.
///
/// Only macOS has such a handle today: its resource fork is opened separately
/// from the capture, and must be proven to belong to the object the capture read.
#[derive(Debug)]
pub(crate) struct CapturedNativeMetadata {
    pub(crate) native: NativeFileMetadata,
    #[cfg(target_os = "macos")]
    pub(crate) macos_identity: Option<tzap_core::macos_metadata::MacosMetadataIdentity>,
}

/// Portable metadata for one input, plus the same re-open handle.
pub(crate) struct CapturedInputMetadata {
    pub(crate) metadata: PortableFileMetadata,
    #[cfg(target_os = "macos")]
    pub(crate) macos_identity: Option<tzap_core::macos_metadata::MacosMetadataIdentity>,
    /// ReFS cannot report exact allocated ranges, so a sparse claim from it is
    /// partial by construction and must be declared as such.
    #[cfg(windows)]
    pub(crate) sparse_layout_partial: bool,
}

/// Whether a capture insists the object still matches the identity the scan saw.
///
/// A directory's mtime, ctime and size change every time a child is created,
/// renamed or removed. That is ordinary activity, not the object being replaced,
/// so holding a directory to a scan-time identity fails on any directory anyone
/// is using -- and, because the expectation is fixed the moment the scan takes
/// it, fails again on every retry. The capture's own open-compare-recompare still
/// catches a directory swapped underneath it, which is the thing worth catching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IdentityExpectation {
    /// The object must still be exactly the one the scan identified.
    Strict,
    /// Describe whatever object is at the path now, coherently.
    Relaxed,
}

pub(crate) fn portable_input_metadata(identity: InputIdentity, input: &Path) -> Result<CapturedInputMetadata> {
    portable_input_metadata_expecting(identity, input, IdentityExpectation::Strict)
}

pub(crate) fn portable_input_metadata_expecting(identity: InputIdentity, input: &Path, expectation: IdentityExpectation) -> Result<CapturedInputMetadata> {
    // tzap-core owns the portable assembly -- source OS, mode origin, owner-name
    // resolution, and the optional-time rules -- so this host and zmanager cannot
    // disagree about it. What stays here is genuinely this host's: the sparse and
    // reparse handling layered on top, and the scan identity it captures against.
    let metadata = fs::symlink_metadata(input)?;
    let (created, accessed) = portable_optional_times(&metadata);
    let captured = capture_native_file_metadata_expecting(input, identity, expectation)?;
    Ok(CapturedInputMetadata {
        metadata: tzap_core::portable_capture::assemble_portable_file_metadata(
            captured.native,
            portable_owner_ids(&identity),
            identity.attributes,
            created,
            accessed,
        ),
        #[cfg(target_os = "macos")]
        macos_identity: captured.macos_identity,
        #[cfg(windows)]
        sparse_layout_partial: false,
    })
}

/// Portable metadata only, for an input whose native capture could not be taken.
///
/// Mode, ownership and times still describe the object; what is missing is the
/// platform-native layer -- xattrs, ACL, flags. Used for a directory that keeps
/// losing the capture race, because the alternative this replaced was to drop the
/// directory *and everything inside it* from the archive over its own xattrs.
pub(crate) fn portable_only_input_metadata(identity: InputIdentity, input: &Path) -> Result<CapturedInputMetadata> {
    let _ = fs::symlink_metadata(input)?;
    // No creation or access time either. Both are owned by `posix-backup-v1`
    // (§16.7.1), and declaring that profile on an entry carrying none of its
    // metadata would tell a reader to expect a native layer that is not there.
    // Dropping them says plainly what happened: this entry is portable-only.
    Ok(CapturedInputMetadata {
        metadata: tzap_core::portable_capture::assemble_portable_file_metadata(
            NativeFileMetadata::default(),
            portable_owner_ids(&identity),
            identity.attributes,
            None,
            None,
        ),
        #[cfg(target_os = "macos")]
        macos_identity: None,
        #[cfg(windows)]
        sparse_layout_partial: false,
    })
}

/// Whether an error is the transient capture race, recognised through whatever
/// context this host added on the way up.
///
/// Renders the whole chain: the capture sites qualify their wording, and this
/// host appends the path, so matching only the outermost message would miss it.
pub(crate) fn is_capture_race(error: &anyhow::Error) -> bool {
    let rendered = format!("{error:#}");
    rendered.contains(tzap_core::portable_capture::CAPTURE_RACE_MARKER) || rendered.contains(tzap_core::portable_capture::CAPTURE_PREOPEN_RACE_MARKER)
}

/// Run one complete observation -- stat, identify, capture -- retrying the whole
/// thing when it loses a race with a concurrent writer.
///
/// Every attempt re-observes. Sampling the identity once and retrying only the
/// capture against it, which the directory and symlink paths did, cannot converge:
/// the expectation is stale from the first failure onwards, so all three attempts
/// fail against an object that has long since settled. Measured directly -- a
/// directory changed once and then left alone still burned the whole budget,
/// while a freshly observed identity succeeded immediately.
pub(crate) fn observe_with_capture_retry<T>(mut observe: impl FnMut() -> Result<T>) -> Result<T> {
    for attempt in 0..tzap_core::portable_capture::CAPTURE_ATTEMPTS {
        match observe() {
            Ok(value) => return Ok(value),
            Err(error) if attempt + 1 < tzap_core::portable_capture::CAPTURE_ATTEMPTS && is_capture_race(&error) => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the retry loop returns from every attempt")
}

pub(crate) fn portable_symlink_metadata(identity: InputIdentity, _input: &Path) -> Result<CapturedInputMetadata> {
    // A symlink carries no creation or access time of its own worth recording.
    #[cfg(target_os = "linux")]
    let captured = CapturedNativeMetadata { native: capture_linux_symlink_metadata(_input, identity)? };
    #[cfg(target_os = "macos")]
    let captured = capture_macos_symlink_metadata(_input, identity)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let captured = CapturedNativeMetadata { native: NativeFileMetadata::default() };
    Ok(CapturedInputMetadata {
        metadata: tzap_core::portable_capture::assemble_portable_file_metadata(captured.native, portable_owner_ids(&identity), identity.attributes, None, None),
        #[cfg(target_os = "macos")]
        macos_identity: captured.macos_identity,
        #[cfg(windows)]
        sparse_layout_partial: false,
    })
}

/// Creation and access times for the portable record.
///
/// Both are optional, so a time the format cannot encode is dropped rather than
/// failing the archive -- the rule tzap-core states and applies in
/// `capture_portable_file_metadata`, which this host must not diverge from.
/// `mtime` is deliberately not here: losing it silently is a different decision.
fn portable_optional_times(metadata: &fs::Metadata) -> (Option<ArchiveTimestamp>, Option<ArchiveTimestamp>) {
    let encodable = |time: ArchiveTimestamp| time.canonical_pax_value().is_ok().then_some(time);
    let created = metadata.created().ok().and_then(|time| archive_timestamp(time).ok()).and_then(encodable);
    // std cannot expose the birth time on musl (statx/STATX_BTIME is unsupported
    // there), so fall back to ctime as core does -- otherwise this host silently
    // drops a creation time that zmanager records on the same file.
    #[cfg(target_os = "linux")]
    let created = created.or_else(|| {
        use std::os::unix::fs::MetadataExt as _;
        Some(ArchiveTimestamp::new(metadata.ctime(), u32::try_from(metadata.ctime_nsec()).unwrap_or(0)))
    });
    #[cfg(target_os = "linux")]
    let created = created.and_then(encodable);
    (created, metadata.accessed().ok().and_then(|time| archive_timestamp(time).ok()).and_then(encodable))
}

/// Ownership as observed when the input was first identified, not re-read here:
/// the archive must describe the object the scan saw.
#[cfg(unix)]
fn portable_owner_ids(identity: &InputIdentity) -> Option<(u64, u64)> {
    Some((identity.uid, identity.gid))
}

#[cfg(not(unix))]
fn portable_owner_ids(_identity: &InputIdentity) -> Option<(u64, u64)> {
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_linux_symlink_metadata(input: &Path, _identity: InputIdentity) -> Result<NativeFileMetadata> {
    tzap_core::portable_capture::with_capture_retry(|| tzap_core::linux_metadata::capture_linux_metadata(input, true)).map_err(Into::into)
}

/// Capture insisting the object is still the one the scan identified.
#[cfg(test)]
pub(crate) fn capture_native_file_metadata(input: &Path, identity: InputIdentity) -> Result<CapturedNativeMetadata> {
    capture_native_file_metadata_expecting(input, identity, IdentityExpectation::Strict)
}

#[cfg(unix)]
pub(crate) fn symlink_target_bytes(path: &Path) -> io::Result<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    Ok(fs::read_link(path)?.as_os_str().as_bytes().to_vec())
}

#[cfg(not(unix))]
pub(crate) fn symlink_target_bytes(path: &Path) -> io::Result<Vec<u8>> {
    fs::read_link(path)?
        .to_str()
        .map(|target| target.as_bytes().to_vec())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "symlink target is not UTF-8"))
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_native_file_metadata_expecting(
    input: &Path,
    _identity: InputIdentity,
    _expectation: IdentityExpectation,
) -> Result<CapturedNativeMetadata> {
    // Linux capture takes no expected identity, so it re-observes on its own and
    // has nothing to go stale. The retry lives with the caller that re-samples.
    let native = tzap_core::linux_metadata::capture_linux_metadata(input, false)?;
    Ok(CapturedNativeMetadata { native })
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_native_file_metadata_expecting(
    input: &Path,
    identity: InputIdentity,
    expectation: IdentityExpectation,
) -> Result<CapturedNativeMetadata> {
    capture_macos_native_metadata(input, identity, false, expectation)
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_macos_symlink_metadata(input: &Path, identity: InputIdentity) -> Result<CapturedNativeMetadata> {
    capture_macos_native_metadata(input, identity, true, IdentityExpectation::Strict)
}

/// macOS capture is tzap-core's. This host supplies only the identity it saw at
/// scan time, so an object swapped between the scan and the capture is refused.
///
/// Both hosts read the same xattrs, ACL, Darwin flags, resource fork, and times
/// through the same code now. They previously kept separate copies of all of it,
/// which is how they came to disagree about whether `LIBARCHIVE.creationtime` is
/// written unconditionally.
#[cfg(target_os = "macos")]
fn capture_macos_native_metadata(input: &Path, identity: InputIdentity, symlink: bool, expectation: IdentityExpectation) -> Result<CapturedNativeMetadata> {
    // No retry here. Retrying against an expectation the caller sampled once can
    // never converge -- the identity is stale from the first failure onwards, so
    // all three attempts fail on an object that has long since settled. The retry
    // belongs where the identity is re-sampled: `observe_input_metadata`.
    let expected = match expectation {
        IdentityExpectation::Strict => identity.macos_identity,
        IdentityExpectation::Relaxed => None,
    };
    let captured = tzap_core::macos_metadata::capture_macos_metadata_with(input, symlink, expected)
        // Add the path, but keep core's own wording: `is_transient_capture_race`
        // matches on it, and a context line that replaced it would leave the
        // retry working while the message stopped saying what happened.
        .map_err(|error| anyhow!("{error}: {}", input.display()))?;
    Ok(CapturedNativeMetadata { native: captured.native, macos_identity: Some(captured.identity) })
}

#[cfg(windows)]
pub(crate) fn capture_native_file_metadata_expecting(
    input: &Path,
    identity: InputIdentity,
    _expectation: IdentityExpectation,
) -> Result<CapturedNativeMetadata> {
    // tzap-core owns Windows capture. This host only supplies the attributes and
    // times it already observed when the input was identified, so the archive
    // describes that observation rather than a second, later one.
    let observed = tzap_core::windows_metadata::WindowsObservedBasicInfo {
        file_attributes: identity.file_attributes,
        creation_time_100ns: identity.creation_time_100ns,
        last_access_time_100ns: identity.last_access_time_100ns,
        change_time_100ns: identity.change_time_100ns,
    };
    let native = tzap_core::windows_metadata::capture_windows_metadata_with(input, Some(observed))
        .with_context(|| format!("failed to capture Windows metadata for {}", input.display()))?;
    Ok(CapturedNativeMetadata { native })
}

#[cfg(windows)]
pub(crate) fn validate_windows_input_path_identity(path: &Path, expected: InputIdentity) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    let mut actual = input_identity(&metadata)?;
    let file = open_windows_metadata_handle(path)?;
    augment_windows_input_identity(&mut actual, &file)?;
    if input_identity_matches_after_read(expected, actual) {
        Ok(())
    } else {
        Err(io::Error::other("Windows input changed during raw EFS export"))
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
pub(crate) fn capture_native_file_metadata_expecting(
    _input: &Path,
    _identity: InputIdentity,
    _expectation: IdentityExpectation,
) -> Result<CapturedNativeMetadata> {
    Ok(CapturedNativeMetadata { native: NativeFileMetadata::default() })
}

pub(crate) fn portable_attributes(metadata: &fs::Metadata) -> Option<u32> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // The bit projection is tzap-core's; this host only supplies the mask.
        Some(tzap_core::entry_metadata::windows_portable_attribute_projection(metadata.file_attributes()))
    }

    #[cfg(target_os = "macos")]
    {
        let _ = metadata;
        // Exact BSD flags are carried by TZAP.macos.st-flags. The portable
        // four-bit projection is Windows-specific and cannot be restored
        // faithfully on macOS.
        None
    }

    #[cfg(all(unix, not(target_os = "macos"), not(windows)))]
    {
        let _ = metadata;
        None
    }
}
