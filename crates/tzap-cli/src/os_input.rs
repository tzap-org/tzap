use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;
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
use tzap_core::{NativeAuxiliaryMetadata, RestoreClass};

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

#[cfg(windows)]
pub(crate) fn add_windows_refs_sparse_layout_omission(native: &mut NativeFileMetadata) {
    const HEADER: &str = "tzap-capture-report-v1\n";
    const ROW: &str = "windows-backup-v1\tsparse-layout\tunsupported-filesystem\tReFS%20does%20not%20expose%20exact%20sparse%20ranges";
    if let Some(report) = native.auxiliary_records.iter_mut().find(|record| record.kind == "tzap.capture-report") {
        let text = std::str::from_utf8(&report.payload).expect("internally generated capture reports are UTF-8");
        let mut rows = text.strip_prefix(HEADER).expect("internally generated capture report has canonical header").split_terminator('\n').collect::<Vec<_>>();
        rows.push(ROW);
        rows.sort_unstable();
        rows.dedup();
        report.payload = format!("{HEADER}{}\n", rows.join("\n")).into_bytes();
        report.logical_size = report.payload.len() as u64;
        return;
    }
    let payload = format!("{HEADER}{ROW}\n").into_bytes();
    let mut report = NativeAuxiliaryMetadata::new("tzap.capture-report", "tzap-core-v1", RestoreClass::None, payload);
    report.native = false;
    native.auxiliary_records.push(report);
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
    let mut portable_metadata = portable_input_metadata(identity, input)?;
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

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum WindowsKnownReparse {
    RelativeSymlink { portable_target: Vec<u8> },
    Junction,
    Opaque,
}

#[cfg(windows)]
pub(crate) fn query_windows_reparse_data(file: &File) -> io::Result<Vec<u8>> {
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const MAX_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
    let mut buffer = vec![0u8; MAX_REPARSE_DATA_BUFFER_SIZE];
    let mut bytes_returned = 0u32;
    // SAFETY: the handle is live and the fixed output allocation remains valid for this
    // synchronous call. FSCTL_GET_REPARSE_POINT has no input buffer.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_GET_REPARSE_POINT,
            ptr::null(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut bytes_returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(bytes_returned as usize);
    if buffer.len() < 8 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reparse buffer is truncated"));
    }
    let tag = u32::from_le_bytes(buffer[0..4].try_into().unwrap());
    let declared = usize::from(u16::from_le_bytes([buffer[4], buffer[5]]));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if declared + header_len != buffer.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "reparse buffer length is inconsistent"));
    }
    Ok(buffer)
}

#[cfg(windows)]
pub(crate) fn validate_windows_known_reparse_data(data: &[u8]) -> io::Result<WindowsKnownReparse> {
    const IO_REPARSE_TAG_MOUNT_POINT: u32 = 0xA000_0003;
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000_000C;
    const SYMLINK_FLAG_RELATIVE: u32 = 1;

    let invalid = |message| io::Error::new(io::ErrorKind::InvalidData, message);
    if data.len() < 8 {
        return Err(invalid("reparse buffer is truncated"));
    }
    let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
    let payload_len = usize::from(u16::from_le_bytes(data[4..6].try_into().unwrap()));
    let header_len = if tag & 0x8000_0000 == 0 { 24 } else { 8 };
    if payload_len + header_len != data.len() {
        return Err(invalid("reparse buffer length is inconsistent"));
    }
    let (fixed_len, flags) = match tag {
        IO_REPARSE_TAG_SYMLINK => {
            if payload_len < 12 {
                return Err(invalid("symbolic-link reparse payload is truncated"));
            }
            (12usize, u32::from_le_bytes(data[16..20].try_into().unwrap()))
        }
        IO_REPARSE_TAG_MOUNT_POINT => {
            if payload_len < 8 {
                return Err(invalid("mount-point reparse payload is truncated"));
            }
            (8usize, 0)
        }
        _ => return Ok(WindowsKnownReparse::Opaque),
    };
    let substitute_offset = usize::from(u16::from_le_bytes(data[8..10].try_into().unwrap()));
    let substitute_len = usize::from(u16::from_le_bytes(data[10..12].try_into().unwrap()));
    let print_offset = usize::from(u16::from_le_bytes(data[12..14].try_into().unwrap()));
    let print_len = usize::from(u16::from_le_bytes(data[14..16].try_into().unwrap()));
    if substitute_offset % 2 != 0 || substitute_len % 2 != 0 || print_offset % 2 != 0 || print_len % 2 != 0 {
        return Err(invalid("reparse path fields are not UTF-16 aligned"));
    }
    let path_buffer = &data[8 + fixed_len..];
    let decode_name = |offset: usize, len: usize| -> io::Result<String> {
        let end = offset.checked_add(len).ok_or_else(|| invalid("reparse path range overflows"))?;
        let bytes = path_buffer.get(offset..end).ok_or_else(|| invalid("reparse path range exceeds the payload"))?;
        let units = bytes.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect::<Vec<_>>();
        let text = String::from_utf16(&units).map_err(|_| invalid("reparse path is not valid UTF-16"))?;
        if text.contains('\0') {
            return Err(invalid("reparse path contains NUL"));
        }
        Ok(text)
    };
    let substitute = decode_name(substitute_offset, substitute_len)?;
    let print = decode_name(print_offset, print_len)?;
    if substitute.is_empty() {
        return Err(invalid("reparse substitute name is empty"));
    }

    if tag == IO_REPARSE_TAG_SYMLINK {
        if flags != SYMLINK_FLAG_RELATIVE {
            return Err(invalid("only relative Windows symbolic links are supported"));
        }
        let target = if print.is_empty() { substitute } else { print };
        let target = target.replace('\\', "/").into_bytes();
        if target.is_empty() || target[0] == b'/' || target.contains(&b':') {
            return Err(invalid("Windows symbolic-link target is absolute"));
        }
        Ok(WindowsKnownReparse::RelativeSymlink { portable_target: target })
    } else {
        if !substitute.starts_with("\\??\\") || print.is_empty() {
            return Err(invalid("junction path fields are not canonical"));
        }
        Ok(WindowsKnownReparse::Junction)
    }
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
pub(crate) fn augment_windows_input_identity(identity: &mut InputIdentity, file: &File) -> io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, BY_HANDLE_FILE_INFORMATION, FILE_BASIC_INFO,
    };

    let handle = file.as_raw_handle().cast();
    let mut basic = FILE_BASIC_INFO::default();
    // SAFETY: `handle` is live and both output pointers reference correctly sized structures.
    if unsafe { GetFileInformationByHandleEx(handle, FileBasicInfo, (&mut basic as *mut FILE_BASIC_INFO).cast(), size_of::<FILE_BASIC_INFO>() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut by_handle = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is live and `by_handle` is a valid writable output structure.
    if unsafe { GetFileInformationByHandle(handle, &mut by_handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    identity.creation_time_100ns = basic.CreationTime as u64;
    identity.last_access_time_100ns = basic.LastAccessTime as u64;
    identity.change_time_100ns = basic.ChangeTime as u64;
    identity.file_attributes = basic.FileAttributes;
    identity.link_count = u64::from(by_handle.nNumberOfLinks);
    identity.volume_serial = u64::from(by_handle.dwVolumeSerialNumber);
    identity.file_index = (u64::from(by_handle.nFileIndexHigh) << 32) | u64::from(by_handle.nFileIndexLow);
    Ok(())
}

#[cfg(windows)]
pub(crate) fn query_windows_allocated_ranges(file: &File, logical_size: u64) -> io::Result<Vec<SparseExtent>> {
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::ERROR_MORE_DATA;
    use windows_sys::Win32::System::Ioctl::{FILE_ALLOCATED_RANGE_BUFFER, FSCTL_QUERY_ALLOCATED_RANGES};
    use windows_sys::Win32::System::IO::DeviceIoControl;

    const QUERY_BATCH: usize = 1024;
    const MAX_EXTENTS: usize = 1_048_576;
    if logical_size == 0 {
        return Ok(Vec::new());
    }
    // FSCTL_QUERY_ALLOCATED_RANGES is not supported by ReFS. Retrieval pointers do not resolve
    // the ambiguity: ReFS reports LCN -1 for a run that may be either a hole or partially
    // allocated. Materialize the logical bytes and pair this fallback with an authenticated
    // sparse-layout omission so the archive cannot claim exact storage-layout fidelity.
    if windows_file_system_is_refs(file)? {
        return Ok(vec![SparseExtent { offset: 0, length: logical_size }]);
    }
    let logical_size_i64 = i64::try_from(logical_size).map_err(|_| io::Error::other("sparse logical size exceeds Windows range API"))?;
    let mut query_start = 0u64;
    let mut extents = Vec::<SparseExtent>::new();
    while query_start < logical_size {
        let mut query = FILE_ALLOCATED_RANGE_BUFFER {
            FileOffset: i64::try_from(query_start).map_err(|_| io::Error::other("sparse query offset exceeds Windows range API"))?,
            Length: logical_size_i64 - query_start as i64,
        };
        let mut output = [FILE_ALLOCATED_RANGE_BUFFER::default(); QUERY_BATCH];
        let mut bytes_returned = 0u32;
        // SAFETY: the live file handle and fixed-size input/output buffers remain valid for the
        // synchronous DeviceIoControl call, and the byte lengths exactly match those buffers.
        let success = unsafe {
            DeviceIoControl(
                file.as_raw_handle().cast(),
                FSCTL_QUERY_ALLOCATED_RANGES,
                (&mut query as *mut FILE_ALLOCATED_RANGE_BUFFER).cast(),
                size_of::<FILE_ALLOCATED_RANGE_BUFFER>() as u32,
                output.as_mut_ptr().cast(),
                size_of::<[FILE_ALLOCATED_RANGE_BUFFER; QUERY_BATCH]>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        let error = io::Error::last_os_error();
        if success == 0 && error.raw_os_error() != Some(ERROR_MORE_DATA as i32) {
            return Err(error);
        }
        if bytes_returned as usize % size_of::<FILE_ALLOCATED_RANGE_BUFFER>() != 0 {
            return Err(io::Error::other("Windows returned a truncated allocated-range row"));
        }
        let count = bytes_returned as usize / size_of::<FILE_ALLOCATED_RANGE_BUFFER>();
        if count > QUERY_BATCH || (success == 0 && count == 0) {
            return Err(io::Error::other("Windows allocated-range query made no progress"));
        }
        let mut next_query_start = query_start;
        for range in &output[..count] {
            if range.FileOffset < 0 || range.Length <= 0 {
                return Err(io::Error::other("Windows returned an invalid allocated range"));
            }
            let offset = range.FileOffset as u64;
            let end = offset.checked_add(range.Length as u64).ok_or_else(|| io::Error::other("Windows allocated range overflow"))?.min(logical_size);
            if offset >= logical_size || end <= offset {
                return Err(io::Error::other("Windows returned an out-of-bounds allocated range"));
            }
            if let Some(previous) = extents.last_mut() {
                let previous_end = previous.offset + previous.length;
                if offset <= previous_end {
                    previous.length = previous_end.max(end) - previous.offset;
                } else {
                    extents.push(SparseExtent { offset, length: end - offset });
                }
            } else {
                extents.push(SparseExtent { offset, length: end - offset });
            }
            if extents.len() > MAX_EXTENTS {
                return Err(io::Error::other("sparse extent count exceeds revision-45 limit"));
            }
            next_query_start = next_query_start.max(end);
        }
        if success != 0 {
            break;
        }
        if next_query_start <= query_start {
            return Err(io::Error::other("Windows allocated-range query did not advance"));
        }
        query_start = next_query_start;
    }
    Ok(extents)
}

#[cfg(windows)]
pub(crate) fn windows_file_system_is_refs(file: &File) -> io::Result<bool> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;

    let mut name = [0u16; 32];
    // SAFETY: the file handle is live, optional outputs are null, and `name` is writable for the
    // exact capacity supplied to this synchronous query.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle().cast(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let length = name.iter().position(|unit| *unit == 0).unwrap_or(name.len());
    Ok(String::from_utf16_lossy(&name[..length]).eq_ignore_ascii_case("refs"))
}

#[cfg(windows)]
pub(crate) fn open_windows_metadata_handle(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT};

    fs::OpenOptions::new().read(true).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(path)
}

pub(crate) struct IdentityCheckedInputReader {
    pub(crate) file: File,
    pub(crate) expected: InputIdentity,
    pub(crate) remaining: u64,
    pub(crate) validated: bool,
}

pub(crate) struct SparseExtentInputReader<'a> {
    pub(crate) file: File,
    pub(crate) expected: InputIdentity,
    pub(crate) expected_extents: &'a [SparseExtent],
    pub(crate) extent_index: usize,
    pub(crate) extent_remaining: u64,
    pub(crate) validated: bool,
}

#[cfg(windows)]
pub(crate) fn windows_alternate_stream_path(base: &Path, name: &[u8]) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    if name.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Windows alternate stream name is not UTF-16LE"));
    }
    let mut stream_path = base.as_os_str().encode_wide().collect::<Vec<_>>();
    stream_path.extend(name.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])));
    Ok(PathBuf::from(OsString::from_wide(&stream_path)))
}

#[cfg(windows)]
pub(crate) struct WindowsSparseAlternateStreamReader {
    pub(crate) file: File,
    pub(crate) logical_size: u64,
    pub(crate) expected_extents: Vec<SparseExtent>,
    pub(crate) extent_index: usize,
    pub(crate) extent_remaining: u64,
    pub(crate) validated: bool,
}

#[cfg(windows)]
impl WindowsSparseAlternateStreamReader {
    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if self.file.metadata()?.len() != self.logical_size || query_windows_allocated_ranges(&self.file, self.logical_size)? != self.expected_extents {
                return Err(io::Error::other("sparse Windows alternate stream changed after scan"));
            }
            self.validated = true;
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Read for WindowsSparseAlternateStreamReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.extent_remaining == 0 {
                let Some(extent) = self.expected_extents.get(self.extent_index) else {
                    self.validate_finished()?;
                    break;
                };
                self.file.seek(SeekFrom::Start(extent.offset))?;
                self.extent_remaining = extent.length;
            }
            let count = (out.len() - written).min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sparse Windows alternate extent ended before its scanned size"));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished()?;
        }
        Ok(written)
    }
}

impl SparseExtentInputReader<'_> {
    fn validate_finished(&mut self) -> io::Result<()> {
        if self.validated {
            return Ok(());
        }
        validate_opened_input_identity(&self.file, self.expected)?;
        #[cfg(windows)]
        if query_windows_allocated_ranges(&self.file, self.expected.len)? != self.expected_extents {
            return Err(io::Error::other("sparse allocated ranges changed after scan"));
        }
        self.validated = true;
        Ok(())
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
                let Some(extent) = self.expected_extents.get(self.extent_index) else {
                    self.validate_finished()?;
                    break;
                };
                self.file.seek(SeekFrom::Start(extent.offset))?;
                self.extent_remaining = extent.length;
            }
            let count = (out.len() - written).min(usize::try_from(self.extent_remaining).unwrap_or(usize::MAX));
            let read = self.file.read(&mut out[written..written + count])?;
            if read == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "sparse extent ended before its scanned size"));
            }
            written += read;
            self.extent_remaining -= read as u64;
            if self.extent_remaining == 0 {
                self.extent_index += 1;
            }
        }
        if self.extent_index == self.expected_extents.len() && self.extent_remaining == 0 {
            self.validate_finished()?;
        }
        Ok(written)
    }
}

impl Read for IdentityCheckedInputReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            if !self.validated {
                validate_opened_input_identity(&self.file, self.expected)?;
                self.validated = true;
            }
            return Ok(0);
        }
        let max_read = out.len().min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.file.read(&mut out[..max_read])?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "input ended before its scanned size"));
        }
        self.remaining -= count as u64;
        if self.remaining == 0 {
            validate_opened_input_identity(&self.file, self.expected)?;
            self.validated = true;
        }
        Ok(count)
    }
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

#[cfg(windows)]
pub(crate) fn unsupported_windows_file_attribute_reason(attributes: u32) -> Option<&'static str> {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_OFFLINE: u32 = 0x0000_1000;
    [
        (FILE_ATTRIBUTE_REPARSE_POINT, "reparse points require exact reparse-data capture"),
        (FILE_ATTRIBUTE_OFFLINE, "offline/cloud placeholders require an explicit hydration policy"),
    ]
    .into_iter()
    .find_map(|(flag, reason)| (attributes & flag != 0).then_some(reason))
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
}

pub(crate) fn portable_input_metadata(identity: InputIdentity, input: &Path) -> Result<CapturedInputMetadata> {
    // tzap-core owns the portable assembly -- source OS, mode origin, owner-name
    // resolution, and the optional-time rules -- so this host and zmanager cannot
    // disagree about it. What stays here is genuinely this host's: the sparse and
    // reparse handling layered on top, and the scan identity it captures against.
    let metadata = fs::symlink_metadata(input)?;
    let (created, accessed) = portable_optional_times(&metadata);
    let captured = capture_native_file_metadata(input, identity)?;
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
    })
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
pub(crate) fn capture_native_file_metadata(input: &Path, _identity: InputIdentity) -> Result<CapturedNativeMetadata> {
    // A file changing mid-capture is ordinary during a live backup, and a re-read
    // almost always succeeds. zmanager has retried this since "Fix TZAP Unicode
    // archives and metadata capture races"; this host never did.
    let native = tzap_core::portable_capture::with_capture_retry(|| tzap_core::linux_metadata::capture_linux_metadata(input, false))?;
    Ok(CapturedNativeMetadata { native })
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_native_file_metadata(input: &Path, identity: InputIdentity) -> Result<CapturedNativeMetadata> {
    capture_macos_native_metadata(input, identity, false)
}

#[cfg(target_os = "macos")]
pub(crate) fn capture_macos_symlink_metadata(input: &Path, identity: InputIdentity) -> Result<CapturedNativeMetadata> {
    capture_macos_native_metadata(input, identity, true)
}

/// macOS capture is tzap-core's. This host supplies only the identity it saw at
/// scan time, so an object swapped between the scan and the capture is refused.
///
/// Both hosts read the same xattrs, ACL, Darwin flags, resource fork, and times
/// through the same code now. They previously kept separate copies of all of it,
/// which is how they came to disagree about whether `LIBARCHIVE.creationtime` is
/// written unconditionally.
#[cfg(target_os = "macos")]
fn capture_macos_native_metadata(input: &Path, identity: InputIdentity, symlink: bool) -> Result<CapturedNativeMetadata> {
    let expected = identity.macos_identity;
    let captured = tzap_core::portable_capture::with_capture_retry(|| tzap_core::macos_metadata::capture_macos_metadata_with(input, symlink, expected))
        // Add the path, but keep core's own wording: `is_transient_capture_race`
        // matches on it, and a context line that replaced it would leave the
        // retry working while the message stopped saying what happened.
        .map_err(|error| anyhow!("{error}: {}", input.display()))?;
    Ok(CapturedNativeMetadata { native: captured.native, macos_identity: Some(captured.identity) })
}

#[cfg(windows)]
pub(crate) fn capture_native_file_metadata(input: &Path, identity: InputIdentity) -> Result<CapturedNativeMetadata> {
    // tzap-core owns Windows capture. This host only supplies the attributes and
    // times it already observed when the input was identified, so the archive
    // describes that observation rather than a second, later one.
    let observed = tzap_core::windows_metadata::WindowsObservedBasicInfo {
        file_attributes: identity.file_attributes,
        creation_time_100ns: identity.creation_time_100ns,
        last_access_time_100ns: identity.last_access_time_100ns,
        change_time_100ns: identity.change_time_100ns,
    };
    let native = tzap_core::portable_capture::with_capture_retry(|| tzap_core::windows_metadata::capture_windows_metadata_with(input, Some(observed)))
        .with_context(|| format!("failed to capture Windows metadata for {}", input.display()))?;
    Ok(CapturedNativeMetadata { native })
}

#[cfg(windows)]
pub(crate) fn windows_backup_capture_enabled() -> bool {
    use std::sync::OnceLock;
    use windows_sys::Win32::Security::SE_BACKUP_NAME;

    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enable_windows_privilege(SE_BACKUP_NAME))
}

#[cfg(windows)]
pub(crate) fn enable_windows_privilege(name: *const u16) -> bool {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError, ERROR_SUCCESS};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = ptr::null_mut();
    // SAFETY: `token` is a valid output pointer and the pseudo process handle is always live.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &mut token) } == 0 {
        return false;
    }
    let enabled = {
        let mut privileges = TOKEN_PRIVILEGES { PrivilegeCount: 1, ..Default::default() };
        // SAFETY: the one-element privilege array provides a valid LUID output slot.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name, &mut privileges.Privileges[0].Luid) } == 0 {
            false
        } else {
            privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            unsafe { SetLastError(ERROR_SUCCESS) };
            // SAFETY: `token` is live and `privileges` is a valid one-entry input structure.
            unsafe { AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut()) != 0 && GetLastError() == ERROR_SUCCESS }
        }
    };
    // SAFETY: `token` was returned by OpenProcessToken and is closed exactly once.
    unsafe { CloseHandle(token) };
    enabled
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsContext(*mut std::ffi::c_void);

#[cfg(windows)]
impl Drop for WindowsRawEfsContext {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::CloseEncryptedFileRaw;

        if !self.0.is_null() {
            // SAFETY: this context was returned by OpenEncryptedFileRawW and is closed once.
            unsafe { CloseEncryptedFileRaw(self.0) };
        }
    }
}

#[cfg(windows)]
pub(crate) fn open_windows_raw_efs(path: &Path, flags: u32) -> io::Result<WindowsRawEfsContext> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::ptr;
    use windows_sys::Win32::Storage::FileSystem::OpenEncryptedFileRawW;

    let wide = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect::<Vec<_>>();
    let mut context = ptr::null_mut();
    // SAFETY: the path is NUL-terminated and `context` is a valid output pointer.
    let status = unsafe { OpenEncryptedFileRawW(wide.as_ptr(), flags, &mut context) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(WindowsRawEfsContext(context))
}

#[cfg(windows)]
pub(crate) enum WindowsRawEfsMessage {
    Data(Vec<u8>),
    Done(io::Result<()>),
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsSendContext {
    pub(crate) sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
}

#[cfg(windows)]
unsafe extern "system" fn send_windows_raw_efs_callback(data: *const u8, context: *const std::ffi::c_void, length: u32) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_OPERATION_ABORTED};

    if length == 0 {
        return 0;
    }
    if data.is_null() || context.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies readable callback bytes and the caller supplied this send context.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    let state = unsafe { &*context.cast::<WindowsRawEfsSendContext>() };
    for chunk in bytes.chunks(64 * 1024) {
        if state.sender.send(WindowsRawEfsMessage::Data(chunk.to_vec())).is_err() {
            return ERROR_OPERATION_ABORTED;
        }
    }
    0
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

#[cfg(windows)]
pub(crate) fn export_windows_raw_efs_to_sender(
    path: &Path,
    expected: InputIdentity,
    sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    validate_windows_input_path_identity(path, expected)?;
    let _ = windows_backup_capture_enabled();
    let context = open_windows_raw_efs(path, 0)?;
    let state = WindowsRawEfsSendContext { sender };
    // SAFETY: callback state and raw EFS context remain live for the synchronous export.
    let status = unsafe { ReadEncryptedFileRaw(Some(send_windows_raw_efs_callback), (&state as *const WindowsRawEfsSendContext).cast(), context.0) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    drop(context);
    validate_windows_input_path_identity(path, expected)
}

#[cfg(windows)]
pub(crate) struct WindowsRawEfsReader {
    pub(crate) receiver: Option<std::sync::mpsc::Receiver<WindowsRawEfsMessage>>,
    pub(crate) current: Vec<u8>,
    pub(crate) current_offset: usize,
    pub(crate) remaining: u64,
    pub(crate) finished: bool,
    pub(crate) pending_error: Option<io::Error>,
    pub(crate) thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(windows)]
impl WindowsRawEfsReader {
    pub(crate) fn spawn(path: PathBuf, expected: InputIdentity, size: u64) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let completion = sender.clone();
        let thread = std::thread::spawn(move || {
            let result = export_windows_raw_efs_to_sender(&path, expected, sender);
            let _ = completion.send(WindowsRawEfsMessage::Done(result));
        });
        Self { receiver: Some(receiver), current: Vec::new(), current_offset: 0, remaining: size, finished: false, pending_error: None, thread: Some(thread) }
    }
}

#[cfg(windows)]
impl Read for WindowsRawEfsReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        let mut written = 0usize;
        while written < out.len() {
            if self.current_offset < self.current.len() {
                let count = (self.current.len() - self.current_offset).min(out.len() - written);
                if count as u64 > self.remaining {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "raw EFS export exceeded its declared size"));
                }
                out[written..written + count].copy_from_slice(&self.current[self.current_offset..self.current_offset + count]);
                self.current_offset += count;
                self.remaining -= count as u64;
                written += count;
                continue;
            }
            if self.finished {
                break;
            }
            let message = self
                .receiver
                .as_ref()
                .ok_or_else(|| io::Error::other("raw EFS export channel is closed"))?
                .recv()
                .map_err(|_| io::Error::other("raw EFS export terminated unexpectedly"))?;
            match message {
                WindowsRawEfsMessage::Data(bytes) => {
                    self.current = bytes;
                    self.current_offset = 0;
                }
                WindowsRawEfsMessage::Done(result) => {
                    self.finished = true;
                    if let Err(error) = result {
                        if written == 0 {
                            return Err(error);
                        }
                        self.pending_error = Some(error);
                    } else if self.remaining != 0 {
                        let error = io::Error::new(io::ErrorKind::UnexpectedEof, "raw EFS export ended before its declared size");
                        if written == 0 {
                            return Err(error);
                        }
                        self.pending_error = Some(error);
                    }
                }
            }
        }
        Ok(written)
    }
}

#[cfg(windows)]
impl Drop for WindowsRawEfsReader {
    fn drop(&mut self) {
        self.receiver.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(all(not(target_os = "linux"), not(target_os = "macos"), not(windows)))]
pub(crate) fn capture_native_file_metadata(_input: &Path, _identity: InputIdentity) -> Result<CapturedNativeMetadata> {
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
