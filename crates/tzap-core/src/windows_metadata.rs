use crate::entry_metadata::SparseExtent;
use crate::{ArchiveTimestamp, NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding, NativeFileMetadata, RestoreClass};
use std::fs::{self, File};
use std::io;
use std::io::{Read, Seek as _, SeekFrom};
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::path::PathBuf;

/// Basic file information a host may already have sampled.
///
/// A host that identified the input at scan time must describe *that*
/// observation, not a fresh one: re-reading attributes and times here would let
/// the archive's index and its PAX records disagree when a file changes between
/// scan and capture, which surfaces later as "metadata flags do not match
/// FileEntry flags".
#[derive(Debug, Clone, Copy)]
pub struct WindowsObservedBasicInfo {
    pub file_attributes: u32,
    pub creation_time_100ns: u64,
    pub last_access_time_100ns: u64,
    pub change_time_100ns: u64,
}

/// Captures Windows basic information, security, reparse data, case-sensitivity,
/// alternate data, EA/property data, object IDs, and raw EFS into v45 metadata.
pub fn capture_windows_metadata(input: &Path) -> io::Result<NativeFileMetadata> {
    capture_windows_metadata_with(input, None)
}

/// As [`capture_windows_metadata`], but using attributes and times the caller
/// already observed. See [`WindowsObservedBasicInfo`].
pub fn capture_windows_metadata_with(input: &Path, observed: Option<WindowsObservedBasicInfo>) -> io::Result<NativeFileMetadata> {
    use std::mem::size_of;
    use windows_sys::Win32::Storage::FileSystem::{
        FileBasicInfo, GetFileInformationByHandleEx, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
    };

    let file = fs::OpenOptions::new().access_mode(FILE_GENERIC_READ).custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).open(input)?;
    let mut basic = FILE_BASIC_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if let Some(observed) = observed {
        basic.FileAttributes = observed.file_attributes;
        basic.CreationTime = observed.creation_time_100ns as i64;
        basic.LastAccessTime = observed.last_access_time_100ns as i64;
        basic.ChangeTime = observed.change_time_100ns as i64;
    }

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert("TZAP.windows.file-attributes".into(), format!("{:08x}", basic.FileAttributes).into_bytes());
    for (key, value) in [("atime", basic.LastAccessTime), ("LIBARCHIVE.creationtime", basic.CreationTime), ("TZAP.windows.change-time", basic.ChangeTime)] {
        native.primary_pax_records.insert(key.into(), windows_filetime_timestamp(value as u64)?.canonical_pax_value().map_err(io::Error::other)?);
    }

    let reparse_data = if basic.FileAttributes & 0x0000_0400 != 0 {
        let data = query_windows_reparse_data(&file)?;
        if data.len() < 8 {
            return Err(io::Error::other("Windows reparse data is truncated"));
        }
        let tag = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let mut record = NativeAuxiliaryMetadata::new("windows.reparse-data", "windows-backup-v1", RestoreClass::System, data.clone());
        record.meta.insert("TZAP.aux.meta.reparse-tag".into(), format!("{tag:08x}").into_bytes());
        native.auxiliary_records.push(record);
        Some(data)
    } else {
        None
    };
    native.auxiliary_records.push(capture_windows_security_descriptor(&file)?);
    const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    if basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        if let Some(case_sensitive) = query_windows_directory_case_sensitive(&file)? {
            native.primary_pax_records.insert("TZAP.windows.directory-case-sensitive".into(), if case_sensitive { b"1" } else { b"0" }.to_vec());
        }
    }
    let (data_stream_attributes, mut streams) = capture_windows_backup_streams(input, &file, reparse_data.as_deref())?;
    if basic.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | 0x0000_0400) == 0 {
        native.primary_pax_records.insert("TZAP.windows.data-stream-attributes".into(), format!("{data_stream_attributes:08x}").into_bytes());
    }
    native.auxiliary_records.append(&mut streams);

    // An encrypted file must be captured in its raw, still-encrypted form: read
    // the ordinary way it yields plaintext and silently undoes the user's
    // encryption (see `capture_windows_efs_raw`).
    //
    // Order matters and is not obvious. The raw EFS APIs refuse to export while
    // an ordinary handle to the file is open, even one that permits every
    // sharing mode -- so every registered BackupRead stream is enumerated first,
    // then the handle is released, and only then is the raw context opened.
    // Doing this earlier, with `file` still live, fails on every real encrypted
    // file.
    // ReFS cannot report exact allocated ranges, so any sparse claim here is
    // partial by construction and must say so. This needs the handle, so it runs
    // before the handle is released for EFS below.
    const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x0000_0200;
    if basic.FileAttributes & FILE_ATTRIBUTE_SPARSE_FILE != 0 && windows_file_system_is_refs(&file)? {
        add_refs_sparse_layout_omission(&mut native);
    }

    if basic.FileAttributes & FILE_ATTRIBUTE_ENCRYPTED != 0 && basic.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        drop(file);
        native.auxiliary_records.push(capture_windows_efs_raw(input)?);
    }
    native.auxiliary_records.sort_by(|left, right| left.kind.cmp(&right.kind).then_with(|| left.name.cmp(&right.name)));
    native.required_profiles.push("windows-backup-v1".into());
    Ok(native)
}

/// Convert a Windows `FILETIME` tick count to a revision-45 timestamp.
pub fn windows_filetime_timestamp(value_100ns: u64) -> io::Result<ArchiveTimestamp> {
    const WINDOWS_TO_UNIX_EPOCH_100NS: i128 = 116_444_736_000_000_000;
    const TICKS_PER_SECOND: i128 = 10_000_000;
    let unix_100ns = i128::from(value_100ns) - WINDOWS_TO_UNIX_EPOCH_100NS;
    let seconds = i64::try_from(unix_100ns.div_euclid(TICKS_PER_SECOND)).map_err(|_| io::Error::other("Windows timestamp exceeds TZAP range"))?;
    let nanoseconds = (unix_100ns.rem_euclid(TICKS_PER_SECOND) * 100) as u32;
    Ok(ArchiveTimestamp::new(seconds, nanoseconds))
}

fn query_windows_reparse_data(file: &File) -> io::Result<Vec<u8>> {
    use windows_sys::Win32::System::Ioctl::FSCTL_GET_REPARSE_POINT;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    let mut buffer = vec![0u8; 16 * 1024];
    let mut returned = 0u32;
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle().cast(),
            FSCTL_GET_REPARSE_POINT,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(returned as usize);
    Ok(buffer)
}

/// Whether a directory has the per-directory case-sensitivity flag set.
pub fn query_windows_directory_case_sensitive(file: &File) -> io::Result<Option<bool>> {
    use std::mem::size_of;
    use windows_sys::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED};
    use windows_sys::Win32::Storage::FileSystem::{FileCaseSensitiveInfo, GetFileInformationByHandleEx, FILE_CASE_SENSITIVE_INFO};
    use windows_sys::Win32::System::SystemServices::FILE_CS_FLAG_CASE_SENSITIVE_DIR;

    let mut info = FILE_CASE_SENSITIVE_INFO::default();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            FileCaseSensitiveInfo,
            (&mut info as *mut FILE_CASE_SENSITIVE_INFO).cast(),
            size_of::<FILE_CASE_SENSITIVE_INFO>() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(code)
                if code == ERROR_INVALID_FUNCTION as i32
                    || code == ERROR_INVALID_PARAMETER as i32
                    || code == ERROR_NOT_SUPPORTED as i32
        ) {
            return Ok(None);
        }
        return Err(error);
    }
    if info.Flags & !FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
        return Err(io::Error::other("Windows returned unknown case-sensitivity flags"));
    }
    Ok(Some(info.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0))
}

/// Capture a self-relative security descriptor, including the SACL when the
/// process can acquire `SE_SECURITY_NAME`.
pub fn capture_windows_security_descriptor(file: &File) -> io::Result<NativeAuxiliaryMetadata> {
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorLength, DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
        PROTECTED_SACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, UNPROTECTED_DACL_SECURITY_INFORMATION, UNPROTECTED_SACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReOpenFile, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, READ_CONTROL};
    use windows_sys::Win32::System::SystemServices::ACCESS_SYSTEM_SECURITY;

    const BASE: u32 = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let original = file.as_raw_handle().cast();
    let sacl_handle = if enable_windows_privilege(windows_sys::Win32::Security::SE_SECURITY_NAME) {
        let handle = unsafe { ReOpenFile(original, READ_CONTROL | ACCESS_SYSTEM_SECURITY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 0) };
        (handle != INVALID_HANDLE_VALUE).then_some(handle)
    } else {
        None
    };
    let requested = BASE | if sacl_handle.is_some() { SACL_SECURITY_INFORMATION } else { 0 };
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            sacl_handle.unwrap_or(original),
            SE_FILE_OBJECT,
            requested,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if let Some(handle) = sacl_handle {
        unsafe {
            CloseHandle(handle);
        }
    }
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Err(io::Error::other("Windows returned an empty security descriptor"));
    }
    let length = unsafe { GetSecurityDescriptorLength(descriptor) } as usize;
    let payload = unsafe { std::slice::from_raw_parts(descriptor.cast::<u8>(), length) }.to_vec();
    if !unsafe { LocalFree(descriptor) }.is_null() {
        return Err(io::Error::other("failed to release Windows security descriptor"));
    }
    if payload.len() < 20 {
        return Err(io::Error::other("Windows security descriptor is truncated"));
    }
    let control = u16::from_le_bytes(payload[2..4].try_into().unwrap());
    let mut represented = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
    if control & 0x0004 != 0 {
        represented |= DACL_SECURITY_INFORMATION;
        represented |= if control & 0x1000 != 0 { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
    }
    if control & 0x0010 != 0 {
        represented |= SACL_SECURITY_INFORMATION;
        represented |= if control & 0x2000 != 0 { PROTECTED_SACL_SECURITY_INFORMATION } else { UNPROTECTED_SACL_SECURITY_INFORMATION };
    }
    let mut record = NativeAuxiliaryMetadata::new("windows.security-descriptor", "windows-backup-v1", RestoreClass::System, payload);
    record.meta.insert("TZAP.aux.meta.security-information".into(), format!("{represented:08x}").into_bytes());
    Ok(record)
}

/// Enable a Windows privilege on this process token, reporting whether it took.
///
/// Capture and restore of several metadata classes are privilege-gated
/// (`SE_SECURITY_NAME` for SACLs, `SE_BACKUP_NAME`/`SE_RESTORE_NAME` for backup
/// semantics). Hosts and their tests need the same answer this module acts on,
/// so there is one implementation rather than a copy per host.
///
/// `name` is one of the `SE_*_NAME` constants, which are wide string literals.
pub fn enable_windows_privilege(name: *const u16) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, SetLastError};
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &mut token) } == 0 {
        return false;
    }
    let mut privileges = TOKEN_PRIVILEGES { PrivilegeCount: 1, ..Default::default() };
    let enabled = if unsafe { LookupPrivilegeValueW(std::ptr::null(), name, &mut privileges.Privileges[0].Luid) } == 0 {
        false
    } else {
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        unsafe {
            SetLastError(0);
        }
        unsafe { AdjustTokenPrivileges(token, 0, &privileges, 0, std::ptr::null_mut(), std::ptr::null_mut()) != 0 && GetLastError() == 0 }
    };
    unsafe {
        CloseHandle(token);
    }
    enabled
}

struct WindowsBackupReader {
    handle: windows_sys::Win32::Foundation::HANDLE,
    context: *mut std::ffi::c_void,
}

impl WindowsBackupReader {
    fn new(file: &File) -> Self {
        Self { handle: file.as_raw_handle().cast(), context: std::ptr::null_mut() }
    }

    fn read_optional_exact(&mut self, out: &mut [u8]) -> io::Result<bool> {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;
        let mut offset = 0usize;
        while offset < out.len() {
            let mut read = 0u32;
            if unsafe {
                BackupRead(
                    self.handle,
                    out[offset..].as_mut_ptr(),
                    u32::try_from(out.len() - offset).map_err(|_| io::Error::other("BackupRead request exceeds u32"))?,
                    &mut read,
                    0,
                    0,
                    &mut self.context,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                return if offset == 0 { Ok(false) } else { Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Windows backup stream ended mid-record")) };
            }
            offset += read as usize;
        }
        Ok(true)
    }

    fn read_vec(&mut self, size: u64) -> io::Result<Vec<u8>> {
        let size = usize::try_from(size).map_err(|_| io::Error::other("Windows backup stream exceeds address space"))?;
        let mut payload = vec![0; size];
        if size != 0 && !self.read_optional_exact(&mut payload)? {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Windows backup stream payload is missing"));
        }
        Ok(payload)
    }

    /// Hash a stream payload without retaining it.
    ///
    /// An alternate data stream can be arbitrarily large. Reading it into memory
    /// -- which this module used to do, capped at 64 MiB -- turns a big ADS into
    /// a hard capture failure. §16.4.6 requires readers to hash an auxiliary
    /// payload without allocating its full size, and the same applies here.
    fn read_sha256(&mut self, mut size: u64) -> io::Result<[u8; 32]> {
        use sha2::{Digest as _, Sha256};

        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        while size > 0 {
            let count = buffer.len().min(usize::try_from(size).unwrap_or(usize::MAX));
            if !self.read_optional_exact(&mut buffer[..count])? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Windows backup stream payload is missing"));
            }
            hasher.update(&buffer[..count]);
            size -= count as u64;
        }
        Ok(hasher.finalize().into())
    }

    /// Consume a payload by reading it, not by seeking.
    ///
    /// `skip` uses `BackupSeek`, which cannot seek within a sparse block: it
    /// fails with ERROR_INVALID_PARAMETER and the whole capture errors out. The
    /// distinction is load-bearing and easy to lose when paraphrasing this loop.
    fn discard(&mut self, mut size: u64) -> io::Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        while size > 0 {
            let take = size.min(buffer.len() as u64) as usize;
            if !self.read_optional_exact(&mut buffer[..take])? {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Windows backup stream payload is missing"));
            }
            size -= take as u64;
        }
        Ok(())
    }

    fn skip(&mut self, size: u64) -> io::Result<()> {
        use windows_sys::Win32::Storage::FileSystem::BackupSeek;
        let mut low = 0u32;
        let mut high = 0u32;
        if unsafe { BackupSeek(self.handle, size as u32, (size >> 32) as u32, &mut low, &mut high, &mut self.context) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if (u64::from(high) << 32) | u64::from(low) != size {
            return Err(io::Error::other("Windows backup stream could not be skipped completely"));
        }
        Ok(())
    }
}

impl Drop for WindowsBackupReader {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::BackupRead;
        let mut ignored = 0;
        unsafe {
            BackupRead(self.handle, std::ptr::null_mut(), 0, &mut ignored, 1, 0, &mut self.context);
        }
    }
}

fn capture_windows_backup_streams(input: &Path, file: &File, expected_reparse: Option<&[u8]>) -> io::Result<(u32, Vec<NativeAuxiliaryMetadata>)> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        BACKUP_ALTERNATE_DATA, BACKUP_DATA, BACKUP_EA_DATA, BACKUP_LINK, BACKUP_OBJECT_ID, BACKUP_PROPERTY_DATA, BACKUP_REPARSE_DATA, BACKUP_SECURITY_DATA,
        BACKUP_SPARSE_BLOCK, BACKUP_TXFS_DATA,
    };

    const HEADER_LEN: usize = 20;
    const RETAINED_CAP: u64 = 64 * 1024 * 1024;
    let mut reader = WindowsBackupReader::new(file);
    let mut data_attributes = None;
    let mut auxiliary = Vec::new();
    let mut sparse_alternate: Vec<(Vec<u8>, u32, RestoreClass)> = Vec::new();
    loop {
        let mut header = [0u8; HEADER_LEN];
        if !reader.read_optional_exact(&mut header)? {
            break;
        }
        let stream_id = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let attributes = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let signed_size = i64::from_le_bytes(header[8..16].try_into().unwrap());
        if signed_size < 0 {
            return Err(io::Error::other("Windows BackupRead returned a negative stream size"));
        }
        let size = signed_size as u64;
        let name_size = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
        if name_size % 2 != 0 || name_size > 65_534 {
            return Err(io::Error::other("Windows BackupRead returned an invalid stream name"));
        }
        let name = reader.read_vec(name_size as u64)?;
        match stream_id {
            BACKUP_DATA => {
                data_attributes = Some(attributes);
                reader.skip(size)?;
            }
            BACKUP_SECURITY_DATA | BACKUP_LINK => reader.skip(size)?,
            BACKUP_SPARSE_BLOCK => {
                // A sparse block is an 8-byte offset followed by its data. The
                // extents are re-derived from the stream itself below, so the
                // block only needs consuming -- but it must be *read*, not
                // seeked: BackupSeek fails inside a sparse block.
                if size < 8 {
                    return Err(io::Error::other("Windows sparse-block stream is shorter than its offset"));
                }
                reader.discard(size)?;
            }
            BACKUP_REPARSE_DATA => {
                let payload = reader.read_vec(size)?;
                if expected_reparse != Some(payload.as_slice()) {
                    return Err(io::Error::other("Windows reparse stream disagrees with the pinned handle"));
                }
            }
            BACKUP_ALTERNATE_DATA => {
                // Streamed, not retained: an alternate stream has no size bound,
                // and reading it into memory turned a large ADS into a capture
                // failure.
                let restore_class = if attributes & 2 != 0 { RestoreClass::System } else { RestoreClass::SameOs };
                const STREAM_ATTRIBUTE_SPARSE: u32 = 0x0000_0008;
                if attributes & STREAM_ATTRIBUTE_SPARSE != 0 {
                    // The payload arrives as following BACKUP_SPARSE_BLOCK
                    // records; the stream itself is re-read by path below so the
                    // v45 sparse map covers exactly the allocated ranges.
                    reader.skip(size)?;
                    sparse_alternate.push((name, attributes, restore_class));
                    continue;
                }
                let sha256 = reader.read_sha256(size)?;
                let mut record = NativeAuxiliaryMetadata::new_streamed("windows.alternate-data", "windows-backup-v1", restore_class, size, sha256);
                record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
                record.name = name;
                record.meta.insert("TZAP.aux.meta.stream-type".into(), b"00000004".to_vec());
                record.meta.insert("TZAP.aux.meta.stream-attributes".into(), format!("{attributes:08x}").into_bytes());
                auxiliary.push(record);
            }
            BACKUP_EA_DATA | BACKUP_PROPERTY_DATA | BACKUP_OBJECT_ID => {
                if size > RETAINED_CAP {
                    return Err(io::Error::other("Windows metadata stream exceeds the retained payload cap"));
                }
                let payload = reader.read_vec(size)?;
                let (kind, stream_type, restore_class) = match stream_id {
                    BACKUP_EA_DATA => ("windows.ea-data", "00000002", if attributes & 2 != 0 { RestoreClass::System } else { RestoreClass::SameOs }),
                    BACKUP_PROPERTY_DATA => {
                        ("windows.property-data", "00000006", if attributes & 2 != 0 { RestoreClass::System } else { RestoreClass::SameOs })
                    }
                    _ => ("windows.object-id", "00000007", RestoreClass::System),
                };
                if !name.is_empty() {
                    return Err(io::Error::other("unnamed Windows metadata stream had a name"));
                }
                let mut record = NativeAuxiliaryMetadata::new(kind, "windows-backup-v1", restore_class, payload);
                record.meta.insert("TZAP.aux.meta.stream-type".into(), stream_type.as_bytes().to_vec());
                record.meta.insert("TZAP.aux.meta.stream-attributes".into(), format!("{attributes:08x}").into_bytes());
                auxiliary.push(record);
            }
            BACKUP_TXFS_DATA => {
                return Err(io::Error::other("Windows transactional streams are not representable"));
            }
            _ => {
                return Err(io::Error::other(format!("unsupported Windows backup stream {stream_id}")));
            }
        }
    }
    let metadata = file.metadata()?;
    let data_attributes = data_attributes.unwrap_or_else(|| if metadata.file_attributes() & 0x0000_0200 != 0 { 8 } else { 0 });

    // Sparse alternate streams are re-opened by path so the stored v45 map
    // describes exactly the allocated ranges. ReFS cannot report those, so there
    // the whole logical extent is materialized and the omission recorded.
    let layout_partial = !sparse_alternate.is_empty() && windows_file_system_is_refs(file)?;
    for (name, attributes, restore_class) in sparse_alternate {
        let stream_path = windows_alternate_stream_path(input, &name)?;
        let mut stream = File::open(stream_path)?;
        let logical_size = stream.metadata()?.len();
        let extents = if layout_partial && logical_size != 0 {
            vec![SparseExtent { offset: 0, length: logical_size }]
        } else {
            query_windows_allocated_ranges(&stream, logical_size)?
        };
        if extents.last().is_some_and(|extent| extent.offset + extent.length > logical_size) {
            return Err(io::Error::other("Windows sparse-block stream exceeds its logical stream size"));
        }
        let map = crate::writer::encode_v45_sparse_map(&extents, logical_size).map_err(io::Error::other)?;
        let sha256 = hash_windows_sparse_alternate_stream(&mut stream, &map, &extents, logical_size)?;
        let mut record =
            NativeAuxiliaryMetadata::new_streamed_sparse("windows.alternate-data", "windows-backup-v1", restore_class, logical_size, extents, sha256)
                .map_err(io::Error::other)?;
        record.name_encoding = NativeAuxiliaryNameEncoding::Utf16Le;
        record.name = name;
        record.meta.insert("TZAP.aux.meta.stream-type".into(), b"00000004".to_vec());
        record.meta.insert("TZAP.aux.meta.stream-attributes".into(), format!("{attributes:08x}").into_bytes());
        auxiliary.push(record);
    }
    Ok((data_attributes, auxiliary))
}

/// A raw EFS export context, closed exactly once on drop.
struct WindowsRawEfsContext(*mut std::ffi::c_void);

impl Drop for WindowsRawEfsContext {
    fn drop(&mut self) {
        use windows_sys::Win32::Storage::FileSystem::CloseEncryptedFileRaw;

        if !self.0.is_null() {
            // SAFETY: returned by OpenEncryptedFileRawW and closed once.
            unsafe { CloseEncryptedFileRaw(self.0) };
        }
    }
}

fn open_windows_raw_efs(path: &Path, flags: u32) -> io::Result<WindowsRawEfsContext> {
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

struct WindowsRawEfsDigest {
    hasher: sha2::Sha256,
    size: u64,
}

unsafe extern "system" fn hash_windows_raw_efs_callback(data: *const u8, context: *const std::ffi::c_void, length: u32) -> u32 {
    use sha2::Digest as _;
    use windows_sys::Win32::Foundation::{ERROR_ARITHMETIC_OVERFLOW, ERROR_INVALID_PARAMETER, ERROR_SUCCESS};

    if length == 0 {
        return ERROR_SUCCESS;
    }
    if data.is_null() || context.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies `length` readable bytes and the caller supplied this digest context.
    let bytes = unsafe { std::slice::from_raw_parts(data, length as usize) };
    // SAFETY: the context is the digest state passed to ReadEncryptedFileRaw.
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsDigest>() };
    let Some(size) = state.size.checked_add(u64::from(length)) else {
        return ERROR_ARITHMETIC_OVERFLOW;
    };
    state.hasher.update(bytes);
    state.size = size;
    ERROR_SUCCESS
}

/// Size and SHA-256 of a file's raw EFS export.
/// Whether this process can acquire `SE_SECURITY_NAME`, and so whether a
/// captured security descriptor will include its SACL.
///
/// Tests need this to decide what to expect: without the privilege the SACL is
/// legitimately absent, and asserting it unconditionally fails on an
/// unprivileged runner rather than finding a defect.
pub fn windows_sacl_capture_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| enable_windows_privilege(windows_sys::Win32::Security::SE_SECURITY_NAME))
}

pub fn hash_windows_raw_efs(path: &Path) -> io::Result<(u64, [u8; 32])> {
    use sha2::Digest as _;
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    let context = open_windows_raw_efs(path, 0)?;
    let mut state = WindowsRawEfsDigest { hasher: sha2::Sha256::new(), size: 0 };
    // SAFETY: the callback state and the raw EFS context stay live for the
    // synchronous export.
    let status = unsafe { ReadEncryptedFileRaw(Some(hash_windows_raw_efs_callback), (&mut state as *mut WindowsRawEfsDigest).cast(), context.0) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok((state.size, state.hasher.finalize().into()))
}

/// Capture the raw EFS form of an encrypted file.
///
/// An EFS-encrypted file read the ordinary way yields **plaintext** to whoever
/// holds the key -- so an archiver that does that silently undoes the protection
/// the user asked for. Windows exposes `ReadEncryptedFileRaw` precisely so a
/// backup tool can copy the still-encrypted form, and §16.18.3 requires "EFS raw
/// capture where supported".
///
/// This lived only in `tzap-cli`, so archives written through any other host --
/// zmanager included -- plaintext-substituted every encrypted file.
fn capture_windows_efs_raw(path: &Path) -> io::Result<NativeAuxiliaryMetadata> {
    let (size, sha256) = hash_windows_raw_efs(path)?;
    let mut record = NativeAuxiliaryMetadata::new_streamed("windows.efs-raw", "windows-backup-v1", RestoreClass::System, size, sha256);
    record.meta.insert("TZAP.aux.meta.efs-version".into(), b"1".to_vec());
    Ok(record)
}

/// Whether the volume holding this handle is ReFS.
///
/// ReFS does not expose an authoritative allocated-range map, so sparse layout
/// there is preserved logically but must be authenticated as partial.
fn windows_file_system_is_refs(file: &File) -> io::Result<bool> {
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;

    let mut name = [0u16; 32];
    // SAFETY: the handle is live, the optional outputs are null, and `name` is
    // writable for exactly the capacity supplied to this synchronous query.
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

/// Record that sparse layout could not be captured exactly on this filesystem.
///
/// §16.6's `unsupported-filesystem` reason: the class could exist here, but the
/// writer cannot enumerate it or prove its absence. The archive stays honest --
/// logical bytes are complete and the omission is authenticated -- rather than
/// silently claiming an exact sparse layout it did not observe.
fn add_refs_sparse_layout_omission(native: &mut NativeFileMetadata) {
    const HEADER: &str = "tzap-capture-report-v1\n";
    const ROW: &str = "windows-backup-v1\tsparse-layout\tunsupported-filesystem\tReFS%20does%20not%20expose%20exact%20sparse%20ranges";

    if let Some(report) = native.auxiliary_records.iter_mut().find(|record| record.kind == "tzap.capture-report") {
        let Ok(text) = std::str::from_utf8(&report.payload) else { return };
        let Some(body) = text.strip_prefix(HEADER) else { return };
        let mut rows = body.split_terminator('\n').collect::<Vec<_>>();
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

/// A host's "is this still the object I scanned?" check, run before any bytes
/// of a streamed auxiliary are read.
///
/// Each host identifies inputs its own way, so the check stays with the host
/// while tzap-core owns the reading.
pub type WindowsStreamValidator = Box<dyn FnOnce(&Path) -> io::Result<()> + Send>;

/// Open a streamed Windows auxiliary for the writer to pull its payload from.
///
/// The counterpart to [`crate::macos_metadata::open_macos_resource_fork`], and
/// the piece that was missing when Windows capture moved here: core began
/// *emitting* streamed `windows.efs-raw` and `windows.alternate-data` records
/// while the readers that serve them stayed in `tzap-cli`. Any other host --
/// zmanager -- then failed every encrypted or ADS-bearing file with "streamed
/// auxiliary source is unsupported on this platform".
///
/// `validate` is the host's own "is this still the object I scanned?" check. It
/// stays with the host because each one identifies inputs differently, and it
/// runs before any bytes are read.
pub fn open_windows_streamed_auxiliary(input: &Path, record: &NativeAuxiliaryMetadata, validate: WindowsStreamValidator) -> io::Result<Box<dyn Read + Send>> {
    match record.kind.as_str() {
        "windows.efs-raw" => {
            if record.name_encoding != NativeAuxiliaryNameEncoding::None || !record.name.is_empty() {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "raw EFS auxiliary source has an unexpected name"));
            }
            Ok(Box::new(WindowsRawEfsReader::spawn(input.to_path_buf(), record.stored_payload_size(), validate)))
        }
        "windows.alternate-data" => {
            if record.name_encoding != NativeAuxiliaryNameEncoding::Utf16Le || record.name.len() % 2 != 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Windows alternate-data auxiliary source has a malformed name"));
            }
            validate(input)?;
            let stream_path = windows_alternate_stream_path(input, &record.name)?;
            let mut stream = File::open(stream_path)?;
            if stream.metadata()?.len() != record.logical_size {
                return Err(io::Error::other("Windows alternate stream changed after scan"));
            }
            let Some(extents) = record.streamed_sparse_extents() else {
                return Ok(Box::new(stream));
            };
            // A sparse stream is stored as the v45 sparse map followed by the
            // allocated extents only.
            let map = crate::encode_v45_sparse_map(extents, record.logical_size).map_err(io::Error::other)?;
            let expected_extents = extents.to_vec();
            stream.seek(SeekFrom::Start(0))?;
            Ok(Box::new(io::Cursor::new(map).chain(WindowsSparseAlternateStreamReader {
                file: stream,
                logical_size: record.logical_size,
                expected_extents,
                extent_index: 0,
                extent_remaining: 0,
                validated: false,
            })))
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported streamed Windows auxiliary source")),
    }
}

struct WindowsSparseAlternateStreamReader {
    file: File,
    logical_size: u64,
    expected_extents: Vec<SparseExtent>,
    extent_index: usize,
    extent_remaining: u64,
    validated: bool,
}

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

enum WindowsRawEfsMessage {
    Data(Vec<u8>),
    Done(io::Result<()>),
}

struct WindowsRawEfsExport {
    sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
}

unsafe extern "system" fn send_windows_raw_efs_callback(data: *const u8, context: *const std::ffi::c_void, length: u32) -> u32 {
    use windows_sys::Win32::Foundation::{ERROR_INVALID_PARAMETER, ERROR_OPERATION_ABORTED, ERROR_SUCCESS};

    if length == 0 {
        return ERROR_SUCCESS;
    }
    if data.is_null() || context.is_null() {
        return ERROR_INVALID_PARAMETER;
    }
    // SAFETY: EFS supplies `length` readable bytes and the caller supplied this export context.
    let chunk = unsafe { std::slice::from_raw_parts(data, length as usize) };
    // SAFETY: the context is the export state passed to ReadEncryptedFileRaw.
    let state = unsafe { &mut *context.cast_mut().cast::<WindowsRawEfsExport>() };
    if state.sender.send(WindowsRawEfsMessage::Data(chunk.to_vec())).is_err() {
        return ERROR_OPERATION_ABORTED;
    }
    ERROR_SUCCESS
}

fn export_windows_raw_efs_to_sender(
    path: &Path,
    validate: WindowsStreamValidator,
    sender: std::sync::mpsc::SyncSender<WindowsRawEfsMessage>,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::ReadEncryptedFileRaw;

    validate(path)?;
    let context = open_windows_raw_efs(path, 0)?;
    let mut state = WindowsRawEfsExport { sender };
    // SAFETY: the callback state and the raw EFS context stay live for the
    // synchronous export.
    let status = unsafe { ReadEncryptedFileRaw(Some(send_windows_raw_efs_callback), (&mut state as *mut WindowsRawEfsExport).cast(), context.0) };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
}

/// Streams a file's raw EFS export, which Windows only delivers through a
/// callback: a worker thread runs the export and this reader drains it.
struct WindowsRawEfsReader {
    receiver: Option<std::sync::mpsc::Receiver<WindowsRawEfsMessage>>,
    current: Vec<u8>,
    current_offset: usize,
    remaining: u64,
    finished: bool,
    pending_error: Option<io::Error>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl WindowsRawEfsReader {
    fn spawn(path: PathBuf, size: u64, validate: WindowsStreamValidator) -> Self {
        let (sender, receiver) = std::sync::mpsc::sync_channel(2);
        let completion = sender.clone();
        let thread = std::thread::spawn(move || {
            let result = export_windows_raw_efs_to_sender(&path, validate, sender);
            let _ = completion.send(WindowsRawEfsMessage::Done(result));
        });
        Self { receiver: Some(receiver), current: Vec::new(), current_offset: 0, remaining: size, finished: false, pending_error: None, thread: Some(thread) }
    }
}

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

impl Drop for WindowsRawEfsReader {
    fn drop(&mut self) {
        self.receiver.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn windows_alternate_stream_path(base: &Path, name: &[u8]) -> io::Result<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};

    if name.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Windows alternate stream name is not UTF-16LE"));
    }
    let mut stream_path = base.as_os_str().encode_wide().collect::<Vec<_>>();
    stream_path.extend(name.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])));
    Ok(PathBuf::from(OsString::from_wide(&stream_path)))
}

fn query_windows_allocated_ranges(file: &File, logical_size: u64) -> io::Result<Vec<SparseExtent>> {
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

fn hash_windows_sparse_alternate_stream(stream: &mut File, map: &[u8], extents: &[SparseExtent], logical_size: u64) -> io::Result<[u8; 32]> {
    use sha2::{Digest as _, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(map);
    let mut buffer = [0u8; 64 * 1024];
    for extent in extents {
        stream.seek(SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.length;
        while remaining > 0 {
            let count = buffer.len().min(usize::try_from(remaining).unwrap_or(usize::MAX));
            stream.read_exact(&mut buffer[..count])?;
            hasher.update(&buffer[..count]);
            remaining -= count as u64;
        }
    }
    if stream.metadata()?.len() != logical_size || query_windows_allocated_ranges(stream, logical_size)? != extents {
        return Err(io::Error::other("Windows sparse alternate stream changed while hashing"));
    }
    Ok(hasher.finalize().into())
}
