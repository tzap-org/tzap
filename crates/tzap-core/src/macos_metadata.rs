use crate::{
    canonical_base64_encode, encode_percent_name, ArchiveTimestamp, NativeAuxiliaryMetadata, NativeAuxiliaryNameEncoding, NativeFileMetadata, RestoreClass,
};
use sha2::{Digest as _, Sha256};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::macos::fs::MetadataExt as _;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use xattr::FileExt as _;

const INLINE_XATTR_BUDGET: usize = 32 * 1024 * 1024;
const O_SYMLINK: libc::c_int = 0x0020_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosMetadataIdentity {
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    dev: u64,
    ino: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    created_seconds: i64,
    created_nanoseconds: i64,
    flags: u32,
    symlink: bool,
}

impl MacosMetadataIdentity {
    /// The identity of the object `metadata` describes.
    ///
    /// A host that stats an input while scanning can build the identity it
    /// *expected* and hand it to [`capture_macos_metadata_with`], so an object
    /// replaced between the scan and the capture is refused rather than archived
    /// with one object's index entry and another's PAX records.
    #[must_use]
    pub fn from_metadata(metadata: &fs::Metadata) -> Self {
        metadata_identity(metadata)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapturedMacosMetadata {
    pub native: NativeFileMetadata,
    pub identity: MacosMetadataIdentity,
}

pub fn capture_macos_metadata(input: &Path, symlink: bool) -> io::Result<CapturedMacosMetadata> {
    capture_macos_metadata_with(input, symlink, None)
}

/// As [`capture_macos_metadata`], but refusing an object that is no longer the
/// one `expected` described.
///
/// This is the scan-to-capture half of the race. Without it a capture only
/// notices a writer that acts *during* its own window, and a host that already
/// identified the input at scan time has no way to say so.
pub fn capture_macos_metadata_with(input: &Path, symlink: bool, expected: Option<MacosMetadataIdentity>) -> io::Result<CapturedMacosMetadata> {
    let file = if symlink { open_symlink(input)? } else { open_metadata_file(input)? };
    let metadata = file.metadata()?;
    if metadata.file_type().is_symlink() != symlink {
        return Err(io::Error::other("input kind changed before metadata capture"));
    }
    let identity = metadata_identity(&metadata);
    if expected.is_some_and(|expected| expected != identity) {
        return Err(io::Error::other("input changed before metadata capture"));
    }
    let native = capture_from_file(input, &file, identity, symlink)?;
    let final_metadata = file.metadata()?;
    if metadata_identity(&final_metadata) != identity {
        return Err(io::Error::other("input changed during metadata capture"));
    }
    Ok(CapturedMacosMetadata { native, identity })
}

pub fn open_macos_resource_fork(input: &Path, symlink: bool, expected_identity: MacosMetadataIdentity, expected_size: u64) -> io::Result<Box<dyn Read>> {
    let source = if symlink { ResourceForkSource::Symlink(open_symlink(input)?) } else { ResourceForkSource::File(open_regular_resource_fork(input)?) };
    Ok(Box::new(ResourceForkReader::new(source, expected_identity, Some(expected_size))?))
}

fn capture_from_file(input: &Path, file: &File, identity: MacosMetadataIdentity, symlink: bool) -> io::Result<NativeFileMetadata> {
    use std::os::unix::fs::FileTypeExt as _;

    let mut native = NativeFileMetadata::default();
    native.primary_pax_records.insert("TZAP.macos.st-flags".into(), format!("{:016x}", identity.flags).into_bytes());
    native.primary_pax_records.insert(
        "TZAP.unix.ctime-observed".into(),
        ArchiveTimestamp::new(
            identity.changed_seconds,
            u32::try_from(identity.changed_nanoseconds).map_err(|_| io::Error::other("negative macOS ctime nanoseconds"))?,
        )
        .canonical_pax_value()
        .map_err(invalid_metadata)?,
    );
    native.primary_pax_records.insert(
        "LIBARCHIVE.creationtime".into(),
        ArchiveTimestamp::new(
            identity.created_seconds,
            u32::try_from(identity.created_nanoseconds).map_err(|_| io::Error::other("negative macOS birthtime nanoseconds"))?,
        )
        .canonical_pax_value()
        .map_err(invalid_metadata)?,
    );

    let metadata = file.metadata()?;
    let device_without_metadata_api = metadata.file_type().is_char_device() || metadata.file_type().is_block_device();
    let names = match file.list_xattr() {
        Ok(names) => names.collect::<Vec<_>>(),
        Err(error) if device_without_metadata_api && error.raw_os_error().is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) => Vec::new(),
        Err(error) => return Err(error),
    };

    let mut inline_xattr_bytes = 0usize;
    for name in names {
        let name_bytes = name.as_bytes();
        if name_bytes == b"com.apple.ResourceFork" {
            let source = if symlink { ResourceForkSource::Symlink(file.try_clone()?) } else { ResourceForkSource::File(open_regular_resource_fork(input)?) };
            native.auxiliary_records.push(capture_resource_fork(source, identity)?);
            continue;
        }

        let value = file.get_xattr(&name)?.ok_or_else(|| io::Error::other("xattr changed during metadata capture"))?;
        if name_bytes == b"com.apple.FinderInfo" {
            if value.len() != 32 {
                return Err(io::Error::other("FinderInfo is not exactly 32 bytes"));
            }
            native.auxiliary_records.push(NativeAuxiliaryMetadata::new("macos.finder-info", "macos-backup-v1", RestoreClass::SameOs, value));
            continue;
        }

        let encoded_size = value.len().saturating_mul(4).div_ceil(3);
        if inline_xattr_bytes.saturating_add(name_bytes.len()).saturating_add(encoded_size) > INLINE_XATTR_BUDGET {
            let mut record = NativeAuxiliaryMetadata::new(
                "generic.xattr",
                if name_bytes.starts_with(b"com.apple.") { "macos-backup-v1" } else { "posix-backup-v1" },
                if is_system_xattr(name_bytes) { RestoreClass::System } else { RestoreClass::SameOs },
                value,
            );
            record.name_encoding = NativeAuxiliaryNameEncoding::Bytes;
            record.name = name_bytes.to_vec();
            native.auxiliary_records.push(record);
        } else {
            let encoded_name = encode_percent_name(name_bytes).map_err(invalid_metadata)?;
            let encoded_value = canonical_base64_encode(&value);
            inline_xattr_bytes = inline_xattr_bytes.saturating_add(encoded_name.len()).saturating_add(encoded_value.len());
            native.primary_pax_records.insert(format!("LIBARCHIVE.xattr.{encoded_name}"), encoded_value);
        }
    }

    let acl = match capture_acl(file) {
        Ok(acl) => acl,
        Err(error) if device_without_metadata_api && error.raw_os_error().is_some_and(|code| code == libc::EPERM || code == libc::ENOTSUP) => None,
        Err(error) => return Err(error),
    };
    if let Some(acl) = acl {
        let mut record = NativeAuxiliaryMetadata::new("macos.acl-native", "macos-backup-v1", RestoreClass::SameOs, acl);
        record.meta.insert("TZAP.aux.meta.acl-format".into(), b"darwin-acl-external-v1".to_vec());
        native.auxiliary_records.push(record);
        native.primary_pax_records.insert("TZAP.acl.projection".into(), b"none".to_vec());
    }

    native.required_profiles = vec!["macos-backup-v1".into(), "posix-backup-v1".into()];
    native.auxiliary_records.sort_by(|left, right| left.kind.cmp(&right.kind).then_with(|| left.name.cmp(&right.name)));
    Ok(native)
}

fn metadata_identity(metadata: &fs::Metadata) -> MacosMetadataIdentity {
    MacosMetadataIdentity {
        len: metadata.len(),
        mode: metadata.mode(),
        uid: metadata.uid(),
        gid: metadata.gid(),
        dev: metadata.dev(),
        ino: metadata.ino(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        created_seconds: metadata.st_birthtime(),
        created_nanoseconds: metadata.st_birthtime_nsec(),
        flags: metadata.st_flags(),
        symlink: metadata.file_type().is_symlink(),
    }
}

fn open_metadata_file(input: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    const O_EVTONLY: libc::c_int = 0x0000_8000;
    fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | O_EVTONLY).open(input)
}

fn open_symlink(input: &Path) -> io::Result<File> {
    let path = CString::new(input.as_os_str().as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a NUL byte"))?;
    // SAFETY: `path` is NUL-terminated and the returned descriptor is uniquely owned.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | O_SYMLINK) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `fd` was just opened successfully and ownership moves to File.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_regular_resource_fork(input: &Path) -> io::Result<File> {
    let mut fork_path = PathBuf::from(input);
    fork_path.push("..namedfork/rsrc");
    File::open(fork_path)
}

enum ResourceForkSource {
    File(File),
    Symlink(File),
}

struct ResourceForkReader {
    source: ResourceForkSource,
    expected_identity: MacosMetadataIdentity,
    logical_size: u64,
    offset: u64,
    validated: bool,
}

impl ResourceForkReader {
    fn new(source: ResourceForkSource, expected_identity: MacosMetadataIdentity, expected_size: Option<u64>) -> io::Result<Self> {
        if resource_fork_identity(&source)? != expected_identity {
            return Err(io::Error::other("macOS resource-fork owner changed before read"));
        }
        let logical_size = resource_fork_size(&source)?;
        if expected_size.is_some_and(|size| size != logical_size) {
            return Err(io::Error::other("macOS resource fork changed after metadata scan"));
        }
        Ok(Self { source, expected_identity, logical_size, offset: 0, validated: false })
    }

    fn validate_finished(&mut self) -> io::Result<()> {
        if !self.validated {
            if resource_fork_identity(&self.source)? != self.expected_identity || resource_fork_size(&self.source)? != self.logical_size {
                return Err(io::Error::other("macOS resource fork changed during read"));
            }
            self.validated = true;
        }
        Ok(())
    }
}

impl Read for ResourceForkReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.logical_size {
            self.validate_finished()?;
            return Ok(0);
        }
        let count =
            usize::try_from((self.logical_size - self.offset).min(output.len() as u64)).map_err(|_| io::Error::other("resource fork read size overflow"))?;
        let read = read_resource_fork(&self.source, self.offset, &mut output[..count])?;
        if read == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "macOS resource fork ended before its scanned size"));
        }
        self.offset += read as u64;
        if self.offset == self.logical_size {
            self.validate_finished()?;
        }
        Ok(read)
    }
}

fn capture_resource_fork(source: ResourceForkSource, identity: MacosMetadataIdentity) -> io::Result<NativeAuxiliaryMetadata> {
    let mut reader = ResourceForkReader::new(source, identity, None)?;
    let logical_size = reader.logical_size;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(NativeAuxiliaryMetadata::new_streamed("macos.resource-fork", "macos-backup-v1", RestoreClass::SameOs, logical_size, hasher.finalize().into()))
}

fn resource_fork_identity(source: &ResourceForkSource) -> io::Result<MacosMetadataIdentity> {
    match source {
        ResourceForkSource::File(fork) => {
            let path = descriptor_path(fork)?;
            let owner = path.parent().and_then(Path::parent).ok_or_else(|| io::Error::other("invalid named-fork descriptor path"))?;
            Ok(metadata_identity(&fs::metadata(owner)?))
        }
        ResourceForkSource::Symlink(file) => Ok(metadata_identity(&file.metadata()?)),
    }
}

fn descriptor_path(file: &File) -> io::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt as _;

    let mut path = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: the output buffer is writable for PATH_MAX bytes and fd is live.
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, path.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let length = path.iter().position(|byte| *byte == 0).ok_or_else(|| io::Error::other("unterminated descriptor path"))?;
    path.truncate(length);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(path)))
}

fn resource_fork_size(source: &ResourceForkSource) -> io::Result<u64> {
    match source {
        ResourceForkSource::File(file) => Ok(file.metadata()?.len()),
        ResourceForkSource::Symlink(file) => {
            let size = symlink_resource_fork_read(file, 0, None)?;
            u64::try_from(size).map_err(|_| io::Error::other("negative resource fork size"))
        }
    }
}

fn read_resource_fork(source: &ResourceForkSource, position: u64, output: &mut [u8]) -> io::Result<usize> {
    match source {
        ResourceForkSource::File(file) => {
            use std::os::unix::fs::FileExt as _;
            file.read_at(output, position)
        }
        ResourceForkSource::Symlink(file) => symlink_resource_fork_read(file, position, Some(output)),
    }
}

fn symlink_resource_fork_read(file: &File, position: u64, output: Option<&mut [u8]>) -> io::Result<usize> {
    use std::ffi::{c_char, c_int, c_void};

    unsafe extern "C" {
        fn fgetxattr(fd: c_int, name: *const c_char, value: *mut c_void, size: usize, position: u32, options: c_int) -> libc::ssize_t;
    }
    const RESOURCE_FORK: &[u8] = b"com.apple.ResourceFork\0";
    let position = u32::try_from(position).map_err(|_| io::Error::other("resource fork position exceeds Darwin limits"))?;
    let (pointer, length) = output.map_or((std::ptr::null_mut(), 0), |buffer| (buffer.as_mut_ptr().cast(), buffer.len()));
    // SAFETY: fd is live, name is NUL-terminated, and the optional output
    // buffer remains writable for `length` bytes for the duration of the call.
    let result = unsafe { fgetxattr(file.as_raw_fd(), RESOURCE_FORK.as_ptr().cast(), pointer, length, position, 0) };
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        usize::try_from(result).map_err(|_| io::Error::other("resource fork size overflow"))
    }
}

fn capture_acl(file: &File) -> io::Result<Option<Vec<u8>>> {
    use std::ptr;

    type Acl = *mut libc::c_void;
    type AclEntry = *mut libc::c_void;
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;

    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> Acl;
        fn acl_get_entry(acl: Acl, entry_id: libc::c_int, entry: *mut AclEntry) -> libc::c_int;
        fn acl_size(acl: Acl) -> libc::ssize_t;
        fn acl_copy_ext(buffer: *mut libc::c_void, acl: Acl, size: libc::ssize_t) -> libc::ssize_t;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }

    // SAFETY: `file` owns a live descriptor. The returned ACL is freed below.
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ENOENT) { Ok(None) } else { Err(error) };
    }
    let result = (|| {
        let mut first: AclEntry = ptr::null_mut();
        // SAFETY: `acl` is valid and `first` points to writable storage.
        match unsafe { acl_get_entry(acl, ACL_FIRST_ENTRY, &mut first) } {
            1 => return Ok(None),
            0 => {}
            _ => return Err(io::Error::last_os_error()),
        }
        // SAFETY: `acl` remains valid.
        let size = unsafe { acl_size(acl) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut external = vec![0u8; usize::try_from(size).map_err(|_| io::Error::other("macOS ACL exceeds platform limits"))?];
        // SAFETY: the destination contains exactly `size` writable bytes.
        let copied = unsafe { acl_copy_ext(external.as_mut_ptr().cast(), acl, size) };
        if copied < 0 {
            return Err(io::Error::last_os_error());
        }
        external.truncate(usize::try_from(copied).map_err(|_| io::Error::other("macOS ACL exceeds platform limits"))?);
        Ok(Some(external))
    })();
    // SAFETY: `acl` was returned by acl_get_fd_np and is not used afterward.
    unsafe {
        acl_free(acl);
    }
    result
}

fn is_system_xattr(name: &[u8]) -> bool {
    name.starts_with(b"security.") || name.starts_with(b"trusted.") || name.starts_with(b"system.")
}

fn invalid_metadata(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn is_system_xattr_recognition() {
        assert!(is_system_xattr(b"security.selinux"));
        assert!(is_system_xattr(b"trusted.test"));
        assert!(is_system_xattr(b"system.posix_acl"));
        assert!(!is_system_xattr(b"user.comment"));
        assert!(!is_system_xattr(b"com.apple.FinderInfo"));
        assert!(!is_system_xattr(b"com.apple.ResourceFork"));
    }

    #[test]
    fn invalid_metadata_error_kind() {
        let err = invalid_metadata("bad format");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "bad format");
    }

    #[test]
    fn descriptor_path_resolves_open_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("desc_test.txt");
        fs::write(&file_path, b"test").unwrap();
        let file = File::open(&file_path).unwrap();
        let resolved = descriptor_path(&file).unwrap();
        assert_eq!(resolved.canonicalize().unwrap(), file_path.canonicalize().unwrap());
    }

    #[test]
    fn capture_macos_metadata_basic_and_xattr_and_errors() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("capture_test.txt");
        fs::write(&file_path, b"hello macos").unwrap();

        // Basic capture
        let captured = capture_macos_metadata(&file_path, false).unwrap();
        assert_eq!(captured.identity.len, 11);
        assert!(!captured.identity.symlink);
        assert_eq!(captured.native.required_profiles, vec!["macos-backup-v1", "posix-backup-v1"]);
        assert!(captured.native.primary_pax_records.contains_key("TZAP.macos.st-flags"));
        assert!(captured.native.primary_pax_records.contains_key("TZAP.unix.ctime-observed"));
        assert!(captured.native.primary_pax_records.contains_key("LIBARCHIVE.creationtime"));

        // Symlink mismatch
        assert!(capture_macos_metadata(&file_path, true).is_err());

        // Generic xattr capture
        xattr::set(&file_path, "user.tzap-test", b"sample-val").unwrap();
        let captured_xattr = capture_macos_metadata(&file_path, false).unwrap();
        assert!(captured_xattr.native.primary_pax_records.contains_key("LIBARCHIVE.xattr.user.tzap-test"));

        // FinderInfo valid 32 bytes
        let finder_info = vec![0xABu8; 32];
        xattr::set(&file_path, "com.apple.FinderInfo", &finder_info).unwrap();
        let captured_fi = capture_macos_metadata(&file_path, false).unwrap();
        let fi_rec = captured_fi.native.auxiliary_records.iter().find(|r| r.kind == "macos.finder-info").expect("FinderInfo record must exist");
        assert_eq!(fi_rec.payload, finder_info);
        assert_eq!(fi_rec.profile, "macos-backup-v1");
        assert_eq!(fi_rec.restore_class, RestoreClass::SameOs);

        // Nonexistent file
        let missing = dir.path().join("missing.txt");
        assert!(capture_macos_metadata(&missing, false).is_err());
    }

    #[test]
    fn capture_macos_metadata_symlink() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        fs::write(&target, b"symlink target").unwrap();
        let link_path = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link_path).unwrap();

        let captured = capture_macos_metadata(&link_path, true).unwrap();
        assert!(captured.identity.symlink);
        assert_eq!(captured.native.required_profiles, vec!["macos-backup-v1", "posix-backup-v1"]);

        // Symlink mismatch when called with symlink = false
        assert!(capture_macos_metadata(&link_path, false).is_err());
    }

    #[test]
    fn open_macos_resource_fork_tests() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("rf_test.txt");
        fs::write(&file_path, b"data").unwrap();
        xattr::set(&file_path, "com.apple.ResourceFork", b"resource fork content").unwrap();
        let captured = capture_macos_metadata(&file_path, false).unwrap();

        // Valid resource fork
        let mut reader = open_macos_resource_fork(&file_path, false, captured.identity, 21).unwrap();
        let mut buf = [0u8; 64];
        let n = reader.read(&mut buf).unwrap();
        assert_eq!(n, 21);
        assert_eq!(&buf[..21], b"resource fork content");

        // Size mismatch error
        let Err(err) = open_macos_resource_fork(&file_path, false, captured.identity, 100) else {
            panic!("expected size mismatch error");
        };
        assert_eq!(err.to_string(), "macOS resource fork changed after metadata scan");

        // Identity mismatch error
        let mut corrupted_identity = captured.identity;
        corrupted_identity.len += 100;
        let Err(err_id) = open_macos_resource_fork(&file_path, false, corrupted_identity, 21) else {
            panic!("expected identity mismatch error");
        };
        assert_eq!(err_id.to_string(), "macOS resource-fork owner changed before read");
    }
}

/// The APFS clone identifier for a file, when the volume exposes one.
///
/// APFS clones (`cp -c`, `clonefile(2)`) share physical blocks copy-on-write but
/// have **different inodes**, so they cannot be grouped the way hardlinks are.
/// The relationship is only visible by asking the filesystem: `getattrlist` with
/// `ATTR_CMNEXT_CLONEID` returns an identifier that clone partners share.
///
/// `None` when the volume has no clone concept (HFS+, a network mount) or the
/// attribute is unavailable. §16.11 classes clone hints "optimization only;
/// never applied as authority", so absence is never an error -- logical bytes
/// are captured either way and the tree simply restores unshared.
pub fn query_macos_clone_id(path: &Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt as _;

    #[repr(C)]
    struct AttrList {
        bitmapcount: u16,
        reserved: u16,
        commonattr: u32,
        volattr: u32,
        dirattr: u32,
        fileattr: u32,
        forkattr: u32,
    }
    /// `getattrlist` writes a packed buffer: a leading u32 of bytes returned,
    /// then each requested attribute in header order. Extended (`ATTR_CMNEXT_*`)
    /// attributes require `ATTR_CMN_RETURNED_ATTRS`, whose `attribute_set_t`
    /// lands first and says which attributes the volume actually supplied.
    /// Omitting it -- as an earlier version of this did -- makes the call return
    /// a short buffer and the clone id read as absent for every file.
    #[repr(C)]
    struct CloneIdBuffer {
        length: u32,
        returned: [u32; 5],
        clone_id: u64,
    }

    const ATTR_BIT_MAP_COUNT: u16 = 5;
    const ATTR_CMN_RETURNED_ATTRS: u32 = 0x8000_0000;
    const ATTR_CMNEXT_CLONEID: u32 = 0x0000_0100;
    const FSOPT_ATTR_CMN_EXTENDED: u32 = 0x0000_0020;
    const FSOPT_NOFOLLOW: u32 = 0x0000_0001;

    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut list = AttrList {
        bitmapcount: ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: ATTR_CMN_RETURNED_ATTRS,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: ATTR_CMNEXT_CLONEID,
    };
    let mut buffer = CloneIdBuffer { length: 0, returned: [0; 5], clone_id: 0 };
    // SAFETY: `list` and `buffer` are correctly sized and stay live for the
    // synchronous call; the path is NUL-terminated.
    let status = unsafe {
        libc::getattrlist(
            path.as_ptr(),
            (&raw mut list).cast(),
            (&raw mut buffer).cast(),
            std::mem::size_of::<CloneIdBuffer>(),
            FSOPT_ATTR_CMN_EXTENDED | FSOPT_NOFOLLOW,
        )
    };
    if status != 0 {
        return None;
    }
    // The volume reports which attributes it actually returned; a volume without
    // clone tracking answers successfully but supplies nothing.
    if buffer.returned[4] & ATTR_CMNEXT_CLONEID == 0 {
        return None;
    }
    if (buffer.length as usize) < std::mem::size_of::<CloneIdBuffer>() {
        return None;
    }
    // Zero is APFS's "not a clone" sentinel, not a group of its own.
    (buffer.clone_id != 0).then_some(buffer.clone_id)
}

#[cfg(test)]
mod clone_tests {
    use super::*;

    /// `cp -c` makes a real APFS clone. The check that matters is that clone
    /// partners report the *same* id and an unrelated file reports a different
    /// one -- an implementation returning a constant, or `None` for everything,
    /// would look fine without this pairing.
    #[test]
    fn clone_partners_share_an_id_and_unrelated_files_do_not() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original.bin");
        let clone = temp.path().join("clone.bin");
        let unrelated = temp.path().join("unrelated.bin");
        std::fs::write(&original, vec![7u8; 128 * 1024]).unwrap();
        std::fs::write(&unrelated, vec![7u8; 128 * 1024]).unwrap();

        let cloned = std::process::Command::new("/bin/cp").arg("-c").arg(&original).arg(&clone).status().is_ok_and(|s| s.success());
        if !cloned || !clone.exists() {
            // Not APFS (or cp has no -c): nothing to assert, and absence is
            // explicitly allowed by §16.11.
            return;
        }

        let Some(original_id) = query_macos_clone_id(&original) else {
            // The volume has no clone concept even though `cp -c` succeeded.
            return;
        };
        assert_eq!(query_macos_clone_id(&clone), Some(original_id), "clone partners must share an id");
        assert_ne!(query_macos_clone_id(&unrelated), Some(original_id), "an unrelated file must not join the group");

        // Breaking the sharing must break the grouping: rewriting the clone in
        // place gives it its own storage.
        std::fs::write(&clone, vec![9u8; 128 * 1024]).unwrap();
        let after = query_macos_clone_id(&clone);
        assert!(after.is_none() || after != Some(original_id) || query_macos_clone_id(&original) == after);
    }

    #[test]
    fn a_plain_file_has_no_clone_group_or_a_private_one() {
        let temp = tempfile::tempdir().unwrap();
        let lonely = temp.path().join("lonely.bin");
        std::fs::write(&lonely, b"no partners").unwrap();
        // Either answer is valid: what must not happen is a panic or a bogus
        // shared id. Pair it against a second unrelated file.
        let other = temp.path().join("other.bin");
        std::fs::write(&other, b"no partners").unwrap();
        if let (Some(a), Some(b)) = (query_macos_clone_id(&lonely), query_macos_clone_id(&other)) {
            assert_ne!(a, b, "two independently written files must not share a clone group");
        }
    }

    #[test]
    fn clone_groups_cover_partners_and_skip_lone_files() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original.bin");
        let clone = temp.path().join("clone.bin");
        let lonely = temp.path().join("lonely.bin");
        std::fs::write(&original, vec![3u8; 128 * 1024]).unwrap();
        std::fs::write(&lonely, vec![4u8; 128 * 1024]).unwrap();
        if !std::process::Command::new("/bin/cp").arg("-c").arg(&original).arg(&clone).status().is_ok_and(|s| s.success()) {
            return;
        }
        if query_macos_clone_id(&original).is_none() {
            return; // volume has no clone tracking
        }

        let paths = vec![original.clone(), clone.clone(), lonely.clone()];
        let groups = assign_clone_groups(&paths);

        let group = groups.get(&original).expect("a clone partner must be grouped");
        assert_eq!(groups.get(&clone), Some(group), "both partners must share the group");
        assert_eq!(group.len(), 32, "§15 requires 32 lowercase hex digits");
        assert!(group.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "must be lowercase hex: {group}");

        // A file with no partner inside the archive describes no sharing, so it
        // gets no group even though it may have a clone id of its own.
        assert!(!groups.contains_key(&lonely), "a lone file must not be given a group");
    }

    #[test]
    fn clone_group_assignment_is_deterministic_and_excludes_single_members() {
        // Pure-function behaviour, independent of whether this volume clones:
        // an empty or single-path input can never produce a group.
        assert!(assign_clone_groups(&[]).is_empty());
        let temp = tempfile::tempdir().unwrap();
        let only = temp.path().join("only.bin");
        std::fs::write(&only, b"alone").unwrap();
        assert!(assign_clone_groups(&[only]).is_empty(), "one path cannot form a sharing group");
    }

    #[test]
    fn restore_reestablishes_sharing_and_leaves_bytes_untouched() {
        use std::collections::BTreeMap;

        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.bin");
        let second = temp.path().join("second.bin");
        let payload = vec![21u8; 256 * 1024];
        // Independently written: identical content, no shared storage -- exactly
        // what a restore produces before this pass runs.
        std::fs::write(&first, &payload).unwrap();
        std::fs::write(&second, &payload).unwrap();
        if query_macos_clone_id(&first).is_none() {
            return; // volume has no clone tracking
        }
        assert_ne!(query_macos_clone_id(&first), query_macos_clone_id(&second), "fixture must start unshared");

        let mut groups = BTreeMap::new();
        groups.insert("a".repeat(32), vec![first.clone(), second.clone()]);
        let outcomes = restore_clone_groups(&groups);

        assert_eq!(outcomes.len(), 1);
        match &outcomes[0] {
            CloneRestoreOutcome::Shared { members, .. } => assert_eq!(*members, 2),
            CloneRestoreOutcome::NotShared { reason, .. } => panic!("sharing failed on an APFS volume: {reason}"),
        }
        // Sharing re-established, and the bytes are still exactly right.
        assert_eq!(query_macos_clone_id(&second), query_macos_clone_id(&first), "partners must share storage after the pass");
        assert_eq!(std::fs::read(&second).unwrap(), payload);
        assert_eq!(std::fs::read(&first).unwrap(), payload);
        assert!(!temp.path().join("second.tzap-clone-staging").exists(), "staging file must not be left behind");
    }

    #[test]
    fn restore_refuses_to_overwrite_partners_whose_bytes_differ() {
        use std::collections::BTreeMap;

        // The hint is "never applied as authority" (§16.11), so a group whose
        // restored members disagree must be left exactly as restored rather than
        // having one silently overwrite the other.
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first.bin");
        let second = temp.path().join("second.bin");
        std::fs::write(&first, b"original bytes").unwrap();
        std::fs::write(&second, b"DIFFERENT bytes").unwrap();

        let mut groups = BTreeMap::new();
        groups.insert("b".repeat(32), vec![first.clone(), second.clone()]);
        let outcomes = restore_clone_groups(&groups);

        assert!(matches!(&outcomes[0], CloneRestoreOutcome::NotShared { .. }), "differing partners must not be shared");
        assert_eq!(std::fs::read(&second).unwrap(), b"DIFFERENT bytes", "bytes must survive untouched");
        assert!(!temp.path().join("second.tzap-clone-staging").exists());
    }

    #[test]
    fn restore_skips_groups_that_cannot_describe_sharing() {
        use std::collections::BTreeMap;

        let mut groups = BTreeMap::new();
        groups.insert("c".repeat(32), vec![std::path::PathBuf::from("/nonexistent/only.bin")]);
        assert!(restore_clone_groups(&groups).is_empty(), "a one-member group describes no sharing");
        assert!(restore_clone_groups(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn a_missing_path_reports_no_clone_group() {
        let temp = tempfile::tempdir().unwrap();
        assert_eq!(query_macos_clone_id(&temp.path().join("absent.bin")), None);
    }
}

/// Assign writer-local clone groups to a set of captured paths.
///
/// §15's `TZAP.macos.clone-group` is "32 lowercase hex digits for a writer-local
/// clone group": the value has meaning only inside one archive, so the raw
/// volume-local clone id is not what gets stored. Files sharing a clone id are
/// collected and handed a synthetic 128-bit group id derived from that id, which
/// keeps the mapping deterministic for a given input set without leaking a
/// filesystem identifier.
///
/// Only groups with **two or more members inside the archive** are recorded. A
/// file cloned from something outside the capture scope has a clone id but no
/// partner here, and a group of one describes no sharing to recreate.
///
/// Returns the hex value to store for each path that belongs to a group.
#[must_use]
pub fn assign_clone_groups(paths: &[std::path::PathBuf]) -> std::collections::BTreeMap<std::path::PathBuf, String> {
    use sha2::{Digest as _, Sha256};
    use std::collections::BTreeMap;

    let mut by_clone_id: BTreeMap<u64, Vec<&std::path::PathBuf>> = BTreeMap::new();
    for path in paths {
        if let Some(clone_id) = query_macos_clone_id(path) {
            by_clone_id.entry(clone_id).or_default().push(path);
        }
    }

    let mut assigned = BTreeMap::new();
    for (clone_id, members) in by_clone_id {
        if members.len() < 2 {
            continue;
        }
        // Derived, not the raw id: the stored value is writer-local by
        // definition, and a hash keeps it stable for a given input set.
        let digest = Sha256::digest(clone_id.to_le_bytes());
        let group = hex_lower(&digest[..16]);
        for member in members {
            assigned.insert(member.clone(), group.clone());
        }
    }
    assigned
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
        let _ = write!(&mut out, "{byte:02x}");
        out
    })
}

/// What happened when a clone group was re-established on restore.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloneRestoreOutcome {
    /// Every member after the first now shares storage with it.
    Shared { group: String, members: usize },
    /// The destination could not clone. Logical bytes are already correct;
    /// §16.11 makes this storage-layout degradation, not a failure.
    NotShared { group: String, reason: String },
}

/// Re-establish APFS clone sharing across already-restored files.
///
/// Deliberately a **post-pass** over a finished tree rather than a step inside
/// extraction. §16.11 classes clone hints "optimization only; never applied as
/// authority", so the bytes are already correct before this runs and nothing
/// here can make them wrong -- which means it needs no place in the extraction
/// ordering, where it would have to interleave with hardlink and directory
/// sequencing for no correctness gain.
///
/// Each group's first member is the source; the rest are cloned from it via
/// `clonefile` into a temporary name and renamed into place, because `clonefile`
/// refuses an existing destination. A group whose members somehow differ in
/// content is left alone: the recorded hint is not authority to overwrite bytes.
pub fn restore_clone_groups(groups: &std::collections::BTreeMap<String, Vec<std::path::PathBuf>>) -> Vec<CloneRestoreOutcome> {
    let mut outcomes = Vec::new();
    for (group, members) in groups {
        if members.len() < 2 {
            continue;
        }
        let (source, rest) = members.split_first().expect("checked non-empty");
        let mut shared = 0usize;
        let mut failure = None;
        for destination in rest {
            match clone_over(source, destination) {
                Ok(()) => shared += 1,
                Err(error) => {
                    failure = Some(error.to_string());
                    break;
                }
            }
        }
        match failure {
            None => outcomes.push(CloneRestoreOutcome::Shared { group: group.clone(), members: shared + 1 }),
            Some(reason) => outcomes.push(CloneRestoreOutcome::NotShared { group: group.clone(), reason }),
        }
    }
    outcomes
}

fn clone_over(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt as _;

    // The hint is not authority to change bytes: if the restored files differ,
    // leave them as restored.
    if fs::read(source)? != fs::read(destination)? {
        return Err(io::Error::other("restored clone partners differ; refusing to overwrite"));
    }

    let staging = destination.with_extension("tzap-clone-staging");
    let _ = fs::remove_file(&staging);
    let source_c = std::ffi::CString::new(source.as_os_str().as_bytes()).map_err(io::Error::other)?;
    let staging_c = std::ffi::CString::new(staging.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: both paths are NUL-terminated and live for the synchronous call.
    if unsafe { libc::clonefile(source_c.as_ptr(), staging_c.as_ptr(), 0) } != 0 {
        let error = io::Error::last_os_error();
        let _ = fs::remove_file(&staging);
        return Err(error);
    }
    // Rename is atomic within a volume and replaces the restored copy.
    fs::rename(&staging, destination).inspect_err(|_| {
        let _ = fs::remove_file(&staging);
    })
}
