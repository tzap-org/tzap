use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::format::FormatError;
use crate::metadata::validate_file_path_bytes;

const TAR_BLOCK_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDiagnostic {
    pub profile: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTarMember {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub data: Vec<u8>,
    pub link_target: Option<Vec<u8>>,
    pub logical_size: u64,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarMember<'a> {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub data: &'a [u8],
    pub link_target: Option<Vec<u8>>,
    pub logical_size: u64,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

impl ParsedTarMember<'_> {
    pub fn to_owned_member(&self) -> OwnedTarMember {
        OwnedTarMember {
            path: self.path.clone(),
            kind: self.kind,
            data: self.data.to_vec(),
            link_target: self.link_target.clone(),
            logical_size: self.logical_size,
            diagnostics: self.diagnostics.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeExtractionOptions {
    pub overwrite_existing: bool,
}

impl Default for SafeExtractionOptions {
    fn default() -> Self {
        Self {
            overwrite_existing: false,
        }
    }
}

#[derive(Default)]
struct LocalMetadata {
    pax_path: Option<Vec<u8>>,
    pax_linkpath: Option<Vec<u8>>,
    pax_size: Option<u64>,
    gnu_long_name: Option<Vec<u8>>,
    gnu_long_link: Option<Vec<u8>>,
    diagnostics: Vec<MetadataDiagnostic>,
}

pub fn parse_tar_member_group<'a>(
    group: &'a [u8],
    max_path_length: u32,
) -> Result<ParsedTarMember<'a>, FormatError> {
    if group.len() < TAR_BLOCK_LEN || group.len() % TAR_BLOCK_LEN != 0 {
        return Err(FormatError::InvalidArchive(
            "tar member group is not block aligned",
        ));
    }

    let mut cursor = 0usize;
    let mut metadata = LocalMetadata::default();

    loop {
        let header = slice(group, cursor, TAR_BLOCK_LEN)?;
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let is_main = matches!(typeflag, 0 | b'0' | b'5' | b'2' | b'1');
        let effective_size = if is_main {
            metadata.pax_size.unwrap_or(header_size)
        } else {
            header_size
        };
        let payload_start = checked_add(cursor, TAR_BLOCK_LEN)?;
        let payload_len = to_usize(effective_size)?;
        let payload_end = checked_add(payload_start, payload_len)?;
        let padded_end = checked_add(payload_end, padding_to_512(payload_len))?;
        let payload = slice(group, payload_start, payload_len)?;
        if padded_end > group.len() {
            return Err(FormatError::InvalidArchive(
                "tar member payload exceeds group",
            ));
        }
        if group[payload_end..padded_end].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive(
                "tar member padding is non-zero",
            ));
        }

        match typeflag {
            b'x' => {
                parse_pax_records(payload, &mut metadata)?;
                cursor = padded_end;
            }
            b'g' => {
                return Err(FormatError::InvalidArchive(
                    "global PAX headers are not allowed",
                ));
            }
            b'L' => {
                metadata.gnu_long_name = Some(trimmed_metadata_payload(payload));
                cursor = padded_end;
            }
            b'K' => {
                metadata.gnu_long_link = Some(trimmed_metadata_payload(payload));
                cursor = padded_end;
            }
            0 | b'0' | b'5' | b'2' | b'1' => {
                if padded_end != group.len() {
                    return Err(FormatError::InvalidArchive(
                        "tar member group has bytes after main entry",
                    ));
                }
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    _ => TarEntryKind::Regular,
                };
                let path = canonical_main_path(header, kind, &metadata, max_path_length)?;
                let link_target =
                    canonical_link_target(header, kind, &path, &metadata, max_path_length)?;
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    ));
                }
                let logical_size = if kind == TarEntryKind::Regular {
                    effective_size
                } else {
                    0
                };
                return Ok(ParsedTarMember {
                    path,
                    kind,
                    data: if kind == TarEntryKind::Regular {
                        payload
                    } else {
                        &[]
                    },
                    link_target,
                    logical_size,
                    diagnostics: metadata.diagnostics,
                });
            }
            _ => {
                return Err(FormatError::ReaderUnsupported("unsupported tar entry type"));
            }
        }

        if cursor >= group.len() {
            return Err(FormatError::InvalidArchive(
                "tar member group has metadata records but no main entry",
            ));
        }
    }
}

pub fn validate_tar_stream_total_extraction_size(
    stream: &[u8],
    max_path_length: u32,
    cap: u64,
) -> Result<(), FormatError> {
    if stream.len() % TAR_BLOCK_LEN != 0 {
        return Err(FormatError::InvalidArchive(
            "tar stream is not block aligned",
        ));
    }

    let mut cursor = 0usize;
    let mut total = 0u64;
    while cursor < stream.len() {
        let group_end = tar_member_group_end(stream, cursor)?;
        let member = parse_tar_member_group(&stream[cursor..group_end], max_path_length)?;
        if member.kind == TarEntryKind::Regular {
            total = total
                .checked_add(member.logical_size)
                .ok_or(FormatError::InvalidArchive(
                    "total extraction size overflow",
                ))?;
            if total > cap {
                return Err(FormatError::ReaderUnsupported(
                    "total extraction size exceeds configured cap",
                ));
            }
        }
        cursor = group_end;
    }
    Ok(())
}

fn tar_member_group_end(stream: &[u8], start: usize) -> Result<usize, FormatError> {
    let mut cursor = start;
    let mut metadata = LocalMetadata::default();

    loop {
        let header = slice(stream, cursor, TAR_BLOCK_LEN)?;
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let is_main = matches!(typeflag, 0 | b'0' | b'5' | b'2' | b'1');
        let effective_size = if is_main {
            metadata.pax_size.unwrap_or(header_size)
        } else {
            header_size
        };
        let payload_start = checked_add(cursor, TAR_BLOCK_LEN)?;
        let payload_len = to_usize(effective_size)?;
        let payload_end = checked_add(payload_start, payload_len)?;
        let padded_end = checked_add(payload_end, padding_to_512(payload_len))?;
        let payload = slice(stream, payload_start, payload_len)?;
        if padded_end > stream.len() {
            return Err(FormatError::InvalidArchive(
                "tar member payload exceeds stream",
            ));
        }
        if stream[payload_end..padded_end]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(FormatError::InvalidArchive(
                "tar member padding is non-zero",
            ));
        }

        match typeflag {
            b'x' => {
                parse_pax_records(payload, &mut metadata)?;
                cursor = padded_end;
            }
            b'L' | b'K' => {
                cursor = padded_end;
            }
            b'g' => {
                return Err(FormatError::InvalidArchive(
                    "global PAX headers are not allowed",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' => return Ok(padded_end),
            _ => return Err(FormatError::ReaderUnsupported("unsupported tar entry type")),
        }

        if cursor >= stream.len() {
            return Err(FormatError::InvalidArchive(
                "tar member group has metadata records but no main entry",
            ));
        }
    }
}

pub fn restore_tar_member(
    root: &Path,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    let destination = prepare_destination(root, &member.path, member.kind, options)?;
    match member.kind {
        TarEntryKind::Regular => write_regular_file(&destination, &member.data, options)?,
        TarEntryKind::Directory => create_directory(&destination)?,
        TarEntryKind::Symlink => {
            let target = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("symlink target is missing"))?;
            validate_symlink_target(&member.path, target)?;
            create_symlink(&destination, target, options)?;
        }
        TarEntryKind::Hardlink => {
            let target = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target_path = existing_safe_regular_path(root, target)?;
            create_hardlink(&destination, &target_path, options)?;
        }
    }
    Ok(member.diagnostics.clone())
}

fn canonical_main_path(
    header: &[u8],
    kind: TarEntryKind,
    metadata: &LocalMetadata,
    max_path_length: u32,
) -> Result<Vec<u8>, FormatError> {
    let mut path = metadata
        .pax_path
        .clone()
        .or_else(|| metadata.gnu_long_name.clone())
        .unwrap_or_else(|| ustar_path(header));
    if kind == TarEntryKind::Directory && path.ends_with(b"/") && !path.ends_with(b"//") {
        path.pop();
    }
    validate_file_path_bytes(&path, max_path_length)?;
    Ok(path)
}

fn canonical_link_target(
    header: &[u8],
    kind: TarEntryKind,
    link_path: &[u8],
    metadata: &LocalMetadata,
    max_path_length: u32,
) -> Result<Option<Vec<u8>>, FormatError> {
    if !matches!(kind, TarEntryKind::Symlink | TarEntryKind::Hardlink) {
        return Ok(None);
    }
    let target = metadata
        .pax_linkpath
        .clone()
        .or_else(|| metadata.gnu_long_link.clone())
        .unwrap_or_else(|| nul_trimmed(&header[157..257]).to_vec());
    if target.is_empty() {
        return Err(FormatError::UnsafeArchivePath);
    }
    match kind {
        TarEntryKind::Hardlink => validate_file_path_bytes(&target, max_path_length)?,
        TarEntryKind::Symlink => validate_symlink_target(link_path, &target)?,
        _ => {}
    }
    Ok(Some(target))
}

fn parse_pax_records(payload: &[u8], metadata: &mut LocalMetadata) -> Result<(), FormatError> {
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let len_digits_start = cursor;
        while cursor < payload.len() && payload[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == len_digits_start || cursor >= payload.len() || payload[cursor] != b' ' {
            return Err(FormatError::InvalidArchive("malformed PAX record"));
        }
        let len = parse_decimal(&payload[len_digits_start..cursor])?;
        let record_start = len_digits_start;
        let record_end = checked_add(record_start, len)?;
        if record_end > payload.len() || len < 4 {
            return Err(FormatError::InvalidArchive("malformed PAX record"));
        }
        let body_start = cursor + 1;
        let record = &payload[body_start..record_end];
        if record.last().copied() != Some(b'\n') {
            return Err(FormatError::InvalidArchive("malformed PAX record"));
        }
        let body = &record[..record.len() - 1];
        let eq = body
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or(FormatError::InvalidArchive("malformed PAX record"))?;
        let key = std::str::from_utf8(&body[..eq])
            .map_err(|_| FormatError::InvalidArchive("malformed PAX key"))?;
        let value = &body[eq + 1..];
        match key {
            "path" => metadata.pax_path = Some(value.to_vec()),
            "linkpath" => metadata.pax_linkpath = Some(value.to_vec()),
            "size" => metadata.pax_size = Some(parse_decimal(value)? as u64),
            key if key.starts_with("SCHILY.xattr.")
                || key.starts_with("LIBARCHIVE.xattr.")
                || key.starts_with("SCHILY.acl.")
                || key.starts_with("GNU.sparse.") =>
            {
                metadata.diagnostics.push(MetadataDiagnostic {
                    profile: "pax-xattrs-acls",
                    message: "unsupported PAX metadata was ignored",
                });
            }
            _ => metadata.diagnostics.push(MetadataDiagnostic {
                profile: "pax-posix-2001",
                message: "unsupported PAX key was ignored",
            }),
        }
        cursor = record_end;
    }
    Ok(())
}

fn validate_symlink_target(link_path: &[u8], target: &[u8]) -> Result<(), FormatError> {
    if target.is_empty()
        || target.contains(&0)
        || target.contains(&b'\\')
        || target.contains(&b':')
        || target[0] == b'/'
    {
        return Err(FormatError::UnsafeArchivePath);
    }
    let target = std::str::from_utf8(target).map_err(|_| FormatError::UnsafeArchivePath)?;
    let link_path = std::str::from_utf8(link_path).map_err(|_| FormatError::UnsafeArchivePath)?;
    let mut stack = link_path
        .split('/')
        .take(link_path.split('/').count().saturating_sub(1))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            return Err(FormatError::UnsafeArchivePath);
        }
        if component == ".." {
            if stack.pop().is_none() {
                return Err(FormatError::UnsafeArchivePath);
            }
        } else {
            validate_file_path_bytes(component.as_bytes(), u32::MAX)?;
            stack.push(component.to_owned());
        }
    }
    Ok(())
}

fn prepare_destination(
    root: &Path,
    archive_path: &[u8],
    kind: TarEntryKind,
    options: SafeExtractionOptions,
) -> Result<PathBuf, FormatError> {
    let components = path_components(archive_path)?;
    validate_root(root)?;
    let mut current = root.to_path_buf();
    for component in &components[..components.len().saturating_sub(1)] {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                let file_type = metadata.file_type();
                if file_type.is_symlink() || !file_type.is_dir() {
                    return Err(FormatError::UnsafeArchivePath);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to create parent directory")
                })?;
                let metadata = fs::symlink_metadata(&current).map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to inspect created parent directory",
                    )
                })?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
                    return Err(FormatError::UnsafeArchivePath);
                }
            }
            Err(_) => {
                return Err(FormatError::FilesystemExtractionFailed(
                    "failed to inspect parent directory",
                ));
            }
        }
    }

    current.push(components.last().ok_or(FormatError::UnsafeArchivePath)?);
    match fs::symlink_metadata(&current) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(FormatError::UnsafeArchivePath);
            }
            if kind == TarEntryKind::Directory {
                if file_type.is_dir() {
                    return Ok(current);
                }
                return Err(FormatError::UnsafeOverwrite);
            }
            if file_type.is_dir() {
                return Err(FormatError::UnsafeOverwrite);
            }
            if !options.overwrite_existing {
                return Err(FormatError::UnsafeOverwrite);
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to inspect destination",
            ));
        }
    }
    Ok(current)
}

fn validate_root(root: &Path) -> Result<(), FormatError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| {
        FormatError::FilesystemExtractionFailed("extraction root must already exist")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(FormatError::UnsafeArchivePath);
    }
    Ok(())
}

fn existing_safe_regular_path(root: &Path, archive_path: &[u8]) -> Result<PathBuf, FormatError> {
    validate_file_path_bytes(archive_path, u32::MAX)?;
    let components = path_components(archive_path)?;
    validate_root(root)?;
    let mut current = root.to_path_buf();
    for (idx, component) in components.iter().enumerate() {
        current.push(component);
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| FormatError::UnsafeArchivePath)?;
        if metadata.file_type().is_symlink() {
            return Err(FormatError::UnsafeArchivePath);
        }
        if idx + 1 != components.len() {
            if !metadata.file_type().is_dir() {
                return Err(FormatError::UnsafeArchivePath);
            }
        } else if !metadata.file_type().is_file() {
            return Err(FormatError::UnsafeArchivePath);
        }
    }
    Ok(current)
}

fn write_regular_file(
    destination: &Path,
    data: &[u8],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing && destination.exists() {
        fs::remove_file(destination)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to remove old file"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to create regular file"))?;
    file.write_all(data)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to write regular file"))
}

fn create_directory(destination: &Path) -> Result<(), FormatError> {
    match fs::create_dir(destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata =
                fs::symlink_metadata(destination).map_err(|_| FormatError::UnsafeOverwrite)?;
            if metadata.file_type().is_dir() {
                Ok(())
            } else {
                Err(FormatError::UnsafeOverwrite)
            }
        }
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to create directory",
        )),
    }
}

fn create_hardlink(
    destination: &Path,
    target: &Path,
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing && destination.exists() {
        fs::remove_file(destination)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to remove old file"))?;
    }
    fs::hard_link(target, destination)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to create hardlink"))
}

#[cfg(unix)]
fn create_symlink(
    destination: &Path,
    target: &[u8],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing && destination.exists() {
        fs::remove_file(destination)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to remove old file"))?;
    }
    let target = std::str::from_utf8(target).map_err(|_| FormatError::UnsafeArchivePath)?;
    std::os::unix::fs::symlink(target, destination)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to create symlink"))
}

#[cfg(windows)]
fn create_symlink(
    destination: &Path,
    target: &[u8],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing && destination.exists() {
        fs::remove_file(destination)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to remove old file"))?;
    }
    let target = std::str::from_utf8(target).map_err(|_| FormatError::UnsafeArchivePath)?;
    std::os::windows::fs::symlink_file(target, destination)
        .map_err(|_| FormatError::FilesystemExtractionFailed("failed to create symlink"))
}

fn path_components(path: &[u8]) -> Result<Vec<String>, FormatError> {
    validate_file_path_bytes(path, u32::MAX)?;
    let path = std::str::from_utf8(path).map_err(|_| FormatError::UnsafeArchivePath)?;
    Ok(path.split('/').map(str::to_owned).collect())
}

fn ustar_path(header: &[u8]) -> Vec<u8> {
    let name = nul_trimmed(&header[0..100]);
    let prefix = nul_trimmed(&header[345..500]);
    if prefix.is_empty() {
        name.to_vec()
    } else {
        let mut out = Vec::with_capacity(prefix.len() + 1 + name.len());
        out.extend_from_slice(prefix);
        out.push(b'/');
        out.extend_from_slice(name);
        out
    }
}

fn trimmed_metadata_payload(payload: &[u8]) -> Vec<u8> {
    let mut end = payload.len();
    while end > 0 && payload[end - 1] == 0 {
        end -= 1;
    }
    payload[..end].to_vec()
}

fn verify_tar_checksum(header: &[u8]) -> Result<(), FormatError> {
    let stored = parse_tar_octal(&header[148..156])?;
    let mut sum = 0u64;
    for (idx, byte) in header.iter().enumerate() {
        if (148..156).contains(&idx) {
            sum += b' ' as u64;
        } else {
            sum += *byte as u64;
        }
    }
    if stored != sum {
        return Err(FormatError::InvalidArchive("tar header checksum mismatch"));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, FormatError> {
    let mut value = 0u64;
    let mut saw_digit = false;
    for byte in field {
        match *byte {
            0 | b' ' if saw_digit => break,
            0 | b' ' => {}
            b'0'..=b'7' => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|acc| acc.checked_add((*byte - b'0') as u64))
                    .ok_or(FormatError::InvalidArchive("tar octal field overflow"))?;
            }
            _ => return Err(FormatError::InvalidArchive("malformed tar octal field")),
        }
    }
    Ok(value)
}

fn parse_decimal(field: &[u8]) -> Result<usize, FormatError> {
    let mut value = 0usize;
    if field.is_empty() {
        return Err(FormatError::InvalidArchive("malformed decimal field"));
    }
    for byte in field {
        if !byte.is_ascii_digit() {
            return Err(FormatError::InvalidArchive("malformed decimal field"));
        }
        value = value
            .checked_mul(10)
            .and_then(|acc| acc.checked_add((byte - b'0') as usize))
            .ok_or(FormatError::InvalidArchive("decimal field overflow"))?;
    }
    Ok(value)
}

fn nul_trimmed(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn padding_to_512(len: usize) -> usize {
    let remainder = len % TAR_BLOCK_LEN;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN - remainder
    }
}

fn slice(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], FormatError> {
    let end = checked_add(offset, len)?;
    bytes.get(offset..end).ok_or(FormatError::InvalidLength {
        structure: "tar member",
        expected: end,
        actual: bytes.len(),
    })
}

fn checked_add(lhs: usize, rhs: usize) -> Result<usize, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive(
        "tar member arithmetic overflow",
    ))
}

fn to_usize(value: u64) -> Result<usize, FormatError> {
    usize::try_from(value).map_err(|_| FormatError::InvalidArchive("tar member size overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn header(path: &[u8], kind: u8, size: usize, link: &[u8]) -> [u8; TAR_BLOCK_LEN] {
        let mut header = [0u8; TAR_BLOCK_LEN];
        header[..path.len()].copy_from_slice(path);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);
        header
    }

    fn member(path: &[u8], kind: u8, data: &[u8], link: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&header(path, kind, data.len(), link));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
        out
    }

    fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
        let mut len = key.len() + value.len() + 4;
        loop {
            let candidate = len.to_string().len() + 1 + key.len() + 1 + value.len() + 1;
            if candidate == len {
                break;
            }
            len = candidate;
        }
        let mut out = Vec::new();
        out.extend_from_slice(len.to_string().as_bytes());
        out.push(b' ');
        out.extend_from_slice(key.as_bytes());
        out.push(b'=');
        out.extend_from_slice(value);
        out.push(b'\n');
        out
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let digits = format!("{value:o}");
        field.fill(0);
        let start = field.len() - 1 - digits.len();
        field[..start].fill(b'0');
        field[start..start + digits.len()].copy_from_slice(digits.as_bytes());
    }

    fn write_checksum(field: &mut [u8], value: u64) {
        let digits = format!("{value:06o}");
        field[0..6].copy_from_slice(digits.as_bytes());
        field[6] = 0;
        field[7] = b' ';
    }

    #[test]
    fn parses_ustar_regular_member() {
        let bytes = member(b"dir/file.txt", b'0', b"hello", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        assert_eq!(parsed.kind, TarEntryKind::Regular);
        assert_eq!(parsed.path, b"dir/file.txt");
        assert_eq!(parsed.data, b"hello");
        assert_eq!(parsed.logical_size, 5);
    }

    #[test]
    fn canonicalizes_one_directory_trailing_slash_only_for_directories() {
        let dir = member(b"dir/", b'5', b"", b"");
        assert_eq!(parse_tar_member_group(&dir, 4096).unwrap().path, b"dir");

        let file = member(b"dir/", b'0', b"", b"");
        assert_eq!(
            parse_tar_member_group(&file, 4096).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }

    #[test]
    fn rejects_global_pax_headers() {
        let bytes = member(b"pax", b'g', b"11 path=x\n", b"");
        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global PAX headers are not allowed")
        );
    }

    #[test]
    fn applies_local_pax_path_and_size() {
        let pax = pax_record("path", b"long/name.txt");
        let mut bytes = member(b"PaxHeaders/name", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"short", b'0', b"abc", b""));

        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        assert_eq!(parsed.path, b"long/name.txt");
        assert_eq!(parsed.data, b"abc");
    }

    #[test]
    fn rejects_platform_escape_paths() {
        for path in [
            b"/abs".as_slice(),
            b"../up".as_slice(),
            b"a//b".as_slice(),
            b"a\\b".as_slice(),
            b"a:b".as_slice(),
            b"CON".as_slice(),
        ] {
            let bytes = member(path, b'0', b"", b"");
            assert_eq!(
                parse_tar_member_group(&bytes, 4096).unwrap_err(),
                FormatError::UnsafeArchivePath
            );
        }
    }

    #[test]
    fn safe_restore_rejects_symlink_parent() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();

        #[cfg(unix)]
        {
            let member = OwnedTarMember {
                path: b"link/file.txt".to_vec(),
                kind: TarEntryKind::Regular,
                data: b"blocked".to_vec(),
                link_target: None,
                logical_size: 7,
                diagnostics: Vec::new(),
            };

            assert_eq!(
                restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default())
                    .unwrap_err(),
                FormatError::UnsafeArchivePath
            );
        }
    }

    #[test]
    fn safe_restore_requires_hardlink_target_to_be_existing_regular_file() {
        let tmp = tempdir().unwrap();
        fs::write(tmp.path().join("target.txt"), b"target").unwrap();
        let member = OwnedTarMember {
            path: b"linked.txt".to_vec(),
            kind: TarEntryKind::Hardlink,
            data: Vec::new(),
            link_target: Some(b"target.txt".to_vec()),
            logical_size: 0,
            diagnostics: Vec::new(),
        };

        restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
        assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
    }

    #[test]
    fn restore_revalidates_symlink_targets_from_owned_members() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"link".to_vec(),
            kind: TarEntryKind::Symlink,
            data: Vec::new(),
            link_target: Some(b"/outside".to_vec()),
            logical_size: 0,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
        assert!(!tmp.path().join("link").exists());
    }

    #[test]
    fn safe_restore_rejects_directory_over_existing_file_even_with_overwrite() {
        let tmp = tempdir().unwrap();
        let conflict = tmp.path().join("conflict");
        fs::write(&conflict, b"not a directory").unwrap();
        let member = OwnedTarMember {
            path: b"conflict".to_vec(),
            kind: TarEntryKind::Directory,
            data: Vec::new(),
            link_target: None,
            logical_size: 0,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(
                tmp.path(),
                &member,
                SafeExtractionOptions {
                    overwrite_existing: true
                }
            )
            .unwrap_err(),
            FormatError::UnsafeOverwrite
        );
        assert!(conflict.is_file());
    }

    #[test]
    fn hardlink_target_checks_use_component_position_not_value() {
        let tmp = tempdir().unwrap();
        fs::create_dir(tmp.path().join("a")).unwrap();
        fs::write(tmp.path().join("a").join("a"), b"target").unwrap();
        let member = OwnedTarMember {
            path: b"linked.txt".to_vec(),
            kind: TarEntryKind::Hardlink,
            data: Vec::new(),
            link_target: Some(b"a/a".to_vec()),
            logical_size: 0,
            diagnostics: Vec::new(),
        };

        restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
        assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
    }

    #[test]
    fn hardlink_targets_obey_max_path_length() {
        let bytes = member(b"link", b'1', b"", b"long/name");

        assert_eq!(
            parse_tar_member_group(&bytes, 4).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }
}
