use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::ambient_authority;
use cap_std::fs::{Dir as CapDir, OpenOptions as CapOpenOptions};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use unicode_normalization::UnicodeNormalization;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::entry_metadata::{
    parse_auxiliary_record, parse_canonical_pax, parse_primary_metadata, parse_sparse_payload,
    validate_group_metadata, ArchiveTimestamp, AuxiliaryRecord, AuxiliaryStreamValidator,
    CaptureReportRow, CaptureStatus, MemberMetadata, PaxRecords, PortableMetadataMirror,
    PrimaryMetadata, RestoreClass, RestorePolicy, SparseStreamValidator, CAPTURE_REPORT_KIND,
    HAS_NATIVE_METADATA, HAS_SPARSE_EXTENTS, MAX_AGGREGATE_PAX_PAYLOAD, MAX_LOCAL_PAX_PAYLOAD,
    REQUIRES_SYSTEM_RESTORE,
};
use crate::format::{ExtractError, FormatError};
use crate::metadata::validate_file_path_bytes;

const TAR_BLOCK_LEN: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TarEntryKind {
    Regular,
    Directory,
    Symlink,
    Hardlink,
    CharacterDevice,
    BlockDevice,
    Fifo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataOperation {
    Capture,
    Parse,
    Verify,
    Plan,
    Restore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataDiagnosticStatus {
    Partial,
    Unsupported,
    Skipped,
    Materialized,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataDiagnostic {
    pub path: Vec<u8>,
    pub profile: String,
    pub metadata_class: String,
    pub operation: MetadataOperation,
    pub status: MetadataDiagnosticStatus,
    pub message: String,
    pub restore_policy: Option<RestorePolicy>,
    pub restore_phase: Option<u8>,
    pub native_host_error: Option<String>,
    pub bytes_staged: Option<u64>,
    pub bytes_committed: Option<u64>,
}

impl MetadataDiagnostic {
    fn new(
        path: &[u8],
        profile: impl Into<String>,
        metadata_class: impl Into<String>,
        operation: MetadataOperation,
        status: MetadataDiagnosticStatus,
        message: impl Into<String>,
    ) -> Self {
        Self {
            path: path.to_vec(),
            profile: profile.into(),
            metadata_class: metadata_class.into(),
            operation,
            status,
            message: message.into(),
            restore_policy: None,
            restore_phase: None,
            native_host_error: None,
            bytes_staged: None,
            bytes_committed: None,
        }
    }

    fn for_restore(mut self, policy: RestorePolicy, phase: u8) -> Self {
        self.restore_policy = Some(policy);
        self.restore_phase = Some(phase);
        self
    }

    fn with_native_error(mut self, error: &std::io::Error) -> Self {
        self.native_host_error = Some(error.to_string());
        self
    }

    fn with_bytes(mut self, staged: u64, committed: u64) -> Self {
        self.bytes_staged = Some(staged);
        self.bytes_committed = Some(committed);
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorePolicyCapability {
    pub policy: RestorePolicy,
    pub policy_complete: bool,
    pub degraded_restore_available: bool,
    pub reason: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMetadataVerification {
    pub path: Vec<u8>,
    pub capture_status: CaptureStatus,
    pub required_profiles: Vec<String>,
    pub optional_profiles: Vec<String>,
    pub auxiliary_kinds: Vec<String>,
    pub policy_capabilities: Vec<RestorePolicyCapability>,
    pub full_fidelity_possible: bool,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataVerificationReport {
    pub all_capture_complete: bool,
    pub full_fidelity_possible: bool,
    pub profiles_present: Vec<String>,
    pub auxiliary_kinds_present: Vec<String>,
    pub entries: Vec<EntryMetadataVerification>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedTarMember {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub data: Vec<u8>,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub reparse_placeholder: bool,
    pub v45_metadata: Option<MemberMetadata>,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedTarMember<'a> {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub data: &'a [u8],
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub reparse_placeholder: bool,
    pub diagnostics: Vec<MetadataDiagnostic>,
    pub v45_metadata: MemberMetadata,
}

impl ParsedTarMember<'_> {
    pub fn to_owned_member(&self) -> Result<OwnedTarMember, FormatError> {
        let data = if let Some(layout) = &self.v45_metadata.sparse_layout {
            let logical_len = usize::try_from(layout.logical_size).map_err(|_| {
                FormatError::ReaderUnsupported("sparse logical size exceeds platform limits")
            })?;
            let mut logical = vec![0u8; logical_len];
            let mut stored_cursor = layout.map_and_padding_size;
            for extent in &layout.extents {
                let extent_len = usize::try_from(extent.length).map_err(|_| {
                    FormatError::ReaderUnsupported("sparse extent exceeds platform limits")
                })?;
                let stored_end = stored_cursor
                    .checked_add(extent_len)
                    .ok_or(FormatError::InvalidArchive("sparse stored range overflow"))?;
                let logical_start = usize::try_from(extent.offset).map_err(|_| {
                    FormatError::ReaderUnsupported("sparse offset exceeds platform limits")
                })?;
                let logical_end = logical_start
                    .checked_add(extent_len)
                    .ok_or(FormatError::InvalidArchive("sparse logical range overflow"))?;
                logical
                    .get_mut(logical_start..logical_end)
                    .ok_or(FormatError::InvalidArchive(
                        "sparse logical range is invalid",
                    ))?
                    .copy_from_slice(self.data.get(stored_cursor..stored_end).ok_or(
                        FormatError::InvalidArchive("sparse stored range is invalid"),
                    )?);
                stored_cursor = stored_end;
            }
            logical
        } else {
            self.data.to_vec()
        };
        Ok(OwnedTarMember {
            path: self.path.clone(),
            kind: self.kind,
            data,
            link_target: self.link_target.clone(),
            mode: self.mode,
            mtime: self.mtime,
            logical_size: self.logical_size,
            reparse_placeholder: self.reparse_placeholder,
            v45_metadata: Some(self.v45_metadata.clone()),
            diagnostics: self.diagnostics.clone(),
        })
    }

    pub(crate) fn to_owned_metadata(&self) -> OwnedTarMember {
        OwnedTarMember {
            path: self.path.clone(),
            kind: self.kind,
            data: Vec::new(),
            link_target: self.link_target.clone(),
            mode: self.mode,
            mtime: self.mtime,
            logical_size: self.logical_size,
            reparse_placeholder: self.reparse_placeholder,
            v45_metadata: Some(self.v45_metadata.clone()),
            diagnostics: self.diagnostics.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SafeExtractionOptions {
    pub overwrite_existing: bool,
    pub restore_policy: RestorePolicy,
    /// Permit a requested same-OS/system operation to skip unsupported
    /// authenticated metadata with durable diagnostics.
    pub allow_degraded: bool,
    /// Explicit caller authorization for system-class restoration. The core
    /// implementation still applies only system items it understands.
    pub system_authorized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamedTarMemberMetadata {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub file_entry_flags: u32,
    pub reparse_placeholder: bool,
    pub v45_metadata: MemberMetadata,
    pub diagnostics: Vec<MetadataDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TarStreamMemberSummary {
    pub path: Vec<u8>,
    pub kind: TarEntryKind,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub mtime: ArchiveTimestamp,
    pub logical_size: u64,
    pub file_entry_flags: u32,
    pub reparse_placeholder: bool,
    pub v45_metadata: MemberMetadata,
    pub diagnostics: Vec<MetadataDiagnostic>,
    pub group_start: u64,
    pub group_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TarStreamSummary {
    pub members: Vec<TarStreamMemberSummary>,
    pub tar_total_size: u64,
    pub total_extraction_size: u64,
}

pub(crate) trait TarMemberGroupReader {
    fn read_some_member_bytes(&mut self, buf: &mut [u8]) -> Result<usize, ExtractError>;

    fn read_exact_member_bytes(&mut self, mut buf: &mut [u8]) -> Result<(), ExtractError> {
        while !buf.is_empty() {
            let read = self.read_some_member_bytes(buf)?;
            if read == 0 {
                return Err(
                    FormatError::InvalidArchive("tar member group exceeds frame range").into(),
                );
            }
            let (_, rest) = buf.split_at_mut(read);
            buf = rest;
        }
        Ok(())
    }
}

trait TarMemberStreamHandler {
    fn on_member(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), ExtractError>;
    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError>;
}

pub(crate) trait TarStreamObserver {
    fn on_member_start(&mut self, _member: &StreamedTarMemberMetadata) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_regular_payload(&mut self, _bytes: &[u8]) -> Result<(), FormatError> {
        Ok(())
    }

    fn on_member_complete(
        &mut self,
        member: &StreamedTarMemberMetadata,
    ) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        Ok(member.diagnostics.clone())
    }

    fn on_archive_complete(&mut self) -> Result<(), FormatError> {
        Ok(())
    }
}

pub(crate) struct NoopTarStreamObserver;

impl TarStreamObserver for NoopTarStreamObserver {}

pub(crate) struct TarStreamFilesystemRestoreObserver<'a> {
    handler: FilesystemRestoreHandler<'a>,
}

impl<'a> TarStreamFilesystemRestoreObserver<'a> {
    pub(crate) fn new(root: &'a Path, options: SafeExtractionOptions) -> Self {
        Self {
            handler: FilesystemRestoreHandler::new_deferred(root, options),
        }
    }
}

impl TarStreamObserver for TarStreamFilesystemRestoreObserver<'_> {
    fn on_member_start(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), FormatError> {
        self.handler
            .on_member(member)
            .map_err(format_error_from_extract_error)
    }

    fn on_regular_payload(&mut self, bytes: &[u8]) -> Result<(), FormatError> {
        self.handler
            .write_regular_payload(bytes)
            .map_err(format_error_from_extract_error)
    }

    fn on_member_complete(
        &mut self,
        member: &StreamedTarMemberMetadata,
    ) -> Result<Vec<MetadataDiagnostic>, FormatError> {
        self.handler
            .finish(member)
            .map_err(format_error_from_extract_error)
    }

    fn on_archive_complete(&mut self) -> Result<(), FormatError> {
        self.handler.finish_archive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V45PaxKind {
    Primary,
    Auxiliary(u32),
}

#[derive(Default)]
struct V45StreamingGroup {
    pending: Option<(V45PaxKind, PaxRecords)>,
    auxiliary: Vec<AuxiliaryRecord>,
    aggregate_pax_bytes: usize,
}

struct StreamingSparsePrimary {
    validator: SparseStreamValidator,
    layout: Option<crate::entry_metadata::SparseLayout>,
    extent_index: usize,
    extent_consumed: u64,
    logical_cursor: u64,
}

impl StreamingSparsePrimary {
    fn new(logical_size: u64) -> Self {
        Self {
            validator: SparseStreamValidator::new(logical_size),
            layout: None,
            extent_index: 0,
            extent_consumed: 0,
            logical_cursor: 0,
        }
    }

    fn observe<O: TarStreamObserver>(
        &mut self,
        bytes: &[u8],
        observer: &mut O,
    ) -> Result<(), FormatError> {
        let before = self.validator.position();
        self.validator.observe(bytes)?;
        if self.layout.is_none() {
            self.layout = self.validator.layout_if_map_complete();
        }
        let Some(layout) = &self.layout else {
            return Ok(());
        };
        let padded = layout.map_and_padding_size as u64;
        let data_offset = if before >= padded {
            0
        } else {
            usize::try_from((padded - before).min(bytes.len() as u64))
                .map_err(|_| FormatError::InvalidArchive("sparse offset exceeds usize"))?
        };
        let mut data = &bytes[data_offset..];
        while !data.is_empty() {
            let extent =
                layout
                    .extents
                    .get(self.extent_index)
                    .ok_or(FormatError::InvalidArchive(
                        "sparse primary has trailing extent bytes",
                    ))?;
            if self.extent_consumed == 0 {
                observer_write_zeros(observer, extent.offset - self.logical_cursor)?;
            }
            let available = extent.length - self.extent_consumed;
            let take = usize::try_from(available.min(data.len() as u64))
                .map_err(|_| FormatError::InvalidArchive("sparse extent exceeds usize"))?;
            observer.on_regular_payload(&data[..take])?;
            self.extent_consumed += take as u64;
            data = &data[take..];
            if self.extent_consumed == extent.length {
                self.logical_cursor = extent.offset + extent.length;
                self.extent_index += 1;
                self.extent_consumed = 0;
            }
        }
        Ok(())
    }

    fn finish<O: TarStreamObserver>(self, observer: &mut O) -> Result<(), FormatError> {
        let layout = self.validator.finish()?;
        if self.extent_index != layout.extents.len() || self.extent_consumed != 0 {
            return Err(FormatError::InvalidArchive(
                "sparse primary extent data is incomplete",
            ));
        }
        observer_write_zeros(observer, layout.logical_size - self.logical_cursor)
    }
}

fn observer_write_zeros<O: TarStreamObserver>(
    observer: &mut O,
    mut len: u64,
) -> Result<(), FormatError> {
    let zeros = [0u8; 64 * 1024];
    while len > 0 {
        let take = len.min(zeros.len() as u64) as usize;
        observer.on_regular_payload(&zeros[..take])?;
        len -= take as u64;
    }
    Ok(())
}

pub fn parse_tar_member_group<'a>(
    group: &'a [u8],
    max_path_length: u32,
) -> Result<ParsedTarMember<'a>, FormatError> {
    if group.len() < TAR_BLOCK_LEN * 3 || group.len() % TAR_BLOCK_LEN != 0 {
        return Err(FormatError::InvalidArchive(
            "tar member group is not block aligned",
        ));
    }

    let mut cursor = 0usize;
    let mut pending: Option<(V45PaxKind, PaxRecords)> = None;
    let mut auxiliary = Vec::<AuxiliaryRecord>::new();
    let mut aggregate_pax_bytes = 0usize;

    loop {
        let header = slice(group, cursor, TAR_BLOCK_LEN)?;
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
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
                if pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    ));
                }
                validate_v45_metadata_header(header)?;
                aggregate_pax_bytes = aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: aggregate_pax_bytes as u64,
                    });
                }
                let records = parse_canonical_pax(payload)?;
                let label = ustar_path(header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != auxiliary.len() as u32 {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        ));
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    ));
                };
                pending = Some((kind, records));
                cursor = padded_end;
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    ));
                };
                validate_v45_auxiliary_header(header, ordinal, header_size, effective_size)?;
                auxiliary.push(parse_auxiliary_record(
                    &records,
                    ordinal,
                    effective_size,
                    payload,
                )?);
                cursor = padded_end;
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                let Some((V45PaxKind::Primary, records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    ));
                };
                if padded_end != group.len() {
                    return Err(FormatError::InvalidArchive(
                        "tar member group has bytes after main entry",
                    ));
                }
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    b'3' => TarEntryKind::CharacterDevice,
                    b'4' => TarEntryKind::BlockDevice,
                    b'6' => TarEntryKind::Fifo,
                    _ => TarEntryKind::Regular,
                };
                let primary = parse_primary_metadata(&records)?;
                validate_v45_primary_header(
                    header,
                    kind,
                    header_size,
                    effective_size,
                    &primary,
                    &records,
                )?;
                let path = v45_primary_path(header, kind, &records, &primary, max_path_length)?;
                let link_target =
                    v45_primary_link_target(header, kind, &path, &primary, max_path_length)?;
                let is_sparse = primary.sparse_logical_size.is_some();
                let reparse_placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    ));
                }
                if reparse_placeholder && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "reparse placeholder has non-zero primary payload",
                    ));
                }
                let sparse_layout = if let Some(logical_size) = primary.sparse_logical_size {
                    if kind != TarEntryKind::Regular || reparse_placeholder {
                        return Err(FormatError::InvalidArchive(
                            "sparse metadata is not valid for this primary type",
                        ));
                    }
                    Some(parse_sparse_payload(payload, logical_size)?)
                } else {
                    None
                };
                let logical_size = if kind == TarEntryKind::Regular && !reparse_placeholder {
                    primary.sparse_logical_size.unwrap_or(effective_size)
                } else {
                    0
                };
                let (file_entry_flags, capture_report) =
                    v45_group_flags(&primary, &auxiliary, kind)?;
                validate_v45_primary_cross_fields(
                    kind,
                    &records,
                    &primary,
                    &auxiliary,
                    V45PrimaryLink {
                        path: &path,
                        target: link_target.as_deref(),
                    },
                    is_sparse,
                    capture_report.as_deref(),
                )?;
                let diagnostics = Vec::new();
                let mtime = decoded_mtime(&primary, header)?;
                let v45_metadata = MemberMetadata {
                    declaration: primary.declaration.clone(),
                    auxiliary,
                    file_entry_flags,
                    sparse_layout,
                    capture_report,
                    primary_has_native_scalar: primary.has_native_scalar,
                    primary_requires_system_restore: primary.requires_system_restore,
                    portable_mirror: portable_metadata_mirror(header, &records, &primary)?,
                };
                return Ok(ParsedTarMember {
                    path,
                    kind,
                    data: if kind == TarEntryKind::Regular {
                        payload
                    } else {
                        &[]
                    },
                    mode: primary.declaration.portable_mode,
                    mtime,
                    link_target,
                    logical_size,
                    reparse_placeholder,
                    diagnostics,
                    v45_metadata,
                });
            }
            _ => {
                return Err(FormatError::InvalidArchive(
                    "unsupported revision-45 tar entry type",
                ));
            }
        }

        if cursor >= group.len() {
            return Err(FormatError::InvalidArchive(
                "tar member group has metadata records but no main entry",
            ));
        }
    }
}

fn validate_v45_metadata_header(header: &[u8]) -> Result<(), FormatError> {
    validate_ustar_header(header)?;
    if parse_tar_octal(&header[100..108])? != 0
        || parse_tar_octal(&header[108..116])? != 0
        || parse_tar_octal(&header[116..124])? != 0
        || parse_tar_octal(&header[136..148])? != 0
        || !nul_trimmed(&header[157..257]).is_empty()
        || !nul_trimmed(&header[265..297]).is_empty()
        || !nul_trimmed(&header[297..329]).is_empty()
        || parse_tar_octal(&header[329..337])? != 0
        || parse_tar_octal(&header[337..345])? != 0
        || !nul_trimmed(&header[345..500]).is_empty()
    {
        return Err(FormatError::InvalidArchive(
            "revision-45 local PAX header has non-zero metadata fields",
        ));
    }
    Ok(())
}

fn validate_ustar_header(header: &[u8]) -> Result<(), FormatError> {
    if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
        return Err(FormatError::InvalidArchive(
            "tar header is not canonical ustar",
        ));
    }
    for field in [
        &header[0..100],
        &header[157..257],
        &header[265..297],
        &header[297..329],
        &header[345..500],
    ] {
        validate_nul_terminated_field(field)?;
    }
    if header[500..512].iter().any(|byte| *byte != 0) {
        return Err(FormatError::InvalidArchive(
            "tar header has non-zero reserved bytes",
        ));
    }
    Ok(())
}

fn validate_nul_terminated_field(field: &[u8]) -> Result<(), FormatError> {
    if let Some(nul) = field.iter().position(|byte| *byte == 0) {
        if field[nul..].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive(
                "ustar string field has bytes after NUL",
            ));
        }
    }
    Ok(())
}

fn parse_auxiliary_pax_label(label: &[u8]) -> Option<u32> {
    let suffix = label.strip_prefix(b"TZAP-PAX/AUX/")?;
    if suffix.len() != 8
        || !suffix
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    u32::from_str_radix(std::str::from_utf8(suffix).ok()?, 16).ok()
}

fn validate_v45_auxiliary_header(
    header: &[u8],
    ordinal: u32,
    header_size: u64,
    effective_size: u64,
) -> Result<(), FormatError> {
    validate_ustar_header(header)?;
    let expected = format!("TZAP-AUX/{ordinal:08x}");
    if ustar_path(header) != expected.as_bytes()
        || parse_tar_octal(&header[100..108])? != 0
        || parse_tar_octal(&header[108..116])? != 0
        || parse_tar_octal(&header[116..124])? != 0
        || parse_tar_octal(&header[136..148])? != 0
        || !nul_trimmed(&header[157..257]).is_empty()
        || !nul_trimmed(&header[265..297]).is_empty()
        || !nul_trimmed(&header[297..329]).is_empty()
        || parse_tar_octal(&header[329..337])? != 0
        || parse_tar_octal(&header[337..345])? != 0
        || !nul_trimmed(&header[345..500]).is_empty()
        || (header_size != effective_size && header_size != 0)
    {
        return Err(FormatError::InvalidArchive(
            "revision-45 auxiliary tar header is not canonical",
        ));
    }
    Ok(())
}

fn validate_v45_primary_header(
    header: &[u8],
    kind: TarEntryKind,
    header_size: u64,
    effective_size: u64,
    primary: &PrimaryMetadata,
    records: &PaxRecords,
) -> Result<(), FormatError> {
    validate_ustar_header(header)?;
    if parse_tar_octal(&header[100..108])? != primary.declaration.portable_mode as u64 {
        return Err(FormatError::InvalidArchive(
            "ustar mode does not match TZAP.portable.mode",
        ));
    }
    if primary.stored_size.is_some() {
        if header_size != 0 && header_size != effective_size {
            return Err(FormatError::InvalidArchive(
                "ustar size conflicts with PAX size",
            ));
        }
    } else if header_size != effective_size {
        return Err(FormatError::InvalidArchive("ustar size is inconsistent"));
    }
    if !primary.declaration.owner_kind_posix
        && (parse_tar_octal(&header[108..116])? != 0
            || parse_tar_octal(&header[116..124])? != 0
            || !nul_trimmed(&header[265..297]).is_empty()
            || !nul_trimmed(&header[297..329]).is_empty())
    {
        return Err(FormatError::InvalidArchive(
            "owner-kind none has non-zero ustar ownership fields",
        ));
    }
    if primary.declaration.owner_kind_posix {
        validate_numeric_pax_header_match(records, "uid", &header[108..116], "UID")?;
        validate_numeric_pax_header_match(records, "gid", &header[116..124], "GID")?;
        validate_string_pax_header_match(records, "uname", &header[265..297], "user name")?;
        validate_string_pax_header_match(records, "gname", &header[297..329], "group name")?;
    }
    if let Some((seconds, _)) = primary.mtime {
        let header_mtime = parse_tar_octal(&header[136..148])?;
        if header_mtime != 0 && (seconds < 0 || u64::try_from(seconds).ok() != Some(header_mtime)) {
            return Err(FormatError::InvalidArchive(
                "ustar mtime conflicts with PAX mtime",
            ));
        }
    }
    let is_device = matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice
    );
    if !is_device
        && (parse_tar_octal(&header[329..337])? != 0 || parse_tar_octal(&header[337..345])? != 0)
    {
        return Err(FormatError::InvalidArchive(
            "non-device primary has device numbers",
        ));
    }
    if is_device {
        validate_numeric_pax_header_match(
            records,
            "TZAP.posix.device-major",
            &header[329..337],
            "device major",
        )?;
        validate_numeric_pax_header_match(
            records,
            "TZAP.posix.device-minor",
            &header[337..345],
            "device minor",
        )?;
    }
    Ok(())
}

fn decoded_mtime(
    primary: &PrimaryMetadata,
    header: &[u8],
) -> Result<ArchiveTimestamp, FormatError> {
    let (seconds, nanoseconds) = match primary.mtime {
        Some(value) => value,
        None => (
            i64::try_from(parse_tar_octal(&header[136..148])?)
                .map_err(|_| FormatError::InvalidArchive("ustar mtime exceeds i64"))?,
            0,
        ),
    };
    Ok(ArchiveTimestamp::new(seconds, nanoseconds))
}

fn portable_metadata_mirror(
    header: &[u8],
    records: &PaxRecords,
    primary: &PrimaryMetadata,
) -> Result<PortableMetadataMirror, FormatError> {
    let numeric = |key: &'static str, field: &[u8]| -> Result<Option<u64>, FormatError> {
        if !primary.declaration.owner_kind_posix {
            return Ok(None);
        }
        if let Some(value) = records.get(key) {
            Ok(Some(parse_minimal_decimal_u64(value, key)?))
        } else {
            Ok(Some(parse_tar_octal(field)?))
        }
    };
    let string = |key: &str, field: &[u8]| -> Option<Vec<u8>> {
        if !primary.declaration.owner_kind_posix {
            return None;
        }
        let value = records
            .get(key)
            .map(Vec::as_slice)
            .unwrap_or_else(|| nul_trimmed(field));
        (!value.is_empty()).then(|| value.to_vec())
    };
    let mtime = if let Some(value) = primary.mtime {
        value
    } else {
        (
            i64::try_from(parse_tar_octal(&header[136..148])?)
                .map_err(|_| FormatError::InvalidArchive("ustar mtime exceeds i64"))?,
            0,
        )
    };
    Ok(PortableMetadataMirror {
        owner_kind_posix: primary.declaration.owner_kind_posix,
        mode_origin_native: primary.declaration.mode_origin_native,
        mode: primary.declaration.portable_mode,
        attributes: primary.declaration.portable_attributes,
        uid: numeric("uid", &header[108..116])?,
        gid: numeric("gid", &header[116..124])?,
        uname: string("uname", &header[265..297]),
        gname: string("gname", &header[297..329]),
        mtime,
    })
}

fn validate_numeric_pax_header_match(
    records: &PaxRecords,
    key: &'static str,
    header_field: &[u8],
    label: &'static str,
) -> Result<(), FormatError> {
    let Some(value) = records.get(key) else {
        return Ok(());
    };
    let pax = parse_minimal_decimal_u64(value, key)?;
    let header = parse_tar_octal(header_field)?;
    if header != 0 && header != pax {
        return Err(FormatError::InvalidMetadata {
            structure: label,
            reason: "ustar field conflicts with PAX value",
        });
    }
    Ok(())
}

fn validate_string_pax_header_match(
    records: &PaxRecords,
    key: &'static str,
    header_field: &[u8],
    label: &'static str,
) -> Result<(), FormatError> {
    if let Some(value) = records.get(key) {
        let header = nul_trimmed(header_field);
        if !header.is_empty() && header != value {
            return Err(FormatError::InvalidMetadata {
                structure: label,
                reason: "ustar field conflicts with PAX value",
            });
        }
    }
    Ok(())
}

fn v45_primary_path(
    header: &[u8],
    kind: TarEntryKind,
    records: &PaxRecords,
    primary: &PrimaryMetadata,
    max_path_length: u32,
) -> Result<Vec<u8>, FormatError> {
    let sparse_name = records.get("GNU.sparse.name");
    let mut path = if let Some(name) = sparse_name {
        if primary.path.is_some() || ustar_path(header) != b"GNUSparseFile.0/TZAP" {
            return Err(FormatError::InvalidArchive(
                "GNU sparse primary path framing is not canonical",
            ));
        }
        name.clone()
    } else if let Some(path) = &primary.path {
        if ustar_path(header) != b"TZAP-PRIMARY" {
            return Err(FormatError::InvalidArchive(
                "PAX path override lacks canonical ustar placeholder",
            ));
        }
        path.clone()
    } else {
        ustar_path(header)
    };
    if kind == TarEntryKind::Directory && path.ends_with(b"/") {
        path.pop();
    }
    validate_file_path_bytes(&path, max_path_length)?;
    Ok(path)
}

fn v45_primary_link_target(
    header: &[u8],
    kind: TarEntryKind,
    path: &[u8],
    primary: &PrimaryMetadata,
    max_path_length: u32,
) -> Result<Option<Vec<u8>>, FormatError> {
    let header_target = nul_trimmed(&header[157..257]);
    match kind {
        TarEntryKind::Symlink | TarEntryKind::Hardlink => {
            let target = if let Some(target) = &primary.linkpath {
                if !header_target.is_empty() {
                    return Err(FormatError::InvalidArchive(
                        "PAX linkpath override has non-empty ustar linkname",
                    ));
                }
                target.clone()
            } else {
                header_target.to_vec()
            };
            if target.is_empty() || target.contains(&0) {
                return Err(FormatError::InvalidArchive("tar link target is empty"));
            }
            if kind == TarEntryKind::Hardlink {
                validate_file_path_bytes(&target, max_path_length)?;
            } else {
                validate_symlink_target(path, &target)?;
            }
            Ok(Some(target))
        }
        _ => {
            if primary.linkpath.is_some() || !header_target.is_empty() {
                return Err(FormatError::InvalidArchive(
                    "non-link primary has a link target",
                ));
            }
            Ok(None)
        }
    }
}

#[derive(Clone, Copy)]
struct V45PrimaryLink<'a> {
    path: &'a [u8],
    target: Option<&'a [u8]>,
}

fn validate_v45_primary_cross_fields(
    kind: TarEntryKind,
    records: &PaxRecords,
    primary: &PrimaryMetadata,
    auxiliary: &[AuxiliaryRecord],
    link: V45PrimaryLink<'_>,
    sparse: bool,
    capture_report: Option<&[CaptureReportRow]>,
) -> Result<(), FormatError> {
    let is_device = matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice
    );
    let has_device_major = records.contains_key("TZAP.posix.device-major");
    let has_device_minor = records.contains_key("TZAP.posix.device-minor");
    if is_device != (has_device_major && has_device_minor) {
        return Err(FormatError::InvalidArchive(
            "device primary and device-number metadata disagree",
        ));
    }
    if (kind == TarEntryKind::Fifo || is_device)
        && !primary.declaration.profile_selected("posix-backup-v1")
    {
        return Err(FormatError::InvalidArchive(
            "special POSIX primary lacks posix-backup-v1",
        ));
    }
    if records.contains_key("TZAP.linux.whiteout") {
        let major = records
            .get("TZAP.posix.device-major")
            .map(|value| parse_minimal_decimal_u64(value, "device major"))
            .transpose()?;
        let minor = records
            .get("TZAP.posix.device-minor")
            .map(|value| parse_minimal_decimal_u64(value, "device minor"))
            .transpose()?;
        if kind != TarEntryKind::CharacterDevice || major != Some(0) || minor != Some(0) {
            return Err(FormatError::InvalidArchive(
                "Linux whiteout is not a character device with major/minor zero",
            ));
        }
    }
    if sparse && kind != TarEntryKind::Regular {
        return Err(FormatError::InvalidArchive(
            "non-regular primary carries sparse metadata",
        ));
    }
    if kind == TarEntryKind::Hardlink {
        if primary.declaration.required_profiles != ["portable-v1"]
            || !primary.declaration.optional_profiles.is_empty()
            || sparse
            || auxiliary
                .iter()
                .any(|record| record.kind != CAPTURE_REPORT_KIND)
        {
            return Err(FormatError::InvalidArchive(
                "hardlink alias carries forbidden native or inode metadata",
            ));
        }
        if link.target == Some(link.path) {
            return Err(FormatError::InvalidArchive("hardlink aliases itself"));
        }
    }
    if records.contains_key("TZAP.windows.directory-case-sensitive")
        && kind != TarEntryKind::Directory
    {
        return Err(FormatError::InvalidArchive(
            "Windows directory case-sensitive state is attached to a non-directory",
        ));
    }
    if records.contains_key("SCHILY.acl.default") && kind != TarEntryKind::Directory {
        return Err(FormatError::InvalidArchive(
            "default POSIX ACL is attached to a non-directory",
        ));
    }
    if records.contains_key("TZAP.macos.clone-group") && kind != TarEntryKind::Regular {
        return Err(FormatError::InvalidArchive(
            "macOS clone group is attached to a non-regular primary",
        ));
    }
    validate_windows_cross_fields(kind, records, primary, auxiliary, sparse, capture_report)?;
    let has_textual_acl = records.contains_key("SCHILY.acl.access")
        || records.contains_key("SCHILY.acl.default")
        || records.contains_key("SCHILY.acl.ace");
    let has_native_macos_acl = auxiliary
        .iter()
        .any(|record| record.kind == "macos.acl-native");
    let acl_projection_none = records
        .get("TZAP.acl.projection")
        .is_some_and(|value| value == b"none");
    if (!has_textual_acl && has_native_macos_acl) != acl_projection_none {
        return Err(FormatError::InvalidArchive(
            "native-only ACL declaration and projection=none disagree",
        ));
    }
    if auxiliary.iter().any(|record| {
        record.kind == "generic.xattr"
            && primary
                .xattr_names
                .iter()
                .any(|name| name == &record.decoded_name)
    }) {
        return Err(FormatError::InvalidArchive(
            "xattr is duplicated in primary and auxiliary metadata",
        ));
    }
    if has_textual_acl
        && (primary.xattr_names.iter().any(|name| {
            matches!(
                name.as_slice(),
                b"system.posix_acl_access"
                    | b"system.posix_acl_default"
                    | b"com.apple.system.Security"
            )
        }) || auxiliary.iter().any(|record| {
            record.kind == "generic.xattr"
                && matches!(
                    record.decoded_name.as_slice(),
                    b"system.posix_acl_access"
                        | b"system.posix_acl_default"
                        | b"com.apple.system.Security"
                )
        }))
    {
        return Err(FormatError::InvalidArchive(
            "filesystem ACL backing xattr duplicates declared ACL metadata",
        ));
    }
    Ok(())
}

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x0000_4000;
const STREAM_CONTAINS_SECURITY: u32 = 0x0000_0002;
const STREAM_SPARSE_ATTRIBUTE: u32 = 0x0000_0008;

fn validate_windows_cross_fields(
    kind: TarEntryKind,
    records: &PaxRecords,
    primary: &PrimaryMetadata,
    auxiliary: &[AuxiliaryRecord],
    sparse: bool,
    capture_report: Option<&[CaptureReportRow]>,
) -> Result<(), FormatError> {
    let selected = primary.declaration.profile_selected("windows-backup-v1");
    let file_attributes = records
        .get("TZAP.windows.file-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows file attributes"))
        .transpose()?;
    let stream_attributes = records
        .get("TZAP.windows.data-stream-attributes")
        .map(|value| parse_lower_hex_u32(value, "Windows data-stream attributes"))
        .transpose()?;
    let placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
    let reparse_count = auxiliary
        .iter()
        .filter(|record| record.kind == "windows.reparse-data")
        .count();
    let security_descriptor_count = auxiliary
        .iter()
        .filter(|record| record.kind == "windows.security-descriptor")
        .count();
    let efs_count = auxiliary
        .iter()
        .filter(|record| record.kind == "windows.efs-raw")
        .count();

    if !selected {
        if file_attributes.is_some()
            || stream_attributes.is_some()
            || placeholder
            || reparse_count != 0
            || security_descriptor_count != 0
            || efs_count != 0
        {
            return Err(FormatError::InvalidArchive(
                "Windows metadata is present without windows-backup-v1",
            ));
        }
        return Ok(());
    }

    let complete = primary.declaration.capture_status == CaptureStatus::Complete;
    if file_attributes.is_none()
        && (complete
            || !has_capture_omission(capture_report, "windows-backup-v1", "file-attributes"))
    {
        return Err(FormatError::InvalidArchive(
            "windows-backup-v1 lacks exact file attributes or a matching omission",
        ));
    }
    if security_descriptor_count == 0
        && (complete
            || !has_capture_omission(capture_report, "windows-backup-v1", "security-descriptor"))
    {
        return Err(FormatError::InvalidArchive(
            "windows-backup-v1 lacks a security descriptor or a matching omission",
        ));
    }
    if let Some(attributes) = file_attributes {
        let is_directory = kind == TarEntryKind::Directory;
        if (attributes & FILE_ATTRIBUTE_DIRECTORY != 0) != is_directory {
            return Err(FormatError::InvalidArchive(
                "Windows directory attribute disagrees with primary type",
            ));
        }
        let is_reparse = attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if reparse_count != 0 && !is_reparse {
            return Err(FormatError::InvalidArchive(
                "Windows reparse data lacks FILE_ATTRIBUTE_REPARSE_POINT",
            ));
        }
        if is_reparse
            && reparse_count == 0
            && (complete
                || !has_capture_omission(capture_report, "windows-backup-v1", "reparse-data")
                || (kind != TarEntryKind::Symlink && !placeholder))
        {
            return Err(FormatError::InvalidArchive(
                "Windows reparse attribute lacks exact data or a safe partial placeholder",
            ));
        }
        if placeholder
            && (!is_reparse || !matches!(kind, TarEntryKind::Regular | TarEntryKind::Directory))
        {
            return Err(FormatError::InvalidArchive(
                "Windows reparse placeholder has invalid attributes or primary type",
            ));
        }
        if attributes & FILE_ATTRIBUTE_ENCRYPTED != 0
            && efs_count == 0
            && (complete || !has_capture_omission(capture_report, "windows-backup-v1", "efs-raw"))
        {
            return Err(FormatError::InvalidArchive(
                "encrypted Windows entry lacks raw EFS data or a matching omission",
            ));
        }
    } else if placeholder || reparse_count != 0 || efs_count != 0 {
        return Err(FormatError::InvalidArchive(
            "Windows native records cannot be checked without file attributes",
        ));
    }

    let ordinary_regular = kind == TarEntryKind::Regular && !placeholder;
    if !ordinary_regular && stream_attributes.is_some() {
        return Err(FormatError::InvalidArchive(
            "Windows default-data-stream attributes disagree with primary type",
        ));
    }
    if ordinary_regular
        && stream_attributes.is_none()
        && (complete
            || !has_capture_omission(
                capture_report,
                "windows-backup-v1",
                "data-stream-attributes",
            ))
    {
        return Err(FormatError::InvalidArchive(
            "Windows regular primary lacks default-data-stream attributes or an omission",
        ));
    }
    if let Some(attributes) = stream_attributes {
        if (attributes & STREAM_SPARSE_ATTRIBUTE != 0) != sparse {
            let fallback = !sparse
                && primary.declaration.capture_status == CaptureStatus::Partial
                && has_capture_omission(capture_report, "windows-backup-v1", "sparse-layout");
            if !fallback {
                return Err(FormatError::InvalidArchive(
                    "Windows primary sparse attribute disagrees with sparse framing",
                ));
            }
        }
        let _requires_system = attributes & STREAM_CONTAINS_SECURITY != 0;
    } else if sparse
        && !has_capture_omission(
            capture_report,
            "windows-backup-v1",
            "data-stream-attributes",
        )
    {
        return Err(FormatError::InvalidArchive(
            "sparse Windows primary lacks default-stream attributes",
        ));
    }
    Ok(())
}

fn has_capture_omission(
    report: Option<&[CaptureReportRow]>,
    profile: &str,
    metadata_class: &str,
) -> bool {
    report.is_some_and(|rows| {
        rows.iter()
            .any(|row| row.profile == profile && row.metadata_class == metadata_class)
    })
}

fn parse_lower_hex_u32(value: &[u8], structure: &'static str) -> Result<u32, FormatError> {
    if value.len() != 8
        || !value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(FormatError::InvalidMetadata {
            structure,
            reason: "value is not eight lowercase hexadecimal digits",
        });
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| u32::from_str_radix(text, 16).ok())
        .ok_or(FormatError::InvalidMetadata {
            structure,
            reason: "hexadecimal value exceeds u32",
        })
}

fn v45_group_flags(
    primary: &PrimaryMetadata,
    auxiliary: &[AuxiliaryRecord],
    kind: TarEntryKind,
) -> Result<(u32, Option<Vec<crate::entry_metadata::CaptureReportRow>>), FormatError> {
    let (mut flags, capture_report) = validate_group_metadata(primary, auxiliary)?;
    if matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
    ) {
        flags |= REQUIRES_SYSTEM_RESTORE;
    }
    Ok((flags, capture_report))
}

fn parse_minimal_decimal_u64(value: &[u8], structure: &'static str) -> Result<u64, FormatError> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err(FormatError::InvalidMetadata {
            structure,
            reason: "value is not minimal unsigned decimal",
        });
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|text| text.parse().ok())
        .ok_or(FormatError::InvalidMetadata {
            structure,
            reason: "value exceeds u64",
        })
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

pub(crate) struct TarStreamTotalExtractionSizeValidator {
    cursor: usize,
    total: u64,
    max_path_length: u32,
    cap: u64,
}

impl TarStreamTotalExtractionSizeValidator {
    pub(crate) fn new(max_path_length: u32, cap: u64) -> Self {
        Self {
            cursor: 0,
            total: 0,
            max_path_length,
            cap,
        }
    }

    pub(crate) fn observe(&mut self, stream: &[u8]) -> Result<(), FormatError> {
        while self.cursor < stream.len() {
            let Some(group_end) = try_tar_member_group_end(stream, self.cursor)? else {
                return Ok(());
            };
            let member =
                parse_tar_member_group(&stream[self.cursor..group_end], self.max_path_length)?;
            if member.kind == TarEntryKind::Regular {
                self.total = self.total.checked_add(member.logical_size).ok_or(
                    FormatError::InvalidArchive("total extraction size overflow"),
                )?;
                if self.total > self.cap {
                    return Err(FormatError::ReaderUnsupported(
                        "total extraction size exceeds configured cap",
                    ));
                }
            }
            self.cursor = group_end;
        }
        Ok(())
    }
}

pub(crate) struct TarStreamSummaryValidator<O = NoopTarStreamObserver> {
    state: StreamingTarState,
    max_path_length: u32,
    total_extraction_size: u64,
    extraction_cap: u64,
    max_metadata_payload_bytes: usize,
    max_member_count: u64,
    members: Vec<TarStreamMemberSummary>,
    observer: O,
}

impl<O: TarStreamObserver> TarStreamSummaryValidator<O> {
    pub(crate) fn with_observer(
        max_path_length: u32,
        extraction_cap: u64,
        max_metadata_payload_bytes: usize,
        max_member_count: u64,
        observer: O,
    ) -> Self {
        Self {
            state: StreamingTarState::new_member(0),
            max_path_length,
            total_extraction_size: 0,
            extraction_cap,
            max_metadata_payload_bytes,
            max_member_count,
            members: Vec::new(),
            observer,
        }
    }

    pub(crate) fn observe(&mut self, mut input: &[u8]) -> Result<(), FormatError> {
        while !input.is_empty() {
            let state = std::mem::replace(&mut self.state, StreamingTarState::new_member(0));
            let (consumed, next) = self.consume_state(state, input)?;
            self.state = self.resolve_ready_state(next)?;
            input = &input[consumed..];
        }
        Ok(())
    }

    fn consume_state(
        &mut self,
        state: StreamingTarState,
        input: &[u8],
    ) -> Result<(usize, StreamingTarState), FormatError> {
        match state {
            StreamingTarState::Header {
                metadata,
                group_start,
                mut group_size,
                mut header,
            } => {
                let needed = TAR_BLOCK_LEN - header.len();
                let take = needed.min(input.len());
                header.extend_from_slice(&input[..take]);
                group_size = checked_u64_add(group_size, take as u64)?;
                checked_u64_add(group_start, group_size)?;
                let next = if header.len() == TAR_BLOCK_LEN {
                    let mut header_bytes = [0u8; TAR_BLOCK_LEN];
                    header_bytes.copy_from_slice(&header);
                    self.state_after_header(metadata, group_start, group_size, header_bytes)?
                } else {
                    StreamingTarState::Header {
                        metadata,
                        group_start,
                        group_size,
                        header,
                    }
                };
                Ok((take, next))
            }
            StreamingTarState::Payload {
                metadata,
                group_start,
                mut group_size,
                mut entry,
                mut remaining,
                padding_remaining,
            } => {
                let take = remaining.min(input.len() as u64) as usize;
                match &mut entry {
                    PendingTarEntry::LocalPax { payload, .. } => {
                        let next_len = checked_add(payload.len(), take)?;
                        let cap = self.max_metadata_payload_bytes.min(MAX_LOCAL_PAX_PAYLOAD);
                        if next_len > cap {
                            return Err(FormatError::ReaderUnsupported(
                                "tar metadata payload exceeds configured streaming cap",
                            ));
                        }
                        payload.extend_from_slice(&input[..take]);
                    }
                    PendingTarEntry::Auxiliary { validator } => {
                        validator.observe(&input[..take])?;
                    }
                    PendingTarEntry::Main { member, sparse, .. }
                        if take > 0 && member.kind == TarEntryKind::Regular =>
                    {
                        if let Some(sparse) = sparse {
                            sparse.observe(&input[..take], &mut self.observer)?;
                        } else {
                            self.observer.on_regular_payload(&input[..take])?;
                        }
                    }
                    PendingTarEntry::Main { .. } => {}
                }
                remaining -= take as u64;
                group_size = checked_u64_add(group_size, take as u64)?;
                checked_u64_add(group_start, group_size)?;
                let next = if remaining == 0 {
                    StreamingTarState::Padding {
                        metadata,
                        group_start,
                        group_size,
                        entry,
                        remaining: padding_remaining,
                    }
                } else {
                    StreamingTarState::Payload {
                        metadata,
                        group_start,
                        group_size,
                        entry,
                        remaining,
                        padding_remaining,
                    }
                };
                Ok((take, next))
            }
            StreamingTarState::Padding {
                metadata,
                group_start,
                mut group_size,
                entry,
                mut remaining,
            } => {
                let take = remaining.min(input.len() as u64) as usize;
                if input[..take].iter().any(|byte| *byte != 0) {
                    return Err(FormatError::InvalidArchive(
                        "tar member padding is non-zero",
                    ));
                }
                remaining -= take as u64;
                group_size = checked_u64_add(group_size, take as u64)?;
                checked_u64_add(group_start, group_size)?;
                let next = if remaining == 0 {
                    self.finish_entry_parts(metadata, group_start, group_size, entry)?
                } else {
                    StreamingTarState::Padding {
                        metadata,
                        group_start,
                        group_size,
                        entry,
                        remaining,
                    }
                };
                Ok((take, next))
            }
        }
    }

    fn resolve_ready_state(
        &mut self,
        mut state: StreamingTarState,
    ) -> Result<StreamingTarState, FormatError> {
        loop {
            state = match state {
                StreamingTarState::Payload {
                    metadata,
                    group_start,
                    group_size,
                    entry,
                    remaining: 0,
                    padding_remaining,
                } => StreamingTarState::Padding {
                    metadata,
                    group_start,
                    group_size,
                    entry,
                    remaining: padding_remaining,
                },
                StreamingTarState::Padding {
                    metadata,
                    group_start,
                    group_size,
                    entry,
                    remaining: 0,
                } => self.finish_entry_parts(metadata, group_start, group_size, entry)?,
                other => return Ok(other),
            };
        }
    }

    pub(crate) fn tar_total_size(&self) -> u64 {
        match &self.state {
            StreamingTarState::Header {
                group_start,
                group_size,
                ..
            }
            | StreamingTarState::Payload {
                group_start,
                group_size,
                ..
            }
            | StreamingTarState::Padding {
                group_start,
                group_size,
                ..
            } => group_start + group_size,
        }
    }

    pub(crate) fn finish(mut self) -> Result<TarStreamSummary, FormatError> {
        let tar_total_size = self.tar_total_size();
        match self.state {
            StreamingTarState::Header {
                header, group_size, ..
            } if header.is_empty() && group_size == 0 => {
                validate_v45_member_graph(&self.members)?;
                self.observer.on_archive_complete()?;
                Ok(TarStreamSummary {
                    members: self.members,
                    tar_total_size,
                    total_extraction_size: self.total_extraction_size,
                })
            }
            _ => Err(FormatError::InvalidArchive(
                "tar stream ended inside member group",
            )),
        }
    }

    fn state_after_header(
        &mut self,
        mut metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        header: [u8; TAR_BLOCK_LEN],
    ) -> Result<StreamingTarState, FormatError> {
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(&header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = metadata
            .pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let padding_remaining = padding_to_512_u64(effective_size);

        let entry = match typeflag {
            b'x' => {
                if metadata.pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    ));
                }
                validate_v45_metadata_header(&header)?;
                if effective_size > MAX_LOCAL_PAX_PAYLOAD as u64
                    || effective_size > self.max_metadata_payload_bytes as u64
                {
                    return Err(FormatError::ReaderUnsupported(
                        "tar metadata payload exceeds configured streaming cap",
                    ));
                }
                let label = ustar_path(&header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != metadata.auxiliary.len() as u32 {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        ));
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    ));
                };
                PendingTarEntry::LocalPax {
                    kind,
                    payload: Vec::new(),
                }
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), records)) = metadata.pending.take()
                else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    ));
                };
                validate_v45_auxiliary_header(&header, ordinal, header_size, effective_size)?;
                PendingTarEntry::Auxiliary {
                    validator: AuxiliaryStreamValidator::new(&records, ordinal, effective_size)?,
                }
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                let Some((V45PaxKind::Primary, records)) = metadata.pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    ));
                };
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    b'3' => TarEntryKind::CharacterDevice,
                    b'4' => TarEntryKind::BlockDevice,
                    b'6' => TarEntryKind::Fifo,
                    _ => TarEntryKind::Regular,
                };
                let primary = parse_primary_metadata(&records)?;
                validate_v45_primary_header(
                    &header,
                    kind,
                    header_size,
                    effective_size,
                    &primary,
                    &records,
                )?;
                let path =
                    v45_primary_path(&header, kind, &records, &primary, self.max_path_length)?;
                let link_target =
                    v45_primary_link_target(&header, kind, &path, &primary, self.max_path_length)?;
                let is_sparse = primary.sparse_logical_size.is_some();
                let reparse_placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    ));
                }
                if reparse_placeholder && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "reparse placeholder has non-zero primary payload",
                    ));
                }
                let logical_size = if kind == TarEntryKind::Regular && !reparse_placeholder {
                    primary.sparse_logical_size.unwrap_or(effective_size)
                } else {
                    0
                };
                let (file_entry_flags, capture_report) =
                    v45_group_flags(&primary, &metadata.auxiliary, kind)?;
                validate_v45_primary_cross_fields(
                    kind,
                    &records,
                    &primary,
                    &metadata.auxiliary,
                    V45PrimaryLink {
                        path: &path,
                        target: link_target.as_deref(),
                    },
                    is_sparse,
                    capture_report.as_deref(),
                )?;
                if kind == TarEntryKind::Regular {
                    self.total_extraction_size =
                        self.total_extraction_size.checked_add(logical_size).ok_or(
                            FormatError::InvalidArchive("total extraction size overflow"),
                        )?;
                    if self.total_extraction_size > self.extraction_cap {
                        return Err(FormatError::ReaderUnsupported(
                            "total extraction size exceeds configured cap",
                        ));
                    }
                }
                let diagnostics = Vec::new();
                let mtime = decoded_mtime(&primary, &header)?;
                let member = StreamedTarMemberMetadata {
                    path,
                    kind,
                    link_target,
                    mode: primary.declaration.portable_mode,
                    mtime,
                    logical_size,
                    file_entry_flags,
                    reparse_placeholder,
                    v45_metadata: MemberMetadata {
                        declaration: primary.declaration.clone(),
                        auxiliary: metadata.auxiliary.clone(),
                        file_entry_flags,
                        sparse_layout: None,
                        capture_report,
                        primary_has_native_scalar: primary.has_native_scalar,
                        primary_requires_system_restore: primary.requires_system_restore,
                        portable_mirror: portable_metadata_mirror(&header, &records, &primary)?,
                    },
                    diagnostics,
                };
                self.observer.on_member_start(&member)?;
                PendingTarEntry::Main {
                    member,
                    group_start,
                    sparse: primary.sparse_logical_size.map(StreamingSparsePrimary::new),
                }
            }
            _ => {
                return Err(FormatError::InvalidArchive(
                    "unsupported revision-45 tar entry type",
                ));
            }
        };

        self.resolve_ready_state(StreamingTarState::Payload {
            metadata,
            group_start,
            group_size,
            entry,
            remaining: effective_size,
            padding_remaining,
        })
    }

    fn finish_entry_parts(
        &mut self,
        mut metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        entry: PendingTarEntry,
    ) -> Result<StreamingTarState, FormatError> {
        match entry {
            PendingTarEntry::LocalPax { kind, payload } => {
                metadata.aggregate_pax_bytes = metadata
                    .aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if metadata.aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: metadata.aggregate_pax_bytes as u64,
                    });
                }
                metadata.pending = Some((kind, parse_canonical_pax(&payload)?));
                Ok(StreamingTarState::Header {
                    metadata,
                    group_start,
                    group_size,
                    header: Vec::new(),
                })
            }
            PendingTarEntry::Auxiliary { validator } => {
                metadata.auxiliary.push(validator.finish()?);
                Ok(StreamingTarState::Header {
                    metadata,
                    group_start,
                    group_size,
                    header: Vec::new(),
                })
            }
            PendingTarEntry::Main {
                member,
                group_start,
                sparse,
            } => {
                if self.members.len() as u64 >= self.max_member_count {
                    return Err(FormatError::ReaderUnsupported(
                        "tar member count exceeds configured streaming cap",
                    ));
                }
                if let Some(sparse) = sparse {
                    sparse.finish(&mut self.observer)?;
                }
                let diagnostics = self.observer.on_member_complete(&member)?;
                self.members.push(TarStreamMemberSummary {
                    path: member.path,
                    kind: member.kind,
                    link_target: member.link_target,
                    mode: member.mode,
                    mtime: member.mtime,
                    logical_size: member.logical_size,
                    file_entry_flags: member.file_entry_flags,
                    reparse_placeholder: member.reparse_placeholder,
                    v45_metadata: member.v45_metadata,
                    diagnostics,
                    group_start,
                    group_size,
                });
                Ok(StreamingTarState::new_member(checked_u64_add(
                    group_start,
                    group_size,
                )?))
            }
        }
    }
}

pub(crate) fn validate_v45_member_graph(
    members: &[TarStreamMemberSummary],
) -> Result<(), FormatError> {
    let mut selected = BTreeMap::<&[u8], &TarStreamMemberSummary>::new();
    for member in members {
        let replace = selected
            .get(member.path.as_slice())
            .is_none_or(|existing| existing.group_start < member.group_start);
        if replace {
            selected.insert(member.path.as_slice(), member);
        }
    }
    for member in selected.values() {
        if member.kind == TarEntryKind::Hardlink {
            let target_path = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target = selected
                .get(target_path)
                .ok_or(FormatError::InvalidArchive(
                    "hardlink target is not present in the selected archive graph",
                ))?;
            if target.kind != TarEntryKind::Regular || target.reparse_placeholder {
                return Err(FormatError::InvalidArchive(
                    "hardlink target is not a canonical regular primary",
                ));
            }
            if member.v45_metadata.portable_mirror != target.v45_metadata.portable_mirror {
                return Err(FormatError::InvalidArchive(
                    "hardlink portable metadata mirror differs from canonical target",
                ));
            }
        }

        let mut ancestor = Vec::new();
        let components: Vec<_> = member.path.split(|byte| *byte == b'/').collect();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !ancestor.is_empty() {
                ancestor.push(b'/');
            }
            ancestor.extend_from_slice(component);
            if let Some(parent) = selected.get(ancestor.as_slice()) {
                if parent.reparse_placeholder || parent.kind == TarEntryKind::Symlink {
                    return Err(FormatError::InvalidArchive(
                        "selected path graph traverses a symlink or reparse ancestor",
                    ));
                }
                if parent.kind != TarEntryKind::Directory {
                    return Err(FormatError::InvalidArchive(
                        "selected path graph traverses a non-directory ancestor",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_owned_restore_plan(
    members: &[&OwnedTarMember],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    let mut selected = BTreeMap::<&[u8], &OwnedTarMember>::new();
    for &member in members {
        if selected.insert(member.path.as_slice(), member).is_some() {
            return Err(FormatError::InvalidArchive(
                "restore plan contains duplicate selected paths",
            ));
        }
        let metadata = member
            .v45_metadata
            .as_ref()
            .ok_or(FormatError::InvalidArchive(
                "revision-45 member metadata is missing",
            ))?;
        plan_restore(
            &member.path,
            metadata,
            member.kind,
            member.reparse_placeholder,
            options,
        )?;
    }
    for member in selected.values() {
        if member.kind == TarEntryKind::Hardlink {
            let target_path = member
                .link_target
                .as_deref()
                .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
            let target = selected
                .get(target_path)
                .ok_or(FormatError::InvalidArchive(
                    "hardlink target is not present in the selected restore graph",
                ))?;
            if target.kind != TarEntryKind::Regular || target.reparse_placeholder {
                return Err(FormatError::InvalidArchive(
                    "hardlink target is not a canonical regular primary",
                ));
            }
            let alias_metadata = member.v45_metadata.as_ref().expect("checked above");
            let target_metadata = target.v45_metadata.as_ref().expect("checked above");
            if alias_metadata.portable_mirror != target_metadata.portable_mirror {
                return Err(FormatError::InvalidArchive(
                    "hardlink portable metadata mirror differs from canonical target",
                ));
            }
        }

        let mut ancestor = Vec::new();
        let components: Vec<_> = member.path.split(|byte| *byte == b'/').collect();
        for component in components.iter().take(components.len().saturating_sub(1)) {
            if !ancestor.is_empty() {
                ancestor.push(b'/');
            }
            ancestor.extend_from_slice(component);
            if let Some(parent) = selected.get(ancestor.as_slice()) {
                if parent.reparse_placeholder || parent.kind == TarEntryKind::Symlink {
                    return Err(FormatError::InvalidArchive(
                        "restore path traverses a selected symlink or reparse ancestor",
                    ));
                }
                if parent.kind != TarEntryKind::Directory {
                    return Err(FormatError::InvalidArchive(
                        "restore path traverses a selected non-directory ancestor",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn restore_phase(member: &OwnedTarMember) -> u8 {
    restore_phase_for_kind(member.kind, member.reparse_placeholder)
}

fn restore_phase_for_kind(kind: TarEntryKind, reparse_placeholder: bool) -> u8 {
    if reparse_placeholder {
        return 3;
    }
    match kind {
        TarEntryKind::Directory => 0,
        TarEntryKind::Regular => 1,
        TarEntryKind::Symlink
        | TarEntryKind::CharacterDevice
        | TarEntryKind::BlockDevice
        | TarEntryKind::Fifo => 2,
        TarEntryKind::Hardlink => 3,
    }
}

enum StreamingTarState {
    Header {
        metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        header: Vec<u8>,
    },
    Payload {
        metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        entry: PendingTarEntry,
        remaining: u64,
        padding_remaining: u64,
    },
    Padding {
        metadata: V45StreamingGroup,
        group_start: u64,
        group_size: u64,
        entry: PendingTarEntry,
        remaining: u64,
    },
}

impl StreamingTarState {
    fn new_member(group_start: u64) -> Self {
        Self::Header {
            metadata: V45StreamingGroup::default(),
            group_start,
            group_size: 0,
            header: Vec::new(),
        }
    }
}

enum PendingTarEntry {
    LocalPax {
        kind: V45PaxKind,
        payload: Vec<u8>,
    },
    Auxiliary {
        validator: AuxiliaryStreamValidator,
    },
    Main {
        member: StreamedTarMemberMetadata,
        group_start: u64,
        sparse: Option<StreamingSparsePrimary>,
    },
}

fn checked_u64_add(lhs: u64, rhs: u64) -> Result<u64, FormatError> {
    lhs.checked_add(rhs).ok_or(FormatError::InvalidArchive(
        "tar member arithmetic overflow",
    ))
}

pub(crate) fn try_tar_member_group_end(
    stream: &[u8],
    start: usize,
) -> Result<Option<usize>, FormatError> {
    let mut cursor = start;
    let mut pending: Option<(V45PaxKind, PaxRecords)> = None;
    let mut auxiliary_count = 0u32;
    let mut aggregate_pax_bytes = 0usize;

    loop {
        let Some(header) = try_slice(stream, cursor, TAR_BLOCK_LEN)? else {
            return Ok(None);
        };
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty"));
        }
        verify_tar_checksum(header)?;
        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let payload_start = checked_add(cursor, TAR_BLOCK_LEN)?;
        let payload_len = to_usize(effective_size)?;
        let payload_end = checked_add(payload_start, payload_len)?;
        let padded_end = checked_add(payload_end, padding_to_512(payload_len))?;
        let Some(payload) = try_slice(stream, payload_start, payload_len)? else {
            return Ok(None);
        };
        if padded_end > stream.len() {
            return Ok(None);
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
                if pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    ));
                }
                validate_v45_metadata_header(header)?;
                aggregate_pax_bytes = aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: aggregate_pax_bytes as u64,
                    });
                }
                let records = parse_canonical_pax(payload)?;
                let label = ustar_path(header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != auxiliary_count {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        ));
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    ));
                };
                pending = Some((kind, records));
                cursor = padded_end;
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), _)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    ));
                };
                validate_v45_auxiliary_header(header, ordinal, header_size, effective_size)?;
                auxiliary_count = auxiliary_count
                    .checked_add(1)
                    .ok_or(FormatError::InvalidArchive("auxiliary count overflow"))?;
                cursor = padded_end;
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                ));
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                if !matches!(pending, Some((V45PaxKind::Primary, _))) {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    ));
                }
                return Ok(Some(padded_end));
            }
            _ => {
                return Err(FormatError::InvalidArchive(
                    "unsupported revision-45 tar entry type",
                ));
            }
        }

        if cursor >= stream.len() {
            return Ok(None);
        }
    }
}

fn try_slice(stream: &[u8], offset: usize, len: usize) -> Result<Option<&[u8]>, FormatError> {
    let end = checked_add(offset, len)?;
    if end > stream.len() {
        return Ok(None);
    }
    Ok(Some(&stream[offset..end]))
}

pub(crate) fn stream_regular_tar_member_group_to_writer<R, W>(
    reader: &mut R,
    expected_path: &[u8],
    expected_file_data_size: u64,
    expected_file_flags: u32,
    group_len: u64,
    max_path_length: u32,
    writer: &mut W,
) -> Result<Vec<MetadataDiagnostic>, ExtractError>
where
    R: TarMemberGroupReader,
    W: Write,
{
    let mut handler = RegularWriterHandler { writer };
    let member = stream_tar_member_group(
        reader,
        expected_path,
        expected_file_data_size,
        expected_file_flags,
        group_len,
        max_path_length,
        &mut handler,
    )?;
    Ok(member.diagnostics)
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamingMemberExpectation<'a> {
    pub path: &'a [u8],
    pub file_data_size: u64,
    pub file_flags: u32,
    pub group_len: u64,
    pub max_path_length: u32,
}

pub(crate) fn restore_streaming_tar_member_group<R>(
    root: &Path,
    expected: StreamingMemberExpectation<'_>,
    options: SafeExtractionOptions,
    reader: &mut R,
) -> Result<Vec<MetadataDiagnostic>, ExtractError>
where
    R: TarMemberGroupReader,
{
    let mut handler = FilesystemRestoreHandler::new(root, options);
    let member = stream_tar_member_group(
        reader,
        expected.path,
        expected.file_data_size,
        expected.file_flags,
        expected.group_len,
        expected.max_path_length,
        &mut handler,
    )?;
    handler.finish(&member)
}

fn stream_tar_member_group<R, H>(
    reader: &mut R,
    expected_path: &[u8],
    expected_file_data_size: u64,
    expected_file_flags: u32,
    group_len: u64,
    max_path_length: u32,
    handler: &mut H,
) -> Result<StreamedTarMemberMetadata, ExtractError>
where
    R: TarMemberGroupReader,
    H: TarMemberStreamHandler,
{
    if group_len < (TAR_BLOCK_LEN * 3) as u64 || group_len % TAR_BLOCK_LEN as u64 != 0 {
        return Err(FormatError::InvalidArchive("tar member group is not block aligned").into());
    }

    let mut remaining = group_len;
    let mut pending: Option<(V45PaxKind, PaxRecords)> = None;
    let mut auxiliary = Vec::<AuxiliaryRecord>::new();
    let mut aggregate_pax_bytes = 0usize;

    loop {
        let mut header = [0u8; TAR_BLOCK_LEN];
        read_member_bytes(reader, &mut header, &mut remaining)?;
        if header.iter().all(|byte| *byte == 0) {
            return Err(FormatError::InvalidArchive("tar member header is empty").into());
        }
        verify_tar_checksum(&header)?;

        let typeflag = header[156];
        let header_size = parse_tar_octal(&header[124..136])?;
        let effective_size = pending
            .as_ref()
            .and_then(|(_, records)| records.get("size"))
            .map(|value| parse_minimal_decimal_u64(value, "PAX size"))
            .transpose()?
            .unwrap_or(header_size);
        let padding_len = padding_to_512_u64(effective_size);
        let entry_payload_len =
            effective_size
                .checked_add(padding_len)
                .ok_or(FormatError::InvalidArchive(
                    "tar member arithmetic overflow",
                ))?;
        if entry_payload_len > remaining {
            return Err(FormatError::InvalidArchive("tar member payload exceeds group").into());
        }

        match typeflag {
            b'x' => {
                if pending.is_some() {
                    return Err(FormatError::InvalidArchive(
                        "PAX header is not immediately consumed",
                    )
                    .into());
                }
                validate_v45_metadata_header(&header)?;
                if effective_size > MAX_LOCAL_PAX_PAYLOAD as u64 {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "local PAX payload bytes",
                        cap: MAX_LOCAL_PAX_PAYLOAD as u64,
                        actual: effective_size,
                    }
                    .into());
                }
                let payload = read_member_vec(reader, effective_size, &mut remaining)?;
                read_zero_padding(reader, padding_len, &mut remaining)?;
                aggregate_pax_bytes = aggregate_pax_bytes
                    .checked_add(payload.len())
                    .ok_or(FormatError::InvalidArchive("aggregate PAX size overflow"))?;
                if aggregate_pax_bytes > MAX_AGGREGATE_PAX_PAYLOAD {
                    return Err(FormatError::ReaderResourceLimitExceeded {
                        field: "aggregate local PAX payload bytes per member group",
                        cap: MAX_AGGREGATE_PAX_PAYLOAD as u64,
                        actual: aggregate_pax_bytes as u64,
                    }
                    .into());
                }
                let records = parse_canonical_pax(&payload)?;
                let label = ustar_path(&header);
                let kind = if label == b"TZAP-PAX/PRIMARY" {
                    V45PaxKind::Primary
                } else if let Some(ordinal) = parse_auxiliary_pax_label(&label) {
                    if ordinal != auxiliary.len() as u32 {
                        return Err(FormatError::InvalidArchive(
                            "auxiliary PAX ordinal is not contiguous",
                        )
                        .into());
                    }
                    V45PaxKind::Auxiliary(ordinal)
                } else {
                    return Err(FormatError::InvalidArchive(
                        "revision-45 PAX header has a non-canonical internal name",
                    )
                    .into());
                };
                pending = Some((kind, records));
            }
            b'Z' => {
                let Some((V45PaxKind::Auxiliary(ordinal), records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "auxiliary entry is missing its local PAX header",
                    )
                    .into());
                };
                validate_v45_auxiliary_header(&header, ordinal, header_size, effective_size)?;
                let mut validator =
                    AuxiliaryStreamValidator::new(&records, ordinal, effective_size)?;
                stream_auxiliary_payload(reader, effective_size, &mut remaining, &mut validator)?;
                read_zero_padding(reader, padding_len, &mut remaining)?;
                auxiliary.push(validator.finish()?);
            }
            b'g' | b'L' | b'K' | b'V' | b'M' | b'N' | b'S' => {
                return Err(FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45",
                )
                .into());
            }
            0 | b'0' | b'5' | b'2' | b'1' | b'3' | b'4' | b'6' => {
                let Some((V45PaxKind::Primary, records)) = pending.take() else {
                    return Err(FormatError::InvalidArchive(
                        "primary entry is missing its canonical local PAX header",
                    )
                    .into());
                };
                let kind = match typeflag {
                    b'5' => TarEntryKind::Directory,
                    b'2' => TarEntryKind::Symlink,
                    b'1' => TarEntryKind::Hardlink,
                    b'3' => TarEntryKind::CharacterDevice,
                    b'4' => TarEntryKind::BlockDevice,
                    b'6' => TarEntryKind::Fifo,
                    _ => TarEntryKind::Regular,
                };
                let primary = parse_primary_metadata(&records)?;
                validate_v45_primary_header(
                    &header,
                    kind,
                    header_size,
                    effective_size,
                    &primary,
                    &records,
                )?;
                let path = v45_primary_path(&header, kind, &records, &primary, max_path_length)?;
                let link_target =
                    v45_primary_link_target(&header, kind, &path, &primary, max_path_length)?;
                let sparse = primary.sparse_logical_size.is_some();
                let reparse_placeholder = records.contains_key("TZAP.windows.reparse-placeholder");
                if kind != TarEntryKind::Regular && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "non-regular tar entry has non-zero payload size",
                    )
                    .into());
                }
                if reparse_placeholder && effective_size != 0 {
                    return Err(FormatError::InvalidArchive(
                        "reparse placeholder has non-zero primary payload",
                    )
                    .into());
                }
                let logical_size = if kind == TarEntryKind::Regular && !reparse_placeholder {
                    primary.sparse_logical_size.unwrap_or(effective_size)
                } else {
                    0
                };
                let (file_entry_flags, capture_report) =
                    v45_group_flags(&primary, &auxiliary, kind)?;
                if file_entry_flags != expected_file_flags {
                    return Err(FormatError::InvalidArchive(
                        "tar member metadata flags do not match FileEntry flags",
                    )
                    .into());
                }
                validate_v45_primary_cross_fields(
                    kind,
                    &records,
                    &primary,
                    &auxiliary,
                    V45PrimaryLink {
                        path: &path,
                        target: link_target.as_deref(),
                    },
                    sparse,
                    capture_report.as_deref(),
                )?;
                let diagnostics = Vec::new();
                let mtime = decoded_mtime(&primary, &header)?;
                let member = StreamedTarMemberMetadata {
                    path,
                    kind,
                    link_target,
                    mode: primary.declaration.portable_mode,
                    mtime,
                    logical_size,
                    file_entry_flags,
                    reparse_placeholder,
                    v45_metadata: MemberMetadata {
                        declaration: primary.declaration.clone(),
                        auxiliary: auxiliary.clone(),
                        file_entry_flags,
                        sparse_layout: None,
                        capture_report,
                        primary_has_native_scalar: primary.has_native_scalar,
                        primary_requires_system_restore: primary.requires_system_restore,
                        portable_mirror: portable_metadata_mirror(&header, &records, &primary)?,
                    },
                    diagnostics,
                };
                if member.path != expected_path {
                    return Err(FormatError::InvalidArchive(
                        "tar member path does not match FileEntry path",
                    )
                    .into());
                }
                if member.logical_size != expected_file_data_size {
                    return Err(FormatError::InvalidArchive(
                        "tar member size does not match FileEntry file_data_size",
                    )
                    .into());
                }
                handler.on_member(&member)?;
                if member.kind == TarEntryKind::Regular {
                    if let Some(logical_size) = primary.sparse_logical_size {
                        stream_sparse_primary_payload(
                            reader,
                            effective_size,
                            logical_size,
                            &mut remaining,
                            handler,
                        )?;
                    } else {
                        stream_regular_payload(reader, effective_size, &mut remaining, handler)?;
                    }
                }
                read_zero_padding(reader, padding_len, &mut remaining)?;
                if remaining != 0 {
                    return Err(FormatError::InvalidArchive(
                        "tar member group has bytes after main entry",
                    )
                    .into());
                }
                return Ok(member);
            }
            _ => {
                return Err(
                    FormatError::InvalidArchive("unsupported revision-45 tar entry type").into(),
                );
            }
        }

        if remaining == 0 {
            return Err(FormatError::InvalidArchive(
                "tar member group has metadata records but no main entry",
            )
            .into());
        }
    }
}

fn plan_restore(
    path: &[u8],
    metadata: &MemberMetadata,
    kind: TarEntryKind,
    reparse_placeholder: bool,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    if options.restore_policy == RestorePolicy::System && !options.system_authorized {
        return Err(FormatError::ReaderUnsupported(
            "system restore policy requires explicit caller authorization",
        ));
    }

    let mut diagnostics = Vec::new();
    if metadata.declaration.capture_status == CaptureStatus::Partial {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "tzap-core-v1",
                "capture-completeness",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Partial,
                "entry capture is partial; full-fidelity restoration is impossible",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
        if let Some(rows) = &metadata.capture_report {
            diagnostics.extend(rows.iter().map(|row| {
                let message = if row.encoded_detail.is_empty() {
                    format!("capture omission: {}", row.reason)
                } else {
                    format!(
                        "capture omission: {}; detail={}",
                        row.reason, row.encoded_detail
                    )
                };
                MetadataDiagnostic::new(
                    path,
                    &row.profile,
                    &row.metadata_class,
                    MetadataOperation::Capture,
                    MetadataDiagnosticStatus::Partial,
                    message,
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                )
            }));
        }
        let required_omission = metadata.capture_report.as_ref().is_some_and(|rows| {
            rows.iter().any(|row| {
                metadata
                    .declaration
                    .required_profiles
                    .binary_search(&row.profile)
                    .is_ok()
            })
        });
        if required_omission && !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "required-profile capture omission needs explicit degraded restore",
            ));
        }
    }
    let unknown_required_profiles = metadata
        .declaration
        .unknown_required_profiles()
        .collect::<Vec<_>>();
    if !unknown_required_profiles.is_empty() {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "requested restore policy requires an unsupported required profile",
            ));
        }
        diagnostics.extend(unknown_required_profiles.into_iter().map(|profile| {
            MetadataDiagnostic::new(
                path,
                profile,
                "required-profile",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Unsupported,
                "unsupported required profile was preserved but not restored",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            )
        }));
    }
    diagnostics.extend(
        metadata
            .declaration
            .unknown_optional_profiles()
            .map(|profile| {
                MetadataDiagnostic::new(
                    path,
                    profile,
                    "optional-profile",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "unsupported optional profile was preserved but not restored",
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                )
            }),
    );

    if options.restore_policy == RestorePolicy::Content {
        for (metadata_class, message) in [
            ("mode", "portable mode is outside content restore policy"),
            (
                "mtime",
                "modification time is outside content restore policy",
            ),
        ] {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    metadata_class,
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    message,
                )
                .for_restore(options.restore_policy, 4),
            );
        }
    }

    if options.restore_policy == RestorePolicy::Content && kind == TarEntryKind::Symlink {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "symlink",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "symlink skipped by content restore policy",
            )
            .for_restore(options.restore_policy, 2),
        );
    }
    if reparse_placeholder {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "windows-backup-v1",
                "reparse-data",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                if options.restore_policy == RestorePolicy::System {
                    "reparse placeholder restoration is unsupported on this host"
                } else {
                    "reparse placeholder is outside the selected restore policy"
                },
            )
            .for_restore(options.restore_policy, 3),
        );
    }
    if matches!(
        kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
    ) {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "posix-backup-v1",
                "special-object",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                if options.restore_policy == RestorePolicy::System {
                    "special object restoration is unsupported on this host"
                } else {
                    "special object is outside the selected restore policy"
                },
            )
            .for_restore(options.restore_policy, 2),
        );
    }
    if options.restore_policy != RestorePolicy::Content
        && matches!(kind, TarEntryKind::Directory | TarEntryKind::Symlink)
    {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "portable directory/symlink metadata restoration needs explicit degraded restore",
            ));
        }
        let (class, message) = if kind == TarEntryKind::Directory {
            (
                "mode-and-mtime",
                "directory mode/mtime finalization is not supported by this conformance class",
            )
        } else {
            (
                "mtime",
                "symlink mtime restoration is not supported by this conformance class",
            )
        };
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                class,
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Unsupported,
                message,
            )
            .for_restore(options.restore_policy, 4),
        );
    }

    if metadata.file_entry_flags & HAS_SPARSE_EXTENTS != 0 {
        if options.restore_policy != RestorePolicy::Content && !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "sparse layout materialization needs explicit degraded restore",
            ));
        }
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "sparse-layout",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Materialized,
                if options.restore_policy == RestorePolicy::Content {
                    "sparse layout is outside content policy; logical bytes will be materialized"
                } else {
                    "sparse layout will be materialized as logical zero bytes"
                },
            )
            .for_restore(options.restore_policy, 1),
        );
    }

    if options.restore_policy != RestorePolicy::Content
        && !cfg!(unix)
        && metadata.declaration.mode_origin_native
        && !matches!(metadata.declaration.portable_mode & 0o1777, 0o444 | 0o666)
    {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "portable mode cannot be represented exactly on this host",
            ));
        }
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mode",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Partial,
                "portable mode can only be projected to host readonly state",
            )
            .for_restore(options.restore_policy, 4),
        );
    }

    if metadata.declaration.owner_kind_posix && options.restore_policy != RestorePolicy::System {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "numeric-ownership",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "numeric ownership is outside the selected restore policy",
            )
            .for_restore(options.restore_policy, 4),
        );
    }
    if metadata.declaration.portable_mode & 0o6000 != 0
        && options.restore_policy != RestorePolicy::System
    {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "setid-mode",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "setuid/setgid mode bits are outside the selected restore policy",
            )
            .for_restore(options.restore_policy, 4),
        );
    }
    if let Some(attributes) = metadata.declaration.portable_attributes {
        let portable_bits = attributes & 0x03;
        let same_os_bits = attributes & 0x0c;
        let unsupported_requested = match options.restore_policy {
            RestorePolicy::Content => false,
            RestorePolicy::Portable => {
                portable_bits != 0 && (!cfg!(windows) || portable_bits & !1 != 0)
            }
            RestorePolicy::SameOs | RestorePolicy::System => {
                (portable_bits != 0 && (!cfg!(windows) || portable_bits & !1 != 0))
                    || same_os_bits != 0
            }
        };
        if unsupported_requested && !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "requested portable attribute projection needs explicit degraded restore",
            ));
        }
        if options.restore_policy == RestorePolicy::Content
            || unsupported_requested
            || (options.restore_policy == RestorePolicy::Portable && same_os_bits != 0)
        {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "portable-attributes",
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "portable attribute projection was wholly or partly outside host policy capability",
                )
                .for_restore(options.restore_policy, 4),
            );
        }
    }

    let requests_same_os = matches!(
        options.restore_policy,
        RestorePolicy::SameOs | RestorePolicy::System
    );
    let requests_system = options.restore_policy == RestorePolicy::System;
    let profile_is_required = |profile: &str| {
        metadata
            .declaration
            .required_profiles
            .binary_search_by(|candidate| candidate.as_str().cmp(profile))
            .is_ok()
    };
    let native_profile = metadata
        .auxiliary
        .iter()
        .find(|record| record.native || record.restore_class >= RestoreClass::SameOs)
        .map(|record| record.profile.as_str())
        .or_else(|| {
            metadata
                .declaration
                .required_profiles
                .iter()
                .chain(&metadata.declaration.optional_profiles)
                .find(|profile| profile.as_str() != "portable-v1")
                .map(String::as_str)
        })
        .unwrap_or("portable-v1");
    let required_native_scalar = metadata.primary_has_native_scalar
        && metadata
            .declaration
            .required_profiles
            .iter()
            .any(|profile| profile != "portable-v1");
    let unsupported_same_os = metadata.auxiliary.iter().any(|record| {
        record.restore_class == RestoreClass::SameOs && profile_is_required(&record.profile)
    }) || required_native_scalar;
    let unsupported_system = metadata.auxiliary.iter().any(|record| {
        record.restore_class == RestoreClass::System && profile_is_required(&record.profile)
    }) || (metadata.primary_requires_system_restore
        && (metadata.declaration.owner_kind_posix || required_native_scalar || !cfg!(unix)))
        || reparse_placeholder
        || matches!(
            kind,
            TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
        );

    if (requests_same_os && unsupported_same_os) || (requests_system && unsupported_system) {
        if !options.allow_degraded {
            return Err(FormatError::ReaderUnsupported(
                "requested native metadata is not supported by this conformance class",
            ));
        }
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                native_profile,
                "native-metadata",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "requested native metadata was skipped under explicit degraded restore",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
    }

    if metadata.file_entry_flags & HAS_NATIVE_METADATA != 0 && !requests_same_os {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                native_profile,
                "native-metadata",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "authenticated native metadata is outside the selected restore policy",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
    }
    if requests_same_os && metadata.primary_has_native_scalar && !required_native_scalar {
        diagnostics.push(
            MetadataDiagnostic::new(
                path,
                native_profile,
                "optional-native-scalar",
                MetadataOperation::Plan,
                MetadataDiagnosticStatus::Skipped,
                "optional native scalar metadata is unsupported on this host",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(kind, reparse_placeholder),
            ),
        );
    }
    for record in &metadata.auxiliary {
        let requested = match options.restore_policy {
            RestorePolicy::Content => record.restore_class == RestoreClass::None,
            RestorePolicy::Portable => record.restore_class <= RestoreClass::Portable,
            RestorePolicy::SameOs => record.restore_class <= RestoreClass::SameOs,
            RestorePolicy::System => true,
        };
        if requested
            && record.restore_class != RestoreClass::None
            && !profile_is_required(&record.profile)
        {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    &record.profile,
                    &record.kind,
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "optional auxiliary record is unsupported on this host",
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                ),
            );
        } else if !requested && record.restore_class != RestoreClass::None {
            diagnostics.push(
                MetadataDiagnostic::new(
                    path,
                    &record.profile,
                    &record.kind,
                    MetadataOperation::Plan,
                    MetadataDiagnosticStatus::Skipped,
                    "authenticated auxiliary record is outside the selected restore policy",
                )
                .for_restore(
                    options.restore_policy,
                    restore_phase_for_kind(kind, reparse_placeholder),
                ),
            );
        }
    }
    Ok(diagnostics)
}

pub(crate) fn metadata_verification_report(
    members: &[TarStreamMemberSummary],
) -> Result<MetadataVerificationReport, FormatError> {
    let mut profiles_present = std::collections::BTreeSet::new();
    let mut auxiliary_kinds_present = std::collections::BTreeSet::new();
    let mut entries = Vec::with_capacity(members.len());

    for member in members {
        let metadata = &member.v45_metadata;
        profiles_present.extend(metadata.declaration.required_profiles.iter().cloned());
        profiles_present.extend(metadata.declaration.optional_profiles.iter().cloned());
        let mut auxiliary_kinds = metadata
            .auxiliary
            .iter()
            .map(|record| record.kind.clone())
            .collect::<Vec<_>>();
        auxiliary_kinds.sort();
        auxiliary_kinds.dedup();
        auxiliary_kinds_present.extend(auxiliary_kinds.iter().cloned());

        let mut policy_capabilities = Vec::with_capacity(4);
        for policy in [
            RestorePolicy::Content,
            RestorePolicy::Portable,
            RestorePolicy::SameOs,
            RestorePolicy::System,
        ] {
            let strict = SafeExtractionOptions {
                restore_policy: policy,
                allow_degraded: false,
                system_authorized: policy == RestorePolicy::System,
                ..SafeExtractionOptions::default()
            };
            let (policy_complete, reason) = match plan_restore(
                &member.path,
                metadata,
                member.kind,
                member.reparse_placeholder,
                strict,
            ) {
                Ok(_) => (true, None),
                Err(FormatError::ReaderUnsupported(reason)) => (false, Some(reason)),
                Err(error) => return Err(error),
            };
            let degraded_restore_available = if policy_complete {
                true
            } else {
                plan_restore(
                    &member.path,
                    metadata,
                    member.kind,
                    member.reparse_placeholder,
                    SafeExtractionOptions {
                        allow_degraded: true,
                        ..strict
                    },
                )
                .is_ok()
            };
            policy_capabilities.push(RestorePolicyCapability {
                policy,
                policy_complete,
                degraded_restore_available,
                reason,
            });
        }

        let mut diagnostics = member.diagnostics.clone();
        diagnostics.extend(plan_restore(
            &member.path,
            metadata,
            member.kind,
            member.reparse_placeholder,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )?);
        let system_complete = policy_capabilities
            .iter()
            .find(|capability| capability.policy == RestorePolicy::System)
            .is_some_and(|capability| capability.policy_complete);
        let full_fidelity_possible = metadata.declaration.capture_status == CaptureStatus::Complete
            && system_complete
            && !diagnostics.iter().any(|diagnostic| {
                matches!(
                    diagnostic.status,
                    MetadataDiagnosticStatus::Materialized
                        | MetadataDiagnosticStatus::Unsupported
                        | MetadataDiagnosticStatus::Failed
                )
            });
        entries.push(EntryMetadataVerification {
            path: member.path.clone(),
            capture_status: metadata.declaration.capture_status,
            required_profiles: metadata.declaration.required_profiles.clone(),
            optional_profiles: metadata.declaration.optional_profiles.clone(),
            auxiliary_kinds,
            policy_capabilities,
            full_fidelity_possible,
            diagnostics,
        });
    }

    Ok(MetadataVerificationReport {
        all_capture_complete: entries
            .iter()
            .all(|entry| entry.capture_status == CaptureStatus::Complete),
        full_fidelity_possible: entries.iter().all(|entry| entry.full_fidelity_possible),
        profiles_present: profiles_present.into_iter().collect(),
        auxiliary_kinds_present: auxiliary_kinds_present.into_iter().collect(),
        entries,
    })
}

struct RegularWriterHandler<'a, W> {
    writer: &'a mut W,
}

impl<W: Write> TarMemberStreamHandler for RegularWriterHandler<'_, W> {
    fn on_member(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), ExtractError> {
        if member.kind != TarEntryKind::Regular || member.reparse_placeholder {
            return Err(FormatError::ReaderUnsupported(
                "extract_file_to_writer returns only regular file payloads",
            )
            .into());
        }
        Ok(())
    }

    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        self.writer.write_all(bytes).map_err(ExtractError::Output)
    }
}

struct FilesystemRestoreHandler<'a> {
    root: &'a Path,
    options: SafeExtractionOptions,
    destination: Option<PreparedDestination>,
    temp_leaf: Option<PathBuf>,
    file: Option<fs::File>,
    skipped_reparse_placeholder: bool,
    skipped_by_policy: bool,
    materialized_hardlink: bool,
    planned_diagnostics: Vec<MetadataDiagnostic>,
    defer_hardlinks: bool,
    deferred_hardlinks: Vec<(Vec<u8>, Vec<u8>)>,
}

impl<'a> FilesystemRestoreHandler<'a> {
    fn new(root: &'a Path, options: SafeExtractionOptions) -> Self {
        Self {
            root,
            options,
            destination: None,
            temp_leaf: None,
            file: None,
            skipped_reparse_placeholder: false,
            skipped_by_policy: false,
            materialized_hardlink: false,
            planned_diagnostics: Vec::new(),
            defer_hardlinks: false,
            deferred_hardlinks: Vec::new(),
        }
    }

    fn new_deferred(root: &'a Path, options: SafeExtractionOptions) -> Self {
        let mut handler = Self::new(root, options);
        handler.defer_hardlinks = true;
        handler
    }

    fn finish_archive(&mut self) -> Result<(), FormatError> {
        for (path, target) in std::mem::take(&mut self.deferred_hardlinks) {
            let destination =
                prepare_destination(self.root, &path, TarEntryKind::Hardlink, self.options)?;
            let target_path = existing_safe_regular_path(self.root, &target)?;
            if self.options.restore_policy == RestorePolicy::Content {
                let (temp_leaf, mut output) = create_temp_regular_file(&destination)?;
                let mut input = open_existing_regular_file(&target_path)?;
                if std::io::copy(&mut input, &mut output).is_err() {
                    let _ = destination.parent.remove_file_or_symlink(&temp_leaf);
                    return Err(FormatError::FilesystemExtractionFailed(
                        "failed to materialize hardlink target",
                    ));
                }
                output.flush().map_err(|_| {
                    FormatError::FilesystemExtractionFailed(
                        "failed to write materialized hardlink target",
                    )
                })?;
                publish_regular_file(&destination, &temp_leaf, output, self.options)?;
            } else {
                create_hardlink(&destination, &target_path, self.options)?;
            }
        }
        Ok(())
    }

    fn finish(
        &mut self,
        member: &StreamedTarMemberMetadata,
    ) -> Result<Vec<MetadataDiagnostic>, ExtractError> {
        let mut diagnostics = member.diagnostics.clone();
        for diagnostic in &mut diagnostics {
            if diagnostic.operation == MetadataOperation::Restore
                && diagnostic.restore_policy.is_none()
            {
                diagnostic.restore_policy = Some(self.options.restore_policy);
                diagnostic.restore_phase = Some(restore_phase_for_kind(
                    member.kind,
                    member.reparse_placeholder,
                ));
            }
        }
        diagnostics.append(&mut self.planned_diagnostics);
        if self.skipped_reparse_placeholder {
            return Ok(diagnostics);
        }
        if self.skipped_by_policy {
            return Ok(diagnostics);
        }
        if member.kind != TarEntryKind::Regular && !self.materialized_hardlink {
            return Ok(diagnostics);
        }

        let mut file = self.file.take().ok_or(FormatError::InvalidArchive(
            "regular file output is missing",
        ))?;
        file.flush()
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to write regular file"))?;

        let destination = self.destination.take().ok_or(FormatError::InvalidArchive(
            "regular file destination is missing",
        ))?;
        let temp_leaf = self.temp_leaf.take().ok_or(FormatError::InvalidArchive(
            "regular file temp path is missing",
        ))?;
        let file = publish_regular_file(&destination, &temp_leaf, file, self.options)?;
        if self.options.restore_policy != RestorePolicy::Content {
            if let Err(error) = apply_restored_regular_file_metadata_parts(
                &file,
                &member.path,
                RestoredRegularMetadata::from(&member.v45_metadata.portable_mirror),
                self.options,
                &mut diagnostics,
            ) {
                drop(file);
                let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                return Err(error.into());
            }
        }
        Ok(diagnostics)
    }
}

impl Drop for FilesystemRestoreHandler<'_> {
    fn drop(&mut self) {
        if let (Some(destination), Some(temp_leaf)) =
            (self.destination.as_ref(), self.temp_leaf.take())
        {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
        }
    }
}

impl TarMemberStreamHandler for FilesystemRestoreHandler<'_> {
    fn on_member(&mut self, member: &StreamedTarMemberMetadata) -> Result<(), ExtractError> {
        if self.destination.is_some() || self.temp_leaf.is_some() || self.file.is_some() {
            return Err(FormatError::InvalidArchive(
                "previous streamed restore member was not finalized",
            )
            .into());
        }
        self.skipped_reparse_placeholder = false;
        self.skipped_by_policy = false;
        self.materialized_hardlink = false;
        self.planned_diagnostics.clear();
        self.planned_diagnostics = plan_restore(
            &member.path,
            &member.v45_metadata,
            member.kind,
            member.reparse_placeholder,
            self.options,
        )?;
        if member.reparse_placeholder {
            self.skipped_reparse_placeholder = true;
            return Ok(());
        }
        if member.kind == TarEntryKind::Symlink
            && self.options.restore_policy == RestorePolicy::Content
        {
            self.skipped_by_policy = true;
            return Ok(());
        }
        if matches!(
            member.kind,
            TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
        ) {
            self.skipped_by_policy = true;
            return Ok(());
        }
        let destination = prepare_destination(self.root, &member.path, member.kind, self.options)?;
        match member.kind {
            TarEntryKind::Regular => {
                let (temp_leaf, file) = create_temp_regular_file(&destination)?;
                self.destination = Some(destination);
                self.temp_leaf = Some(temp_leaf);
                self.file = Some(file);
            }
            TarEntryKind::Directory => {
                create_directory(&destination)?;
            }
            TarEntryKind::Symlink => {
                let target = member
                    .link_target
                    .as_deref()
                    .ok_or(FormatError::InvalidArchive("symlink target is missing"))?;
                validate_symlink_target(&member.path, target)?;
                create_symlink(&destination, target, self.options)?;
            }
            TarEntryKind::Hardlink => {
                let target = member
                    .link_target
                    .as_deref()
                    .ok_or(FormatError::InvalidArchive("hardlink target is missing"))?;
                if self.defer_hardlinks {
                    self.deferred_hardlinks
                        .push((member.path.clone(), target.to_vec()));
                    self.skipped_by_policy = true;
                    if self.options.restore_policy == RestorePolicy::Content {
                        self.planned_diagnostics.push(
                            MetadataDiagnostic::new(
                                &member.path,
                                "portable-v1",
                                "hardlink-topology",
                                MetadataOperation::Restore,
                                MetadataDiagnosticStatus::Materialized,
                                "hardlink topology was materialized by content restore policy",
                            )
                            .for_restore(self.options.restore_policy, 3),
                        );
                    }
                    return Ok(());
                }
                let target_path = existing_safe_regular_path(self.root, target)?;
                if self.options.restore_policy == RestorePolicy::Content {
                    let (temp_leaf, mut output) = create_temp_regular_file(&destination)?;
                    let mut input = open_existing_regular_file(&target_path)?;
                    let materialized_bytes =
                        std::io::copy(&mut input, &mut output).map_err(|_| {
                            FormatError::FilesystemExtractionFailed(
                                "failed to materialize hardlink target",
                            )
                        })?;
                    self.destination = Some(destination);
                    self.temp_leaf = Some(temp_leaf);
                    self.file = Some(output);
                    self.materialized_hardlink = true;
                    self.planned_diagnostics.push(
                        MetadataDiagnostic::new(
                            &member.path,
                            "portable-v1",
                            "hardlink-topology",
                            MetadataOperation::Restore,
                            MetadataDiagnosticStatus::Materialized,
                            "hardlink topology was materialized by content restore policy",
                        )
                        .for_restore(self.options.restore_policy, 3)
                        .with_bytes(materialized_bytes, materialized_bytes),
                    );
                } else {
                    create_hardlink(&destination, &target_path, self.options)?;
                }
            }
            TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => {
                unreachable!("special objects return before destination preparation")
            }
        }
        Ok(())
    }

    fn write_regular_payload(&mut self, bytes: &[u8]) -> Result<(), ExtractError> {
        let file = self.file.as_mut().ok_or(FormatError::InvalidArchive(
            "regular file output is missing",
        ))?;
        file.write_all(bytes)
            .map_err(|_| FormatError::FilesystemExtractionFailed("failed to write regular file"))?;
        Ok(())
    }
}

fn format_error_from_extract_error(error: ExtractError) -> FormatError {
    match error {
        ExtractError::Format(error) => error,
        ExtractError::Output(_) => {
            FormatError::FilesystemExtractionFailed("failed to write regular file")
        }
    }
}

fn read_member_bytes<R: TarMemberGroupReader>(
    reader: &mut R,
    buf: &mut [u8],
    remaining: &mut u64,
) -> Result<(), ExtractError> {
    if buf.len() as u64 > *remaining {
        return Err(FormatError::InvalidArchive("tar member payload exceeds group").into());
    }
    reader.read_exact_member_bytes(buf)?;
    *remaining -= buf.len() as u64;
    Ok(())
}

fn read_member_vec<R: TarMemberGroupReader>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
) -> Result<Vec<u8>, ExtractError> {
    let mut out = vec![0u8; to_usize(len)?];
    read_member_bytes(reader, &mut out, remaining)?;
    Ok(out)
}

fn read_zero_padding<R: TarMemberGroupReader>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
) -> Result<(), ExtractError> {
    let mut pending = len;
    let mut buf = [0u8; 8192];
    while pending > 0 {
        let chunk_len = pending.min(buf.len() as u64) as usize;
        read_member_bytes(reader, &mut buf[..chunk_len], remaining)?;
        if buf[..chunk_len].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive("tar member padding is non-zero").into());
        }
        pending -= chunk_len as u64;
    }
    Ok(())
}

fn stream_regular_payload<R, H>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
    handler: &mut H,
) -> Result<(), ExtractError>
where
    R: TarMemberGroupReader,
    H: TarMemberStreamHandler,
{
    let mut pending = len;
    let mut buf = [0u8; 64 * 1024];
    while pending > 0 {
        let chunk_len = pending.min(buf.len() as u64).min(*remaining) as usize;
        let read = reader.read_some_member_bytes(&mut buf[..chunk_len])?;
        if read == 0 {
            return Err(FormatError::InvalidArchive("tar member group exceeds frame range").into());
        }
        *remaining -= read as u64;
        pending -= read as u64;
        handler.write_regular_payload(&buf[..read])?;
    }
    Ok(())
}

fn stream_auxiliary_payload<R: TarMemberGroupReader>(
    reader: &mut R,
    len: u64,
    remaining: &mut u64,
    validator: &mut AuxiliaryStreamValidator,
) -> Result<(), ExtractError> {
    let mut pending = len;
    let mut buf = [0u8; 64 * 1024];
    while pending > 0 {
        let chunk_len = pending.min(buf.len() as u64).min(*remaining) as usize;
        let read = reader.read_some_member_bytes(&mut buf[..chunk_len])?;
        if read == 0 {
            return Err(FormatError::InvalidArchive("tar member group exceeds frame range").into());
        }
        *remaining -= read as u64;
        pending -= read as u64;
        validator.observe(&buf[..read])?;
    }
    Ok(())
}

fn stream_sparse_primary_payload<R, H>(
    reader: &mut R,
    stored_size: u64,
    logical_size: u64,
    remaining: &mut u64,
    handler: &mut H,
) -> Result<(), ExtractError>
where
    R: TarMemberGroupReader,
    H: TarMemberStreamHandler,
{
    if stored_size < TAR_BLOCK_LEN as u64 {
        return Err(FormatError::InvalidArchive("sparse primary map is truncated").into());
    }
    let mut validator = SparseStreamValidator::new(logical_size);
    let mut consumed = 0u64;
    let layout = loop {
        if consumed
            .checked_add(TAR_BLOCK_LEN as u64)
            .is_none_or(|value| value > stored_size)
        {
            return Err(FormatError::InvalidArchive("sparse primary map is truncated").into());
        }
        let mut block = [0u8; TAR_BLOCK_LEN];
        read_member_bytes(reader, &mut block, remaining)?;
        consumed += TAR_BLOCK_LEN as u64;
        validator.observe(&block)?;
        if let Some(layout) = validator.layout_if_map_complete() {
            if layout.map_and_padding_size as u64 == consumed {
                break layout;
            }
        }
    };
    let extent_bytes = layout.extents.iter().try_fold(0u64, |sum, extent| {
        sum.checked_add(extent.length)
            .ok_or(FormatError::InvalidArchive(
                "sparse extent byte count overflow",
            ))
    })?;
    if consumed
        .checked_add(extent_bytes)
        .is_none_or(|value| value != stored_size)
    {
        return Err(FormatError::InvalidArchive(
            "sparse primary stored size does not match its map",
        )
        .into());
    }

    let zeros = [0u8; 64 * 1024];
    let mut logical_cursor = 0u64;
    let mut buf = [0u8; 64 * 1024];
    for extent in &layout.extents {
        write_zero_run(handler, &zeros, extent.offset - logical_cursor)?;
        let mut extent_remaining = extent.length;
        while extent_remaining > 0 {
            let chunk_len = extent_remaining.min(buf.len() as u64) as usize;
            read_member_bytes(reader, &mut buf[..chunk_len], remaining)?;
            validator.observe(&buf[..chunk_len])?;
            handler.write_regular_payload(&buf[..chunk_len])?;
            extent_remaining -= chunk_len as u64;
        }
        logical_cursor = extent.offset + extent.length;
    }
    write_zero_run(handler, &zeros, logical_size - logical_cursor)?;
    validator.finish()?;
    Ok(())
}

fn write_zero_run<H: TarMemberStreamHandler>(
    handler: &mut H,
    zeros: &[u8],
    mut len: u64,
) -> Result<(), ExtractError> {
    while len > 0 {
        let chunk_len = len.min(zeros.len() as u64) as usize;
        handler.write_regular_payload(&zeros[..chunk_len])?;
        len -= chunk_len as u64;
    }
    Ok(())
}

fn tar_member_group_end(stream: &[u8], start: usize) -> Result<usize, FormatError> {
    try_tar_member_group_end(stream, start)?.ok_or(FormatError::InvalidArchive(
        "tar member payload exceeds stream",
    ))
}

#[cfg(test)]
fn restore_tar_member(
    root: &Path,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
) -> Result<Vec<MetadataDiagnostic>, FormatError> {
    let mut diagnostics = member.diagnostics.clone();
    if let Some(metadata) = &member.v45_metadata {
        diagnostics.extend(plan_restore(
            &member.path,
            metadata,
            member.kind,
            member.reparse_placeholder,
            options,
        )?);
    }
    if member.reparse_placeholder {
        diagnostics.push(
            MetadataDiagnostic::new(
                &member.path,
                "windows-backup-v1",
                "reparse-data",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Skipped,
                "reparse placeholder skipped by portable restore policy",
            )
            .for_restore(options.restore_policy, 3),
        );
        return Ok(diagnostics);
    }
    if member.kind == TarEntryKind::Symlink && options.restore_policy == RestorePolicy::Content {
        return Ok(diagnostics);
    }
    if matches!(
        member.kind,
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo
    ) {
        diagnostics.push(
            MetadataDiagnostic::new(
                &member.path,
                "posix-backup-v1",
                "special-object",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Skipped,
                "special object skipped by portable restore policy",
            )
            .for_restore(
                options.restore_policy,
                restore_phase_for_kind(member.kind, member.reparse_placeholder),
            ),
        );
        return Ok(diagnostics);
    }
    let destination = prepare_destination(root, &member.path, member.kind, options)?;
    match member.kind {
        TarEntryKind::Regular => {
            let (temp_leaf, mut file) = create_temp_regular_file(&destination)?;
            file.write_all(&member.data).map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to write regular file")
            })?;
            file.flush().map_err(|_| {
                FormatError::FilesystemExtractionFailed("failed to write regular file")
            })?;
            let file = publish_regular_file(&destination, &temp_leaf, file, options)?;
            if options.restore_policy != RestorePolicy::Content {
                if let Err(error) =
                    apply_restored_regular_file_metadata(&file, member, options, &mut diagnostics)
                {
                    drop(file);
                    let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                    return Err(error);
                }
            }
        }
        TarEntryKind::Directory => {
            create_directory(&destination)?;
        }
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
            if options.restore_policy == RestorePolicy::Content {
                let (temp_leaf, mut output) = create_temp_regular_file(&destination)?;
                let mut input = open_existing_regular_file(&target_path)?;
                let materialized_bytes = std::io::copy(&mut input, &mut output).map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to materialize hardlink target")
                })?;
                output.flush().map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to materialize hardlink target")
                })?;
                publish_regular_file(&destination, &temp_leaf, output, options)?;
                diagnostics.push(
                    MetadataDiagnostic::new(
                        &member.path,
                        "portable-v1",
                        "hardlink-topology",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Materialized,
                        "hardlink topology was materialized by content restore policy",
                    )
                    .for_restore(options.restore_policy, 3)
                    .with_bytes(materialized_bytes, materialized_bytes),
                );
            } else {
                create_hardlink(&destination, &target_path, options)?;
            }
        }
        TarEntryKind::CharacterDevice | TarEntryKind::BlockDevice | TarEntryKind::Fifo => {
            unreachable!("special objects return before destination preparation")
        }
    }
    Ok(diagnostics)
}

#[cfg(test)]
fn apply_restored_regular_file_metadata(
    file: &fs::File,
    member: &OwnedTarMember,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let metadata = member.v45_metadata.as_ref().map_or(
        RestoredRegularMetadata {
            mode: member.mode,
            mtime: (member.mtime.seconds, member.mtime.nanoseconds),
            attributes: None,
            mode_origin_native: false,
        },
        |metadata| RestoredRegularMetadata::from(&metadata.portable_mirror),
    );
    apply_restored_regular_file_metadata_parts(file, &member.path, metadata, options, diagnostics)
}

#[derive(Clone, Copy)]
struct RestoredRegularMetadata {
    mode: u32,
    mtime: (i64, u32),
    attributes: Option<u32>,
    mode_origin_native: bool,
}

impl From<&PortableMetadataMirror> for RestoredRegularMetadata {
    fn from(metadata: &PortableMetadataMirror) -> Self {
        Self {
            mode: metadata.mode,
            mtime: metadata.mtime,
            attributes: metadata.attributes,
            mode_origin_native: metadata.mode_origin_native,
        }
    }
}

fn apply_restored_regular_file_metadata_parts(
    file: &fs::File,
    path: &[u8],
    metadata: RestoredRegularMetadata,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let RestoredRegularMetadata {
        mode,
        mtime,
        attributes,
        mode_origin_native,
    } = metadata;
    let mode = if options.restore_policy == RestorePolicy::System && options.system_authorized {
        mode
    } else {
        mode & !0o6000
    };
    apply_regular_file_mode(file, path, mode, mode_origin_native, options, diagnostics)?;
    apply_regular_file_mtime(file, path, mtime, options, diagnostics)?;
    apply_regular_file_attributes(file, path, attributes, options, diagnostics)
}

#[cfg(windows)]
fn apply_regular_file_attributes(
    file: &fs::File,
    path: &[u8],
    attributes: Option<u32>,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let Some(attributes) = attributes else {
        return Ok(());
    };
    let metadata = match file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "portable-attributes",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying readonly attribute projection",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying readonly attribute projection",
            );
        }
    };
    let mut permissions = metadata.permissions();
    permissions.set_readonly(attributes & 1 != 0);
    if let Err(error) = file.set_permissions(permissions) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "portable-attributes",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply readonly attribute projection",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply readonly attribute projection",
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_regular_file_attributes(
    _file: &fs::File,
    _path: &[u8],
    _attributes: Option<u32>,
    _options: SafeExtractionOptions,
    _diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    Ok(())
}

#[cfg(unix)]
fn apply_regular_file_mode(
    file: &fs::File,
    path: &[u8],
    mode: u32,
    _mode_origin_native: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    match file.metadata() {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_mode(mode & 0o7777);
            if let Err(error) = file.set_permissions(permissions) {
                return record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "mode",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply mode metadata",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply mode metadata",
                );
            }
        }
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying mode metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying mode metadata",
            );
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_regular_file_mode(
    file: &fs::File,
    path: &[u8],
    mode: u32,
    mode_origin_native: bool,
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    match file.metadata() {
        Ok(metadata) => {
            let mut permissions = metadata.permissions();
            permissions.set_readonly(mode & 0o222 == 0);
            if let Err(error) = file.set_permissions(permissions) {
                return record_metadata_application_failure(
                    diagnostics,
                    MetadataDiagnostic::new(
                        path,
                        "portable-v1",
                        "mode",
                        MetadataOperation::Restore,
                        MetadataDiagnosticStatus::Failed,
                        "failed to apply mode metadata",
                    )
                    .for_restore(options.restore_policy, 4)
                    .with_native_error(&error),
                    options,
                    "failed to apply mode metadata",
                );
            }
            if mode_origin_native && mode & 0o777 != 0o444 && mode & 0o777 != 0o666 {
                let diagnostic = MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Partial,
                    "mode metadata was only partially applied on this platform",
                )
                .for_restore(options.restore_policy, 4);
                if options.allow_degraded {
                    diagnostics.push(diagnostic);
                } else {
                    return Err(FormatError::FilesystemExtractionFailed(
                        "portable mode cannot be represented exactly on this host",
                    ));
                }
            }
        }
        Err(error) => {
            return record_metadata_application_failure(
                diagnostics,
                MetadataDiagnostic::new(
                    path,
                    "portable-v1",
                    "mode",
                    MetadataOperation::Restore,
                    MetadataDiagnosticStatus::Failed,
                    "failed to inspect file before applying mode metadata",
                )
                .for_restore(options.restore_policy, 4)
                .with_native_error(&error),
                options,
                "failed to inspect file before applying mode metadata",
            );
        }
    }
    Ok(())
}

fn apply_regular_file_mtime(
    file: &fs::File,
    path: &[u8],
    (seconds, nanoseconds): (i64, u32),
    options: SafeExtractionOptions,
    diagnostics: &mut Vec<MetadataDiagnostic>,
) -> Result<(), FormatError> {
    let duration = Duration::new(seconds.unsigned_abs(), nanoseconds);
    let modified = if seconds < 0 {
        SystemTime::UNIX_EPOCH.checked_sub(duration)
    } else {
        SystemTime::UNIX_EPOCH.checked_add(duration)
    };
    let Some(modified) = modified else {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply mtime metadata",
            )
            .for_restore(options.restore_policy, 4),
            options,
            "mtime cannot be represented on this host",
        );
    };
    let times = fs::FileTimes::new().set_modified(modified);
    if let Err(error) = file.set_times(times) {
        return record_metadata_application_failure(
            diagnostics,
            MetadataDiagnostic::new(
                path,
                "portable-v1",
                "mtime",
                MetadataOperation::Restore,
                MetadataDiagnosticStatus::Failed,
                "failed to apply mtime metadata",
            )
            .for_restore(options.restore_policy, 4)
            .with_native_error(&error),
            options,
            "failed to apply mtime metadata",
        );
    }
    Ok(())
}

fn record_metadata_application_failure(
    diagnostics: &mut Vec<MetadataDiagnostic>,
    diagnostic: MetadataDiagnostic,
    options: SafeExtractionOptions,
    strict_error: &'static str,
) -> Result<(), FormatError> {
    if options.allow_degraded {
        diagnostics.push(diagnostic);
        Ok(())
    } else {
        Err(FormatError::FilesystemExtractionFailed(strict_error))
    }
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
    if target.nfc().collect::<String>() != target {
        return Err(FormatError::UnsafeArchivePath);
    }
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

struct PreparedDestination {
    parent: CapDir,
    leaf: PathBuf,
}

fn prepare_destination(
    root: &Path,
    archive_path: &[u8],
    kind: TarEntryKind,
    options: SafeExtractionOptions,
) -> Result<PreparedDestination, FormatError> {
    let components = path_components(archive_path)?;
    let mut parent = open_extraction_root(root)?;
    for component in &components[..components.len().saturating_sub(1)] {
        parent = open_or_create_safe_child_dir(&parent, component)?;
    }

    let leaf = PathBuf::from(components.last().ok_or(FormatError::UnsafeArchivePath)?);
    match parent.symlink_metadata(&leaf) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(FormatError::UnsafeArchivePath);
            }
            if kind == TarEntryKind::Directory {
                if file_type.is_dir() {
                    return Ok(PreparedDestination { parent, leaf });
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
    Ok(PreparedDestination { parent, leaf })
}

fn open_extraction_root(root: &Path) -> Result<CapDir, FormatError> {
    let metadata = fs::symlink_metadata(root).map_err(|_| {
        FormatError::FilesystemExtractionFailed("extraction root must already exist")
    })?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
        return Err(FormatError::UnsafeArchivePath);
    }
    CapDir::open_ambient_dir(root, ambient_authority())
        .map_err(|_| FormatError::FilesystemExtractionFailed("extraction root must already exist"))
}

fn open_or_create_safe_child_dir(parent: &CapDir, component: &str) -> Result<CapDir, FormatError> {
    match parent.open_dir_nofollow(component) {
        Ok(child) => return Ok(child),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(FormatError::UnsafeArchivePath),
    }

    match parent.create_dir(component) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(_) => {
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to create parent directory",
            ));
        }
    }
    parent
        .open_dir_nofollow(component)
        .map_err(|_| FormatError::UnsafeArchivePath)
}

fn existing_safe_regular_path(
    root: &Path,
    archive_path: &[u8],
) -> Result<PreparedDestination, FormatError> {
    validate_file_path_bytes(archive_path, u32::MAX)?;
    let components = path_components(archive_path)?;
    let mut parent = open_extraction_root(root)?;
    for component in &components[..components.len().saturating_sub(1)] {
        parent = parent
            .open_dir_nofollow(component)
            .map_err(|_| FormatError::UnsafeArchivePath)?;
    }

    let leaf = PathBuf::from(components.last().ok_or(FormatError::UnsafeArchivePath)?);
    let metadata = parent
        .symlink_metadata(&leaf)
        .map_err(|_| FormatError::UnsafeArchivePath)?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(FormatError::UnsafeArchivePath);
    }
    Ok(PreparedDestination { parent, leaf })
}

fn create_new_file_options() -> CapOpenOptions {
    let mut options = CapOpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    options
}

fn open_existing_regular_file(target: &PreparedDestination) -> Result<fs::File, FormatError> {
    let mut options = CapOpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    target
        .parent
        .open_with(&target.leaf, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| {
            FormatError::FilesystemExtractionFailed(
                "failed to open hardlink target for materialization",
            )
        })
}

fn create_temp_regular_file(
    destination: &PreparedDestination,
) -> Result<(PathBuf, fs::File), FormatError> {
    for _ in 0..1000u32 {
        let mut candidate = destination.leaf.as_os_str().to_os_string();
        candidate.push(format!(".tzap-tmp-{}", uuid::Uuid::new_v4()));
        let leaf = PathBuf::from(candidate);
        match destination
            .parent
            .open_with(&leaf, &create_new_file_options())
        {
            Ok(file) => return Ok((leaf, file.into_std())),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(FormatError::FilesystemExtractionFailed(
                    "failed to create regular file",
                ));
            }
        }
    }
    Err(FormatError::FilesystemExtractionFailed(
        "failed to create regular file",
    ))
}

fn publish_regular_file(
    destination: &PreparedDestination,
    temp_leaf: &Path,
    mut temp_file: fs::File,
    options: SafeExtractionOptions,
) -> Result<fs::File, FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }

    let mut output = match destination
        .parent
        .open_with(&destination.leaf, &create_new_file_options())
    {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
            return Err(FormatError::UnsafeOverwrite);
        }
        Err(_) => {
            let _ = destination.parent.remove_file_or_symlink(temp_leaf);
            return Err(FormatError::FilesystemExtractionFailed(
                "failed to create regular file",
            ));
        }
    };

    let copy_result = temp_file
        .seek(SeekFrom::Start(0))
        .and_then(|_| std::io::copy(&mut temp_file, &mut output))
        .and_then(|_| output.flush());

    if copy_result.is_err() {
        let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
        let _ = destination.parent.remove_file_or_symlink(temp_leaf);
        return Err(FormatError::FilesystemExtractionFailed(
            "failed to write regular file",
        ));
    }

    let _ = destination.parent.remove_file_or_symlink(temp_leaf);
    Ok(output)
}

fn remove_existing_leaf_if_needed(destination: &PreparedDestination) -> Result<(), FormatError> {
    match destination.parent.symlink_metadata(&destination.leaf) {
        Ok(metadata) => {
            if metadata.file_type().is_dir() {
                return Err(FormatError::UnsafeOverwrite);
            }
            destination
                .parent
                .remove_file_or_symlink(&destination.leaf)
                .map_err(|_| FormatError::FilesystemExtractionFailed("failed to remove old file"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to inspect destination",
        )),
    }
}

fn create_directory(destination: &PreparedDestination) -> Result<(), FormatError> {
    match destination.parent.create_dir(&destination.leaf) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = destination
                .parent
                .symlink_metadata(&destination.leaf)
                .map_err(|_| FormatError::UnsafeOverwrite)?;
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                Err(FormatError::UnsafeArchivePath)
            } else if file_type.is_dir() {
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
    destination: &PreparedDestination,
    target: &PreparedDestination,
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    match target
        .parent
        .hard_link(&target.leaf, &destination.parent, &destination.leaf)
    {
        Ok(()) => {
            let metadata = destination
                .parent
                .symlink_metadata(&destination.leaf)
                .map_err(|_| {
                    FormatError::FilesystemExtractionFailed("failed to inspect hardlink")
                })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                let _ = destination.parent.remove_file_or_symlink(&destination.leaf);
                return Err(FormatError::UnsafeArchivePath);
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(FormatError::UnsafeOverwrite)
        }
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to create hardlink",
        )),
    }
}

fn create_symlink(
    destination: &PreparedDestination,
    target: &[u8],
    options: SafeExtractionOptions,
) -> Result<(), FormatError> {
    if options.overwrite_existing {
        remove_existing_leaf_if_needed(destination)?;
    }
    let target = std::str::from_utf8(target).map_err(|_| FormatError::UnsafeArchivePath)?;
    match destination.parent.symlink_file(target, &destination.leaf) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(FormatError::UnsafeOverwrite)
        }
        Err(_) => Err(FormatError::FilesystemExtractionFailed(
            "failed to create symlink",
        )),
    }
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

fn padding_to_512_u64(len: u64) -> u64 {
    let remainder = len % TAR_BLOCK_LEN as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - remainder
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
        member_with_declared_size(path, kind, data.len(), data, link)
    }

    fn member_with_declared_size(
        path: &[u8],
        kind: u8,
        declared_size: usize,
        data: &[u8],
        link: &[u8],
    ) -> Vec<u8> {
        let records =
            crate::entry_metadata::portable_primary_pax(path, 0o644, "other", false).unwrap();
        let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
        let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
        write_octal(&mut pax_header[100..108], 0);
        pax_header[148..156].fill(b' ');
        let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut pax_header[148..156], checksum);
        let mut out = Vec::new();
        out.extend_from_slice(&pax_header);
        out.extend_from_slice(&pax);
        out.resize(out.len() + padding_to_512(pax.len()), 0);
        out.extend_from_slice(&header(path, kind, declared_size, link));
        out.extend_from_slice(data);
        out.resize(out.len() + padding_to_512(data.len()), 0);
        out
    }

    fn member_with_prefix(prefix: &[u8], path: &[u8], kind: u8, data: &[u8]) -> Vec<u8> {
        let mut full_path = prefix.to_vec();
        full_path.push(b'/');
        full_path.extend_from_slice(path);
        let records =
            crate::entry_metadata::portable_primary_pax(&full_path, 0o644, "other", false).unwrap();
        let pax = crate::entry_metadata::encode_canonical_pax(&records).unwrap();
        let mut pax_header = header(b"TZAP-PAX/PRIMARY", b'x', pax.len(), b"");
        write_octal(&mut pax_header[100..108], 0);
        pax_header[148..156].fill(b' ');
        let checksum = pax_header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut pax_header[148..156], checksum);
        let mut header = header(path, kind, data.len(), b"");
        header[345..345 + prefix.len()].copy_from_slice(prefix);
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);

        let mut out = Vec::new();
        out.extend_from_slice(&pax_header);
        out.extend_from_slice(&pax);
        out.resize(out.len() + padding_to_512(pax.len()), 0);
        out.extend_from_slice(&header);
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
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45")
        );
    }

    #[test]
    fn rejects_global_pax_before_main_entry() {
        let global_pax = pax_record("path", b"poisoned.txt");
        let mut bytes = member(b"GlobalHead/path", b'g', &global_pax, b"");
        bytes.extend_from_slice(&member(b"safe.txt", b'0', b"abc", b""));

        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45")
        );
    }

    #[test]
    fn rejects_global_gnu_headers() {
        for typeflag in [b'V', b'M', b'N'] {
            let bytes = member(b"global", typeflag, b"archive-label", b"");

            assert_eq!(
                parse_tar_member_group(&bytes, 4096).unwrap_err(),
                FormatError::InvalidArchive(
                    "global or GNU tar metadata is forbidden in revision 45"
                ),
                "typeflag {typeflag:?}"
            );
        }
    }

    #[test]
    fn rejects_unsupported_gnu_sparse_entry_type() {
        let bytes = member(b"sparse.bin", b'S', b"", b"");

        assert_eq!(
            parse_tar_member_group(&bytes, 4096).unwrap_err(),
            FormatError::InvalidArchive("global or GNU tar metadata is forbidden in revision 45")
        );
    }

    #[test]
    fn rejects_noncanonical_extra_local_pax_path_and_size() {
        let pax = pax_record("path", b"long/name.txt");
        let mut bytes = member(b"PaxHeaders/name", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"short", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_gnu_long_name_and_link_records() {
        let mut named = member(b"././@LongLink", b'L', b"long/path.txt\0", b"");
        named.extend_from_slice(&member(b"short", b'0', b"abc", b""));
        assert!(parse_tar_member_group(&named, 4096).is_err());

        let mut linked = member(b"././@LongLink", b'K', b"target/file.txt\0", b"");
        linked.extend_from_slice(&member(b"short-link", b'2', b"", b"fallback"));
        assert!(parse_tar_member_group(&linked, 4096).is_err());
    }

    #[test]
    fn supported_tar_metadata_profile_matrix_matches_buffered_and_streaming_parsers() {
        struct Case {
            name: &'static str,
            bytes: Vec<u8>,
            expected_path: &'static [u8],
            expected_kind: TarEntryKind,
            expected_data: &'static [u8],
            expected_link_target: Option<&'static [u8]>,
            expected_logical_size: u64,
        }

        let cases = vec![
            Case {
                name: "regular ustar member",
                bytes: member(b"dir/file.txt", b'0', b"hello", b""),
                expected_path: b"dir/file.txt",
                expected_kind: TarEntryKind::Regular,
                expected_data: b"hello",
                expected_link_target: None,
                expected_logical_size: 5,
            },
            Case {
                name: "ustar prefix plus name",
                bytes: member_with_prefix(b"dir/prefix", b"file.txt", b'0', b"abc"),
                expected_path: b"dir/prefix/file.txt",
                expected_kind: TarEntryKind::Regular,
                expected_data: b"abc",
                expected_link_target: None,
                expected_logical_size: 3,
            },
            Case {
                name: "directory trailing slash",
                bytes: member(b"dir/", b'5', b"", b""),
                expected_path: b"dir",
                expected_kind: TarEntryKind::Directory,
                expected_data: b"",
                expected_link_target: None,
                expected_logical_size: 0,
            },
            Case {
                name: "canonical symlink",
                bytes: member(b"links/link", b'2', b"", b"target/file.txt"),
                expected_path: b"links/link",
                expected_kind: TarEntryKind::Symlink,
                expected_data: b"",
                expected_link_target: Some(b"target/file.txt"),
                expected_logical_size: 0,
            },
        ];

        for case in cases {
            let parsed = parse_tar_member_group(&case.bytes, 4096).unwrap_or_else(|err| {
                panic!("{} should parse in buffered tar parser: {err:?}", case.name)
            });
            assert_eq!(parsed.path, case.expected_path, "{}", case.name);
            assert_eq!(parsed.kind, case.expected_kind, "{}", case.name);
            assert_eq!(parsed.data, case.expected_data, "{}", case.name);
            assert_eq!(
                parsed.link_target.as_deref(),
                case.expected_link_target,
                "{}",
                case.name
            );
            assert_eq!(
                parsed.logical_size, case.expected_logical_size,
                "{}",
                case.name
            );

            let mut streaming = TarStreamSummaryValidator::with_observer(
                4096,
                u64::MAX,
                4096,
                16,
                NoopTarStreamObserver,
            );
            streaming.observe(&case.bytes).unwrap_or_else(|err| {
                panic!(
                    "{} should parse in streaming tar parser: {err:?}",
                    case.name
                )
            });
            let summary = streaming.finish().unwrap_or_else(|err| {
                panic!(
                    "{} should finish in streaming tar parser: {err:?}",
                    case.name
                )
            });
            assert_eq!(summary.members.len(), 1, "{}", case.name);
            let member = &summary.members[0];
            assert_eq!(member.path, case.expected_path, "{}", case.name);
            assert_eq!(member.kind, case.expected_kind, "{}", case.name);
            assert_eq!(
                member.link_target.as_deref(),
                case.expected_link_target,
                "{}",
                case.name
            );
            assert_eq!(
                member.logical_size, case.expected_logical_size,
                "{}",
                case.name
            );
        }
    }

    #[test]
    fn tar_metadata_rejects_unsafe_or_inconsistent_overrides_matrix() {
        let mut pax_absolute_path = member(
            b"PaxHeaders/file",
            b'x',
            &pax_record("path", b"/absolute"),
            b"",
        );
        pax_absolute_path.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

        let mut pax_parent_path = member(
            b"PaxHeaders/file",
            b'x',
            &pax_record("path", b"../escape"),
            b"",
        );
        pax_parent_path.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

        let mut pax_absolute_link = member(
            b"PaxHeaders/link",
            b'x',
            &pax_record("linkpath", b"/target"),
            b"",
        );
        pax_absolute_link.extend_from_slice(&member(b"links/link", b'2', b"", b"safe"));

        let mut gnu_unsafe_name = member(b"././@LongLink", b'L', b"bad:name.txt\0", b"");
        gnu_unsafe_name.extend_from_slice(&member(b"fallback", b'0', b"abc", b""));

        let mut gnu_parent_hardlink = member(b"././@LongLink", b'K', b"../target.txt\0", b"");
        gnu_parent_hardlink.extend_from_slice(&member(b"links/hard", b'1', b"", b"safe"));

        let mut pax_size_on_directory =
            member(b"PaxHeaders/dir", b'x', &pax_record("size", b"1"), b"");
        pax_size_on_directory
            .extend_from_slice(&member_with_declared_size(b"dir", b'5', 0, b"x", b""));

        for (name, bytes) in [
            ("pax absolute path", pax_absolute_path),
            ("pax parent path", pax_parent_path),
            ("pax absolute symlink target", pax_absolute_link),
            ("gnu unsafe long name", gnu_unsafe_name),
            ("gnu hardlink parent target", gnu_parent_hardlink),
            ("pax size on directory", pax_size_on_directory),
        ] {
            assert!(parse_tar_member_group(&bytes, 4096).is_err(), "{name}");

            let mut streaming = TarStreamSummaryValidator::with_observer(
                4096,
                u64::MAX,
                4096,
                16,
                NoopTarStreamObserver,
            );
            assert!(streaming.observe(&bytes).is_err(), "{name}");
        }
    }

    #[test]
    fn pax_size_exceeding_available_group_is_rejected_by_buffered_and_streaming_parsers() {
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax_record("size", b"4096"), b"");
        bytes.extend_from_slice(&member_with_declared_size(b"file", b'0', 0, b"short", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());

        let mut streaming = TarStreamSummaryValidator::with_observer(
            4096,
            u64::MAX,
            4096,
            16,
            NoopTarStreamObserver,
        );
        assert!(streaming.observe(&bytes).is_err());
    }

    #[test]
    fn malformed_pax_record_matrix_rejects_before_metadata_is_trusted() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("missing length", b"path=file\n".to_vec()),
            ("missing space", b"12path=file\n".to_vec()),
            ("record too short", b"3 a\n".to_vec()),
            ("missing newline", b"11 path=file".to_vec()),
            ("missing equals", b"10 pathfile\n".to_vec()),
            ("non utf8 key", vec![7, b' ', 0xff, b'=', b'x', b'\n']),
            ("bad size value", pax_record("size", b"12x")),
        ];

        for (name, payload) in cases {
            let mut bytes = member(b"PaxHeaders/file", b'x', &payload, b"");
            bytes.extend_from_slice(&member(b"file", b'0', b"abc", b""));

            assert!(
                matches!(
                    parse_tar_member_group(&bytes, 4096).unwrap_err(),
                    FormatError::InvalidArchive(_)
                ),
                "{name}"
            );

            let mut streaming = TarStreamSummaryValidator::with_observer(
                4096,
                u64::MAX,
                4096,
                16,
                NoopTarStreamObserver,
            );
            assert!(
                matches!(
                    streaming.observe(&bytes).unwrap_err(),
                    FormatError::InvalidArchive(_)
                ),
                "{name}"
            );
        }
    }

    #[test]
    fn rejects_unregistered_legacy_xattr_and_acl_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("SCHILY.xattr.user.comment", b"hello"));
        pax.extend_from_slice(&pax_record("LIBARCHIVE.xattr.user.comment", b"hello"));
        pax.extend_from_slice(&pax_record("SCHILY.acl.access", b"user::rw-"));
        pax.extend_from_slice(&pax_record("LIBARCHIVE.acl.access", b"user::rw-"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_unregistered_legacy_timestamp_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("atime", b"1.123456789"));
        pax.extend_from_slice(&pax_record("ctime", b"2.123456789"));
        pax.extend_from_slice(&pax_record("mtime", b"3.123456789"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_noncanonical_sparse_and_unknown_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("GNU.sparse.realsize", b"1024"));
        pax.extend_from_slice(&pax_record("GNU.sparse.map", b"0,1"));
        pax.extend_from_slice(&pax_record("comment", b"ignored"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
    }

    #[test]
    fn rejects_mixed_unregistered_local_pax_keys() {
        let mut pax = Vec::new();
        pax.extend_from_slice(&pax_record("SCHILY.xattr.user.comment", b"hello"));
        pax.extend_from_slice(&pax_record("GNU.sparse.realsize", b"1024"));
        pax.extend_from_slice(&pax_record("mtime", b"1.123456789"));
        pax.extend_from_slice(&pax_record("comment", b"ignored"));
        let mut bytes = member(b"PaxHeaders/file", b'x', &pax, b"");
        bytes.extend_from_slice(&member(b"file.txt", b'0', b"abc", b""));

        assert!(parse_tar_member_group(&bytes, 4096).is_err());
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

    #[cfg(unix)]
    #[test]
    fn safe_restore_rejects_symlink_parent() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();

        let member = OwnedTarMember {
            path: b"link/file.txt".to_vec(),
            kind: TarEntryKind::Regular,
            data: b"blocked".to_vec(),
            link_target: None,
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 7,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
    }

    #[cfg(unix)]
    #[test]
    fn prepared_regular_file_uses_open_parent_after_parent_path_swap() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let original_parent = tmp.path().join("a");
        let held_parent = tmp.path().join("held");
        fs::create_dir(&original_parent).unwrap();

        let destination = prepare_destination(
            tmp.path(),
            b"a/file.txt",
            TarEntryKind::Regular,
            SafeExtractionOptions::default(),
        )
        .unwrap();

        fs::rename(&original_parent, &held_parent).unwrap();
        std::os::unix::fs::symlink(outside.path(), &original_parent).unwrap();

        let (temp_leaf, mut file) = create_temp_regular_file(&destination).unwrap();
        file.write_all(b"inside").unwrap();
        publish_regular_file(
            &destination,
            &temp_leaf,
            file,
            SafeExtractionOptions::default(),
        )
        .unwrap();

        assert_eq!(fs::read(held_parent.join("file.txt")).unwrap(), b"inside");
        assert!(!outside.path().join("file.txt").exists());
    }

    #[cfg(unix)]
    #[test]
    fn create_directory_rechecks_leaf_without_following_symlink() {
        let tmp = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let destination = prepare_destination(
            tmp.path(),
            b"dir",
            TarEntryKind::Directory,
            SafeExtractionOptions::default(),
        )
        .unwrap();

        std::os::unix::fs::symlink(outside.path(), tmp.path().join("dir")).unwrap();

        assert_eq!(
            create_directory(&destination).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
        assert!(outside.path().read_dir().unwrap().next().is_none());
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
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();
        assert_eq!(fs::read(tmp.path().join("linked.txt")).unwrap(), b"target");
    }

    #[cfg(unix)]
    #[test]
    fn restore_applies_regular_file_mode_metadata() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"script.sh".to_vec(),
            kind: TarEntryKind::Regular,
            data: b"#!/bin/sh\n".to_vec(),
            link_target: None,
            mode: 0o755,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 10,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        let diagnostics =
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();

        assert!(diagnostics.is_empty());
        let mode = fs::metadata(tmp.path().join("script.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn restore_applies_regular_file_mtime_metadata() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"dated.txt".to_vec(),
            kind: TarEntryKind::Regular,
            data: b"dated".to_vec(),
            link_target: None,
            mode: 0o666,
            mtime: ArchiveTimestamp::from_seconds(1_700_000_000),
            logical_size: 5,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        let diagnostics =
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap();

        assert!(diagnostics.is_empty());
        let modified = fs::metadata(tmp.path().join("dated.txt"))
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(modified, 1_700_000_000);
    }

    #[test]
    fn restore_revalidates_symlink_targets_from_owned_members() {
        let tmp = tempdir().unwrap();
        let member = OwnedTarMember {
            path: b"link".to_vec(),
            kind: TarEntryKind::Symlink,
            data: Vec::new(),
            link_target: Some(b"/outside".to_vec()),
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(tmp.path(), &member, SafeExtractionOptions::default()).unwrap_err(),
            FormatError::UnsafeArchivePath
        );
        assert!(!tmp.path().join("link").exists());
    }

    #[test]
    fn skipped_entries_do_not_create_destination_parents() {
        let tmp = tempdir().unwrap();
        for (path, kind, target) in [
            (
                b"symlink-parent/link".as_slice(),
                TarEntryKind::Symlink,
                Some(b"target".to_vec()),
            ),
            (b"special-parent/fifo".as_slice(), TarEntryKind::Fifo, None),
        ] {
            let member = OwnedTarMember {
                path: path.to_vec(),
                kind,
                data: Vec::new(),
                link_target: target,
                mode: 0o644,
                mtime: ArchiveTimestamp::UNIX_EPOCH,
                logical_size: 0,
                reparse_placeholder: false,
                v45_metadata: None,
                diagnostics: Vec::new(),
            };
            restore_tar_member(
                tmp.path(),
                &member,
                SafeExtractionOptions {
                    restore_policy: RestorePolicy::Content,
                    ..SafeExtractionOptions::default()
                },
            )
            .unwrap();
        }

        assert!(!tmp.path().join("symlink-parent").exists());
        assert!(!tmp.path().join("special-parent").exists());
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
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
            diagnostics: Vec::new(),
        };

        assert_eq!(
            restore_tar_member(
                tmp.path(),
                &member,
                SafeExtractionOptions {
                    overwrite_existing: true,
                    ..SafeExtractionOptions::default()
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
            mode: 0o644,
            mtime: ArchiveTimestamp::UNIX_EPOCH,
            logical_size: 0,
            reparse_placeholder: false,
            v45_metadata: None,
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

    fn member_summary(bytes: &[u8], group_start: u64) -> TarStreamMemberSummary {
        let parsed = parse_tar_member_group(bytes, 4096).unwrap();
        TarStreamMemberSummary {
            path: parsed.path,
            kind: parsed.kind,
            link_target: parsed.link_target,
            mode: parsed.mode,
            mtime: parsed.mtime,
            logical_size: parsed.logical_size,
            file_entry_flags: parsed.v45_metadata.file_entry_flags,
            reparse_placeholder: parsed.reparse_placeholder,
            v45_metadata: parsed.v45_metadata,
            diagnostics: parsed.diagnostics,
            group_start,
            group_size: bytes.len() as u64,
        }
    }

    #[test]
    fn member_graph_accepts_hardlink_target_after_alias_and_rejects_mirror_mismatch() {
        let alias_bytes = member(b"alias.txt", b'1', b"", b"target.txt");
        let target_bytes = member(b"target.txt", b'0', b"payload", b"");
        let alias = member_summary(&alias_bytes, 0);
        let target = member_summary(&target_bytes, alias_bytes.len() as u64);
        assert!(validate_v45_member_graph(&[alias.clone(), target.clone()]).is_ok());

        let mut mismatched_alias = alias;
        mismatched_alias.v45_metadata.portable_mirror.mode = 0o600;
        assert_eq!(
            validate_v45_member_graph(&[mismatched_alias, target]).unwrap_err(),
            FormatError::InvalidArchive(
                "hardlink portable metadata mirror differs from canonical target"
            )
        );
    }

    #[test]
    fn member_graph_rejects_writes_below_selected_symlink() {
        let link_bytes = member(b"dir", b'2', b"", b"target");
        let child_bytes = member(b"dir/file.txt", b'0', b"payload", b"");
        let link = member_summary(&link_bytes, 0);
        let child = member_summary(&child_bytes, link_bytes.len() as u64);

        assert_eq!(
            validate_v45_member_graph(&[link, child]).unwrap_err(),
            FormatError::InvalidArchive(
                "selected path graph traverses a symlink or reparse ancestor"
            )
        );
    }

    #[test]
    fn partial_capture_diagnostics_preserve_authenticated_omission_details() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata.declaration.capture_status = CaptureStatus::Partial;
        metadata.capture_report = Some(vec![CaptureReportRow {
            profile: "portable-v1".into(),
            metadata_class: "sparse-layout".into(),
            reason: "changed-during-read".into(),
            encoded_detail: "extent%20map%20changed".into(),
        }]);

        let diagnostics = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();

        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "portable-v1"
                && diagnostic.metadata_class == "sparse-layout"
                && diagnostic.operation == MetadataOperation::Capture
                && diagnostic.status == MetadataDiagnosticStatus::Partial
                && diagnostic.message
                    == "capture omission: changed-during-read; detail=extent%20map%20changed"
        }));
    }

    #[test]
    fn content_restore_reports_portable_mode_and_mtime_as_skipped() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        let diagnostics = plan_restore(
            b"file.txt",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::Content,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();

        for metadata_class in ["mode", "mtime"] {
            assert!(diagnostics.iter().any(|diagnostic| {
                diagnostic.profile == "portable-v1"
                    && diagnostic.metadata_class == metadata_class
                    && diagnostic.status == MetadataDiagnosticStatus::Skipped
                    && diagnostic.restore_policy == Some(RestorePolicy::Content)
            }));
        }
    }

    #[test]
    fn unsupported_required_profile_needs_explicit_degraded_restore() {
        let bytes = member(b"file.txt", b'0', b"payload", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        let mut metadata = parsed.v45_metadata;
        metadata
            .declaration
            .required_profiles
            .push("x.com.example.test-v1".into());
        metadata
            .declaration
            .optional_profiles
            .push("x.com.example.optional-v1".into());

        assert_eq!(
            plan_restore(
                b"file.txt",
                &metadata,
                TarEntryKind::Regular,
                false,
                SafeExtractionOptions::default(),
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "requested restore policy requires an unsupported required profile"
            )
        );
        let diagnostics = plan_restore(
            b"file.txt",
            &metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "x.com.example.test-v1"
                && diagnostic.metadata_class == "required-profile"
                && diagnostic.status == MetadataDiagnosticStatus::Unsupported
        }));
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.profile == "x.com.example.optional-v1"
                && diagnostic.metadata_class == "optional-profile"
                && diagnostic.status == MetadataDiagnosticStatus::Skipped
        }));
    }

    #[test]
    fn portable_directory_metadata_requires_explicit_degraded_restore() {
        let bytes = member(b"dir", b'5', b"", b"");
        let parsed = parse_tar_member_group(&bytes, 4096).unwrap();

        assert_eq!(
            plan_restore(
                b"dir",
                &parsed.v45_metadata,
                TarEntryKind::Directory,
                false,
                SafeExtractionOptions::default(),
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "portable directory/symlink metadata restoration needs explicit degraded restore"
            )
        );
        let diagnostics = plan_restore(
            b"dir",
            &parsed.v45_metadata,
            TarEntryKind::Directory,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(diagnostics.iter().any(|diagnostic| {
            diagnostic.path == b"dir"
                && diagnostic.metadata_class == "mode-and-mtime"
                && diagnostic.operation == MetadataOperation::Plan
                && diagnostic.status == MetadataDiagnosticStatus::Unsupported
                && diagnostic.restore_policy == Some(RestorePolicy::Portable)
                && diagnostic.restore_phase == Some(4)
        }));
    }

    #[test]
    fn sparse_layout_materialization_requires_explicit_degraded_portable_restore() {
        let bytes = member(b"sparse.bin", b'0', b"data", b"");
        let mut parsed = parse_tar_member_group(&bytes, 4096).unwrap();
        parsed.v45_metadata.file_entry_flags |= HAS_SPARSE_EXTENTS;

        assert_eq!(
            plan_restore(
                b"sparse.bin",
                &parsed.v45_metadata,
                TarEntryKind::Regular,
                false,
                SafeExtractionOptions::default(),
            )
            .unwrap_err(),
            FormatError::ReaderUnsupported(
                "sparse layout materialization needs explicit degraded restore"
            )
        );

        let degraded = plan_restore(
            b"sparse.bin",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                allow_degraded: true,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(degraded.iter().any(|diagnostic| {
            diagnostic.metadata_class == "sparse-layout"
                && diagnostic.status == MetadataDiagnosticStatus::Materialized
                && diagnostic.restore_policy == Some(RestorePolicy::Portable)
        }));

        let content = plan_restore(
            b"sparse.bin",
            &parsed.v45_metadata,
            TarEntryKind::Regular,
            false,
            SafeExtractionOptions {
                restore_policy: RestorePolicy::Content,
                ..SafeExtractionOptions::default()
            },
        )
        .unwrap();
        assert!(content.iter().any(|diagnostic| {
            diagnostic.metadata_class == "sparse-layout"
                && diagnostic.restore_policy == Some(RestorePolicy::Content)
        }));
    }
}
