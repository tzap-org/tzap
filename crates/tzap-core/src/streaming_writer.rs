use std::io::{self, ErrorKind, Read};

use crate::crypto::{KdfParams, MasterKey};
use crate::format::{ArchiveWriteError, FormatError};
use crate::metadata::{
    normalize_lookup_file_path, validate_directory_path_bytes, validate_file_path_bytes,
};
use crate::writer::{
    write_single_pass_archive_to_sink, ArchiveWriteSink, MemoryArchiveSink, RootAuthAuthenticator,
    RootAuthWriterConfig, StreamingRegularMember, WriterOptions, WrittenArchive,
    WrittenArchiveSummary,
};

const TAR_BLOCK_LEN: usize = 512;
const MAX_TAR_STDIN_METADATA_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingTarWriterSummary {
    pub archive: WrittenArchiveSummary,
    pub input_member_count: u64,
    pub input_tar_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingRawWriterSummary {
    pub archive: WrittenArchiveSummary,
    pub input_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TarStdinInputSummary {
    regular_file_count: u64,
    skipped_directory_count: u64,
    input_tar_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TarStdinRegularMember {
    path: Vec<u8>,
    mode: u32,
    mtime: u64,
    logical_size: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalTarMetadata {
    pending_header: bool,
    pax_path: Option<Vec<u8>>,
    pax_size: Option<u64>,
    pax_mode: Option<u32>,
    pax_mtime: Option<u64>,
    gnu_long_name: Option<Vec<u8>>,
}

impl LocalTarMetadata {
    fn has_pending(&self) -> bool {
        self.pending_header
            || self.pax_path.is_some()
            || self.pax_size.is_some()
            || self.pax_mode.is_some()
            || self.pax_mtime.is_some()
            || self.gnu_long_name.is_some()
    }
}

pub fn write_tar_stream_archive<R: Read>(
    reader: R,
    master_key: &MasterKey,
    options: WriterOptions,
) -> Result<WrittenArchive, FormatError> {
    let mut sink = MemoryArchiveSink::default();
    let summary = write_tar_stream_archive_to_sink(reader, master_key, options, &mut sink)
        .map_err(format_error_from_archive_write_error)?;
    Ok(WrittenArchive {
        bytes: sink
            .volumes
            .first()
            .cloned()
            .ok_or(FormatError::WriterInvariant("no volumes emitted"))?,
        volumes: sink.volumes,
        bootstrap_sidecar: sink.bootstrap_sidecar,
        archive_uuid: summary.archive.archive_uuid,
        session_id: summary.archive.session_id,
    })
}

pub fn write_tar_stream_archive_to_sink<R, O>(
    reader: R,
    master_key: &MasterKey,
    options: WriterOptions,
    sink: &mut O,
) -> Result<StreamingTarWriterSummary, ArchiveWriteError>
where
    R: Read,
    O: ArchiveWriteSink,
{
    write_tar_stream_archive_to_sink_with_kdf_and_root_auth(
        reader,
        master_key,
        options,
        &KdfParams::Raw,
        None,
        None,
        sink,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth<R, O>(
    mut reader: R,
    archive_path: &str,
    input_size: u64,
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<StreamingRawWriterSummary, ArchiveWriteError>
where
    R: Read,
    O: ArchiveWriteSink,
{
    validate_streaming_create_writer_options(options)?;
    let archive_path = normalize_lookup_file_path(archive_path, options.max_path_length)?;
    let archive = write_single_pass_archive_to_sink(
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        sink,
        |writer| {
            let mut payload = SizedRawPayloadReader {
                reader: &mut reader,
                remaining: input_size,
            };
            writer.write_regular_member_from_reader(
                StreamingRegularMember {
                    archive_path,
                    file_data_size: input_size,
                    mode: 0o644,
                    mtime: 0,
                },
                &mut payload,
            )?;
            if payload.remaining != 0 {
                return Err(FormatError::WriterInvariant(
                    "raw stdin payload was not fully consumed",
                )
                .into());
            }
            reject_trailing_raw_stdin_bytes(&mut reader)?;
            Ok(())
        },
    )?;
    Ok(StreamingRawWriterSummary {
        archive,
        input_bytes: input_size,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn write_tar_stream_archive_to_sink_with_kdf_and_root_auth<R, O>(
    mut reader: R,
    master_key: &MasterKey,
    options: WriterOptions,
    kdf_params: &KdfParams,
    root_auth: Option<RootAuthWriterConfig<'_>>,
    authenticator: Option<&mut RootAuthAuthenticator<'_>>,
    sink: &mut O,
) -> Result<StreamingTarWriterSummary, ArchiveWriteError>
where
    R: Read,
    O: ArchiveWriteSink,
{
    validate_streaming_create_writer_options(options)?;
    let mut input_summary = None;
    let archive = write_single_pass_archive_to_sink(
        master_key,
        options,
        kdf_params,
        root_auth,
        authenticator,
        sink,
        |writer| {
            let summary = stream_tar_stdin_regulars(
                &mut reader,
                options.max_path_length,
                |member, payload| {
                    writer.write_regular_member_from_reader(
                        StreamingRegularMember {
                            archive_path: member.path,
                            file_data_size: member.logical_size,
                            mode: member.mode,
                            mtime: member.mtime,
                        },
                        payload,
                    )
                },
            )?;
            input_summary = Some(summary);
            Ok(())
        },
    )?;
    let input_summary = input_summary.ok_or(FormatError::WriterInvariant(
        "streaming tar parser did not return a summary",
    ))?;
    Ok(StreamingTarWriterSummary {
        archive,
        input_member_count: input_summary.regular_file_count,
        input_tar_bytes: input_summary.input_tar_bytes,
    })
}

fn format_error_from_archive_write_error(error: ArchiveWriteError) -> FormatError {
    match error {
        ArchiveWriteError::Format(error) => error,
        ArchiveWriteError::Io(_) => FormatError::WriterInvariant("in-memory archive writer failed"),
    }
}

fn validate_streaming_create_writer_options(options: WriterOptions) -> Result<(), FormatError> {
    if options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported(
            "streaming create cannot tolerate volume loss",
        ));
    }
    if options.target_volume_size.is_some() {
        return Err(FormatError::WriterUnsupported(
            "streaming create does not support target volume sizing",
        ));
    }
    Ok(())
}

struct SizedRawPayloadReader<'a, R: Read> {
    reader: &'a mut R,
    remaining: u64,
}

impl<R: Read> Read for SizedRawPayloadReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let max_read = out
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        match self.reader.read(&mut out[..max_read]) {
            Ok(read) => {
                self.remaining -= read as u64;
                Ok(read)
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => self.read(out),
            Err(error) => Err(error),
        }
    }
}

fn reject_trailing_raw_stdin_bytes<R: Read>(reader: &mut R) -> Result<(), ArchiveWriteError> {
    let mut extra = [0u8; 1];
    loop {
        match reader.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(
                    FormatError::InvalidArchive("raw stdin exceeds declared --stdin-size").into(),
                )
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(ArchiveWriteError::Io(error)),
        }
    }
}

fn stream_tar_stdin_regulars<R, F>(
    reader: &mut R,
    max_path_length: u32,
    mut on_regular: F,
) -> Result<TarStdinInputSummary, ArchiveWriteError>
where
    R: Read,
    F: for<'a> FnMut(
        TarStdinRegularMember,
        &mut LimitedTarPayloadReader<'a, R>,
    ) -> Result<(), ArchiveWriteError>,
{
    let mut summary = TarStdinInputSummary::default();
    let mut metadata = LocalTarMetadata::default();

    loop {
        let Some(header) = read_tar_block(reader, &mut summary.input_tar_bytes)? else {
            if metadata.has_pending() {
                return Err(
                    FormatError::InvalidArchive("tar stream ended after metadata header").into(),
                );
            }
            return Ok(summary);
        };
        if header.iter().all(|byte| *byte == 0) {
            if metadata.has_pending() {
                return Err(
                    FormatError::InvalidArchive("tar stream ended after metadata header").into(),
                );
            }
            let second = read_tar_block(reader, &mut summary.input_tar_bytes)?.ok_or(
                FormatError::InvalidArchive("tar stream ended inside end-of-archive marker"),
            )?;
            if second.iter().any(|byte| *byte != 0) {
                return Err(FormatError::InvalidArchive(
                    "tar stream has non-zero bytes after end-of-archive marker",
                )
                .into());
            }
            drain_zero_blocks_to_eof(reader, &mut summary.input_tar_bytes)?;
            return Ok(summary);
        }

        verify_tar_checksum(&header)?;
        let typeflag = header[156];
        let header_size = parse_tar_number(&header[124..136])?;
        match typeflag {
            b'x' => {
                let payload =
                    read_metadata_payload(reader, header_size, &mut summary.input_tar_bytes)?;
                metadata.pending_header = true;
                parse_pax_records(&payload, &mut metadata)?;
            }
            b'L' => {
                let payload =
                    read_metadata_payload(reader, header_size, &mut summary.input_tar_bytes)?;
                metadata.pending_header = true;
                metadata.gnu_long_name = Some(trimmed_metadata_payload(&payload));
            }
            b'K' => {
                let _payload =
                    read_metadata_payload(reader, header_size, &mut summary.input_tar_bytes)?;
                metadata.pending_header = true;
            }
            b'g' => {
                return Err(
                    FormatError::InvalidArchive("global PAX headers are not allowed").into(),
                )
            }
            b'V' | b'M' | b'N' => {
                return Err(
                    FormatError::InvalidArchive("global GNU headers are not allowed").into(),
                )
            }
            b'S' => {
                return Err(
                    FormatError::ReaderUnsupported("unsupported GNU sparse tar entry").into(),
                )
            }
            0 | b'0' | b'5' | b'1' | b'2' | b'3' | b'4' | b'6' => {
                let effective_size = metadata.pax_size.unwrap_or(header_size);
                let mode = metadata
                    .pax_mode
                    .unwrap_or(parse_tar_number(&header[100..108])? as u32);
                let mtime = metadata
                    .pax_mtime
                    .unwrap_or(parse_tar_number(&header[136..148])?);
                let path = canonical_main_path(&header, typeflag, &metadata, max_path_length)?;
                metadata = LocalTarMetadata::default();

                match typeflag {
                    0 | b'0' => {
                        let member = TarStdinRegularMember {
                            path,
                            mode,
                            mtime,
                            logical_size: effective_size,
                        };
                        {
                            let mut payload = LimitedTarPayloadReader {
                                reader,
                                remaining: effective_size,
                                input_tar_bytes: &mut summary.input_tar_bytes,
                            };
                            on_regular(member, &mut payload)?;
                            if payload.remaining != 0 {
                                return Err(FormatError::WriterInvariant(
                                    "streaming tar payload was not fully consumed",
                                )
                                .into());
                            }
                        }
                        drain_tar_padding(
                            reader,
                            padding_to_512_u64(effective_size),
                            &mut summary.input_tar_bytes,
                        )?;
                        summary.regular_file_count = checked_input_add(
                            summary.regular_file_count,
                            1,
                            "tar regular file count",
                        )?;
                    }
                    b'5' => {
                        if effective_size != 0 {
                            return Err(FormatError::InvalidArchive(
                                "non-regular tar entry has non-zero payload size",
                            )
                            .into());
                        }
                        summary.skipped_directory_count = checked_input_add(
                            summary.skipped_directory_count,
                            1,
                            "tar directory count",
                        )?;
                    }
                    _ => {
                        return Err(FormatError::WriterUnsupported(
                            "streaming tar stdin supports regular files and directory entries only",
                        )
                        .into())
                    }
                }
            }
            _ => return Err(FormatError::ReaderUnsupported("unsupported tar entry type").into()),
        }
    }
}

struct LimitedTarPayloadReader<'a, R: Read> {
    reader: &'a mut R,
    remaining: u64,
    input_tar_bytes: &'a mut u64,
}

impl<R: Read> Read for LimitedTarPayloadReader<'_, R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.remaining == 0 {
            return Ok(0);
        }
        let max_read = out
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        match self.reader.read(&mut out[..max_read]) {
            Ok(0) => Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "tar stream ended inside member payload",
            )),
            Ok(read) => {
                self.remaining -= read as u64;
                *self.input_tar_bytes =
                    checked_input_add(*self.input_tar_bytes, read as u64, "tar input size")
                        .map_err(io_error_from_format)?;
                Ok(read)
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => self.read(out),
            Err(error) => Err(error),
        }
    }
}

fn read_tar_block<R: Read>(
    reader: &mut R,
    input_tar_bytes: &mut u64,
) -> Result<Option<[u8; TAR_BLOCK_LEN]>, ArchiveWriteError> {
    let mut block = [0u8; TAR_BLOCK_LEN];
    let mut filled = 0usize;
    while filled < TAR_BLOCK_LEN {
        match reader.read(&mut block[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(
                    FormatError::InvalidArchive("tar stream ended inside member group").into(),
                )
            }
            Ok(read) => {
                filled += read;
                *input_tar_bytes =
                    checked_input_add(*input_tar_bytes, read as u64, "tar input size")?;
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(ArchiveWriteError::Io(error)),
        }
    }
    Ok(Some(block))
}

fn read_metadata_payload<R: Read>(
    reader: &mut R,
    size: u64,
    input_tar_bytes: &mut u64,
) -> Result<Vec<u8>, ArchiveWriteError> {
    let len = usize::try_from(size)
        .map_err(|_| FormatError::ReaderUnsupported("tar metadata payload is too large"))?;
    if len > MAX_TAR_STDIN_METADATA_PAYLOAD_BYTES {
        return Err(
            FormatError::ReaderUnsupported("tar metadata payload exceeds streaming cap").into(),
        );
    }
    let mut payload = vec![0u8; len];
    read_exact_counted(reader, &mut payload, input_tar_bytes)?;
    drain_tar_padding(reader, padding_to_512_u64(size), input_tar_bytes)?;
    Ok(payload)
}

fn read_exact_counted<R: Read>(
    reader: &mut R,
    mut out: &mut [u8],
    input_tar_bytes: &mut u64,
) -> Result<(), ArchiveWriteError> {
    while !out.is_empty() {
        match reader.read(out) {
            Ok(0) => {
                return Err(
                    FormatError::InvalidArchive("tar stream ended inside member group").into(),
                )
            }
            Ok(read) => {
                *input_tar_bytes =
                    checked_input_add(*input_tar_bytes, read as u64, "tar input size")?;
                let remaining = out;
                out = &mut remaining[read..];
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(ArchiveWriteError::Io(error)),
        }
    }
    Ok(())
}

fn drain_tar_padding<R: Read>(
    reader: &mut R,
    padding: u64,
    input_tar_bytes: &mut u64,
) -> Result<(), ArchiveWriteError> {
    let mut remaining = padding;
    let mut buf = [0u8; TAR_BLOCK_LEN];
    while remaining > 0 {
        let take = buf
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        read_exact_counted(reader, &mut buf[..take], input_tar_bytes)?;
        if buf[..take].iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive("tar member padding is non-zero").into());
        }
        remaining -= take as u64;
    }
    Ok(())
}

fn drain_zero_blocks_to_eof<R: Read>(
    reader: &mut R,
    input_tar_bytes: &mut u64,
) -> Result<(), ArchiveWriteError> {
    while let Some(block) = read_tar_block(reader, input_tar_bytes)? {
        if block.iter().any(|byte| *byte != 0) {
            return Err(FormatError::InvalidArchive(
                "tar stream has non-zero bytes after end-of-archive marker",
            )
            .into());
        }
    }
    Ok(())
}

fn canonical_main_path(
    header: &[u8],
    typeflag: u8,
    metadata: &LocalTarMetadata,
    max_path_length: u32,
) -> Result<Vec<u8>, FormatError> {
    let mut path = metadata
        .pax_path
        .clone()
        .or_else(|| metadata.gnu_long_name.clone())
        .unwrap_or_else(|| ustar_path(header));
    while path.starts_with(b"./") {
        path.drain(..2);
    }
    if typeflag == b'5' && path.ends_with(b"/") && !path.ends_with(b"//") {
        path.pop();
    }
    if typeflag == b'5' {
        validate_directory_path_bytes(&path, max_path_length)?;
    } else {
        validate_file_path_bytes(&path, max_path_length)?;
    }
    Ok(path)
}

fn ustar_path(header: &[u8]) -> Vec<u8> {
    let name = nul_trimmed(&header[0..100]);
    let prefix = nul_trimmed(&header[345..500]);
    if prefix.is_empty() {
        return name.to_vec();
    }
    let mut path = Vec::with_capacity(prefix.len() + 1 + name.len());
    path.extend_from_slice(prefix);
    path.push(b'/');
    path.extend_from_slice(name);
    path
}

fn parse_pax_records(payload: &[u8], metadata: &mut LocalTarMetadata) -> Result<(), FormatError> {
    let mut cursor = 0usize;
    while cursor < payload.len() {
        let len_digits_start = cursor;
        while cursor < payload.len() && payload[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == len_digits_start || cursor >= payload.len() || payload[cursor] != b' ' {
            return Err(FormatError::InvalidArchive("malformed PAX record"));
        }
        let len = parse_decimal_usize(&payload[len_digits_start..cursor])?;
        let record_start = len_digits_start;
        let record_end = record_start
            .checked_add(len)
            .ok_or(FormatError::InvalidArchive("malformed PAX record"))?;
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
            "size" => metadata.pax_size = Some(parse_decimal_u64(value)?),
            "mode" => {
                metadata.pax_mode = Some(
                    u32::try_from(parse_decimal_u64(value)?)
                        .map_err(|_| FormatError::WriterUnsupported("tar mode overflow"))?,
                )
            }
            "mtime" => metadata.pax_mtime = Some(parse_pax_mtime(value)?),
            key if key.starts_with("GNU.sparse.") => {
                return Err(FormatError::ReaderUnsupported(
                    "unsupported GNU sparse tar entry",
                ))
            }
            _ => {}
        }
        cursor = record_end;
    }
    Ok(())
}

fn verify_tar_checksum(header: &[u8]) -> Result<(), FormatError> {
    let expected = parse_tar_number(&header[148..156])?;
    let actual = header[..148]
        .iter()
        .chain(header[156..].iter())
        .fold(8u64 * 32, |sum, byte| sum + u64::from(*byte));
    if actual != expected {
        return Err(FormatError::InvalidArchive("tar header checksum mismatch"));
    }
    Ok(())
}

fn parse_tar_number(field: &[u8]) -> Result<u64, FormatError> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return parse_tar_base256(field);
    }
    parse_tar_octal(field)
}

fn parse_tar_base256(field: &[u8]) -> Result<u64, FormatError> {
    let Some(first) = field.first() else {
        return Err(FormatError::InvalidArchive("empty tar numeric field"));
    };
    if first & 0x40 != 0 {
        return Err(FormatError::ReaderUnsupported(
            "negative tar base-256 numeric fields are not supported",
        ));
    }
    let mut value = u128::from(first & 0x7f);
    for byte in &field[1..] {
        value = value
            .checked_mul(256)
            .and_then(|current| current.checked_add(u128::from(*byte)))
            .ok_or(FormatError::InvalidArchive("tar base-256 field overflow"))?;
    }
    u64::try_from(value).map_err(|_| FormatError::ReaderUnsupported("tar numeric field too large"))
}

fn parse_tar_octal(field: &[u8]) -> Result<u64, FormatError> {
    let field = field
        .split(|byte| *byte == 0)
        .next()
        .unwrap_or(field)
        .iter()
        .copied()
        .skip_while(|byte| *byte == b' ' || *byte == b'0')
        .take_while(|byte| *byte != b' ')
        .collect::<Vec<_>>();
    if field.is_empty() {
        return Ok(0);
    }
    let mut value = 0u64;
    for byte in field {
        if !(b'0'..=b'7').contains(&byte) {
            return Err(FormatError::InvalidArchive("invalid tar octal field"));
        }
        value = value
            .checked_mul(8)
            .and_then(|current| current.checked_add(u64::from(byte - b'0')))
            .ok_or(FormatError::InvalidArchive("tar octal field overflow"))?;
    }
    Ok(value)
}

fn parse_decimal_usize(bytes: &[u8]) -> Result<usize, FormatError> {
    usize::try_from(parse_decimal_u64(bytes)?)
        .map_err(|_| FormatError::InvalidArchive("decimal field overflow"))
}

fn parse_decimal_u64(bytes: &[u8]) -> Result<u64, FormatError> {
    if bytes.is_empty() {
        return Err(FormatError::InvalidArchive("malformed decimal field"));
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(FormatError::InvalidArchive("malformed decimal field"));
        }
        value = value
            .checked_mul(10)
            .and_then(|current| current.checked_add(u64::from(byte - b'0')))
            .ok_or(FormatError::InvalidArchive("decimal field overflow"))?;
    }
    Ok(value)
}

fn parse_pax_mtime(bytes: &[u8]) -> Result<u64, FormatError> {
    let whole = bytes.split(|byte| *byte == b'.').next().unwrap_or(bytes);
    parse_decimal_u64(whole)
}

fn trimmed_metadata_payload(payload: &[u8]) -> Vec<u8> {
    let mut end = payload.len();
    while end > 0 && payload[end - 1] == 0 {
        end -= 1;
    }
    payload[..end].to_vec()
}

fn nul_trimmed(bytes: &[u8]) -> &[u8] {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    &bytes[..end]
}

fn padding_to_512_u64(len: u64) -> u64 {
    let remainder = len % TAR_BLOCK_LEN as u64;
    if remainder == 0 {
        0
    } else {
        TAR_BLOCK_LEN as u64 - remainder
    }
}

fn checked_input_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, FormatError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::WriterUnsupported(field))
}

fn io_error_from_format(error: FormatError) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::crypto::MasterKey;
    use crate::format::{FormatError, BLOCK_RECORD_FRAMING_LEN, MASTER_KEY_LEN, VOLUME_HEADER_LEN};
    use crate::reader::{open_archive, open_archive_volumes};
    use crate::root_auth::data_block_merkle_leaf_hash;
    use crate::wire::{BlockRecord, CryptoHeader, VolumeHeader};
    use crate::writer::{write_archive, RegularFile};

    use super::*;

    fn master_key() -> MasterKey {
        MasterKey::from_raw_key(&[0x31; MASTER_KEY_LEN]).unwrap()
    }

    fn options() -> WriterOptions {
        WriterOptions {
            archive_uuid: Some([0x41; 16]),
            session_id: Some([0x42; 16]),
            closed_at_ns: 987_654_321,
            stripe_width: 1,
            volume_loss_tolerance: 0,
            bit_rot_buffer_pct: 0,
            index_root_fec_parity_shards: 0,
            ..WriterOptions::default()
        }
    }

    fn single_pass_equivalence_options() -> WriterOptions {
        WriterOptions {
            // The single-pass writer must commit the CryptoHeader before stdin is
            // consumed, so it predeclares the largest supported IndexRoot class.
            // Compare byte identity against the legacy writer with that same
            // declared class, not against the legacy default that can be raised
            // after payload planning.
            index_root_fec_data_shards: u16::MAX,
            ..options()
        }
    }

    fn multi_volume_options(stripe_width: u32) -> WriterOptions {
        WriterOptions {
            stripe_width,
            volume_loss_tolerance: 0,
            ..options()
        }
    }

    fn tar_stream(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for (path, data) in entries {
            out.extend_from_slice(&tar_header(path.as_bytes(), b'0', data.len() as u64));
            out.extend_from_slice(data);
            out.resize(out.len() + padding_to_512(data.len()), 0);
        }
        out.extend_from_slice(&[0u8; TAR_BLOCK_LEN * 2]);
        out
    }

    fn tar_header(path: &[u8], kind: u8, size: u64) -> [u8; TAR_BLOCK_LEN] {
        let mut header = [0u8; TAR_BLOCK_LEN];
        header[..path.len()].copy_from_slice(path);
        write_octal(&mut header[100..108], 0o644);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], size);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);
        header
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

    fn write_base256(field: &mut [u8], value: u64) {
        field.fill(0);
        let mut value = value;
        for byte in field.iter_mut().rev() {
            *byte = (value & 0xff) as u8;
            value >>= 8;
        }
        field[0] |= 0x80;
    }

    fn padding_to_512(len: usize) -> usize {
        let remainder = len % TAR_BLOCK_LEN;
        if remainder == 0 {
            0
        } else {
            TAR_BLOCK_LEN - remainder
        }
    }

    fn data_leaf_hash_sequence(bytes: &[u8]) -> Vec<(u64, [u8; 32])> {
        let volume_header = VolumeHeader::parse(&bytes[..VOLUME_HEADER_LEN]).unwrap();
        let crypto_start = volume_header.crypto_header_offset as usize;
        let crypto_end = crypto_start + volume_header.crypto_header_length as usize;
        let crypto_header = CryptoHeader::parse(
            &bytes[crypto_start..crypto_end],
            volume_header.crypto_header_length,
        )
        .unwrap();
        let block_size = crypto_header.fixed.block_size as usize;
        let record_len = block_size + BLOCK_RECORD_FRAMING_LEN;
        let mut offset = crypto_end;
        let mut hashes = Vec::new();
        while bytes.get(offset..offset + 4) == Some(b"TZBK") {
            let record =
                BlockRecord::parse(&bytes[offset..offset + record_len], block_size).unwrap();
            if record.kind.is_data() {
                hashes.push((
                    record.block_index,
                    data_block_merkle_leaf_hash(
                        record.block_index,
                        record.kind,
                        record.flags,
                        &record.payload,
                    ),
                ));
            }
            offset += record_len;
        }
        hashes
    }

    struct TinyReadCursor {
        data: Vec<u8>,
        cursor: usize,
        max_chunk: usize,
        reads: usize,
    }

    impl TinyReadCursor {
        fn new(data: Vec<u8>, max_chunk: usize) -> Self {
            Self {
                data,
                cursor: 0,
                max_chunk,
                reads: 0,
            }
        }
    }

    impl Read for TinyReadCursor {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            if self.cursor >= self.data.len() {
                return Ok(0);
            }
            let len = self
                .max_chunk
                .min(buf.len())
                .min(self.data.len() - self.cursor);
            buf[..len].copy_from_slice(&self.data[self.cursor..self.cursor + len]);
            self.cursor += len;
            Ok(len)
        }
    }

    #[test]
    fn tar_stdin_single_volume_round_trips_list_verify_and_extract() {
        let input = tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.txt", b"beta payload".as_slice()),
        ]);
        let mut reader = TinyReadCursor::new(input, 17);

        let archive = write_tar_stream_archive(&mut reader, &master_key(), options()).unwrap();

        assert!(reader.reads > 10);
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();
        opened.verify().unwrap();
        let listed = opened
            .list_files()
            .unwrap()
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        assert_eq!(listed, vec!["alpha.txt", "dir/beta.txt"]);
        assert_eq!(
            opened.extract_file("dir/beta.txt").unwrap(),
            Some(b"beta payload".to_vec())
        );
    }

    #[test]
    fn sized_raw_stdin_round_trips_as_regular_tar_member_archive() {
        let input = b"raw bytes from stdin";
        let mut sink = MemoryArchiveSink::default();

        let summary = write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth(
            input.as_slice(),
            "raw/data.bin",
            input.len() as u64,
            &master_key(),
            options(),
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.input_bytes, input.len() as u64);
        let opened = open_archive(&sink.volumes[0], &master_key()).unwrap();
        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("raw/data.bin").unwrap(),
            Some(input.to_vec())
        );
    }

    #[test]
    fn sized_raw_stdin_known_size_multi_volume_round_trips() {
        let input = (0..150_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut sink = MemoryArchiveSink::default();

        let summary = write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth(
            input.as_slice(),
            "raw/data.bin",
            input.len() as u64,
            &master_key(),
            multi_volume_options(3),
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap();

        assert_eq!(summary.archive.volume_count, 3);
        assert_eq!(sink.volumes.len(), 3);
        let refs = sink.volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&refs, &master_key()).unwrap();
        opened.verify().unwrap();
        assert_eq!(
            opened.extract_file("raw/data.bin").unwrap(),
            Some(input.to_vec())
        );
    }

    #[test]
    fn sized_raw_stdin_rejects_short_input() {
        let mut sink = MemoryArchiveSink::default();

        let error = write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth(
            b"short".as_slice(),
            "raw/data.bin",
            6,
            &master_key(),
            options(),
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap_err();

        assert!(matches!(error, ArchiveWriteError::Io(_)));
    }

    #[test]
    fn sized_raw_stdin_rejects_trailing_input() {
        let mut sink = MemoryArchiveSink::default();

        let error = write_sized_raw_member_archive_to_sink_with_kdf_and_root_auth(
            b"toolong".as_slice(),
            "raw/data.bin",
            3,
            &master_key(),
            options(),
            &KdfParams::Raw,
            None,
            None,
            &mut sink,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ArchiveWriteError::Format(FormatError::InvalidArchive(
                "raw stdin exceeds declared --stdin-size"
            ))
        ));
    }

    #[test]
    fn tar_stdin_sink_summary_reports_input_not_output_tar_size() {
        let input = tar_stream(&[("one.txt", b"one".as_slice())]);
        let mut sink = MemoryArchiveSink::default();

        let summary =
            write_tar_stream_archive_to_sink(&input[..], &master_key(), options(), &mut sink)
                .unwrap();

        assert_eq!(summary.input_member_count, 1);
        assert_eq!(summary.input_tar_bytes, input.len() as u64);
        assert_eq!(summary.archive.volume_count, 1);
        assert_eq!(sink.volumes.len(), 1);
        open_archive(&sink.volumes[0], &master_key())
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn tar_stdin_large_single_volume_round_trips() {
        let beta = (0..150_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let input = tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.bin", beta.as_slice()),
        ]);

        let archive = write_tar_stream_archive(&input[..], &master_key(), options()).unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        opened.verify().unwrap();
        assert_eq!(opened.extract_file("dir/beta.bin").unwrap(), Some(beta));
    }

    #[test]
    fn tar_stdin_multi_volume_round_trips_list_verify_and_extract() {
        let beta = (0..150_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let input = tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.bin", beta.as_slice()),
        ]);
        let mut reader = TinyReadCursor::new(input, 31);
        let mut sink = MemoryArchiveSink::default();

        let summary = write_tar_stream_archive_to_sink(
            &mut reader,
            &master_key(),
            multi_volume_options(4),
            &mut sink,
        )
        .unwrap();

        assert!(reader.reads > 10);
        assert_eq!(summary.input_member_count, 2);
        assert_eq!(summary.archive.volume_count, 4);
        assert_eq!(sink.volumes.len(), 4);
        let refs = sink.volumes.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let opened = open_archive_volumes(&refs, &master_key()).unwrap();
        assert_eq!(
            opened.extract_file("alpha.txt").unwrap(),
            Some(b"alpha payload".to_vec())
        );
        assert_eq!(
            opened.extract_file("dir/beta.bin").unwrap(),
            Some(beta.clone())
        );
        opened.verify().unwrap();
        let listed = opened
            .list_files()
            .unwrap()
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        assert_eq!(listed, vec!["alpha.txt", "dir/beta.bin"]);
    }

    #[test]
    fn tar_stdin_emits_identical_bytes_to_file_list_create_with_streaming_metadata_class() {
        let input = tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.txt", b"beta payload".as_slice()),
        ]);
        let options = single_pass_equivalence_options();

        let streaming = write_tar_stream_archive(&input[..], &master_key(), options).unwrap();
        let legacy = write_archive(
            &[
                RegularFile::new("alpha.txt", b"alpha payload"),
                RegularFile::new("dir/beta.txt", b"beta payload"),
            ],
            &master_key(),
            options,
        )
        .unwrap();

        assert_eq!(streaming.bytes, legacy.bytes);
        assert_eq!(streaming.bootstrap_sidecar, legacy.bootstrap_sidecar);
    }

    #[test]
    fn tar_stdin_data_leaf_hashes_match_file_list_writer_sequence() {
        let input = tar_stream(&[
            ("alpha.txt", b"alpha payload".as_slice()),
            ("dir/beta.txt", b"beta payload".as_slice()),
        ]);
        let options = single_pass_equivalence_options();

        let streaming = write_tar_stream_archive(&input[..], &master_key(), options).unwrap();
        let legacy = write_archive(
            &[
                RegularFile::new("alpha.txt", b"alpha payload"),
                RegularFile::new("dir/beta.txt", b"beta payload"),
            ],
            &master_key(),
            options,
        )
        .unwrap();

        assert_eq!(
            data_leaf_hash_sequence(&streaming.bytes),
            data_leaf_hash_sequence(&legacy.bytes)
        );
    }

    #[test]
    fn tar_stdin_empty_stream_accepts_two_zero_eof_blocks() {
        let input = vec![0u8; TAR_BLOCK_LEN * 2];
        let mut sink = MemoryArchiveSink::default();

        let summary =
            write_tar_stream_archive_to_sink(&input[..], &master_key(), options(), &mut sink)
                .unwrap();

        assert_eq!(summary.input_member_count, 0);
        assert_eq!(summary.input_tar_bytes, input.len() as u64);
        let opened = open_archive(&sink.volumes[0], &master_key()).unwrap();
        opened.verify().unwrap();
        assert!(opened.list_files().unwrap().is_empty());
    }

    #[test]
    fn tar_stdin_accepts_base256_numeric_size_fields() {
        let mut header = tar_header(b"large-format.txt", b'0', 0);
        write_base256(&mut header[124..136], 4);
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        write_checksum(&mut header[148..156], checksum);
        let mut input = Vec::new();
        input.extend_from_slice(&header);
        input.extend_from_slice(b"data");
        input.resize(input.len() + padding_to_512(4), 0);
        input.extend_from_slice(&[0u8; TAR_BLOCK_LEN * 2]);

        let archive = write_tar_stream_archive(&input[..], &master_key(), options()).unwrap();
        let opened = open_archive(&archive.bytes, &master_key()).unwrap();

        assert_eq!(
            opened.extract_file("large-format.txt").unwrap(),
            Some(b"data".to_vec())
        );
    }

    #[test]
    fn tar_stdin_rejects_metadata_header_without_following_member() {
        let payload = b"13 comment=x\n";
        let mut input = Vec::new();
        input.extend_from_slice(&tar_header(
            b"PaxHeaders/unused",
            b'x',
            payload.len() as u64,
        ));
        input.extend_from_slice(payload);
        input.resize(input.len() + padding_to_512(payload.len()), 0);
        input.extend_from_slice(&[0u8; TAR_BLOCK_LEN * 2]);

        let error = write_tar_stream_archive(&input[..], &master_key(), options()).unwrap_err();

        assert_eq!(
            error,
            FormatError::InvalidArchive("tar stream ended after metadata header")
        );
    }

    #[test]
    fn tar_stdin_skips_directory_entries_and_keeps_regular_children() {
        let mut input = Vec::new();
        input.extend_from_slice(&tar_header(b"dir/", b'5', 0));
        input.extend_from_slice(&tar_header(b"dir/file.txt", b'0', 4));
        input.extend_from_slice(b"data");
        input.resize(input.len() + padding_to_512(4), 0);
        input.extend_from_slice(&[0u8; TAR_BLOCK_LEN * 2]);
        let mut sink = MemoryArchiveSink::default();

        let summary =
            write_tar_stream_archive_to_sink(&input[..], &master_key(), options(), &mut sink)
                .unwrap();

        assert_eq!(summary.input_member_count, 1);
        let opened = open_archive(&sink.volumes[0], &master_key()).unwrap();
        assert_eq!(
            opened
                .list_files()
                .unwrap()
                .into_iter()
                .map(|entry| entry.path)
                .collect::<Vec<_>>(),
            vec!["dir/file.txt"]
        );
    }

    #[test]
    fn tar_stdin_rejects_unsupported_symlink_entries() {
        let mut input = Vec::new();
        input.extend_from_slice(&tar_header(b"link", b'2', 0));
        input.extend_from_slice(&[0u8; TAR_BLOCK_LEN * 2]);
        let mut sink = MemoryArchiveSink::default();

        let error =
            write_tar_stream_archive_to_sink(&input[..], &master_key(), options(), &mut sink)
                .unwrap_err();

        match error {
            ArchiveWriteError::Format(error) => assert_eq!(
                error,
                FormatError::WriterUnsupported(
                    "streaming tar stdin supports regular files and directory entries only"
                )
            ),
            ArchiveWriteError::Io(error) => panic!("unexpected I/O error: {error}"),
        }
        assert!(!sink.volumes.is_empty());
    }

    #[test]
    fn tar_stdin_rejects_volume_loss_tolerance() {
        let mut bad = options();
        bad.volume_loss_tolerance = 1;

        let error = write_tar_stream_archive(
            &tar_stream(&[("x", b"x".as_slice())])[..],
            &master_key(),
            bad,
        )
        .unwrap_err();

        assert_eq!(
            error,
            FormatError::WriterUnsupported("streaming create cannot tolerate volume loss")
        );
    }
}
