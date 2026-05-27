use std::io::{Cursor, ErrorKind, Read};

use crate::crypto::{KdfParams, MasterKey};
use crate::format::{ArchiveWriteError, FormatError};
use crate::tar_model::{parse_tar_member_group, try_tar_member_group_end, TarEntryKind};
use crate::writer::{
    write_archive_sources_to_sink, ArchiveWriteSink, MemoryArchiveSink, RegularFileSource,
    WriterOptions, WrittenArchive, WrittenArchiveSummary,
};

const TAR_BLOCK_LEN: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingTarWriterSummary {
    pub archive: WrittenArchiveSummary,
    pub input_member_count: u64,
    pub input_tar_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BufferedRegularTarMember {
    path: String,
    data: Vec<u8>,
    mode: u32,
    mtime: u64,
}

impl RegularFileSource for BufferedRegularTarMember {
    fn archive_path(&self) -> &str {
        &self.path
    }

    fn file_data_size(&self) -> u64 {
        self.data.len() as u64
    }

    fn mode(&self) -> u32 {
        self.mode
    }

    fn mtime(&self) -> u64 {
        self.mtime
    }

    fn open(&self) -> Result<Box<dyn Read + '_>, ArchiveWriteError> {
        Ok(Box::new(Cursor::new(&self.data)))
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
    mut reader: R,
    master_key: &MasterKey,
    options: WriterOptions,
    sink: &mut O,
) -> Result<StreamingTarWriterSummary, ArchiveWriteError>
where
    R: Read,
    O: ArchiveWriteSink,
{
    validate_streaming_tar_writer_options(options)?;
    let parsed = read_regular_tar_members(&mut reader, options.max_path_length)?;
    let archive = write_archive_sources_to_sink(
        &parsed.members,
        master_key,
        options,
        None,
        &KdfParams::Raw,
        None,
        None,
        sink,
    )?;
    Ok(StreamingTarWriterSummary {
        archive,
        input_member_count: parsed.members.len() as u64,
        input_tar_bytes: parsed.input_tar_bytes,
    })
}

fn format_error_from_archive_write_error(error: ArchiveWriteError) -> FormatError {
    match error {
        ArchiveWriteError::Format(error) => error,
        ArchiveWriteError::Io(_) => FormatError::WriterInvariant("in-memory archive writer failed"),
    }
}

fn validate_streaming_tar_writer_options(options: WriterOptions) -> Result<(), FormatError> {
    if options.stripe_width != 1 {
        return Err(FormatError::WriterUnsupported(
            "streaming tar stdin is single-volume only",
        ));
    }
    if options.volume_loss_tolerance != 0 {
        return Err(FormatError::WriterUnsupported(
            "streaming tar stdin cannot tolerate volume loss",
        ));
    }
    if options.target_volume_size.is_some() {
        return Err(FormatError::WriterUnsupported(
            "streaming tar stdin does not support target volume sizing",
        ));
    }
    Ok(())
}

struct ParsedRegularTarStream {
    members: Vec<BufferedRegularTarMember>,
    input_tar_bytes: u64,
}

fn read_regular_tar_members<R: Read>(
    reader: &mut R,
    max_path_length: u32,
) -> Result<ParsedRegularTarStream, ArchiveWriteError> {
    let mut members = Vec::new();
    let mut input_tar_bytes = 0u64;
    let mut saw_eof_marker = false;

    while let Some(block) = read_tar_block(reader)? {
        input_tar_bytes = checked_input_add(input_tar_bytes, TAR_BLOCK_LEN as u64)?;
        if block.iter().all(|byte| *byte == 0) {
            saw_eof_marker = true;
            continue;
        }
        if saw_eof_marker {
            return Err(FormatError::InvalidArchive(
                "tar stream has non-zero bytes after end-of-archive marker",
            )
            .into());
        }

        let mut group = block.to_vec();
        loop {
            if let Some(group_end) = try_tar_member_group_end(&group, 0)? {
                if group_end != group.len() {
                    return Err(
                        FormatError::WriterInvariant("tar group parser over-read input").into(),
                    );
                }
                let member = parse_tar_member_group(&group, max_path_length)?;
                if member.kind != TarEntryKind::Regular {
                    return Err(FormatError::WriterUnsupported(
                        "streaming tar stdin currently supports regular files only",
                    )
                    .into());
                }
                let path = String::from_utf8(member.path)
                    .map_err(|_| FormatError::WriterInvariant("validated tar path is not UTF-8"))?;
                members.push(BufferedRegularTarMember {
                    path,
                    data: member.data.to_vec(),
                    mode: member.mode,
                    mtime: member.mtime,
                });
                break;
            }

            let next = read_tar_block(reader)?.ok_or(FormatError::InvalidArchive(
                "tar stream ended inside member group",
            ))?;
            input_tar_bytes = checked_input_add(input_tar_bytes, TAR_BLOCK_LEN as u64)?;
            group.extend_from_slice(&next);
        }
    }

    Ok(ParsedRegularTarStream {
        members,
        input_tar_bytes,
    })
}

fn read_tar_block<R: Read>(
    reader: &mut R,
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
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(ArchiveWriteError::Io(error)),
        }
    }
    Ok(Some(block))
}

fn checked_input_add(lhs: u64, rhs: u64) -> Result<u64, ArchiveWriteError> {
    lhs.checked_add(rhs)
        .ok_or(FormatError::WriterUnsupported("tar input size overflow").into())
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::crypto::MasterKey;
    use crate::format::{FormatError, MASTER_KEY_LEN};
    use crate::reader::open_archive;

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
            ..WriterOptions::default()
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

    fn padding_to_512(len: usize) -> usize {
        let remainder = len % TAR_BLOCK_LEN;
        if remainder == 0 {
            0
        } else {
            TAR_BLOCK_LEN - remainder
        }
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
    fn tar_stdin_rejects_unsupported_directory_entries_before_writing_archive() {
        let mut input = Vec::new();
        input.extend_from_slice(&tar_header(b"dir", b'5', 0));
        input.extend_from_slice(&[0u8; TAR_BLOCK_LEN * 2]);
        let mut sink = MemoryArchiveSink::default();

        let error =
            write_tar_stream_archive_to_sink(&input[..], &master_key(), options(), &mut sink)
                .unwrap_err();

        match error {
            ArchiveWriteError::Format(error) => assert_eq!(
                error,
                FormatError::WriterUnsupported(
                    "streaming tar stdin currently supports regular files only"
                )
            ),
            ArchiveWriteError::Io(error) => panic!("unexpected I/O error: {error}"),
        }
        assert!(sink.volumes.is_empty());
    }

    #[test]
    fn tar_stdin_rejects_multi_volume_options() {
        let mut bad = options();
        bad.stripe_width = 2;

        let error = write_tar_stream_archive(
            &tar_stream(&[("x", b"x".as_slice())])[..],
            &master_key(),
            bad,
        )
        .unwrap_err();

        assert_eq!(
            error,
            FormatError::WriterUnsupported("streaming tar stdin is single-volume only")
        );
    }
}
