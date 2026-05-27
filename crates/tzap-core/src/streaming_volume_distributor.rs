use crate::format::{ArchiveWriteError, FormatError};
use crate::wire::BlockRecord;
use crate::writer::ArchiveWriteSink;

impl<T> ArchiveWriteSink for &mut T
where
    T: ArchiveWriteSink + ?Sized,
{
    fn begin_archive(&mut self, volume_count: usize) -> Result<(), ArchiveWriteError> {
        (**self).begin_archive(volume_count)
    }

    fn write_volume(&mut self, volume_index: usize, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        (**self).write_volume(volume_index, bytes)
    }

    fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        (**self).write_bootstrap_sidecar(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamingVolumeMode {
    SingleVolume,
    FixedMultiVolume { volume_count: usize },
}

impl StreamingVolumeMode {
    fn volume_count(self) -> Result<usize, FormatError> {
        let volume_count = match self {
            Self::SingleVolume => 1,
            Self::FixedMultiVolume { volume_count } => volume_count,
        };
        if volume_count == 0 {
            return Err(FormatError::WriterUnsupported("zero streaming volumes"));
        }
        Ok(volume_count)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamingVolumeProgress {
    pub bytes_written: u64,
    pub block_count: u64,
    pub terminal_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamingVolumeSetSummary {
    pub volume_count: usize,
    pub archive_bytes: u64,
    pub next_block_index: u64,
    pub volumes: Vec<StreamingVolumeProgress>,
}

#[derive(Debug, Clone)]
struct VolumeState {
    progress: StreamingVolumeProgress,
}

#[derive(Debug)]
pub struct StreamingVolumeSetSink<S> {
    sink: S,
    stripe_width: usize,
    volumes: Vec<VolumeState>,
    next_block_index: u64,
}

impl<S> StreamingVolumeSetSink<S>
where
    S: ArchiveWriteSink,
{
    pub fn begin(mut sink: S, mode: StreamingVolumeMode) -> Result<Self, ArchiveWriteError> {
        let volume_count = mode.volume_count()?;
        sink.begin_archive(volume_count)?;
        Ok(Self {
            sink,
            stripe_width: volume_count,
            volumes: vec![
                VolumeState {
                    progress: StreamingVolumeProgress::default()
                };
                volume_count
            ],
            next_block_index: 0,
        })
    }

    pub fn begin_single_volume(sink: S) -> Result<Self, ArchiveWriteError> {
        Self::begin(sink, StreamingVolumeMode::SingleVolume)
    }

    pub fn begin_fixed_multi_volume(
        sink: S,
        volume_count: usize,
    ) -> Result<Self, ArchiveWriteError> {
        Self::begin(sink, StreamingVolumeMode::FixedMultiVolume { volume_count })
    }

    pub fn stripe_width(&self) -> usize {
        self.stripe_width
    }

    pub fn next_block_index(&self) -> u64 {
        self.next_block_index
    }

    pub fn progress(&self) -> Vec<StreamingVolumeProgress> {
        self.volumes.iter().map(|volume| volume.progress).collect()
    }

    pub fn volume_progress(&self, volume_index: usize) -> Option<StreamingVolumeProgress> {
        self.volumes.get(volume_index).map(|volume| volume.progress)
    }

    pub fn write_volume_preamble(
        &mut self,
        volume_index: usize,
        bytes: &[u8],
    ) -> Result<(), ArchiveWriteError> {
        if self
            .volume_mut(volume_index)?
            .progress
            .terminal_offset
            .is_some()
        {
            return Err(FormatError::WriterInvariant(
                "streaming preamble cannot follow terminal material",
            )
            .into());
        }
        self.write_volume_bytes(volume_index, bytes)
    }

    pub fn emit_block_record(&mut self, record: &BlockRecord) -> Result<(), ArchiveWriteError> {
        if self
            .volumes
            .iter()
            .any(|volume| volume.progress.terminal_offset.is_some())
        {
            return Err(FormatError::WriterInvariant(
                "streaming block record cannot follow terminal material",
            )
            .into());
        }
        self.validate_next_block(record.block_index)?;
        let volume_index = (record.block_index % self.stripe_width as u64) as usize;
        let expected_local_index = checked_mul(
            self.volumes[volume_index].progress.block_count,
            self.stripe_width as u64,
            "streaming volume block index",
        )
        .and_then(|base| checked_add(base, volume_index as u64, "streaming volume block index"))?;
        if record.block_index != expected_local_index {
            return Err(FormatError::WriterInvariant(
                "streaming block record violates stripe placement",
            )
            .into());
        }

        let record_bytes = record.to_bytes();
        self.write_volume_bytes(volume_index, &record_bytes)?;
        self.volumes[volume_index].progress.block_count = checked_add(
            self.volumes[volume_index].progress.block_count,
            1,
            "streaming volume block count",
        )?;
        self.next_block_index =
            checked_add(self.next_block_index, 1, "streaming global block index")?;
        Ok(())
    }

    pub fn write_terminal_bytes(
        &mut self,
        volume_index: usize,
        bytes: &[u8],
    ) -> Result<(), ArchiveWriteError> {
        self.mark_terminal_offset(volume_index)?;
        self.write_volume_bytes(volume_index, bytes)
    }

    pub fn mark_terminal_offset(&mut self, volume_index: usize) -> Result<u64, ArchiveWriteError> {
        let volume = self.volume_mut(volume_index)?;
        let offset = volume.progress.bytes_written;
        if let Some(existing) = volume.progress.terminal_offset {
            return Ok(existing);
        }
        volume.progress.terminal_offset = Some(offset);
        Ok(offset)
    }

    pub fn write_bootstrap_sidecar(&mut self, bytes: &[u8]) -> Result<(), ArchiveWriteError> {
        self.sink.write_bootstrap_sidecar(bytes)
    }

    pub fn finish(self) -> Result<(S, StreamingVolumeSetSummary), ArchiveWriteError> {
        let archive_bytes = self.volumes.iter().try_fold(0u64, |total, volume| {
            checked_add(
                total,
                volume.progress.bytes_written,
                "streaming archive byte count",
            )
        })?;
        let summary = StreamingVolumeSetSummary {
            volume_count: self.stripe_width,
            archive_bytes,
            next_block_index: self.next_block_index,
            volumes: self.progress(),
        };
        Ok((self.sink, summary))
    }

    fn write_volume_bytes(
        &mut self,
        volume_index: usize,
        bytes: &[u8],
    ) -> Result<(), ArchiveWriteError> {
        self.volume_mut(volume_index)?;
        self.sink.write_volume(volume_index, bytes)?;
        let volume = self.volume_mut(volume_index)?;
        volume.progress.bytes_written = checked_add(
            volume.progress.bytes_written,
            bytes.len() as u64,
            "streaming volume byte count",
        )?;
        Ok(())
    }

    fn validate_next_block(&self, block_index: u64) -> Result<(), ArchiveWriteError> {
        if block_index != self.next_block_index {
            return Err(FormatError::WriterInvariant(
                "streaming block records must be dense and in order",
            )
            .into());
        }
        Ok(())
    }

    fn volume_mut(&mut self, volume_index: usize) -> Result<&mut VolumeState, ArchiveWriteError> {
        self.volumes.get_mut(volume_index).ok_or_else(|| {
            FormatError::WriterInvariant("streaming volume index out of bounds").into()
        })
    }
}

fn checked_add(left: u64, right: u64, context: &'static str) -> Result<u64, ArchiveWriteError> {
    left.checked_add(right)
        .ok_or_else(|| FormatError::WriterUnsupported(context).into())
}

fn checked_mul(left: u64, right: u64, context: &'static str) -> Result<u64, ArchiveWriteError> {
    left.checked_mul(right)
        .ok_or_else(|| FormatError::WriterUnsupported(context).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::BlockKind;
    use crate::writer::MemoryArchiveSink;

    fn record(block_index: u64, payload_byte: u8) -> BlockRecord {
        BlockRecord {
            block_index,
            kind: BlockKind::PayloadData,
            flags: 0,
            payload: vec![payload_byte; 4],
            record_crc32c: 0,
        }
    }

    fn parse_volume_records(volume: &[u8]) -> Vec<BlockRecord> {
        volume
            .chunks_exact(4 + crate::format::BLOCK_RECORD_FRAMING_LEN)
            .map(|bytes| BlockRecord::parse(bytes, 4).unwrap())
            .collect()
    }

    #[test]
    fn single_volume_receives_dense_blocks() {
        let sink = MemoryArchiveSink::default();
        let mut distributor = StreamingVolumeSetSink::begin_single_volume(sink).unwrap();

        distributor.emit_block_record(&record(0, 1)).unwrap();
        distributor.emit_block_record(&record(1, 2)).unwrap();
        distributor.write_terminal_bytes(0, b"term").unwrap();

        let (sink, summary) = distributor.finish().unwrap();
        assert_eq!(summary.volume_count, 1);
        assert_eq!(summary.next_block_index, 2);
        assert_eq!(summary.volumes[0].block_count, 2);
        assert_eq!(summary.volumes[0].terminal_offset, Some(48));
        assert_eq!(summary.volumes[0].bytes_written, 52);

        let records = parse_volume_records(&sink.volumes[0][..48]);
        assert_eq!(
            records
                .iter()
                .map(|record| record.block_index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }

    #[test]
    fn fixed_multi_volume_stripes_by_global_block_index() {
        let sink = MemoryArchiveSink::default();
        let mut distributor = StreamingVolumeSetSink::begin_fixed_multi_volume(sink, 3).unwrap();

        for volume_index in 0..3 {
            distributor
                .write_volume_preamble(volume_index, &[volume_index as u8])
                .unwrap();
        }
        for block_index in 0..7 {
            distributor
                .emit_block_record(&record(block_index, block_index as u8))
                .unwrap();
        }
        for volume_index in 0..3 {
            distributor
                .write_terminal_bytes(volume_index, b"end")
                .unwrap();
        }

        let (sink, summary) = distributor.finish().unwrap();
        assert_eq!(
            summary.archive_bytes,
            sink.volumes.iter().map(|v| v.len() as u64).sum()
        );
        assert_eq!(
            summary
                .volumes
                .iter()
                .map(|v| v.block_count)
                .collect::<Vec<_>>(),
            vec![3, 2, 2]
        );
        assert_eq!(
            summary
                .volumes
                .iter()
                .map(|v| v.terminal_offset)
                .collect::<Vec<_>>(),
            vec![Some(73), Some(49), Some(49)]
        );

        let volume_0_records = parse_volume_records(&sink.volumes[0][1..73]);
        let volume_1_records = parse_volume_records(&sink.volumes[1][1..49]);
        let volume_2_records = parse_volume_records(&sink.volumes[2][1..49]);
        assert_eq!(
            volume_0_records
                .iter()
                .map(|record| record.block_index)
                .collect::<Vec<_>>(),
            vec![0, 3, 6]
        );
        assert_eq!(
            volume_1_records
                .iter()
                .map(|record| record.block_index)
                .collect::<Vec<_>>(),
            vec![1, 4]
        );
        assert_eq!(
            volume_2_records
                .iter()
                .map(|record| record.block_index)
                .collect::<Vec<_>>(),
            vec![2, 5]
        );
    }

    #[test]
    fn rejects_out_of_order_or_missing_blocks() {
        let sink = MemoryArchiveSink::default();
        let mut distributor = StreamingVolumeSetSink::begin_fixed_multi_volume(sink, 2).unwrap();

        distributor.emit_block_record(&record(0, 1)).unwrap();
        let error = distributor.emit_block_record(&record(2, 2)).unwrap_err();
        assert!(matches!(
            error,
            ArchiveWriteError::Format(FormatError::WriterInvariant(
                "streaming block records must be dense and in order"
            ))
        ));
    }

    #[test]
    fn rejects_zero_fixed_volumes() {
        let sink = MemoryArchiveSink::default();
        let error = StreamingVolumeSetSink::begin_fixed_multi_volume(sink, 0).unwrap_err();
        assert!(matches!(
            error,
            ArchiveWriteError::Format(FormatError::WriterUnsupported("zero streaming volumes"))
        ));
    }

    #[test]
    fn rejects_blocks_after_terminal_material_starts() {
        let sink = MemoryArchiveSink::default();
        let mut distributor = StreamingVolumeSetSink::begin_single_volume(sink).unwrap();

        distributor.emit_block_record(&record(0, 1)).unwrap();
        distributor.write_terminal_bytes(0, b"term").unwrap();
        let error = distributor.emit_block_record(&record(1, 2)).unwrap_err();
        assert!(matches!(
            error,
            ArchiveWriteError::Format(FormatError::WriterInvariant(
                "streaming block record cannot follow terminal material"
            ))
        ));
    }

    #[test]
    fn can_wrap_borrowed_archive_write_sink() {
        let mut sink = MemoryArchiveSink::default();
        {
            let mut distributor = StreamingVolumeSetSink::begin_single_volume(&mut sink).unwrap();
            distributor.emit_block_record(&record(0, 1)).unwrap();
            let (_, summary) = distributor.finish().unwrap();
            assert_eq!(summary.volumes[0].block_count, 1);
        }

        let records = parse_volume_records(&sink.volumes[0]);
        assert_eq!(records[0].block_index, 0);
    }
}
