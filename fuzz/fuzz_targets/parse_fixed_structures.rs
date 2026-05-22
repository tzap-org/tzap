#![no_main]

use libfuzzer_sys::fuzz_target;
use tzap_core::format::{BLOCK_RECORD_FRAMING_LEN, MANIFEST_FOOTER_LEN, VOLUME_TRAILER_LEN};
use tzap_core::wire::{
    BlockRecord, BootstrapSidecarHeader, ManifestFooter, VolumeHeader, VolumeTrailer,
};

const FUZZ_BLOCK_SIZE: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let _ = VolumeHeader::parse(data);
    let _ = ManifestFooter::parse(data);
    let _ = VolumeTrailer::parse(data);
    let _ = BootstrapSidecarHeader::parse(data);

    if data.len() >= FUZZ_BLOCK_SIZE + BLOCK_RECORD_FRAMING_LEN {
        let _ = BlockRecord::parse(&data[..FUZZ_BLOCK_SIZE + BLOCK_RECORD_FRAMING_LEN], FUZZ_BLOCK_SIZE);
    }
    if data.len() >= MANIFEST_FOOTER_LEN {
        let _ = ManifestFooter::parse(&data[..MANIFEST_FOOTER_LEN]);
    }
    if data.len() >= VOLUME_TRAILER_LEN {
        let _ = VolumeTrailer::parse(&data[..VOLUME_TRAILER_LEN]);
    }
});
