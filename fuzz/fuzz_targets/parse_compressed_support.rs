use tzap_core::compression::{decompress_exact_zstd_frame, validate_exact_zstd_frame};
use tzap_core::padding::depad_suffix_padding;

const MAX_FUZZ_DECOMPRESSED_SIZE: usize = 64 * 1024;

pub fn parse_compressed_and_padding(data: &[u8]) {
    let _ = validate_exact_zstd_frame(data);
    if data.len() >= 4 {
        let expected_size =
            u32::from_le_bytes(data[..4].try_into().expect("slice length checked")) as usize;
        let expected_size = expected_size.min(MAX_FUZZ_DECOMPRESSED_SIZE);
        let _ = validate_exact_zstd_frame(&data[4..]);
        let _ = decompress_exact_zstd_frame(&data[4..], expected_size);
    }
    let _ = depad_suffix_padding(data);
}
