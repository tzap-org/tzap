#![no_main]

use libfuzzer_sys::fuzz_target;

mod parse_compressed_support;

fuzz_target!(|data: &[u8]| parse_compressed_support::parse_compressed_and_padding(data));
