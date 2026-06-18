#![no_main]

use libfuzzer_sys::fuzz_target;

mod parse_metadata_support;

fuzz_target!(|data: &[u8]| parse_metadata_support::parse_metadata(data));
