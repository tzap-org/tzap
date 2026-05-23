#![no_main]

use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|data: &[u8]| support::parse_metadata(data));
