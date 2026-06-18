#![no_main]

use libfuzzer_sys::fuzz_target;

mod parse_fixed_support;

fuzz_target!(|data: &[u8]| {
    parse_fixed_support::parse_fixed_structures(data);
});
