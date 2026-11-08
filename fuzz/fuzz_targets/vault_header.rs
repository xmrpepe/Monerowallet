//! Fuzz the vault header parser: must be total (no panic, no hang, no
//! unbounded allocation) and every accepted header must re-serialise to the
//! same bytes.
#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(h) = kage_vault::parse_header(data) {
        let bytes = h.to_bytes();
        assert_eq!(&bytes[..], &data[..kage_vault::HEADER_LEN]);
    }
});
