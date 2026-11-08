//! Fuzz the air-gap envelope parser: total, and round-trips exactly.
#![no_main]
#![forbid(unsafe_code)]

use kage_airgap::{Envelope, Network, Side};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = Envelope::parse(data) {
        let re = env.encode().expect("accepted envelope must re-encode");
        assert_eq!(re, data);
    }
    let _ = Envelope::parse_for(data, Side::Signer, Network::Stagenet);
    let _ = Envelope::parse_for(data, Side::Hot, Network::Testnet);
});
