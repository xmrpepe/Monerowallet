//! Fuzz node host parsing + policy validation (config input is untrusted).
#![no_main]
#![forbid(unsafe_code)]

use kage_node::policy::{Endpoint, Host, Ownership, Transport};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = core::str::from_utf8(data) else {
        return;
    };
    if let Ok(host) = Host::parse(s) {
        for transport in [Transport::Direct, Transport::Tor] {
            for ownership in [Ownership::Own, Ownership::Remote] {
                let ep = Endpoint {
                    host: host.clone(),
                    port: 18081,
                    transport,
                    ownership,
                };
                let _ = ep.validate();
            }
        }
    }
});
