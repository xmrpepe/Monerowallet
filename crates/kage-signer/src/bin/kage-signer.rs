//! `kage-signer` binary entry point.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use kage_harden::{Profile, harden_process};

fn main() -> ExitCode {
    // Hardening comes first, before anything touches a secret. Fail closed.
    let report = match harden_process(Profile::Signer) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("kage-signer: {e}");
            return ExitCode::FAILURE;
        }
    };
    for w in &report.warnings {
        eprintln!("kage-signer: WARNING: {w}");
    }
    eprintln!(
        "kage-signer: process hardening OK (memory: {:?}). Signing is not implemented yet (Stage 4).",
        report.memory
    );
    ExitCode::from(2)
}
