//! `zerotrace`: terminal UI entry point.
//!
//! Stage 3 implements the UI (ratatui + crossterm, Omarchy themes, command
//! palette, vim-style navigation). This skeleton only applies hardening.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use kage_harden::{Profile, harden_process};

fn main() -> ExitCode {
    let report = match harden_process(Profile::Online) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("zerotrace: {e}");
            return ExitCode::FAILURE;
        }
    };
    for w in &report.warnings {
        eprintln!("zerotrace: WARNING: {w}");
    }
    eprintln!(
        "zerotrace {} ({:?}): skeleton build, UI arrives in Stage 3.",
        env!("CARGO_PKG_VERSION"),
        kage_core::Network::Stagenet
    );
    ExitCode::from(2)
}
