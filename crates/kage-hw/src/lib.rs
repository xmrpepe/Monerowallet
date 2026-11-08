//! # kage-hw: hardware-wallet signing (deferred)
//!
//! **Intentionally empty.** See `docs/DECISIONS.md`, ADR-003.
//!
//! Writing the host side of Ledger's current (CLSAG) Monero protocol now would
//! mean new, security-critical protocol code for a feature that stops working
//! at the FCMP++ hard fork. This crate gets implemented once Ledger publishes
//! an FCMP++/Carrot-capable Monero app. It is tested against the Speculos
//! emulator (monero PR #10421). No other crate depends on it.

#![forbid(unsafe_code)]
