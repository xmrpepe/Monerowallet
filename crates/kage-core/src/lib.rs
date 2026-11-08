//! # kage-core: view-only wallet logic
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! Holds the **private view key and public spend key only**, so it cannot
//! spend. There is no code path that accepts a spend key or seed. The signer's
//! vault content type (`SignerSecrets`) is rejected when opened as a
//! `ViewWallet`.
//!
//! - [`keys`]: view-only keys, verified against the primary address.
//! - [`sync`]: scanning with reorg handling, local RingCT index verification,
//!   and **private spend detection** by ring appearances (no key image is ever
//!   sent to the node).
//! - [`balance`]: wallet2-compatible spendability rules.
//! - [`intent`]: unsigned transaction intents for the signer (ADR-019).
//! - [`codec`] / [`wallet`]: the encrypted wallet file.
//!
//! This crate performs no I/O beyond its own wallet file. Chain data arrives
//! through the `monero-interface` traits, which `kage-node` implements.

#![forbid(unsafe_code)]

pub mod balance;
pub mod codec;
pub mod intent;
pub mod keys;
pub mod state;
pub mod subaddr;
pub mod sync;
pub mod wallet;

pub use kage_airgap::Network;
pub use kage_airgap::payload;
pub use monero_wallet;

#[cfg(test)]
mod tests;
