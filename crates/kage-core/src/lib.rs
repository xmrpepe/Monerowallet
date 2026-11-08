//! # kage-core: view-only wallet logic
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! Holds the **private view key and public spend key only**. It cannot spend.
//! It never sees the spend key or seed, and has no code path that accepts one
//! (the signer's vault content type, `ContentType::SignerSecrets`, is rejected
//! by `kage-vault` when opened as `ViewWallet`).
//!
//! Stage 3 scope (stagenet only, ADR-002):
//! - chain scanning via [`monero_wallet`] (ADR-001), fed blocks by `kage-node`
//!   through a trait defined here, so this crate stays network-free;
//! - balances, including key-image import from the signer. Before FCMP++ a
//!   view-only wallet cannot see its own spends without key images (§2 of
//!   `docs/RESEARCH.md`);
//! - subaddress derivation and bookkeeping;
//! - output selection and **unsigned** transaction construction, with decoy
//!   selection delegated to `monero-wallet` and differentially tested against
//!   `monero-wallet-rpc` on stagenet.

#![forbid(unsafe_code)]

pub use kage_airgap::Network;
