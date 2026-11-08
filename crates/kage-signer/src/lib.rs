//! # kage-signer: the air-gapped signer
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! This is the only crate in ZeroTrace that ever handles the spend key or the
//! seed. Invariants, all enforced in CI:
//!
//! - **No networking.** No networking or async-runtime crate anywhere in the
//!   dependency tree (`cargo deny` with `crates/kage-signer/deny.toml`, plus
//!   an allowlist in `scripts/check-signer-deps.sh`). No socket types in our
//!   own code (`clippy.toml` `disallowed-types`). At runtime the signer is
//!   additionally started in an empty network namespace (Stage 5, T-SIGN-NET).
//! - **No `unsafe`** (`#![forbid(unsafe_code)]`). Locked memory comes from
//!   `kage-sys`.
//! - **Fail closed.** Process hardening (`kage-harden`, `Profile::Signer`)
//!   must succeed before any secret is read.
//! - **Show everything, reject what can't be decoded.** Before signing, the
//!   signer shows every destination address in full, each amount, the change
//!   (verified to return to this wallet), and the fee. Input it cannot fully
//!   decode is rejected (ADR-006).
//!
//! Responsibilities (Stage 4):
//! 1. seed creation/restore (25-word Monero seed, ADR-009) and verified backup;
//! 2. key-image export for the view-only wallet (pre-FCMP++ requirement);
//! 3. review and signing of unsigned transactions built by `kage-core`, using
//!    the protocol code in [`monero_wallet`] (ADR-001). No cryptography is
//!    implemented here.

#![forbid(unsafe_code)]

pub use kage_airgap::Network;
