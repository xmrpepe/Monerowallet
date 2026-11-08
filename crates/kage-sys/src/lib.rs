//! # kage-sys: the single `unsafe` island of ZeroTrace
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! Every other crate in the workspace has `#![forbid(unsafe_code)]`. This crate
//! exists so that the small amount of `unsafe` required to keep secrets out of
//! swap and core dumps lives in one place, behind a safe API, where an auditor
//! can read all of it in one sitting.
//!
//! The only `unsafe` in this crate is in [`locked`]. It calls `mmap`,
//! `mprotect`, `mlock`, `madvise`, `munlock` and `munmap` (via `rustix`) and
//! builds slices over that mapping. No C/C++ code is linked.
//!
//! Linux-only by design (see `docs/DECISIONS.md`, ADR-007).

#![deny(unsafe_code)]

#[cfg(not(target_os = "linux"))]
compile_error!("kage-sys supports Linux only (ADR-007).");

pub mod locked;

pub use locked::{LockError, LockedBytes};
