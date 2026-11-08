//! # kage-node: node connection policy and transport
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! Stage 2 provides the **connection policy** ([`policy`]). Stage 3 adds the
//! RPC client and the arti (Tor) transport.
//!
//! Rules (ADR-005):
//! - The default is the user's **own** node.
//! - Only loopback and private-network addresses may be reached directly.
//!   Every other host, and every remote (not user-owned) node, must be
//!   reached over Tor.
//! - `.onion` hosts must use Tor.
//! - **No silent fallback.** If the configured node is unreachable, the
//!   wallet reports it and waits. Switching nodes is always an explicit user
//!   action.

#![forbid(unsafe_code)]

pub mod policy;
