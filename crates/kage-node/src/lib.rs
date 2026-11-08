//! # kage-node: node connection policy and transport
//!
//! **Security-critical. Listed in `AUDIT.md`.**
//!
//! - [`policy`]: which endpoints are allowed, and how they must be reached (ADR-005).
//! - [`transport`]: bounded HTTP/1.1 over direct TCP (local only) or Tor.
//! - [`Node`]: a verified connection. The node's `nettype` must match the
//!   wallet's network, and mainnet is always refused (ADR-002).
//! - [`TorHandle`]: the embedded arti client.
//!
//! Rules (ADR-005):
//! - The default is the user's **own** node.
//! - Only loopback and private-network addresses may be reached directly.
//!   Every other host, and every remote (not user-owned) node, must be
//!   reached over Tor.
//! - `.onion` hosts must use Tor.
//! - **No silent fallback.** A [`Node`] has exactly one endpoint. Switching
//!   nodes is always an explicit user action that builds a new [`Node`].

#![forbid(unsafe_code)]

mod client;
pub mod policy;
mod tor;
pub mod transport;

pub use client::{Node, NodeConfig, NodeError, NodeInfo, parse_info, verify_network};
pub use tor::TorHandle;
