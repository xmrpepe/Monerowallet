//! Connecting to a node: policy check, network identity check, then the
//! `monero-daemon-rpc` client.
//!
//! There is exactly one endpoint per [`Node`]. Nothing in this crate retries
//! another endpoint (ADR-005, T-NODE-FALLBACK).

use std::time::Duration;

use kage_airgap::Network;
use monero_daemon_rpc::MoneroDaemon;
use monero_interface::InterfaceError;

use crate::policy::{Endpoint, PolicyError, Transport};
use crate::transport::{Connector, DEFAULT_TIMEOUT, NodeTransport};

/// Largest accepted `get_info` response.
const INFO_LIMIT: usize = 64 * 1024;

/// Errors connecting to a node.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeError {
    /// The endpoint violates the connection policy.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// Transport or RPC failure.
    #[error("node RPC error: {0}")]
    Interface(#[from] InterfaceError),
    /// The node is on a different network.
    #[error("node is on {got:?}, wallet is on {expected}: refusing")]
    WrongNetwork {
        /// Wallet network.
        expected: &'static str,
        /// What the node reported.
        got: String,
    },
    /// The node is a mainnet node (ADR-002).
    #[error("node reports mainnet; mainnet is disabled in this build (ADR-002)")]
    Mainnet,
    /// A regtest wallet may only talk to a loopback `fakechain` daemon (ADR-016).
    #[error("regtest is only permitted against a loopback daemon (ADR-016)")]
    RegtestNotLoopback,
    /// Tor needed but unavailable or failed.
    #[error("Tor: {0}")]
    Tor(String),
    /// Malformed `get_info` response.
    #[error("unexpected get_info response: {0}")]
    BadInfo(String),
}

/// What the node reported about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeInfo {
    /// `nettype` (e.g. "stagenet").
    pub nettype: String,
    /// Chain height.
    pub height: u64,
    /// Whether the node considers itself synchronized.
    pub synchronized: bool,
    /// Daemon version string.
    pub version: String,
}

/// Connection settings.
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Where to connect.
    pub endpoint: Endpoint,
    /// The wallet's network; the node must match.
    pub network: Network,
    /// Per-request deadline.
    pub timeout: Duration,
}

impl NodeConfig {
    /// Config with the default timeout.
    #[must_use]
    pub fn new(endpoint: Endpoint, network: Network) -> Self {
        Self {
            endpoint,
            network,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

/// A verified connection to one node.
#[derive(Clone)]
pub struct Node {
    daemon: MoneroDaemon<NodeTransport>,
    transport: NodeTransport,
    info: NodeInfo,
}

impl core::fmt::Debug for Node {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Node")
            .field("transport", &self.transport)
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Node {
    /// Connects, enforcing the policy and verifying the node's network.
    ///
    /// `tor` must be provided when the endpoint uses Tor.
    ///
    /// # Errors
    /// Any [`NodeError`]. Nothing is retried against another node.
    pub async fn connect(
        cfg: &NodeConfig,
        tor: Option<&crate::TorHandle>,
    ) -> Result<Self, NodeError> {
        cfg.endpoint.validate()?;
        check_regtest_locality(cfg)?;

        let connector = match cfg.endpoint.transport {
            Transport::Direct => Connector::Direct,
            Transport::Tor => tor_connector(tor)?,
        };
        let transport = NodeTransport::new(cfg.endpoint.clone(), connector, cfg.timeout);

        let info = fetch_info(&transport).await?;
        verify_network(cfg.network, &info.nettype)?;

        let daemon = MoneroDaemon::new(transport.clone()).await?;
        Ok(Self {
            daemon,
            transport,
            info,
        })
    }

    /// The RPC client. Implements the `monero-interface` traits that
    /// `kage-core` consumes.
    #[must_use]
    pub fn daemon(&self) -> &MoneroDaemon<NodeTransport> {
        &self.daemon
    }

    /// What the node reported when we connected.
    #[must_use]
    pub fn info(&self) -> &NodeInfo {
        &self.info
    }

    /// Re-reads `get_info` (status bar refresh).
    ///
    /// # Errors
    /// RPC failure or malformed response.
    pub async fn refresh_info(&mut self) -> Result<&NodeInfo, NodeError> {
        self.info = fetch_info(&self.transport).await?;
        Ok(&self.info)
    }

    /// Whether this connection goes over Tor.
    #[must_use]
    pub fn is_tor(&self) -> bool {
        self.transport.is_tor()
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        self.transport.endpoint()
    }
}

#[cfg(feature = "tor")]
fn tor_connector(tor: Option<&crate::TorHandle>) -> Result<Connector, NodeError> {
    let tor =
        tor.ok_or_else(|| NodeError::Tor("endpoint requires Tor but Tor is not running".into()))?;
    Ok(Connector::Tor(tor.isolated()))
}

#[cfg(not(feature = "tor"))]
fn tor_connector(_tor: Option<&crate::TorHandle>) -> Result<Connector, NodeError> {
    Err(NodeError::Tor("this build has no Tor support".into()))
}

#[cfg(feature = "regtest")]
fn check_regtest_locality(cfg: &NodeConfig) -> Result<(), NodeError> {
    use crate::policy::Host;
    if cfg.network == Network::Regtest {
        let loopback = matches!(&cfg.endpoint.host, Host::Ip(ip) if ip.is_loopback());
        if !loopback || cfg.endpoint.transport != Transport::Direct {
            return Err(NodeError::RegtestNotLoopback);
        }
    }
    Ok(())
}

#[cfg(not(feature = "regtest"))]
#[allow(clippy::unnecessary_wraps)]
fn check_regtest_locality(_cfg: &NodeConfig) -> Result<(), NodeError> {
    Ok(())
}

/// Checks the node's reported `nettype` against the wallet network.
///
/// # Errors
/// [`NodeError::Mainnet`] or [`NodeError::WrongNetwork`].
pub fn verify_network(expected: Network, nettype: &str) -> Result<(), NodeError> {
    if nettype == "mainnet" {
        return Err(NodeError::Mainnet);
    }
    if nettype != expected.daemon_nettype() {
        return Err(NodeError::WrongNetwork {
            expected: expected.name(),
            got: nettype.to_owned(),
        });
    }
    Ok(())
}

async fn fetch_info(t: &NodeTransport) -> Result<NodeInfo, NodeError> {
    let body = br#"{"jsonrpc":"2.0","id":0,"method":"get_info"}"#.to_vec();
    let raw = t.post_raw("json_rpc", body, Some(INFO_LIMIT)).await?;
    parse_info(&raw)
}

/// Parses a `get_info` JSON-RPC response. Total on arbitrary input.
///
/// # Errors
/// [`NodeError::BadInfo`].
pub fn parse_info(raw: &[u8]) -> Result<NodeInfo, NodeError> {
    let v: serde_json::Value =
        serde_json::from_slice(raw).map_err(|e| NodeError::BadInfo(format!("not JSON: {e}")))?;
    let r = v
        .get("result")
        .ok_or_else(|| NodeError::BadInfo("missing result".into()))?;
    let s = |k: &str| r.get(k).and_then(serde_json::Value::as_str);
    if s("status") != Some("OK") {
        return Err(NodeError::BadInfo("status is not OK".into()));
    }
    let nettype = s("nettype")
        .filter(|n| n.len() <= 32)
        .ok_or_else(|| NodeError::BadInfo("missing nettype".into()))?;
    Ok(NodeInfo {
        nettype: nettype.to_owned(),
        height: r
            .get("height")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| NodeError::BadInfo("missing height".into()))?,
        synchronized: r
            .get("synchronized")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        version: s("version").unwrap_or("unknown").chars().take(64).collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_checks() {
        assert!(verify_network(Network::Stagenet, "stagenet").is_ok());
        assert!(matches!(
            verify_network(Network::Stagenet, "mainnet"),
            Err(NodeError::Mainnet)
        ));
        assert!(matches!(
            verify_network(Network::Stagenet, "testnet"),
            Err(NodeError::WrongNetwork { .. })
        ));
        assert!(matches!(
            verify_network(Network::Testnet, "fakechain"),
            Err(NodeError::WrongNetwork { .. })
        ));
    }

    #[test]
    fn info_parsing() {
        let ok = br#"{"result":{"status":"OK","nettype":"stagenet","height":42,"synchronized":true,"version":"0.18.5.4"}}"#;
        let i = parse_info(ok).expect("parse");
        assert_eq!(
            (i.nettype.as_str(), i.height, i.synchronized),
            ("stagenet", 42, true)
        );
        for bad in [
            &b"not json"[..],
            br#"{"result":{"status":"BUSY","nettype":"stagenet","height":1}}"#,
            br#"{"result":{"status":"OK","height":1}}"#,
            br#"{"result":{"status":"OK","nettype":"stagenet"}}"#,
            br#"{"error":{"code":-1}}"#,
        ] {
            assert!(parse_info(bad).is_err());
        }
    }

    #[cfg(feature = "regtest")]
    #[test]
    fn regtest_requires_loopback_direct() {
        use crate::policy::{Host, Ownership};
        let mk = |ip: [u8; 4]| {
            NodeConfig::new(
                Endpoint {
                    host: Host::Ip(std::net::IpAddr::from(ip)),
                    port: 18081,
                    transport: Transport::Direct,
                    ownership: Ownership::Own,
                },
                Network::Regtest,
            )
        };
        assert!(check_regtest_locality(&mk([127, 0, 0, 1])).is_ok());
        assert!(matches!(
            check_regtest_locality(&mk([192, 168, 1, 2])),
            Err(NodeError::RegtestNotLoopback)
        ));
    }
}
