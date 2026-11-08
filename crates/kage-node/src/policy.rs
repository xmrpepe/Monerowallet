//! Node endpoint validation. Pure logic: no I/O.

use std::net::IpAddr;

/// Who runs the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// The user's own node (the default).
    Own,
    /// A third-party node. Treated as untrusted and always reached via Tor.
    Remote,
}

/// How to reach the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A plain TCP connection.
    Direct,
    /// Over Tor, via the embedded arti client.
    Tor,
}

/// Parsed host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// IP literal.
    Ip(IpAddr),
    /// Tor v3 onion service (lower-case, validated).
    Onion(String),
    /// DNS name. Only allowed over Tor, which resolves it at the exit, so the
    /// local resolver never sees it.
    Dns(String),
}

/// A configured node endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// Host.
    pub host: Host,
    /// TCP port.
    pub port: u16,
    /// Transport.
    pub transport: Transport,
    /// Ownership.
    pub ownership: Ownership,
}

/// Policy violations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyError {
    /// The host string could not be parsed.
    #[error("invalid host: {0}")]
    InvalidHost(String),
    /// Port 0.
    #[error("invalid port 0")]
    InvalidPort,
    /// `.onion` requires Tor.
    #[error("onion services can only be reached over Tor")]
    OnionRequiresTor,
    /// A remote (third-party) node must be reached over Tor.
    #[error("remote nodes must be reached over Tor (ADR-005)")]
    RemoteRequiresTor,
    /// Direct connections are only allowed to loopback/private addresses.
    #[error(
        "direct connections are only allowed to loopback or private-network addresses; use Tor"
    )]
    PublicDirect,
}

impl Host {
    /// Parses a host string.
    ///
    /// # Errors
    /// [`PolicyError::InvalidHost`].
    pub fn parse(s: &str) -> Result<Self, PolicyError> {
        let s = s.trim();
        if let Ok(ip) = s
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
        {
            return Ok(Self::Ip(ip));
        }
        let lower = s.to_ascii_lowercase();
        if let Some(label) = lower.strip_suffix(".onion") {
            // v3 onion: 56 base32 characters [a-z2-7].
            let ok = label.len() == 56
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b));
            return if ok {
                Ok(Self::Onion(lower))
            } else {
                Err(PolicyError::InvalidHost(s.to_owned()))
            };
        }
        let valid_dns = !lower.is_empty()
            && lower.len() <= 253
            && lower.split('.').all(|l| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            });
        if valid_dns {
            Ok(Self::Dns(lower))
        } else {
            Err(PolicyError::InvalidHost(s.to_owned()))
        }
    }

    fn is_local(&self) -> bool {
        match self {
            Self::Ip(IpAddr::V4(v4)) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
            Self::Ip(IpAddr::V6(v6)) => {
                v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local()
            }
            Self::Onion(_) | Self::Dns(_) => false,
        }
    }
}

impl Endpoint {
    /// Validates the endpoint against the connection policy.
    ///
    /// # Errors
    /// The first violated rule.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.port == 0 {
            return Err(PolicyError::InvalidPort);
        }
        if matches!(self.host, Host::Onion(_)) && self.transport != Transport::Tor {
            return Err(PolicyError::OnionRequiresTor);
        }
        if self.ownership == Ownership::Remote && self.transport != Transport::Tor {
            return Err(PolicyError::RemoteRequiresTor);
        }
        if self.transport == Transport::Direct && !self.host.is_local() {
            return Err(PolicyError::PublicDirect);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(host: &str, transport: Transport, ownership: Ownership) -> Endpoint {
        Endpoint {
            host: Host::parse(host).expect("host"),
            port: 38081,
            transport,
            ownership,
        }
    }

    const ONION: &str = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion";

    #[test]
    fn own_local_direct_ok() {
        for h in ["127.0.0.1", "::1", "192.168.1.10", "10.0.0.2", "[fd00::1]"] {
            assert_eq!(
                ep(h, Transport::Direct, Ownership::Own).validate(),
                Ok(()),
                "{h}"
            );
        }
    }

    #[test]
    fn public_direct_rejected_even_if_own() {
        for h in ["8.8.8.8", "node.example.org", "2001:db8::1"] {
            assert_eq!(
                ep(h, Transport::Direct, Ownership::Own).validate(),
                Err(PolicyError::PublicDirect),
                "{h}"
            );
        }
    }

    #[test]
    fn remote_requires_tor() {
        assert_eq!(
            ep("192.168.1.10", Transport::Direct, Ownership::Remote).validate(),
            Err(PolicyError::RemoteRequiresTor)
        );
        assert_eq!(
            ep("node.example.org", Transport::Tor, Ownership::Remote).validate(),
            Ok(())
        );
    }

    #[test]
    fn onion_rules() {
        assert_eq!(
            ep(ONION, Transport::Tor, Ownership::Remote).validate(),
            Ok(())
        );
        assert_eq!(
            ep(ONION, Transport::Direct, Ownership::Own).validate(),
            Err(PolicyError::OnionRequiresTor)
        );
        assert!(Host::parse("short.onion").is_err());
    }

    #[test]
    fn invalid_hosts() {
        for h in ["", "-bad.example", "a..b", "exa mple.org", "x_y.org"] {
            assert!(Host::parse(h).is_err(), "{h:?}");
        }
    }
}
