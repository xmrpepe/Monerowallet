//! HTTP transport for `monero-daemon-rpc`, over a direct TCP stream (loopback
//! or private network only) or an arti Tor stream.
//!
//! Hardening (T-NODE-DOS, T-NODE-LIE):
//! - every request has a total deadline;
//! - response bodies are read through a hard size cap, even when the caller
//!   passes no limit;
//! - only `200 OK` is accepted;
//! - the route is restricted to `[a-z0-9_.]` so it cannot alter the request line;
//! - one connection per request: no pooling, so no response desynchronisation
//!   across requests.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper_util::rt::TokioIo;
use monero_interface::InterfaceError;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::policy::{Endpoint, Host, Transport};

/// Absolute ceiling on any response body (128 MiB), applied even when the
/// caller passes no limit. Blocks larger than this cannot be fetched; that is
/// far above current Monero block sizes.
pub const HARD_RESPONSE_CAP: usize = 128 * 1024 * 1024;
/// Default per-request deadline.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_mins(1);

/// How streams are opened.
#[derive(Clone)]
pub(crate) enum Connector {
    /// Plain TCP. Policy allows this only for loopback/private IP literals.
    Direct,
    /// Tor via arti. Stream isolation is per `NodeTransport`.
    #[cfg(feature = "tor")]
    Tor(Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>),
}

impl core::fmt::Debug for Connector {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Direct => f.write_str("Direct"),
            #[cfg(feature = "tor")]
            Self::Tor(_) => f.write_str("Tor"),
        }
    }
}

struct Inner {
    endpoint: Endpoint,
    connector: Connector,
    timeout: Duration,
}

/// A `monero_daemon_rpc::HttpTransport` bound to one validated endpoint.
#[derive(Clone)]
pub struct NodeTransport {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for NodeTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeTransport")
            .field("endpoint", &self.inner.endpoint)
            .field("connector", &self.inner.connector)
            .finish_non_exhaustive()
    }
}

impl NodeTransport {
    pub(crate) fn new(endpoint: Endpoint, connector: Connector, timeout: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                endpoint,
                connector,
                timeout,
            }),
        }
    }

    /// The endpoint this transport talks to.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner.endpoint
    }

    /// Whether requests go over Tor.
    #[must_use]
    pub fn is_tor(&self) -> bool {
        self.inner.endpoint.transport == Transport::Tor
    }

    /// POSTs `body` to `/<route>` and returns the response body.
    ///
    /// # Errors
    /// Connection failure, timeout, non-200 status, oversized response.
    pub async fn post_raw(
        &self,
        route: &str,
        body: Vec<u8>,
        limit: Option<usize>,
    ) -> Result<Vec<u8>, InterfaceError> {
        let deadline = self.inner.timeout;
        tokio::time::timeout(deadline, self.inner.post(route, body, limit))
            .await
            .map_err(|_| {
                InterfaceError::InterfaceError(format!("node request timed out after {deadline:?}"))
            })?
    }
}

impl monero_daemon_rpc::HttpTransport for NodeTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
        let this = self.clone();
        let route = route.to_owned();
        async move { this.post_raw(&route, body, response_size_limit).await }
    }
}

fn valid_route(route: &str) -> bool {
    !route.is_empty()
        && route.len() <= 64
        && route
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'.')
}

fn host_header(endpoint: &Endpoint) -> String {
    match &endpoint.host {
        Host::Ip(std::net::IpAddr::V6(v6)) => format!("[{v6}]:{}", endpoint.port),
        Host::Ip(ip) => format!("{ip}:{}", endpoint.port),
        Host::Onion(h) | Host::Dns(h) => format!("{h}:{}", endpoint.port),
    }
}

impl Inner {
    async fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        limit: Option<usize>,
    ) -> Result<Vec<u8>, InterfaceError> {
        if !valid_route(route) {
            return Err(InterfaceError::InternalError(format!(
                "refusing unexpected RPC route {route:?}"
            )));
        }
        let cap = limit.map_or(HARD_RESPONSE_CAP, |l| l.min(HARD_RESPONSE_CAP));
        match (&self.connector, &self.endpoint.host) {
            (Connector::Direct, Host::Ip(ip)) => {
                let stream = tokio::net::TcpStream::connect((*ip, self.endpoint.port))
                    .await
                    .map_err(|e| InterfaceError::InterfaceError(format!("connect failed: {e}")))?;
                stream
                    .set_nodelay(true)
                    .map_err(|e| InterfaceError::InterfaceError(e.to_string()))?;
                exchange(stream, &host_header(&self.endpoint), route, body, cap).await
            }
            (Connector::Direct, _) => Err(InterfaceError::InternalError(
                "direct connections require an IP literal (ADR-005)".into(),
            )),
            #[cfg(feature = "tor")]
            (Connector::Tor(tor), host) => {
                let target = match host {
                    Host::Ip(ip) => ip.to_string(),
                    Host::Onion(h) | Host::Dns(h) => h.clone(),
                };
                let stream = tor
                    .connect((target.as_str(), self.endpoint.port))
                    .await
                    .map_err(|e| {
                        InterfaceError::InterfaceError(format!("Tor connect failed: {e}"))
                    })?;
                exchange(stream, &host_header(&self.endpoint), route, body, cap).await
            }
        }
    }
}

/// One HTTP/1.1 request/response over an already-connected stream.
async fn exchange<S>(
    stream: S,
    host: &str,
    route: &str,
    body: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, InterfaceError>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .map_err(|e| InterfaceError::InterfaceError(format!("HTTP handshake failed: {e}")))?;
    // Drive the connection; it ends when the response is complete or dropped.
    let driver = tokio::spawn(async move {
        let _: Result<(), hyper::Error> = conn.await;
    });

    let req = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("/{route}"))
        .header(http::header::HOST, host)
        .header(http::header::CONTENT_TYPE, "application/json")
        .header(http::header::CONNECTION, "close")
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| InterfaceError::InternalError(format!("building request: {e}")))?;

    let result = async {
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| InterfaceError::InterfaceError(format!("request failed: {e}")))?;
        if resp.status() != http::StatusCode::OK {
            return Err(InterfaceError::InterfaceError(format!(
                "node returned HTTP {}",
                resp.status().as_u16()
            )));
        }
        let collected = Limited::new(resp.into_body(), cap)
            .collect()
            .await
            .map_err(|e| InterfaceError::InvalidInterface(format!("response rejected: {e}")))?;
        Ok(collected.to_bytes().to_vec())
    }
    .await;
    driver.abort();
    result
}

/// TEST-ONLY (`regtest` feature): a plain HTTP transport to a loopback port,
/// for driving `monero-wallet-rpc` in differential tests. Not a node
/// connection: no network check is performed.
#[cfg(feature = "regtest")]
#[must_use]
pub fn loopback_for_tests(port: u16) -> NodeTransport {
    use crate::policy::Ownership;
    NodeTransport::new(
        Endpoint {
            host: Host::Ip(std::net::IpAddr::from([127, 0, 0, 1])),
            port,
            transport: Transport::Direct,
            ownership: Ownership::Own,
        },
        Connector::Direct,
        DEFAULT_TIMEOUT,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Ownership;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    fn local_endpoint(port: u16) -> Endpoint {
        Endpoint {
            host: Host::Ip(std::net::IpAddr::from([127, 0, 0, 1])),
            port,
            transport: Transport::Direct,
            ownership: Ownership::Own,
        }
    }

    /// A one-shot fake HTTP server that returns `response` verbatim.
    async fn serve_once(response: Vec<u8>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.expect("read");
            buf.truncate(n);
            sock.write_all(&response).await.expect("write");
            let _ = sock.shutdown().await;
            buf
        });
        (port, handle)
    }

    #[test]
    fn route_validation() {
        assert!(valid_route("json_rpc"));
        assert!(valid_route("get_o_indexes.bin"));
        assert!(!valid_route("json_rpc HTTP/1.1\r\nX: y"));
        assert!(!valid_route("../admin"));
        assert!(!valid_route(""));
    }

    #[tokio::test]
    async fn ok_response_and_request_shape() {
        let (port, h) = serve_once(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}".to_vec(),
        )
        .await;
        let t = NodeTransport::new(local_endpoint(port), Connector::Direct, DEFAULT_TIMEOUT);
        let body = t
            .post_raw("json_rpc", b"{\"a\":1}".to_vec(), Some(1024))
            .await
            .expect("post");
        assert_eq!(body, b"{}");
        let req = String::from_utf8(h.await.expect("join")).expect("utf8");
        assert!(req.starts_with("POST /json_rpc HTTP/1.1\r\n"), "{req}");
        assert!(
            req.to_ascii_lowercase()
                .contains(&format!("host: 127.0.0.1:{port}"))
        );
    }

    #[tokio::test]
    async fn oversized_response_rejected() {
        let mut resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n".to_vec();
        resp.extend(std::iter::repeat_n(b'x', 4096));
        let (port, _h) = serve_once(resp).await;
        let t = NodeTransport::new(local_endpoint(port), Connector::Direct, DEFAULT_TIMEOUT);
        let err = t.post_raw("json_rpc", vec![], Some(100)).await.unwrap_err();
        assert!(
            matches!(err, InterfaceError::InvalidInterface(_)),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn non_200_rejected() {
        let (port, _h) =
            serve_once(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
        let t = NodeTransport::new(local_endpoint(port), Connector::Direct, DEFAULT_TIMEOUT);
        assert!(t.post_raw("json_rpc", vec![], None).await.is_err());
    }

    #[tokio::test]
    async fn timeout_enforced() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let _hold = tokio::spawn(async move {
            let (_sock, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let t = NodeTransport::new(
            local_endpoint(port),
            Connector::Direct,
            Duration::from_millis(200),
        );
        let err = t.post_raw("json_rpc", vec![], None).await.unwrap_err();
        assert!(format!("{err}").contains("timed out"), "{err}");
    }

    #[tokio::test]
    async fn direct_requires_ip_literal() {
        let ep = Endpoint {
            host: Host::Dns("localhost".into()),
            port: 1,
            transport: Transport::Direct,
            ownership: Ownership::Own,
        };
        let t = NodeTransport::new(ep, Connector::Direct, DEFAULT_TIMEOUT);
        assert!(t.post_raw("json_rpc", vec![], None).await.is_err());
    }
}
