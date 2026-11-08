//! Embedded Tor client (arti).
//!
//! State and cache live in directories the caller chooses, normally under the
//! wallet directory. Each [`Node`](crate::Node) gets an *isolated* client
//! handle, so its streams never share circuits with other wallets or nodes
//! (T-NODE-IPLEAK).

use std::path::Path;

use crate::client::NodeError;

/// A bootstrapped Tor client.
#[derive(Clone)]
pub struct TorHandle {
    #[cfg(feature = "tor")]
    client: std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>>,
}

impl core::fmt::Debug for TorHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TorHandle")
    }
}

impl TorHandle {
    /// Bootstraps Tor, persisting state in `state_dir` and directory data in
    /// `cache_dir`. Can take tens of seconds on first run.
    ///
    /// # Errors
    /// [`NodeError::Tor`] if configuration or bootstrap fails.
    #[cfg(feature = "tor")]
    pub async fn bootstrap(state_dir: &Path, cache_dir: &Path) -> Result<Self, NodeError> {
        let config =
            arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
                .build()
                .map_err(|e| NodeError::Tor(format!("config: {e}")))?;
        let client = arti_client::TorClient::create_bootstrapped(config)
            .await
            .map_err(|e| NodeError::Tor(format!("bootstrap: {e}")))?;
        Ok(Self { client })
    }

    /// Always fails: this build has no Tor support.
    ///
    /// # Errors
    /// Always [`NodeError::Tor`].
    #[cfg(not(feature = "tor"))]
    #[allow(clippy::unused_async)]
    pub async fn bootstrap(_state_dir: &Path, _cache_dir: &Path) -> Result<Self, NodeError> {
        Err(NodeError::Tor("this build has no Tor support".into()))
    }

    #[cfg(feature = "tor")]
    pub(crate) fn isolated(
        &self,
    ) -> std::sync::Arc<arti_client::TorClient<tor_rtcompat::PreferredRuntime>> {
        self.client.isolated_client()
    }
}
