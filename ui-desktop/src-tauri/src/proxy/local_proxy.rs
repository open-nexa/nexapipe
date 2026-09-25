use anyhow::Result;
use nexapipe_client::endpoint_group::EndpointGroup;
use nexapipe_client::LocalProxy;
use std::sync::Arc;

pub struct LocalProxyWrapper {
    inner: Arc<LocalProxy>,
}

impl LocalProxyWrapper {
    /// Build the local proxy on an already-configured [`EndpointGroup`].
    ///
    /// The group is the caller's: it carries the relay mode, the QUIC transport
    /// tuning and any 2FA credentials. An earlier version built its own group
    /// here, which silently dropped all three — the relay was never pinned, the
    /// per-stream window fell back to a 50 Mbps ceiling, and 2FA handshakes were
    /// skipped — while also doubling the number of iroh endpoints.
    pub async fn new(
        listen_addr: &str,
        proxy_domains: Vec<String>,
        endpoint_group: Arc<EndpointGroup>,
    ) -> Result<Self> {
        let inner = LocalProxy::new(listen_addr, proxy_domains, endpoint_group)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        tracing::info!("Local proxy created on: {}", listen_addr);

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub async fn run(&self) -> Result<()> {
        self.inner.run().await.map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn stop(&self) {
        tracing::info!("Stopping local proxy");
        self.inner.stop();
        self.inner.close_all().await;
    }
}
