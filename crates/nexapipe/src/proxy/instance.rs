//! The proxy, assembled from a store and a configuration.
//!
//! The constructor is where the store is chosen, and it is the only place
//! that has to know which one it is: everything below it asks the store for
//! the configuration, the credentials and the counters, and never names a
//! path.
//!
//! A builder rather than an argument list, because the pieces are optional
//! and a positional list of seven would be one more piece away from being
//! readable at the call site.

use crate::proxy::{ProxyOptions, run_proxy};
use crate::routes::RoutingTable;
use crate::shutdown::ShutdownSignal;
use crate::storage::Storage;

use std::sync::Arc;

/// The proxy, ready to run.
pub struct Proxy {
    routes: Arc<RoutingTable>,
    storage: Arc<dyn Storage>,
    options: ProxyOptions,
    shutdown_signal: Arc<ShutdownSignal>,
}

impl Proxy {
    /// The builder that assembles one.
    pub fn builder() -> ProxyBuilder {
        ProxyBuilder {
            routes: None,
            storage: None,
            options: None,
            shutdown_signal: None,
        }
    }

    /// Runs the proxy until the shutdown signal says otherwise.
    pub async fn run(self) -> anyhow::Result<()> {
        run_proxy(
            self.routes,
            self.storage,
            self.shutdown_signal,
            self.options,
        )
        .await
    }
}

/// What a proxy is made of.
///
/// Every piece is optional here and required by [`ProxyBuilder::build`]: a
/// builder that says what it has is easier to read at the call site than one
/// that takes seven arguments, and a missing piece is a message that names
/// it rather than a `None` that surfaces somewhere later.
pub struct ProxyBuilder {
    routes: Option<Arc<RoutingTable>>,
    storage: Option<Arc<dyn Storage>>,
    options: Option<ProxyOptions>,
    shutdown_signal: Option<Arc<ShutdownSignal>>,
}

impl ProxyBuilder {
    /// Where the configuration, the credentials and the counters are kept.
    pub fn storage(mut self, storage: Arc<dyn Storage>) -> Self {
        self.storage = Some(storage);
        self
    }

    /// The routing table the proxy serves.
    pub fn routes(mut self, routes: Arc<RoutingTable>) -> Self {
        self.routes = Some(routes);
        self
    }

    /// The rest of the configuration: the listener, the relay, the limits.
    pub fn options(mut self, options: ProxyOptions) -> Self {
        self.options = Some(options);
        self
    }

    /// The signal that says the proxy should stop.
    pub fn shutdown_signal(mut self, signal: Arc<ShutdownSignal>) -> Self {
        self.shutdown_signal = Some(signal);
        self
    }

    /// The proxy, or the reason there is not one.
    pub fn build(self) -> anyhow::Result<Proxy> {
        Ok(Proxy {
            routes: self
                .routes
                .ok_or_else(|| anyhow::anyhow!("the proxy needs a routing table"))?,
            storage: self
                .storage
                .ok_or_else(|| anyhow::anyhow!("the proxy needs a storage"))?,
            options: self
                .options
                .ok_or_else(|| anyhow::anyhow!("the proxy needs its options"))?,
            shutdown_signal: self
                .shutdown_signal
                .ok_or_else(|| anyhow::anyhow!("the proxy needs a shutdown signal"))?,
        })
    }
}
