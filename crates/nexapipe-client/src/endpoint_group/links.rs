//! How a backend is reached.
//!
//! Traffic reaches a backend directly or through a relay, and the group can
//! say which, how far away the link is, and let go of the connections it
//! cached when the device changed networks.

#[cfg(feature = "jni")]
use crate::jni_log;

use crate::connection_pool::{LinkKind, LinkStatus};

use iroh::EndpointId;

use super::EndpointGroup;

impl EndpointGroup {
    /// How traffic is currently reaching each backend, and how far away it is.
    ///
    /// One entry per *distinct backend*, because that is what a link describes — two domains
    /// served by the same node share one connection pool and therefore one answer.
    ///
    /// A backend that has never connected reports [`LinkKind::Unknown`]; the caller decides
    /// whether that means "not connected yet" or "not connected at all". The round-trip time
    /// is `None` until iroh has a sample, which is not the same as zero.
    pub async fn link_statuses(&self) -> Vec<(EndpointId, LinkStatus)> {
        let mut statuses = Vec::new();
        for (backend_id, pool) in self.unique_pools() {
            statuses.push((backend_id, pool.link_status().await));
        }
        statuses
    }

    /// How traffic is currently reaching each backend: direct, or via a relay.
    ///
    /// The kind on its own, for the callers that only draw an icon.
    pub async fn link_kinds(&self) -> Vec<(EndpointId, LinkKind)> {
        self.link_statuses()
            .await
            .into_iter()
            .map(|(id, status)| (id, status.kind))
            .collect()
    }

    /// Closes and forgets every cached connection to every backend, keeping the endpoints.
    ///
    /// Called when the device switched networks: the tunnel itself stays up, but the
    /// connections inside it were opened on the old network and are dead while still looking
    /// open. See [`IrohConnectionPool::drop_connections`] for why they have to be closed
    /// explicitly instead of waiting for QUIC to notice.
    ///
    /// [`IrohConnectionPool::drop_connections`]: crate::connection_pool::IrohConnectionPool::drop_connections
    pub async fn drop_connections(&self) {
        let pools = self.unique_pools();
        for (backend_id, pool) in pools {
            pool.drop_connections().await;
            jni_log!(
                "[drop-connections] dropped cached connections to {}",
                backend_id
            );
        }
    }
}
