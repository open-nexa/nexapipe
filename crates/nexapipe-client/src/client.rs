use crate::ClientError;
use crate::connection_pool::IrohConnectionPool;
use crate::http::{HttpRequest, HttpResponse};
use iroh::endpoint::Connection;
use iroh::{EndpointAddr, EndpointId};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const MAX_RESPONSE_SIZE: usize = 1024 * 1024 * 10;

/// Budget for a single request/response exchange, once a connection has been
/// taken from the pool.
///
/// Neither `open_bi` nor `read_to_end` carries a deadline of its own, so a peer
/// that accepts the stream but never answers would otherwise hold the caller
/// for as long as the process lives.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct IrohProxyClient {
    conn_pool: Arc<IrohConnectionPool>,
}

impl IrohProxyClient {
    pub async fn new(endpoint_addr: EndpointAddr) -> Result<Self, ClientError> {
        let conn_pool = Arc::new(IrohConnectionPool::new(endpoint_addr).await?);
        Ok(Self { conn_pool })
    }

    pub async fn new_with_pool(conn_pool: IrohConnectionPool) -> Self {
        Self {
            conn_pool: Arc::new(conn_pool),
        }
    }

    pub fn node_id(&self) -> EndpointId {
        self.conn_pool.node_id()
    }

    pub async fn send_request(&self, request: &HttpRequest) -> Result<HttpResponse, ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let response = Self::exchange(&conn, request.to_bytes().as_slice()).await?;
        self.conn_pool.return_connection(conn).await;

        HttpResponse::parse(&response)
    }

    pub async fn send_raw(&self, data: &[u8]) -> Result<Vec<u8>, ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let response = Self::exchange(&conn, data).await?;
        self.conn_pool.return_connection(conn).await;

        Ok(response)
    }

    /// Writes `payload` on a fresh bidirectional stream and reads the peer's
    /// whole reply, under `EXCHANGE_TIMEOUT`.
    async fn exchange(conn: &Connection, payload: &[u8]) -> Result<Vec<u8>, ClientError> {
        let request = async {
            let (mut send, mut recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

            send.write_all(payload).await?;
            send.finish().map_err(|e| anyhow::anyhow!(e))?;

            let response = recv
                .read_to_end(MAX_RESPONSE_SIZE)
                .await
                .map_err(|e| anyhow::anyhow!(e))?;

            Ok::<_, ClientError>(response)
        };

        timeout(EXCHANGE_TIMEOUT, request)
            .await
            .map_err(|_| ClientError::TimeoutError)?
    }

    pub async fn open_bi_stream(
        &self,
    ) -> Result<(iroh::endpoint::SendStream, iroh::endpoint::RecvStream), ClientError> {
        let conn = self.conn_pool.get_connection().await?;
        let (send, recv) = conn.open_bi().await.map_err(|e| anyhow::anyhow!(e))?;

        Ok((send, recv))
    }

    pub async fn close(&self) {
        self.conn_pool.close_all().await;
    }
}

pub async fn create_client(
    server_node_id: Option<&str>,
    server_ticket: Option<&str>,
) -> Result<IrohProxyClient, ClientError> {
    let endpoint_addr = crate::connection_pool::parse_endpoint_addr(server_node_id, server_ticket)?;
    IrohProxyClient::new(endpoint_addr).await
}
