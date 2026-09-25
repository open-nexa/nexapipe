use crate::client::IrohProxyClient;
use crate::http::{HttpRequest, HttpResponse};
use crate::ClientError;
use std::sync::Arc;
use uniffi::export;

#[export]
pub fn new_client(
    server_node_id: Option<String>,
    server_ticket: Option<String>,
) -> Result<Arc<IrohProxyClient>, ClientError> {
    let rt = tokio::runtime::Runtime::new().map_err(ClientError::IoError)?;

    let node_id_str = server_node_id.as_deref();
    let ticket_str = server_ticket.as_deref();

    rt.block_on(async move { crate::client::create_client(node_id_str, ticket_str).await })
        .map(Arc::new)
}

#[export]
pub fn client_node_id(client: Arc<IrohProxyClient>) -> String {
    client.node_id().to_string()
}

#[export]
pub fn client_send_request(
    client: Arc<IrohProxyClient>,
    request: HttpRequest,
) -> Result<HttpResponse, ClientError> {
    let rt = tokio::runtime::Runtime::new().map_err(ClientError::IoError)?;

    rt.block_on(async move { client.send_request(&request).await })
}

#[export]
pub fn client_send_raw(
    client: Arc<IrohProxyClient>,
    data: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    let rt = tokio::runtime::Runtime::new().map_err(ClientError::IoError)?;

    rt.block_on(async move { client.send_raw(&data).await })
}

#[export]
pub fn client_close(client: Arc<IrohProxyClient>) {
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    rt.block_on(async move { client.close().await });
}
