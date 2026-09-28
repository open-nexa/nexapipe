use crate::ClientError;
use crate::client::IrohProxyClient;
use crate::http::{HttpRequest, HttpResponse};
use once_cell::sync::OnceCell;
use std::sync::Arc;
use tokio::runtime::Runtime;
use uniffi::export;

/// One runtime for the whole process.
///
/// iroh drives an endpoint from tasks spawned on the ambient runtime, so a
/// runtime that is created and dropped inside one exported call takes those
/// tasks with it on return: the endpoint handed out by an earlier call stops
/// making progress, and the next call blocks on a connection that is already
/// dead instead of failing. `jni.rs` keeps its runtime for the same reason.
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

fn runtime() -> Result<&'static Runtime, ClientError> {
    RUNTIME
        .get_or_try_init(Runtime::new)
        .map_err(ClientError::IoError)
}

#[export]
pub fn new_client(
    server_node_id: Option<String>,
    server_ticket: Option<String>,
) -> Result<Arc<IrohProxyClient>, ClientError> {
    let rt = runtime()?;

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
    let rt = runtime()?;

    rt.block_on(async move { client.send_request(&request).await })
}

#[export]
pub fn client_send_raw(
    client: Arc<IrohProxyClient>,
    data: Vec<u8>,
) -> Result<Vec<u8>, ClientError> {
    let rt = runtime()?;

    rt.block_on(async move { client.send_raw(&data).await })
}

#[export]
pub fn client_close(client: Arc<IrohProxyClient>) {
    // `()` leaves nowhere to report a failure to, and a runtime that cannot
    // start means there is no endpoint to shut down in the first place.
    if let Ok(rt) = runtime() {
        rt.block_on(async move { client.close().await });
    }
}
