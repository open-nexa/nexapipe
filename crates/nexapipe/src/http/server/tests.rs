//! The tests of the tunnel path.

use super::serve::serve_io;
use super::*;
use futures_util::FutureExt;
use http_body_util::BodyExt;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A backend that answers every request with an empty body.
async fn answering_backend() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let port = listener.local_addr().expect("an address").port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // **Every request on this connection is answered.** The
                // client pools the connection, so the second request may
                // arrive on the one the first request used, and a
                // connection that answers once would leave it hanging.
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    let read = stream.read(&mut byte).await.expect("the request comes in");
                    if read == 0 {
                        break;
                    }
                    head.push(byte[0]);
                    if !head.ends_with(b"\r\n\r\n") {
                        continue;
                    }
                    // The head, and an empty body: what the test is about
                    // is the ids, and a body would only have to be read.
                    let _ = stream
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await;
                    let _ = stream.flush().await;
                    head.clear();
                }
            });
        }
    });

    port
}

/// The context of a connection that serves one host.
fn context_for(port: u16) -> Arc<Context> {
    let route = crate::routes::Route::new(
        "app.test",
        "/",
        true,
        vec![format!("http://127.0.0.1:{port}")],
        crate::lb::LoadBalancingStrategy::RoundRobin,
        crate::config::RouteMode::Http,
        None,
    );
    let config = Arc::new(crate::routes::RoutingTable::new(vec![route]));
    let clients = crate::http::client::BackendClients::new(std::time::Duration::from_secs(5), None)
        .expect("the clients");

    Arc::new(Context {
        config,
        clients: Arc::new(clients),
        peer: "peer.test".to_string(),
        acl: None,
        // The id of the stream. The service replaces it with the id of
        // the request it is serving.
        request_id: "stream-id".to_string(),
        who: crate::conn::peers::PeerIdentity::default(),
    })
}

/// The head of a response, up to the blank line that ends it.
async fn read_head(stream: &mut tokio::io::DuplexStream) -> String {
    let mut head = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        let read = stream.read(&mut byte).await.expect("the answer comes back");
        assert!(read > 0, "the answer ended before its head was whole");
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&head).to_string()
}

/// The value of a header in a response head.
fn header(head: &str, name: &str) -> String {
    head.lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().to_string())
        .unwrap_or_else(|| panic!("the head carries no {name}: {head}"))
}

/// The access lines, once there are `want` of them for this peer.
///
/// The line of a request that was answered is written when its body is
/// over, which is after the answer has been read — so the test waits for
/// it rather than assuming it is there.
async fn wait_for_lines(
    capture: &crate::log::AccessLineCapture,
    peer: &str,
    want: usize,
) -> Vec<String> {
    for _ in 0..200 {
        let lines = capture.lines();
        if lines.iter().filter(|line| line.contains(peer)).count() >= want {
            return lines;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    capture.lines()
}

/// Two requests on one stream get two ids.
///
/// The id belongs to the request. Hyper serves keep-alive requests on one
/// stream, so an id minted per stream would be the id of every request on
/// it: the client would be handed the same `x-request-id` twice, and a
/// client quoting it could not be matched to one log line.
#[tokio::test]
async fn two_requests_on_one_stream_get_two_request_ids() {
    let port = answering_backend().await;
    let ctx = context_for(port);
    let capture = crate::log::capture_access_lines();

    // One stream, and two requests on it.
    let (mut client, server) = tokio::io::duplex(4096);
    let serving = tokio::spawn(async move {
        serve_io(
            hyper_util::rt::TokioIo::new(server),
            std::time::Duration::from_secs(5),
            ctx,
        )
        .await
    });

    client
        .write_all(b"GET /one HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .expect("the first request goes out");
    let first = read_head(&mut client).await;

    client
        .write_all(b"GET /two HTTP/1.1\r\nHost: app.test\r\n\r\n")
        .await
        .expect("the second request goes out");
    let second = read_head(&mut client).await;

    let first_id = header(&first, "x-request-id");
    let second_id = header(&second, "x-request-id");
    assert_ne!(
        first_id, second_id,
        "two requests on one stream were given one id"
    );

    // And the access log has a line for each of them, carrying its own
    // id: the id the client was given is the id of one log line.
    let lines = wait_for_lines(&capture, "peer.test", 2).await;
    let mine: Vec<&String> = lines
        .iter()
        .filter(|line| line.contains("peer.test"))
        .collect();
    assert_eq!(mine.len(), 2, "one access line per request: {lines:?}");
    assert!(
        mine.iter()
            .any(|line| line.contains(&format!("id={first_id}")) && line.contains("/one")),
        "the first request's line does not carry its own id: {mine:?}"
    );
    assert!(
        mine.iter()
            .any(|line| line.contains(&format!("id={second_id}")) && line.contains("/two")),
        "the second request's line does not carry its own id: {mine:?}"
    );

    serving.abort();
}

/// A body that answers its polls from a script.
///
/// The reader is what these tests are about, so the body itself only has
/// to say what it says: nothing here waits for a client.
struct ScriptedBody {
    steps: Vec<Step>,
    at: usize,
}

/// What a scripted body says on one poll.
#[derive(Clone, Copy)]
enum Step {
    /// Not ready yet.
    Pending,
    /// A piece of the body.
    Data(&'static [u8]),
    /// The body failed.
    Failed,
    /// The body is over.
    End,
}

impl ScriptedBody {
    fn new(steps: Vec<Step>) -> Self {
        ScriptedBody { steps, at: 0 }
    }
}

impl hyper::body::Body for ScriptedBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.as_mut().get_mut();
        let step = this.steps.get(this.at).copied();
        this.at += 1;
        match step {
            Some(Step::Pending) => Poll::Pending,
            Some(Step::Data(data)) => {
                Poll::Ready(Some(Ok(Frame::data(bytes::Bytes::copy_from_slice(data)))))
            }
            Some(Step::Failed) => Poll::Ready(Some(Err(std::io::Error::other("the body failed")))),
            Some(Step::End) | None => Poll::Ready(None),
        }
    }
}

/// The body, over a budget of the test's own.
fn body_over_script(
    steps: Vec<Step>,
    budget: Arc<crate::conn::limits::ByteBudget>,
) -> IncomingBody<ScriptedBody> {
    IncomingBody::with_budget(ScriptedBody::new(steps), Duration::from_secs(60), budget)
}

/// The reader goes back when the body is not ready yet.
///
/// The copy that is lent out next has to find the reader: the bytes are
/// on the client's stream once, and a reader that stayed with the task
/// that polled it would take them with it.
#[tokio::test]
async fn the_reader_goes_back_when_the_body_is_not_ready() {
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(1024));
    let body = body_over_script(
        vec![Step::Pending, Step::Data(b"the body"), Step::End],
        budget,
    );

    let mut lent = body.lend();
    let first = lent.frame().now_or_never();
    assert!(first.is_none(), "the body is not ready yet");

    // The reader is back, so the copy lent out next reads the rest.
    let mut next = body.lend();
    let frame = tokio::time::timeout(Duration::from_secs(5), next.frame())
        .await
        .expect("the reader is there")
        .expect("a frame")
        .expect("the frame is not an error");
    assert_eq!(frame.into_data().expect("data").as_ref(), b"the body");
}

/// The reader goes back when the body fails.
///
/// A failed body ends the request, but it does not take the reader with
/// it: the copy that is lent out next is not left waiting for a reader
/// that will never come.
#[tokio::test]
async fn the_reader_goes_back_when_the_body_fails() {
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(1024));
    let body = body_over_script(vec![Step::Failed, Step::End], budget);

    let mut lent = body.lend();
    let outcome = lent.frame().await.expect("a frame");
    assert!(outcome.is_err(), "the body failed");

    let mut next = body.lend();
    let over = tokio::time::timeout(Duration::from_secs(5), next.frame())
        .await
        .expect("the reader is there");
    assert!(over.is_none(), "the body is over");
}

/// The reader goes back when the budget refuses the bytes.
///
/// The bytes the budget will not hold end the body, but the reader is
/// not the body: it goes back into the cell, so the copy lent out next
/// finds it.
#[tokio::test]
async fn the_reader_goes_back_when_the_budget_refuses_the_bytes() {
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(8));
    let body = body_over_script(
        vec![Step::Data(b"0123456789abcdef"), Step::End],
        budget.clone(),
    );

    let mut lent = body.lend();
    let outcome = lent.frame().await.expect("a frame");
    assert!(outcome.is_err(), "a body the budget cannot hold is refused");

    let mut next = body.lend();
    let over = tokio::time::timeout(Duration::from_secs(5), next.frame())
        .await
        .expect("the reader is there");
    assert!(over.is_none(), "the body is over");
    assert_eq!(budget.held(), 0, "the refused bytes are given back");
}

/// A body whose first poll holds until it is let go.
///
/// The reader is only out of the cell between one `take` and its
/// `put_back`, and the two sit inside a single synchronous poll — so the
/// only way another task finds the cell empty is if it polls while this
/// one is inside its poll. Holding the poll open is what makes that
/// window certain rather than a race.
struct BlockingBody {
    /// Tells the other side that the reader is held.
    entered: std::sync::mpsc::Sender<()>,
    /// Lets the poll go on.
    release: std::sync::mpsc::Receiver<()>,
    /// Whether the next poll is the one that waits.
    waits: bool,
}

impl hyper::body::Body for BlockingBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.waits {
            self.waits = false;
            let _ = self.entered.send(());
            let _ = self.release.recv();
        }
        Poll::Ready(None)
    }
}

/// A second poller **waits** for the reader, and is woken when it comes
/// back.
///
/// The reader is shared between the owner of a request and the copy the
/// request carries, and the retry path can have both alive at once. The
/// second one must not park a worker thread on a lock: it registers its
/// waker and is woken when the holder puts the reader back.
///
/// That is the behaviour the cell exists for, and it is the one that was
/// not covered: the reader is only out of the cell for the length of one
/// synchronous poll, so the window is made wide on purpose — the body
/// above holds its poll until it is let go — and the assertions are that
/// the second poller is *waiting* and that it is woken rather than left
/// asleep.
#[tokio::test]
async fn a_second_poller_waits_for_the_reader_and_is_woken_when_it_comes_back() {
    use std::future::Future;

    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let budget = Arc::new(crate::conn::limits::ByteBudget::new(1024));
    let body = Arc::new(IncomingBody::with_budget(
        BlockingBody {
            entered: entered_tx,
            release: release_rx,
            waits: true,
        },
        Duration::from_secs(60),
        budget,
    ));

    // The holder takes the reader and keeps it inside its poll. It runs
    // on a thread of its own, because the poll it is holding blocks.
    let held = body.clone();
    let holder = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime");
        rt.block_on(async move {
            let mut lent = held.lend();
            lent.frame().await
        })
    });

    // Wait until the reader is held.
    entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("the reader is held");

    // The second poller finds the cell empty. Its first poll is made
    // explicitly, so that the waker the cell keeps is this task's own:
    // a waker that is not the task's would wake nothing.
    let (polled_tx, polled_rx) = tokio::sync::oneshot::channel();
    let waiting = body.clone();
    let waiter = tokio::spawn(async move {
        let mut lent = waiting.lend();
        let mut frame = Box::pin(lent.frame());
        let mut polled_tx = Some(polled_tx);
        let first = std::future::poll_fn(|cx| {
            let polled = frame.as_mut().poll(cx);
            // Tell the other side that the cell was found empty.
            if let Some(tx) = polled_tx.take() {
                let _ = tx.send(());
            }
            Poll::Ready(polled)
        })
        .await;
        match first {
            Poll::Pending => frame.await,
            Poll::Ready(value) => value,
        }
    });

    // The poll happened, and the reader was not there.
    tokio::time::timeout(Duration::from_secs(5), polled_rx)
        .await
        .expect("the second poller polled")
        .expect("the second poller said so");
    assert!(
        !waiter.is_finished(),
        "the second poller is waiting for the reader"
    );

    // The reader comes back, and the waiting task is woken.
    release_tx.send(()).expect("the holder is let go");
    let outcome = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the waiting task is woken")
        .expect("the task finished");
    assert!(outcome.is_none(), "the body is over");

    holder.join().expect("the holder finished");
}
