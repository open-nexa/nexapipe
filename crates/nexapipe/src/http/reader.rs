//! The reader a request's body is shared through.
//!
//! The body of a request is read once and may be sent again, so the reader
//! that carries it is shared by the request that owns the body and by the copy
//! the request carries.
//!
//! **The share must not cost a thread.** A `std::sync::Mutex` held for the
//! length of a poll parks the worker thread every other task on that runtime
//! is scheduled on. So the reader **leaves the cell** instead of being locked
//! in it: the task that has it owns it outright, and a task that finds the
//! cell empty registers its waker and is woken when the holder puts the
//! reader back.
//!
//! What this promises is that the lock is **never held across the poll of
//! the body**: the cell's own lock is still taken, but only for the swap —
//! nanoseconds — and never while the body is being read. A task that finds
//! the cell empty does not take the lock at all; it registers its waker and
//! waits to be woken.

use std::sync::MutexGuard;
use std::task::{Context, Waker};

/// The reader, shared by the owner of a request and the copy it carries.
pub(super) struct SharedReader<B> {
    /// The cell the reader lives in.
    cell: std::sync::Mutex<ReaderCell<B>>,
}

/// What the cell holds.
struct ReaderCell<B> {
    /// The reader, while no task holds it.
    reader: Option<B>,
    /// The tasks waiting for it.
    ///
    /// A list rather than a single slot: the owner of a request and the copy
    /// it carries may both want the reader, and a cell that kept one waker
    /// would drop the other — and that task would never wake.
    waiters: Vec<Waker>,
}

impl<B> SharedReader<B> {
    /// A reader, and the cell it lives in.
    pub(super) fn new(reader: B) -> Self {
        Self {
            cell: std::sync::Mutex::new(ReaderCell {
                reader: Some(reader),
                waiters: Vec::new(),
            }),
        }
    }

    /// The reader, if no task holds it.
    ///
    /// `None` means another task has it: the waker of this task is then
    /// registered, and the task is woken when the reader comes back.
    ///
    /// **The check for the reader and the storing of the waker are one
    /// step.** A reader that came back between them would find no waiter to
    /// wake, and the task waiting for it would sleep for ever — so the two
    /// happen under one lock, and neither can happen without the other.
    pub(super) fn take(&self, cx: &mut Context<'_>) -> Option<B> {
        let mut cell = self.lock();
        if let Some(reader) = cell.reader.take() {
            return Some(reader);
        }
        let waker = cx.waker();
        // The same task, with the same waker, is one waiter: a list that grew
        // under it would be a list nobody prunes.
        if !cell.waiters.iter().any(|waiting| waiting.will_wake(waker)) {
            cell.waiters.push(waker.clone());
        }
        None
    }

    /// The reader goes back into the cell, and whoever was waiting for it is
    /// woken.
    ///
    /// The wakers are woken with the cell unlocked: a woken task looks for
    /// the reader at once, and it must not find the lock held.
    pub(super) fn put_back(&self, reader: B) {
        let waiters = {
            let mut cell = self.lock();
            debug_assert!(
                cell.reader.is_none(),
                "the reader is in one place at a time"
            );
            cell.reader = Some(reader);
            std::mem::take(&mut cell.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    /// The cell, with the lock taken.
    ///
    /// A poisoned lock is not one this code causes — nothing in the cell
    /// panics — but a lock that is poisoned anyway must not stop a body from
    /// being read.
    fn lock(&self) -> MutexGuard<'_, ReaderCell<B>> {
        self.cell
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;

    use super::*;

    /// A body that is never ready.
    ///
    /// The reader is what the tests are about, so the body itself only has to
    /// exist.
    #[derive(Default)]
    struct QuietBody;

    impl hyper::body::Body for QuietBody {
        type Data = bytes::Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    /// A waker that counts how many times it was woken.
    ///
    /// The wake is the whole of what a waiting task is promised: the reader
    /// is back, so the task may look for it again.
    struct CountingWaker(Arc<AtomicUsize>);

    impl std::task::Wake for CountingWaker {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }

        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A waker that counts its wakes.
    fn counting_waker(woken: &Arc<AtomicUsize>) -> Waker {
        Waker::from(Arc::new(CountingWaker(woken.clone())))
    }

    /// A task that finds the cell empty is woken when the reader comes back.
    ///
    /// The holder has the reader, so the waiter has to wait; the promise is
    /// that it is woken the moment the reader is back, rather than sleeping
    /// until something else happens to wake it.
    #[test]
    fn a_waiter_is_woken_when_the_reader_comes_back() {
        let reader = Arc::new(SharedReader::new(QuietBody));
        let woken = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&woken);
        let mut cx = Context::from_waker(&waker);

        // The holder takes the reader.
        let held = reader.take(&mut cx).expect("the reader is free");
        assert!(
            reader.take(&mut cx).is_none(),
            "the cell is empty while the holder has the reader"
        );

        // The holder gives it back, and the waiter is woken.
        reader.put_back(held);
        assert_eq!(
            woken.load(Ordering::SeqCst),
            1,
            "the waiter was not woken when the reader came back"
        );
    }

    /// A reader that comes back while a waiter is registering still wakes the
    /// waiter.
    ///
    /// The window is between the waiter's check for the reader and the
    /// storing of its waker: a reader that came back in it would find no
    /// waiter to wake, and the task would sleep for ever. The check and the
    /// registration are one step here, so the reader cannot come back
    /// between them — and this test races the two against each other to say
    /// so.
    #[test]
    fn a_reader_that_comes_back_while_a_waiter_registers_wakes_the_waiter() {
        for _ in 0..200 {
            let reader = Arc::new(SharedReader::new(QuietBody));
            let woken = Arc::new(AtomicUsize::new(0));
            let waker = counting_waker(&woken);
            let mut cx = Context::from_waker(&waker);

            // The holder has the reader, and gives it back while the waiter
            // is looking for it.
            let held = reader.take(&mut cx).expect("the reader is free");
            let holder = reader.clone();
            let given_back = std::thread::spawn(move || holder.put_back(held));

            let found = reader.take(&mut cx);
            given_back.join().expect("the holder gives the reader back");

            if found.is_none() {
                assert_eq!(
                    woken.load(Ordering::SeqCst),
                    1,
                    "the waiter found the cell empty and was never woken"
                );
            }
        }
    }

    /// Two waiters are both woken.
    ///
    /// The owner of a request and the copy it carries may both want the
    /// reader, and a cell that kept one waker would drop the other — and
    /// that task would never wake.
    #[test]
    fn two_waiters_are_both_woken() {
        let reader = Arc::new(SharedReader::new(QuietBody));
        let first_woken = Arc::new(AtomicUsize::new(0));
        let second_woken = Arc::new(AtomicUsize::new(0));
        let first_waker = counting_waker(&first_woken);
        let second_waker = counting_waker(&second_woken);
        let mut first = Context::from_waker(&first_waker);
        let mut second = Context::from_waker(&second_waker);

        let held = reader.take(&mut first).expect("the reader is free");
        assert!(
            reader.take(&mut first).is_none(),
            "the first task waits for the reader"
        );
        assert!(
            reader.take(&mut second).is_none(),
            "the second task waits for the reader"
        );

        reader.put_back(held);
        assert_eq!(
            first_woken.load(Ordering::SeqCst),
            1,
            "the first waiter was not woken"
        );
        assert_eq!(
            second_woken.load(Ordering::SeqCst),
            1,
            "the second waiter was not woken"
        );
    }

    /// A task that is polled again is one waiter, not several.
    ///
    /// The same task, with the same waker, is one waiter: a list that grew
    /// under it would be a list nobody ever prunes.
    #[test]
    fn a_task_polled_again_is_one_waiter() {
        let reader = Arc::new(SharedReader::new(QuietBody));
        let woken = Arc::new(AtomicUsize::new(0));
        let waker = counting_waker(&woken);
        let mut cx = Context::from_waker(&waker);

        let held = reader.take(&mut cx).expect("the reader is free");
        for _ in 0..10 {
            assert!(
                reader.take(&mut cx).is_none(),
                "the reader is held by the other task"
            );
        }
        assert_eq!(
            reader.lock().waiters.len(),
            1,
            "a task that is polled again is one waiter"
        );

        reader.put_back(held);
        assert_eq!(woken.load(Ordering::SeqCst), 1, "the waiter was woken once");
    }
}
