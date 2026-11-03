//! The device the stack is bound to: IP frames in, IP frames out.
//!
//! smoltcp talks to the outside world through a [`Device`], and this is that
//! device for the TUN proxy: the frames the device sends are the frames the
//! tunnel carries, and the frames the tunnel brings are the frames the
//! device receives. There is no packet socket and no kernel buffer in
//! between — the queues here are the whole interface.

use std::collections::VecDeque;

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use tokio::sync::mpsc;

/// The device the smoltcp interface is bound to.
pub(super) struct FrameDevice {
    /// The frames waiting to be handed to the stack.
    rx: VecDeque<Vec<u8>>,
    /// Where the frames the stack produces go.
    tx: mpsc::Sender<Vec<u8>>,
    /// The largest frame the device carries.
    mtu: usize,
}

impl FrameDevice {
    /// A device with nothing in it.
    pub(super) fn new(tx: mpsc::Sender<Vec<u8>>, mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx,
            mtu,
        }
    }

    /// A frame on its way into the stack.
    pub(super) fn push(&mut self, frame: Vec<u8>) {
        self.rx.push_back(frame);
    }
}

impl Device for FrameDevice {
    type RxToken<'a> = FrameRxToken;
    type TxToken<'a> = FrameTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // Room for the answer is reserved *before* the frame is taken. If the
        // queue out is full, the frame stays where it is and the stack tries
        // again — rather than being taken and then having nowhere to go.
        let permit = self.tx.try_reserve().ok()?;
        let frame = self.rx.pop_front()?;
        Some((FrameRxToken { frame }, FrameTxToken { permit }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        // No room for the frame means the stack keeps it and sends it again.
        let permit = self.tx.try_reserve().ok()?;
        Some(FrameTxToken { permit })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

/// A frame on its way into the stack.
pub(super) struct FrameRxToken {
    frame: Vec<u8>,
}

impl RxToken for FrameRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

/// A frame on its way out of the stack, with the room it was promised.
pub(super) struct FrameTxToken<'a> {
    permit: mpsc::Permit<'a, Vec<u8>>,
}

impl TxToken for FrameTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.permit.send(buffer);
        result
    }
}
