use zeroize::Zeroizing;

use super::{CodecError, SERIALIZED_CAPACITY, WipingBuffer};

/// The message types of the binary form.
pub(super) mod kind {
    pub const START: u8 = 0x01;
    pub const CHALLENGE: u8 = 0x02;
    pub const RESPONSE: u8 = 0x03;
    pub const OK: u8 = 0x04;
    pub const FAILED: u8 = 0x05;
    pub const ENROLL_START: u8 = 0x06;
    pub const ENROLL_ISSUE: u8 = 0x07;
    pub const ENROLL_FAILED: u8 = 0x08;
}

/// The flags of the binary form: one bit per optional field.
pub(super) mod flag {
    /// The message carries a device id.
    pub const DEVICE_ID: u8 = 0b0000_0001;
    /// The message carries a public key.
    pub const PUBLIC_KEY: u8 = 0b0000_0010;
    /// The message announces the protocol version it speaks.
    pub const VERSION: u8 = 0b0000_0100;
}

/// The flags a message type may carry.
///
/// A flag a type has no meaning for is refused rather than ignored: a future
/// version that adds one would otherwise be read as if the field were
/// absent, which is the kind of quiet difference a version byte exists to
/// prevent.
pub(super) fn allowed_flags(kind: u8) -> u8 {
    match kind {
        kind::START => flag::DEVICE_ID | flag::VERSION,
        kind::RESPONSE => flag::DEVICE_ID,
        kind::ENROLL_START => flag::DEVICE_ID | flag::PUBLIC_KEY,
        kind::ENROLL_ISSUE => flag::DEVICE_ID,
        _ => 0,
    }
}

/// Writes the binary form, a field at a time.
///
/// The buffer is a [`WipingBuffer`]: the binary form carries a credential —
/// the enrollment token, the secret the server issues — and the bytes of it
/// are wiped when the writer goes out of scope, and when it outgrows the
/// block it is in.
pub(super) struct Writer {
    bytes: WipingBuffer,
}

impl Default for Writer {
    fn default() -> Self {
        Writer {
            bytes: WipingBuffer::with_capacity(SERIALIZED_CAPACITY),
        }
    }
}

impl Writer {
    pub(super) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(super) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(super) fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    /// A string: a `u16le` length and the UTF-8 bytes.
    ///
    /// Every string in the protocol is short — a client id is 255 bytes at
    /// most, a reason is a sentence — so two bytes of length are enough, and
    /// a string that would not fit is a message this build cannot write
    /// rather than one it writes wrong.
    pub(super) fn string(&mut self, value: &str) -> Result<(), CodecError> {
        let bytes = value.as_bytes();
        let len = u16::try_from(bytes.len()).map_err(|_| {
            CodecError::Binary(format!(
                "a string of {} bytes does not fit the wire format",
                bytes.len()
            ))
        })?;
        self.u16(len);
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// A byte string: a `u32le` length and the bytes.
    pub(super) fn bytes(&mut self, value: &[u8]) -> Result<(), CodecError> {
        let len = u32::try_from(value.len()).map_err(|_| {
            CodecError::Binary(format!(
                "{} bytes of payload do not fit the wire format",
                value.len()
            ))
        })?;
        self.u32(len);
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    /// The bytes written, in a buffer that wipes itself.
    pub(super) fn into_bytes(self) -> Zeroizing<Vec<u8>> {
        self.bytes.into_wiped()
    }
}

/// Reads the binary form, a field at a time.
pub(super) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    /// The next `len` bytes — or an error if there are not that many left.
    ///
    /// The length in the payload is the peer's to write, so it is checked
    /// against what is actually there before anything is allocated for it.
    pub(super) fn take(&mut self, len: usize) -> Result<&'a [u8], CodecError> {
        let end = self.at.checked_add(len).ok_or_else(|| {
            CodecError::Binary("the payload claims more bytes than it has".to_string())
        })?;
        if end > self.bytes.len() {
            return Err(CodecError::Binary(format!(
                "the payload ends after {} of the {len} bytes it claims",
                self.bytes.len() - self.at
            )));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    pub(super) fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    pub(super) fn u16(&mut self) -> Result<u16, CodecError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub(super) fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub(super) fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub(super) fn i64(&mut self) -> Result<i64, CodecError> {
        Ok(self.u64()? as i64)
    }

    pub(super) fn string(&mut self) -> Result<String, CodecError> {
        let len = self.u16()? as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| CodecError::Binary("a string is not UTF-8".to_string()))
    }

    pub(super) fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}
