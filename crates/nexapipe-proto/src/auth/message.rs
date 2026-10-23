use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secret::SecretString;

use super::codec::{Reader, Writer, allowed_flags, flag, kind};
use super::{
    Algorithm, CodecError, Format, SERIALIZED_CAPACITY, VERSION_BINARY, VERSION_JSON, WipingBuffer,
};

/// Messages exchanged during authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMessage {
    /// Client initiates authentication
    #[serde(rename = "AUTH_START")]
    Start {
        client_id: String,
        timestamp: i64,
        /// Which of this client's devices is authenticating. `None` is the
        /// device that was never given one, which is the only kind that
        /// existed before a client could have several.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// The version of the protocol this client speaks, when it speaks more
        /// than one.
        ///
        /// **Absent** is a client that does not: the server answers in the
        /// old form and the two never leave it. That is what an old client
        /// sends, and it is why the field is optional — a peer that predates
        /// it drops the field and is understood as one that has only the old
        /// form.
        ///
        /// A new client announces the best version it speaks here, because
        /// this message has to be readable by a server that predates the
        /// version byte: the announcement is inside the JSON, where an old
        /// server ignores it, rather than in front of it, where an old server
        /// would choke on it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        version: Option<u8>,
    },
    /// Server sends challenge nonce
    #[serde(rename = "AUTH_CHALLENGE")]
    Challenge { nonce: Vec<u8> },
    /// Client responds with TOTP code
    #[serde(rename = "AUTH_RESPONSE")]
    Response {
        client_id: String,
        timestamp: i64,
        /// The current TOTP code. Empty when the device is known by a key:
        /// there is no code for it, and the signature is the whole proof.
        totp_code: String,
        /// Over `nonce || timestamp.to_le_bytes()`: HMAC-SHA256 keyed with the
        /// client's TOTP secret, or an Ed25519 signature by the device's key
        /// when the server holds one for it. Both prove the same thing — this
        /// client saw this connection's challenge at this time — so which one
        /// this is depends on the receiving end's credential, not on anything
        /// said here.
        signature: Vec<u8>,
        /// The same device [`AuthMessage::Start`] named. It is signed over
        /// nowhere, so it is not proof of anything on its own — what it does is
        /// say which device's credential the response is to be checked against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    /// Server confirms authentication success
    #[serde(rename = "AUTH_OK")]
    Ok,
    /// Server rejects authentication
    #[serde(rename = "AUTH_FAILED")]
    Failed { reason: String },
    /// Client offers a one-time enrollment token instead of a secret
    #[serde(rename = "ENROLL_START")]
    EnrollStart {
        client_id: String,
        /// The token out of a `v=2` invite; valid until it has been exchanged
        /// once.
        ///
        /// A [`SecretString`]: an unspent token is a credential, and this one is
        /// wiped when the message is dropped.
        token: SecretString,
        /// The name the device asking to enroll wants to be issued under. The
        /// server is free to answer with the same name or refuse; the token is
        /// what authorizes the exchange, not this field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// The device key this client is asking to be issued under, as the
        /// public half of an Ed25519 key pair in lowercase hex.
        ///
        /// Absent for a client that has no key to offer, which is every client
        /// built before keys existed; a server that predates this field ignores
        /// it and issues a secret as before, so a client offering one has to
        /// keep working with what it is given. Present, it must arrive with a
        /// device name — a key belongs to one device, and the device that names
        /// none answers with the client's shared secret, which has no key to
        /// check against.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        public_key: Option<String>,
    },
    /// Server issues the credential the token was standing in for
    #[serde(rename = "ENROLL_ISSUE")]
    EnrollIssue {
        client_id: String,
        /// Base32-encoded secret, generated fresh for this enrollment. Empty
        /// when the device was issued a key instead: the server recorded the
        /// public key the client offered, and this device will prove itself
        /// with a signature rather than a code.
        ///
        /// A [`SecretString`]: a credential that has just been issued is the
        /// most valuable thing this process holds.
        secret: SecretString,
        /// The algorithm the issued secret is to be used with.
        ///
        /// A closed set, and it was a string: the name was free-form on the
        /// wire, so a peer had to decide what to do with a name nobody
        /// supports. The names are the canonical ones, and they are read in
        /// any case.
        algorithm: Algorithm,
        digits: u32,
        period: u64,
        /// The device this credential was issued for, which is how the client
        /// learns the name it will have to send back. Absent when the server
        /// answered an enrollment that named no device — a client that predates
        /// per-device credentials reads that as "the shared one".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    /// Server refuses the token
    #[serde(rename = "ENROLL_FAILED")]
    EnrollFailed { reason: String },
}

impl AuthMessage {
    /// Serialize message to bytes.
    ///
    /// The buffer is wiped when it goes out of scope. A message may carry a
    /// credential — the enrollment token of an [`AuthMessage::EnrollStart`],
    /// the secret an [`AuthMessage::EnrollIssue`] hands out — and the
    /// serialized copy of it used to be a plain `Vec<u8>`: the caller wrote it
    /// to the socket and dropped it, and the bytes stayed in the heap for the
    /// allocator to hand out again.
    ///
    /// The credential itself is a [`SecretString`], and that one *is* wiped —
    /// but only the copy the wrapper holds. This is the copy that never left
    /// the process, and it was the one nobody remembered.
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        let mut bytes = WipingBuffer::with_capacity(SERIALIZED_CAPACITY);
        serde_json::to_writer(&mut bytes, self)?;
        Ok(bytes.into_wiped())
    }

    /// Deserialize message from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// The message as it travels, in the form asked for.
    ///
    /// The version byte is part of the payload: the frame around it is
    /// `[u32le length][payload]`, and the length covers the byte.
    ///
    /// The payload is wiped when it goes out of scope, for the same reason
    /// [`AuthMessage::to_bytes`] wipes its buffer: two of the messages carry a
    /// credential.
    pub fn to_payload(&self, format: Format) -> Result<Zeroizing<Vec<u8>>, CodecError> {
        match format {
            Format::LegacyJson => self.to_bytes().map_err(CodecError::Json),
            Format::Json => {
                let mut payload = WipingBuffer::with_capacity(SERIALIZED_CAPACITY);
                payload.push(VERSION_JSON);
                serde_json::to_writer(&mut payload, self).map_err(CodecError::Json)?;
                Ok(payload.into_wiped())
            }
            Format::Binary => {
                let mut writer = Writer::default();
                writer.u8(VERSION_BINARY);
                self.write_binary(&mut writer)?;
                Ok(writer.into_bytes())
            }
        }
    }

    /// The message a payload carries, and the form it was in.
    ///
    /// The form is read from the payload's first byte, and a payload that
    /// does not start with a version byte is the JSON form — which is what
    /// every peer sent before the version byte existed.
    pub fn from_payload(payload: &[u8]) -> Result<(Self, Format), CodecError> {
        match payload.first() {
            None => Err(CodecError::Binary("the payload is empty".to_string())),
            Some(&VERSION_JSON) => Ok((
                serde_json::from_slice(&payload[1..]).map_err(CodecError::Json)?,
                Format::Json,
            )),
            Some(&VERSION_BINARY) => Ok((Self::from_binary(&payload[1..])?, Format::Binary)),
            Some(_) => Ok((
                serde_json::from_slice(payload).map_err(CodecError::Json)?,
                Format::LegacyJson,
            )),
        }
    }

    /// The version this message announces, if it announces one.
    ///
    /// Only [`AuthMessage::Start`] announces: it is the first message of a
    /// handshake, and it has to be one an old peer can read.
    pub fn announced_version(&self) -> Option<u8> {
        match self {
            AuthMessage::Start { version, .. } => *version,
            _ => None,
        }
    }

    /// The message in the binary form, written into the writer.
    ///
    /// The buffer is wiped when it goes out of scope, like the JSON form's:
    /// the binary form carries the same credential.
    fn write_binary(&self, writer: &mut Writer) -> Result<(), CodecError> {
        match self {
            AuthMessage::Start {
                client_id,
                timestamp,
                device_id,
                version,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                if version.is_some() {
                    flags |= flag::VERSION;
                }
                writer.u8(kind::START);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.i64(*timestamp);
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
                if let Some(version) = version {
                    writer.u8(*version);
                }
            }
            AuthMessage::Challenge { nonce } => {
                writer.u8(kind::CHALLENGE);
                writer.u8(0);
                writer.bytes(nonce)?;
            }
            AuthMessage::Response {
                client_id,
                timestamp,
                totp_code,
                signature,
                device_id,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                writer.u8(kind::RESPONSE);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.i64(*timestamp);
                writer.string(totp_code)?;
                writer.bytes(signature)?;
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
            }
            AuthMessage::Ok => {
                writer.u8(kind::OK);
                writer.u8(0);
            }
            AuthMessage::Failed { reason } => {
                writer.u8(kind::FAILED);
                writer.u8(0);
                writer.string(reason)?;
            }
            AuthMessage::EnrollStart {
                client_id,
                token,
                device_id,
                public_key,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                if public_key.is_some() {
                    flags |= flag::PUBLIC_KEY;
                }
                writer.u8(kind::ENROLL_START);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.string(token.expose_secret())?;
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
                if let Some(public_key) = public_key {
                    writer.string(public_key)?;
                }
            }
            AuthMessage::EnrollIssue {
                client_id,
                secret,
                algorithm,
                digits,
                period,
                device_id,
            } => {
                let mut flags = 0;
                if device_id.is_some() {
                    flags |= flag::DEVICE_ID;
                }
                writer.u8(kind::ENROLL_ISSUE);
                writer.u8(flags);
                writer.string(client_id)?;
                writer.string(secret.expose_secret())?;
                writer.u8(algorithm.to_byte());
                writer.u32(*digits);
                writer.u64(*period);
                if let Some(device_id) = device_id {
                    writer.string(device_id)?;
                }
            }
            AuthMessage::EnrollFailed { reason } => {
                writer.u8(kind::ENROLL_FAILED);
                writer.u8(0);
                writer.string(reason)?;
            }
        }
        Ok(())
    }

    /// The message a binary payload carries.
    fn from_binary(payload: &[u8]) -> Result<Self, CodecError> {
        let mut reader = Reader::new(payload);
        let kind = reader.u8()?;
        let flags = reader.u8()?;
        if flags & !allowed_flags(kind) != 0 {
            return Err(CodecError::Binary(format!(
                "a message of type {kind:#04x} carries flags {flags:#04x} that it has no meaning for"
            )));
        }
        match kind {
            kind::START => {
                let client_id = reader.string()?;
                let timestamp = reader.i64()?;
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                let version = if flags & flag::VERSION != 0 {
                    Some(reader.u8()?)
                } else {
                    None
                };
                Ok(AuthMessage::Start {
                    client_id,
                    timestamp,
                    device_id,
                    version,
                })
            }
            kind::CHALLENGE => {
                let nonce = reader.bytes()?;
                Ok(AuthMessage::Challenge { nonce })
            }
            kind::RESPONSE => {
                let client_id = reader.string()?;
                let timestamp = reader.i64()?;
                let totp_code = reader.string()?;
                let signature = reader.bytes()?;
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                Ok(AuthMessage::Response {
                    client_id,
                    timestamp,
                    totp_code,
                    signature,
                    device_id,
                })
            }
            kind::OK => Ok(AuthMessage::Ok),
            kind::FAILED => {
                let reason = reader.string()?;
                Ok(AuthMessage::Failed { reason })
            }
            kind::ENROLL_START => {
                let client_id = reader.string()?;
                let token = SecretString::new(reader.string()?);
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                let public_key = if flags & flag::PUBLIC_KEY != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                Ok(AuthMessage::EnrollStart {
                    client_id,
                    token,
                    device_id,
                    public_key,
                })
            }
            kind::ENROLL_ISSUE => {
                let client_id = reader.string()?;
                let secret = SecretString::new(reader.string()?);
                let algorithm = Algorithm::from_byte(reader.u8()?).ok_or_else(|| {
                    CodecError::Binary("the algorithm is not one this build knows".to_string())
                })?;
                let digits = reader.u32()?;
                let period = reader.u64()?;
                let device_id = if flags & flag::DEVICE_ID != 0 {
                    Some(reader.string()?)
                } else {
                    None
                };
                Ok(AuthMessage::EnrollIssue {
                    client_id,
                    secret,
                    algorithm,
                    digits,
                    period,
                    device_id,
                })
            }
            kind::ENROLL_FAILED => {
                let reason = reader.string()?;
                Ok(AuthMessage::EnrollFailed { reason })
            }
            other => Err(CodecError::Binary(format!(
                "unknown message type {other:#04x}"
            ))),
        }
    }
}
