use super::codec::kind;
use super::*;
use crate::secret::SecretString;

/// The heap, watched.
///
/// The defect this fixes is a credential that survives in the heap after
/// the message that carried it is gone, and the only way to *show* that it
/// does not survive is to look at the memory after it is freed. The
/// allocator is where that memory comes back from, so the allocator is
/// where the proof is: a block on its way out that still holds the
/// credential is a block the credential survived in.
mod heap {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The bytes the probe is watching for.
    ///
    /// A string no other test uses, so a block that holds it is one this
    /// test made.
    pub const NEEDLE: &str = "nexapipe-heap-probe-4f2a9c";

    /// The turn the tests that watch the heap take.
    ///
    /// The probe watches every block the allocator frees, in the whole
    /// process, and the tests that use it share one needle. Two of them
    /// watching at once would see each other's blocks: the bytes a test
    /// reads are dropped outside its own watched window — a test that
    /// reads a message off the wire holds those bytes for the length of
    /// the test — and the other test, watching at that moment, finds the
    /// needle in them and reports a leak that is not there.
    ///
    /// The turn is held for the whole test, so the needle-bearing data of
    /// one test is gone before the next one starts watching.
    pub static LOCK: Mutex<()> = Mutex::new(());

    /// Whether the probe is watching.
    static WATCHING: AtomicBool = AtomicBool::new(false);

    /// Whether the needle was seen in a block on its way out.
    static FOUND: AtomicBool = AtomicBool::new(false);

    /// The allocator that watches.
    struct Probe;

    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            scan(ptr, layout.size());
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc_zeroed(layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            scan(ptr, layout.size());
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static PROBE: Probe = Probe;

    /// Looks for the needle in a block that is about to be freed.
    ///
    /// The block is read a byte at a time with `read_volatile` rather
    /// than through a slice: the tail of a buffer past its length was
    /// never written, and a reference to it would be a reference to
    /// uninitialized memory.
    fn scan(ptr: *mut u8, len: usize) {
        if !WATCHING.load(Ordering::Relaxed) || len < NEEDLE.len() {
            return;
        }
        let needle = NEEDLE.as_bytes();
        for start in 0..=(len - needle.len()) {
            let mut matched = true;
            for (offset, expected) in needle.iter().enumerate() {
                // SAFETY: `ptr` is the block that is being freed, `start`
                // is at most `len - needle.len()` and `offset` is at most
                // `needle.len() - 1`, so the byte read is inside the
                // block. The read is volatile, so the compiler does not
                // assume anything about the bytes it reads.
                let byte = unsafe { ptr.add(start + offset).read_volatile() };
                if byte != *expected {
                    matched = false;
                    break;
                }
            }
            if matched {
                FOUND.store(true, Ordering::SeqCst);
                return;
            }
        }
    }

    /// Runs `body` with the heap watched, and says whether the needle was
    /// left behind in it.
    pub fn watched<R>(body: impl FnOnce() -> R) -> bool {
        WATCHING.store(true, Ordering::SeqCst);
        FOUND.store(false, Ordering::SeqCst);
        body();
        WATCHING.store(false, Ordering::SeqCst);
        !FOUND.load(Ordering::SeqCst)
    }
}

/// The JSON of a message, as text.
///
/// The buffer a message is serialized into wipes itself, so a test that
/// wants to read the JSON copies it out — which is what a test may do and
/// what the code may not.
fn json_of(message: &AuthMessage) -> String {
    String::from_utf8(message.to_bytes().expect("serializable").to_vec()).expect("utf-8")
}

/// The wire format, byte for byte.
///
/// The handshake used to be written down twice, and these strings are what
/// the other copy produced — dumped from the code as it was before the
/// move, not from the code as it is now. A message that came out
/// differently would be a handshake that dies on its first message, and
/// the only thing that would notice is a peer built against the old
/// format.
///
/// So this is the whole contract, in one list.
#[test]
fn every_message_keeps_its_wire_format() {
    let messages = vec![
        (
            AuthMessage::Start {
                client_id: "c".to_string(),
                timestamp: 7,
                device_id: None,
                version: None,
            },
            r#"{"type":"AUTH_START","client_id":"c","timestamp":7}"#,
        ),
        (
            AuthMessage::Start {
                client_id: "c".to_string(),
                timestamp: 7,
                device_id: Some("laptop".to_string()),
                version: None,
            },
            r#"{"type":"AUTH_START","client_id":"c","timestamp":7,"device_id":"laptop"}"#,
        ),
        (
            AuthMessage::Challenge {
                nonce: vec![1, 2, 3],
            },
            r#"{"type":"AUTH_CHALLENGE","nonce":[1,2,3]}"#,
        ),
        (
            AuthMessage::Response {
                client_id: "c".to_string(),
                timestamp: 7,
                totp_code: "123456".to_string(),
                signature: vec![9],
                device_id: None,
            },
            r#"{"type":"AUTH_RESPONSE","client_id":"c","timestamp":7,"totp_code":"123456","signature":[9]}"#,
        ),
        (
            AuthMessage::Response {
                client_id: "c".to_string(),
                timestamp: 7,
                totp_code: "123456".to_string(),
                signature: vec![9],
                device_id: Some("laptop".to_string()),
            },
            r#"{"type":"AUTH_RESPONSE","client_id":"c","timestamp":7,"totp_code":"123456","signature":[9],"device_id":"laptop"}"#,
        ),
        (AuthMessage::Ok, r#"{"type":"AUTH_OK"}"#),
        (
            AuthMessage::Failed {
                reason: "no".to_string(),
            },
            r#"{"type":"AUTH_FAILED","reason":"no"}"#,
        ),
        (
            AuthMessage::EnrollStart {
                client_id: "c".to_string(),
                token: SecretString::new("tok".to_string()),
                device_id: None,
                public_key: None,
            },
            r#"{"type":"ENROLL_START","client_id":"c","token":"tok"}"#,
        ),
        (
            AuthMessage::EnrollStart {
                client_id: "c".to_string(),
                token: SecretString::new("tok".to_string()),
                device_id: Some("laptop".to_string()),
                public_key: Some("abcd".to_string()),
            },
            r#"{"type":"ENROLL_START","client_id":"c","token":"tok","device_id":"laptop","public_key":"abcd"}"#,
        ),
        (
            AuthMessage::EnrollIssue {
                client_id: "c".to_string(),
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                device_id: None,
            },
            r#"{"type":"ENROLL_ISSUE","client_id":"c","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","digits":6,"period":30}"#,
        ),
        (
            AuthMessage::EnrollIssue {
                client_id: "c".to_string(),
                secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
                algorithm: Algorithm::Sha1,
                digits: 6,
                period: 30,
                device_id: Some("laptop".to_string()),
            },
            r#"{"type":"ENROLL_ISSUE","client_id":"c","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha1","digits":6,"period":30,"device_id":"laptop"}"#,
        ),
        (
            AuthMessage::EnrollFailed {
                reason: "no".to_string(),
            },
            r#"{"type":"ENROLL_FAILED","reason":"no"}"#,
        ),
    ];

    for (message, wire) in messages {
        let json = json_of(&message);
        assert_eq!(json, wire, "the wire format of {message:?} changed");
    }
}

/// The tag is what the other side switches on, so the names are part of the
/// contract with `crates/nexapipe-client/src/auth.rs`, which spells them
/// out again. A rename here that misses there is a handshake that dies on
/// the first message.
#[test]
fn enrollment_messages_keep_their_wire_names() {
    let start = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new("tok".to_string()),
        device_id: None,
        public_key: None,
    };
    let json = json_of(&start);
    assert!(json.contains(r#""type":"ENROLL_START""#), "{json}");
    assert_eq!(
        AuthMessage::from_bytes(json.as_bytes())
            .unwrap()
            .to_bytes()
            .unwrap(),
        start.to_bytes().unwrap()
    );

    let issue = AuthMessage::EnrollIssue {
        client_id: "client-001".to_string(),
        secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        device_id: None,
    };
    let json = json_of(&issue);
    assert!(json.contains(r#""type":"ENROLL_ISSUE""#), "{json}");

    let failed = AuthMessage::EnrollFailed {
        reason: "no".to_string(),
    };
    let json = json_of(&failed);
    assert!(json.contains(r#""type":"ENROLL_FAILED""#), "{json}");
}

/// The credential travels as the plain string it always was.
///
/// The token and the secret are `Secret`s now, and a `Secret` that
/// serialized differently would break every peer built before it: the
/// field names and the spelling of the value are the contract, and the
/// wrapper changes neither.
#[test]
fn a_credential_travels_as_the_plain_string_it_always_was() {
    let start = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new("tok".to_string()),
        device_id: None,
        public_key: None,
    };
    let json = json_of(&start);
    assert!(json.contains(r#""token":"tok""#), "{json}");

    let issue = AuthMessage::EnrollIssue {
        client_id: "client-001".to_string(),
        secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        device_id: None,
    };
    let json = json_of(&issue);
    assert!(json.contains(r#""secret":"JBSWY3DPEHPK3PXP""#), "{json}");
}

/// The credential does not survive in the buffer it was serialized into.
///
/// The credential is a `Secret`, and the `Secret` wipes itself — but the
/// *serialized* copy was a plain `Vec<u8>` that nobody wiped. The caller
/// wrote it to the socket and dropped it, and the bytes stayed in the heap
/// for the allocator to hand out again: a core dump, a swap file or a read
/// of `/proc/<pid>/mem` finds the token there long after the handshake
/// that needed it.
///
/// This is the proof that it does not: the heap is watched while the
/// message is serialized and dropped, and a block on its way out that
/// still holds the credential fails the test.
#[test]
fn the_serialized_credential_does_not_survive_in_the_heap() {
    // The turn is taken before anything else, so it is given up last:
    // the data this test holds has to be gone before another test starts
    // watching.
    let _turn = heap::LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let start = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new(heap::NEEDLE.to_string()),
        device_id: None,
        public_key: None,
    };
    let issue = AuthMessage::EnrollIssue {
        client_id: "client-001".to_string(),
        secret: SecretString::new(heap::NEEDLE.to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        device_id: None,
    };
    // A credential long enough that the buffer has to grow while it is
    // written — the case where a `Vec` hands the block it outgrows back to
    // the allocator without wiping it.
    let long = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new(heap::NEEDLE.repeat(400)),
        device_id: None,
        public_key: None,
    };

    let clean = heap::watched(|| {
        // Every form a message travels in, and the message itself.
        drop(start.to_bytes().expect("serializable"));
        drop(start.to_payload(Format::Json).expect("writable"));
        drop(start.to_payload(Format::Binary).expect("writable"));
        drop(issue.to_bytes().expect("serializable"));
        drop(issue.to_payload(Format::Json).expect("writable"));
        drop(issue.to_payload(Format::Binary).expect("writable"));
        drop(long.to_bytes().expect("serializable"));
        drop(long.to_payload(Format::Json).expect("writable"));
        drop(long.to_payload(Format::Binary).expect("writable"));
        drop(start);
        drop(issue);
        drop(long);
    });

    assert!(
        clean,
        "the credential was still in a freed block of the heap"
    );
}

/// The credential does not survive when the serialization fails either.
///
/// A message can fail halfway through being written: the credential is
/// written first, and the field behind it can be one the wire format
/// cannot hold. The buffer is dropped on the way out of that failure, and
/// a buffer that is only wiped on the success path leaves the credential
/// in the heap — which is the one thing the buffer is here to prevent.
///
/// The failure is forced with a device id too long for the wire format:
/// it is written after the token, and the length check fails on it.
#[test]
fn the_serialized_credential_does_not_survive_when_the_serialization_fails() {
    let _turn = heap::LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let start = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new(heap::NEEDLE.to_string()),
        device_id: Some("x".repeat(70_000)),
        public_key: None,
    };

    let clean = heap::watched(|| {
        let result = start.to_payload(Format::Binary);
        assert!(result.is_err(), "the message is too long to be written");
        drop(result);
        drop(start);
    });

    assert!(
        clean,
        "the credential was still in a freed block of the heap after the serialization failed"
    );
}

/// The credential does not survive in the heap on the way in either.
///
/// The JSON form is the one that has to be checked: `AuthMessage` is a
/// tagged enum, and a tagged enum is read by buffering the fields before
/// the variant is known — so the question is whether the buffered value
/// reaches the [`SecretString`] by a copy or by a move. It is a move:
/// serde hands the buffered string straight to the wrapper, and the one
/// allocation that holds the credential is the wrapper's, which wipes
/// itself.
///
/// The binary form is read the same way: the reader copies the bytes out
/// of the payload and hands them to the wrapper, and there is no third
/// copy of it anywhere.
///
/// What this does *not* cover is the caller's own buffer: the payload the
/// message was read out of belongs to whoever read it off the socket, and
/// wiping that is that reader's business.
#[test]
fn the_received_credential_does_not_survive_in_the_heap() {
    // The turn is taken before the bytes this test reads are built, so
    // they are dropped while this test still holds it — they hold the
    // needle, and another test watching the heap would find it in them.
    let _turn = heap::LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let json = format!(
        r#"{{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"{secret}","algorithm":"sha1","digits":6,"period":30}}"#,
        secret = heap::NEEDLE
    );

    // The binary form, written out by hand: an ENROLL_ISSUE, the client
    // id, the secret, the algorithm, the digits and the period.
    let mut binary = vec![VERSION_BINARY, kind::ENROLL_ISSUE, 0x00];
    binary.extend_from_slice(&10u16.to_le_bytes());
    binary.extend_from_slice(b"client-001");
    binary.extend_from_slice(&(heap::NEEDLE.len() as u16).to_le_bytes());
    binary.extend_from_slice(heap::NEEDLE.as_bytes());
    binary.push(Algorithm::Sha1.to_byte());
    binary.extend_from_slice(&6u32.to_le_bytes());
    binary.extend_from_slice(&30u64.to_le_bytes());

    let clean = heap::watched(|| {
        drop(AuthMessage::from_bytes(json.as_bytes()).expect("the JSON form parses"));
        drop(AuthMessage::from_payload(&binary).expect("the binary form parses"));
    });

    assert!(
        clean,
        "the credential was still in a freed block of the heap"
    );
}

/// A peer on either side of this change has to be able to talk to one on
/// the other side, and the whole interop story is one sentence: the field
/// is absent when it is not being used. A peer that never heard of devices
/// sends no such key, and this one reads that as the unnamed device.
#[test]
fn a_message_from_a_peer_that_never_heard_of_devices_still_parses() {
    let wire = r#"{"type":"AUTH_START","client_id":"client-001","timestamp":1}"#;

    let parsed = AuthMessage::from_bytes(wire.as_bytes()).expect("an old client still parses");
    let AuthMessage::Start {
        client_id,
        timestamp,
        device_id,
        version,
    } = parsed
    else {
        panic!("expected AUTH_START, got {parsed:?}");
    };

    assert_eq!(client_id, "client-001");
    assert_eq!(timestamp, 1);
    assert_eq!(device_id, None, "no name sent is the unnamed device");

    // And it goes back out the way it came in, so the two peers agree on
    // what a handshake between them looks like.
    assert_eq!(
        json_of(&AuthMessage::Start {
            client_id,
            timestamp,
            device_id,
            version,
        }),
        wire,
    );
}

/// The other half of that sentence: an unset device id is left off the
/// wire entirely rather than sent as `null`, so a peer that does know the
/// field cannot tell this one apart from an older one — which is what
/// keeps nobody having to negotiate a version.
#[test]
fn an_unnamed_device_sends_no_device_id_at_all() {
    let json = json_of(&AuthMessage::Response {
        client_id: "client-001".to_string(),
        timestamp: 1,
        totp_code: "123456".to_string(),
        signature: vec![7],
        device_id: None,
    });

    assert!(!json.contains("device_id"), "{json}");
}

/// Every message that can carry one, so a variant added later and given the
/// field by copy-paste cannot end up with it spelled differently.
#[test]
fn a_named_device_survives_the_round_trip() {
    let messages = [
        AuthMessage::Start {
            client_id: "client-001".to_string(),
            timestamp: 1,
            device_id: Some("laptop".to_string()),
            version: None,
        },
        AuthMessage::Response {
            client_id: "client-001".to_string(),
            timestamp: 1,
            totp_code: "123456".to_string(),
            signature: vec![7],
            device_id: Some("laptop".to_string()),
        },
        AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: Some("laptop".to_string()),
            public_key: None,
        },
        AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            device_id: Some("laptop".to_string()),
        },
    ];

    for message in &messages {
        let bytes = message.to_bytes().expect("serializable");
        let json = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(json.contains(r#""device_id":"laptop""#), "{json}");

        let back = AuthMessage::from_bytes(&bytes).expect("parses");
        assert_eq!(
            back.to_bytes().unwrap(),
            bytes,
            "a device id must not change shape on the way through"
        );
    }
}

/// A device id ends up in the log line for whatever happens to it, so it is
/// held to what a client id is held to rather than to a rule of its own.
#[test]
fn a_device_id_is_refused_the_way_a_client_id_is() {
    assert!(is_presentable_device_id("laptop"));
    assert!(!is_presentable_device_id(""), "empty names nobody");
    assert!(
        !is_presentable_device_id("laptop\r\nINFO: connected"),
        "a trailing CRLF would write the next log line"
    );
    assert!(!is_presentable_device_id(
        &"d".repeat(MAX_DEVICE_ID_LEN + 1)
    ));

    // The two rules really are one rule: whatever is refused for one id is
    // refused for the other.
    for id in ["", "laptop\r\nINFO: connected", &"x".repeat(256)] {
        assert_eq!(is_presentable_device_id(id), is_presentable_client_id(id));
    }
}

/// A key offered at enrollment is what the server records and what the
/// device will sign with, so it has to reach the other side exactly as it
/// was said: a field that changes shape on the way through is a device
/// that can never authenticate.
#[test]
fn an_enrollment_that_offers_a_key_carries_it_whole() {
    let key = "a1".repeat(32);
    let start = AuthMessage::EnrollStart {
        client_id: "client-001".to_string(),
        token: SecretString::new("tok".to_string()),
        device_id: Some("phone".to_string()),
        public_key: Some(key.clone()),
    };

    let json = json_of(&start);
    assert!(json.contains(&format!(r#""public_key":"{key}""#)), "{json}");

    let back = AuthMessage::from_bytes(json.as_bytes()).expect("parses");
    assert_eq!(back.to_bytes().unwrap(), start.to_bytes().unwrap());
}

/// The other half of the absence-means-old-client rule, for enrollment: a
/// client that has no key — every client built before this field existed —
/// sends no such key, and what it sends goes back out byte for byte.
#[test]
fn an_enrollment_from_a_client_with_no_key_still_parses() {
    let wire =
        r#"{"type":"ENROLL_START","client_id":"client-001","token":"tok","device_id":"laptop"}"#;

    let parsed = AuthMessage::from_bytes(wire.as_bytes()).expect("an old client still parses");
    let AuthMessage::EnrollStart { public_key, .. } = parsed else {
        panic!("expected ENROLL_START");
    };
    assert_eq!(public_key, None, "no key sent is a secret-based device");

    assert_eq!(
        json_of(&AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("tok".to_string()),
            device_id: Some("laptop".to_string()),
            public_key: None,
        }),
        wire,
    );
}

// ===== The binary form =====

/// Every message, in every shape it has.
fn every_message() -> Vec<AuthMessage> {
    vec![
        AuthMessage::Start {
            client_id: "client-001".to_string(),
            timestamp: 7,
            device_id: None,
            version: None,
        },
        AuthMessage::Start {
            client_id: "client-001".to_string(),
            timestamp: 7,
            device_id: Some("laptop".to_string()),
            version: None,
        },
        AuthMessage::Start {
            client_id: "client-001".to_string(),
            timestamp: 7,
            device_id: Some("laptop".to_string()),
            version: Some(VERSION_BINARY),
        },
        AuthMessage::Challenge {
            nonce: (0..32u8).collect(),
        },
        AuthMessage::Response {
            client_id: "client-001".to_string(),
            timestamp: 1_750_000_000,
            totp_code: "123456".to_string(),
            signature: vec![9u8; 32],
            device_id: None,
        },
        AuthMessage::Response {
            client_id: "client-001".to_string(),
            timestamp: 1_750_000_000,
            totp_code: String::new(),
            signature: vec![7u8; 64],
            device_id: Some("laptop".to_string()),
        },
        AuthMessage::Ok,
        AuthMessage::Failed {
            reason: "the credentials were refused".to_string(),
        },
        AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("0123456789abcdef".to_string()),
            device_id: None,
            public_key: None,
        },
        AuthMessage::EnrollStart {
            client_id: "client-001".to_string(),
            token: SecretString::new("0123456789abcdef".to_string()),
            device_id: Some("laptop".to_string()),
            public_key: Some("ab".repeat(32)),
        },
        AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: 30,
            device_id: None,
        },
        AuthMessage::EnrollIssue {
            client_id: "client-001".to_string(),
            secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
            algorithm: Algorithm::Sha512,
            digits: 8,
            period: 60,
            device_id: Some("laptop".to_string()),
        },
        AuthMessage::EnrollFailed {
            reason: "the enrollment token was not accepted".to_string(),
        },
    ]
}

/// The binary form is the same message.
///
/// Every message goes out in the binary form and comes back as the same
/// message — and as the same JSON, which is what says the two encoders
/// are two views of one thing rather than two things that happen to look
/// alike.
#[test]
fn every_message_survives_the_binary_form() {
    for message in every_message() {
        let payload = message
            .to_payload(Format::Binary)
            .expect("the binary form is writable");
        assert_eq!(payload[0], VERSION_BINARY, "the version byte comes first");

        let (back, format) =
            AuthMessage::from_payload(&payload).expect("the binary form is readable");
        assert_eq!(format, Format::Binary);
        assert_eq!(
            back.to_bytes().expect("serializable"),
            message.to_bytes().expect("serializable"),
            "{message:?} came back as something else"
        );
    }
}

/// The same for the versioned JSON form.
#[test]
fn every_message_survives_the_versioned_json_form() {
    for message in every_message() {
        let payload = message
            .to_payload(Format::Json)
            .expect("the versioned JSON form is writable");
        assert_eq!(payload[0], VERSION_JSON);

        let (back, format) =
            AuthMessage::from_payload(&payload).expect("the versioned JSON form is readable");
        assert_eq!(format, Format::Json);
        assert_eq!(
            back.to_bytes().expect("serializable"),
            message.to_bytes().expect("serializable"),
            "{message:?} came back as something else"
        );
    }
}

/// A payload that does not start with a version byte is the JSON form.
///
/// That is what every peer sent before the version byte existed, and it
/// has to keep working: a JSON message starts with `{`, which is neither
/// of the two version bytes, so the three are told apart by one look.
#[test]
fn a_payload_without_a_version_byte_is_the_json_form() {
    for message in every_message() {
        let payload = message.to_bytes().expect("serializable");
        assert_eq!(payload[0], b'{', "a JSON message starts with a brace");

        let (back, format) = AuthMessage::from_payload(&payload).expect("an old peer still parses");
        assert_eq!(format, Format::LegacyJson);
        assert_eq!(
            back.to_bytes().expect("serializable"),
            payload,
            "{message:?} came back as something else"
        );
    }
}

/// The binary form is smaller than the JSON, and that is the reason it
/// exists.
///
/// The two big messages are the ones that carry a nonce and a signature,
/// and the JSON writes those as arrays of decimal numbers — three bytes
/// per byte. The numbers here are the ones a real handshake produces.
#[test]
fn the_binary_form_is_smaller_than_the_json_one() {
    let handshake = [
        AuthMessage::Start {
            client_id: "client-001".to_string(),
            timestamp: 1_750_000_000,
            device_id: None,
            version: None,
        },
        AuthMessage::Challenge {
            nonce: (0..32u8).collect(),
        },
        AuthMessage::Response {
            client_id: "client-001".to_string(),
            timestamp: 1_750_000_000,
            totp_code: "123456".to_string(),
            signature: (0..32u8).collect(),
            device_id: None,
        },
        AuthMessage::Ok,
    ];

    let json: usize = handshake
        .iter()
        .map(|message| message.to_bytes().expect("serializable").len())
        .sum();
    let binary: usize = handshake
        .iter()
        .map(|message| {
            message
                .to_payload(Format::Binary)
                .expect("the binary form is writable")
                .len()
        })
        .sum();

    assert!(
        binary * 2 < json,
        "the binary form is {binary} bytes against the JSON's {json}"
    );
}

/// A payload that is not a message is refused, and it is refused without
/// a panic and without allocating for a length the peer made up.
#[test]
fn a_broken_binary_payload_is_refused() {
    let good = AuthMessage::Challenge {
        nonce: vec![1, 2, 3],
    }
    .to_payload(Format::Binary)
    .expect("writable");

    // Truncated at every length: a payload that ends early is not a
    // message, and none of the cuts may take the process down.
    for cut in 1..good.len() {
        let error = AuthMessage::from_payload(&good[..cut])
            .expect_err("a truncated payload is not a message");
        assert!(
            !error.to_string().is_empty(),
            "the refusal says something: {error}"
        );
    }

    // A type byte nobody knows.
    let mut unknown_type = good.clone();
    unknown_type[1] = 0x7f;
    let error = AuthMessage::from_payload(&unknown_type).expect_err("an unknown type is refused");
    assert!(
        error.to_string().contains("unknown message type"),
        "{error}"
    );

    // A flag the message type has no meaning for: refusing it is what
    // stops a future version being read as if the field were absent.
    let mut unknown_flag = good.clone();
    unknown_flag[2] = 0b1000_0000;
    let error = AuthMessage::from_payload(&unknown_flag).expect_err("an unknown flag is refused");
    assert!(error.to_string().contains("flags"), "{error}");

    // A length that overruns the payload: the length is the peer's to
    // write, so it is checked before anything is allocated for it.
    let mut overrun = good.clone();
    overrun[3] = 0xff;
    overrun[4] = 0xff;
    let error = AuthMessage::from_payload(&overrun).expect_err("an overrunning length is refused");
    assert!(!error.to_string().is_empty(), "{error}");
}

/// The algorithm is a closed set, in both forms.
#[test]
fn the_algorithm_is_a_closed_set() {
    // A byte that is not one of the three.
    let mut payload = AuthMessage::EnrollIssue {
        client_id: "client-001".to_string(),
        secret: SecretString::new("JBSWY3DPEHPK3PXP".to_string()),
        algorithm: Algorithm::Sha1,
        digits: 6,
        period: 30,
        device_id: None,
    }
    .to_payload(Format::Binary)
    .expect("writable");
    // The algorithm is the byte after the type, the flags, the client id
    // and the secret — each of the two strings behind its own length.
    let at = 1 + 1 + 1 + 2 + "client-001".len() + 2 + "JBSWY3DPEHPK3PXP".len();
    payload[at] = 0x09;
    let error = AuthMessage::from_payload(&payload).expect_err("an unknown algorithm is refused");
    assert!(error.to_string().contains("algorithm"), "{error}");

    // A name nobody supports, in the JSON form.
    let wire = r#"{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXP","algorithm":"sha-256","digits":6,"period":30}"#;
    let error =
        AuthMessage::from_payload(wire.as_bytes()).expect_err("a name nobody supports is refused");
    assert!(
        error.to_string().contains("sha-256"),
        "the refusal names the value: {error}"
    );
}

/// The names are read in any case and written in one.
///
/// The wire has always carried the canonical lowercase name, and the
/// configuration it comes from is read in any case — so a peer that says
/// `SHA1` is understood, and the answer is always `sha1`.
#[test]
fn an_algorithm_name_is_read_in_any_case() {
    for (said, meant) in [
        ("sha1", Algorithm::Sha1),
        ("SHA1", Algorithm::Sha1),
        ("Sha1", Algorithm::Sha1),
        ("sha256", Algorithm::Sha256),
        ("SHA256", Algorithm::Sha256),
        ("sha512", Algorithm::Sha512),
        ("SHA512", Algorithm::Sha512),
    ] {
        let wire = format!(
            r#"{{"type":"ENROLL_ISSUE","client_id":"client-001","secret":"JBSWY3DPEHPK3PXP","algorithm":"{said}","digits":6,"period":30}}"#
        );
        let (parsed, _) = AuthMessage::from_payload(wire.as_bytes())
            .unwrap_or_else(|e| panic!("{said} parses: {e}"));
        let AuthMessage::EnrollIssue { algorithm, .. } = parsed else {
            panic!("expected ENROLL_ISSUE");
        };
        assert_eq!(algorithm, meant, "{said}");
        assert_eq!(algorithm.name(), said.to_ascii_lowercase());
    }
}

/// The announcement is the only thing a message says about the version,
/// and only the first message says it.
#[test]
fn only_the_first_message_announces_a_version() {
    let start = AuthMessage::Start {
        client_id: "client-001".to_string(),
        timestamp: 1,
        device_id: None,
        version: Some(VERSION_BINARY),
    };
    assert_eq!(start.announced_version(), Some(VERSION_BINARY));
    assert_eq!(
        AuthMessage::Ok.announced_version(),
        None,
        "nothing else announces anything"
    );
}
