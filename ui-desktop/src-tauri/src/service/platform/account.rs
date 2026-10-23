//! Which account a caller, a file or an install belongs to.
//!
//! The service runs elevated — root under systemd and launchd, LocalSystem
//! under the service control manager — and listens on a loopback port. A
//! loopback socket says nothing about who dialled it, so the service has to ask
//! the operating system instead. Two answers matter here:
//!
//! * the **peer credential** of an accepted socket, which the kernel attributes
//!   to the process on the other end, and
//! * the **owner** of the file a secret came from.
//!
//! Both are compared against the account the service was installed for; see
//! [`allows`] for the policy that comes out of it.
//!
//! The account is spelled differently on each platform — a Unix user id, a
//! Windows security identifier — and [`AccountId`] carries whichever the
//! platform has, so the policy itself is written once.

use std::path::Path;

/// The account a thing belongs to.
///
/// One type for all three roles — the account on the other end of the socket,
/// the account that owns a token file, and the account the service was
/// installed for — because the whole point is to compare them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountId {
    /// A Unix user id.
    #[cfg(unix)]
    Unix(u32),
    /// A Windows security identifier, in the canonical `S-1-5-...` spelling.
    #[cfg(windows)]
    Windows(String),
}

impl AccountId {
    /// The account this process runs as.
    ///
    /// The desktop uses this to name the account it is installing the service
    /// for: it knows who it is, and the elevated child does not — root is root
    /// on both sides of the elevation.
    pub fn current() -> Option<AccountId> {
        #[cfg(unix)]
        {
            // Safe: `geteuid` takes no arguments and cannot fail.
            Some(AccountId::Unix(unsafe { libc::geteuid() }))
        }
        #[cfg(windows)]
        {
            current_user_sid().map(AccountId::Windows)
        }
    }

    /// The account on the other end of an accepted socket.
    ///
    /// `None` when the operating system would not say, and that is a refusal
    /// rather than a shrug: a service that cannot name its caller does not
    /// serve it.
    ///
    /// The socket this is asked about is the one the IPC runs over — a
    /// Unix-domain socket on Unix, a loopback TCP port on Windows — because
    /// that is the only kind of socket whose peer the kernel can name. See
    /// [`crate::service::ipc::IPC_SOCKET_PATH`].
    pub fn peer_of(stream: &crate::service::ipc::IpcStream) -> Option<AccountId> {
        #[cfg(unix)]
        {
            peer_uid(stream).map(AccountId::Unix)
        }
        #[cfg(windows)]
        {
            peer_sid(stream).map(AccountId::Windows)
        }
    }

    /// The account that owns a file.
    ///
    /// `None` when the file cannot be stat'ed or its owner cannot be read,
    /// which is a refusal: a secret nobody can be attributed to is a secret
    /// anybody may present.
    pub fn owner_of(path: &Path) -> Option<AccountId> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(path)
                .ok()
                .map(|m| AccountId::Unix(m.uid()))
        }
        #[cfg(windows)]
        {
            owner_sid(path).map(AccountId::Windows)
        }
    }

    /// The spelling an account is written down in.
    ///
    /// The same spelling the recorded owner is kept in, so the two can be
    /// compared after a round trip through a file or a registry value.
    pub fn to_text(&self) -> String {
        match self {
            #[cfg(unix)]
            AccountId::Unix(uid) => uid.to_string(),
            #[cfg(windows)]
            AccountId::Windows(sid) => sid.clone(),
        }
    }

    /// Reads an account back from the spelling [`AccountId::to_text`] writes.
    ///
    /// `None` for anything else, so a file that was tampered with is a file
    /// that is not read rather than one that is read as some other account.
    pub fn parse(text: &str) -> Option<AccountId> {
        let text = text.trim();
        #[cfg(unix)]
        {
            text.parse::<u32>().ok().map(AccountId::Unix)
        }
        #[cfg(windows)]
        {
            // The canonical spelling is upper case; comparing case-insensitively
            // keeps a hand-written record from being refused for its casing.
            (!text.is_empty()).then(|| AccountId::Windows(text.to_ascii_uppercase()))
        }
    }
}

impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(unix)]
            AccountId::Unix(uid) => write!(f, "uid {uid}"),
            #[cfg(windows)]
            AccountId::Windows(sid) => write!(f, "sid {sid}"),
        }
    }
}

/// Whether a caller may drive the service.
///
/// The whole policy, over three identities and nothing else, so that it can be
/// read — and tested — without a socket, a service or a root:
///
/// * `installed_by` is the account that installed the service, as recorded at
///   install time. `None` when the service cannot say who installed it.
/// * `peer` is the account on the other end of the socket.
/// * `token_owner` is the account that owns the token file that answered.
///
/// With a recorded installer the service serves that account and nobody else:
/// the peer has to *be* it, and the token has to belong to it. The service's
/// actions — the TUN device, the machine-wide routes, the DNS hijack — are the
/// machine's rather than one account's, so a second local account has no
/// business asking for them even though it holds a token of its own.
///
/// Without a recorded installer the service cannot tell which account it was
/// installed for, and falls back to requiring the peer to own the token it
/// answered with. That still stops one account from using another's token, but
/// it does not stop a local account from driving the service at all — so the
/// caller of this function has to say so loudly.
pub fn allows(installed_by: Option<&AccountId>, peer: &AccountId, token_owner: &AccountId) -> bool {
    match installed_by {
        Some(installer) => peer == installer && token_owner == installer,
        None => peer == token_owner,
    }
}

/// Whether a token file at `path` is in a directory a secret may be read from.
///
/// The service reads token files from every account's profile, so the question
/// is not whether the *file* is private — that is checked separately, by the
/// file's mode — but whether the *directory* it is in can be changed by
/// somebody else while the service is not looking:
///
/// * the directory holding the token must not be writable by group or other,
///   or another account can put a file of its own there and have it read as a
///   token;
/// * and the file has to belong to whoever owns that directory, or a file
///   that was moved into place from elsewhere is read as if it had always
///   been there.
///
/// On Unix there is a third rule: no directory between the token and the
/// filesystem root may be world-writable, because a world-writable directory
/// lets another account replace the directories below it — which would make the
/// first rule a statement about a directory the attacker owns.
pub fn token_directory_is_trusted(path: &Path, owner: &AccountId) -> bool {
    let Some(directory) = path.parent() else {
        return false;
    };

    // The file belongs to whoever owns the directory it is in.
    if AccountId::owner_of(directory).as_ref() != Some(owner) {
        return false;
    }

    #[cfg(unix)]
    {
        directory_is_private(directory) && directory_chain_is_trusted(directory)
    }
    #[cfg(windows)]
    {
        // Windows has no mode bits to read. The token file carries an explicit
        // DACL of its own (owner, SYSTEM, administrators — see
        // `ipc_token::write_private`), and the directory it lives in is the
        // account's own, so the ownership check above is what stands in for the
        // mode check on Unix.
        true
    }
}

/// Whether a directory may hold a token: not writable by group or other.
///
/// The pure half of the Unix rule, so that it can be tested without a
/// filesystem.
#[cfg(any(unix, test))]
pub fn mode_is_private(mode: u32) -> bool {
    mode & 0o022 == 0
}

/// Whether no directory in a chain is world-writable.
///
/// The pure half of the Unix chain rule, so that it can be tested without a
/// filesystem. `modes` are the modes of the directories from the one holding
/// the token up to the filesystem root.
#[cfg(any(unix, test))]
pub fn chain_is_trusted(modes: &[u32]) -> bool {
    modes.iter().all(|mode| mode & 0o002 == 0)
}

/// The modes of the directories from `directory` up to the filesystem root.
#[cfg(unix)]
fn directory_chain_modes(directory: &Path) -> Option<Vec<u32>> {
    use std::os::unix::fs::PermissionsExt;

    let mut modes = Vec::new();
    let mut current = directory;
    loop {
        let metadata = std::fs::metadata(current).ok()?;
        modes.push(metadata.permissions().mode());

        match current.parent() {
            Some(parent) => current = parent,
            None => return Some(modes),
        }
    }
}

/// Whether no directory between `directory` and the filesystem root is
/// world-writable.
#[cfg(unix)]
fn directory_chain_is_trusted(directory: &Path) -> bool {
    match directory_chain_modes(directory) {
        Some(modes) => chain_is_trusted(&modes),
        // A directory that cannot be stat'ed is a directory nobody can vouch
        // for, and a directory nobody can vouch for is not one to read a
        // secret from.
        None => false,
    }
}

/// Whether a directory may hold a token, by the mode it carries.
#[cfg(unix)]
fn directory_is_private(directory: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(directory)
        .map(|metadata| mode_is_private(metadata.permissions().mode()))
        .unwrap_or(false)
}

/// The user id on the other end of a connected socket.
///
/// Linux answers this with `SO_PEERCRED`, which the kernel fills in from the
/// credentials of the process that connected. macOS has `getpeereid`, which
/// asks the same question.
///
/// Both of them answer it for a **Unix-domain socket**. On a TCP socket the
/// question has no answer at all: `SO_PEERCRED` succeeds on one and fills the
/// uid in with `-1`, because a TCP connection carries no credentials, and
/// `getpeereid` fails outright — neither is a uid anybody can be compared
/// with. A uid of `-1` is not a caller either: it is the absence of one, and
/// reading it as an identity would make the service refuse every caller while
/// looking, in the log, as though it had named one. That is why the IPC runs
/// over a Unix-domain socket on Unix; see
/// [`crate::service::ipc::IPC_SOCKET_PATH`].
#[cfg(target_os = "linux")]
fn peer_uid(stream: &tokio::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    /// The kernel's `struct ucred`, which `SO_PEERCRED` fills in.
    ///
    /// Spelled out here rather than taken from `libc`, because the layout is
    /// the kernel's and not the C library's: three 32-bit fields, in that
    /// order.
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    let mut credentials = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<Ucred>() as libc::socklen_t;

    // Safe: the buffer is a `Ucred` of exactly the length passed, and the
    // socket is open for as long as the caller holds it.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut Ucred as *mut libc::c_void,
            &mut length,
        )
    };

    if result != 0 {
        return None;
    }
    // The kernel fills the uid in with `-1` when the socket carries no
    // credentials, and a uid of `-1` is not an account: it is the absence of
    // one, and a caller cannot be the absence of one.
    (credentials.uid != u32::MAX).then_some(credentials.uid)
}

/// The user id on the other end of a connected socket, on the platforms that
/// answer with `getpeereid`.
///
/// A Unix-domain socket, for the reason the Linux half gives above.
#[cfg(all(unix, not(target_os = "linux")))]
fn peer_uid(stream: &tokio::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;

    let mut effective_uid: libc::uid_t = 0;
    let mut effective_gid: libc::gid_t = 0;

    // Safe: both out-parameters are valid for writing, and the socket is open
    // for as long as the caller holds it.
    let result =
        unsafe { libc::getpeereid(stream.as_raw_fd(), &mut effective_uid, &mut effective_gid) };

    (result == 0).then_some(effective_uid)
}

/// The security identifier on the other end of a connected socket.
///
/// Windows has no socket credential of its own, so the peer is found in two
/// steps: the connection table says which process owns the connection, and the
/// process token says which account that process runs as.
#[cfg(windows)]
fn peer_sid(stream: &tokio::net::TcpStream) -> Option<String> {
    let local = stream.local_addr().ok()?;
    let remote = stream.peer_addr().ok()?;
    // The table holds a row per **endpoint**, and the two ends of a
    // connection have their addresses the other way round: this socket's row
    // says local = this side's address and remote = the peer's, and the
    // peer's row says the opposite. The peer is the owner of the second one,
    // so the addresses are swapped for the lookup — looking for this
    // socket's own row answers with this process, and every client would be
    // read as the account the service itself runs as.
    let pid = owning_pid(remote, local)?;
    process_user_sid(pid)
}

/// The process that owns the connection between two addresses.
#[cfg(windows)]
fn owning_pid(local: std::net::SocketAddr, remote: std::net::SocketAddr) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::AF_INET;

    /// What the call says when the buffer it was given is too small, and the
    /// size it needs now is in the out-parameter.
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    let local_address = ipv4_in_table_order(local.ip())?;
    let remote_address = ipv4_in_table_order(remote.ip())?;
    // The table keeps the ports in network byte order, in a 32-bit word: the
    // two bytes of the port, followed by two zero bytes.
    let local_port = port_in_table_order(local.port());
    let remote_port = port_in_table_order(remote.port());

    let mut size: u32 = 0;
    // Safe: a null buffer asks for the size the table needs.
    unsafe {
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        )
    };
    if size == 0 {
        return None;
    }

    // The table is read into `u32`s rather than into bytes: its header and
    // its rows are 32-bit fields, and a buffer of bytes carries no promise
    // about being aligned for them.
    //
    // The first call measures the table and the second one fills it, and a
    // connection that opens in between makes the second one say the buffer
    // is too small — with the size the table needs *now* in `size`. So the
    // call is repeated with the size it reports, a few times over, before
    // the answer is taken as no: this runs for every IPC connection, and a
    // machine with ordinary connection churn would otherwise refuse a
    // legitimate client now and then.
    let mut buffer: Vec<u32>;
    let mut attempts = 0;
    loop {
        buffer = vec![0u32; (size as usize).div_ceil(std::mem::size_of::<u32>())];
        // Safe: the buffer is at least `size` bytes long, which is what the
        // call asks for, and it is aligned for the 32-bit fields it fills in.
        let result = unsafe {
            GetExtendedTcpTable(
                buffer.as_mut_ptr() as *mut std::ffi::c_void,
                &mut size,
                0,
                AF_INET as u32,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        };
        match result {
            0 => break,
            // The table grew: `size` holds the size it needs now.
            ERROR_INSUFFICIENT_BUFFER if attempts < 4 => attempts += 1,
            _ => return None,
        }
    }

    // Safe: the call filled the buffer with a table of `dwNumEntries` rows.
    let table = buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID;
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };

    rows.iter()
        .find(|row| {
            row.dwLocalAddr == local_address
                && row.dwLocalPort == local_port
                && row.dwRemoteAddr == remote_address
                && row.dwRemotePort == remote_port
        })
        .map(|row| row.dwOwningPid)
}

/// The IPv4 address as the connection table spells it.
///
/// The table keeps addresses in network byte order, so the four bytes of the
/// address are read as a little-endian word — the same value the table holds.
#[cfg(windows)]
fn ipv4_in_table_order(address: std::net::IpAddr) -> Option<u32> {
    match address {
        std::net::IpAddr::V4(v4) => Some(u32::from_le_bytes(v4.octets())),
        // The table this reads is the IPv4 one.
        std::net::IpAddr::V6(_) => None,
    }
}

/// The port as the connection table spells it.
///
/// The table keeps the port in network byte order, in the low two bytes of
/// the 32-bit word it holds it in: the two bytes of the port, read as a
/// little-endian word. The same value comes out of `ntohs` on the low half
/// of the word the table holds.
#[cfg(windows)]
fn port_in_table_order(port: u16) -> u32 {
    let bytes = port.to_be_bytes();
    u32::from_le_bytes([bytes[0], bytes[1], 0, 0])
}

/// The account a process runs as, read off its token.
#[cfg(windows)]
fn process_user_sid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // Safe: the handles are closed before this returns, and every out-parameter
    // points at a live local.
    unsafe {
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;

        let mut token = HANDLE(std::ptr::null_mut());
        // The process handle is closed whether the token opened or not: an
        // early return between the two would leak it, and this runs for every
        // IPC connection, so the leak would run the handle table down.
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token).is_ok();
        let _ = CloseHandle(process);
        if !opened {
            return None;
        }

        let account = token_user_sid(token);

        let _ = CloseHandle(token);
        account
    }
}

/// The account this process runs as, read off its own token.
#[cfg(windows)]
fn current_user_sid() -> Option<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // Safe: `GetCurrentProcess` returns a pseudo-handle that must not be
    // closed, and the token handle is closed before this returns.
    unsafe {
        let mut token = HANDLE(std::ptr::null_mut());
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).ok()?;

        let account = token_user_sid(token);

        let _ = CloseHandle(token);
        account
    }
}

/// The account a token belongs to.
#[cfg(windows)]
fn token_user_sid(token: windows::Win32::Foundation::HANDLE) -> Option<String> {
    use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};

    // Safe: the buffer is sized by the call itself, and the token is open for
    // as long as the caller holds it.
    unsafe {
        let mut needed: u32 = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        if needed == 0 {
            return None;
        }

        let mut buffer = vec![0u8; needed as usize];
        GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut std::ffi::c_void),
            needed,
            &mut needed,
        )
        .ok()?;

        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        sid_to_string(user.User.Sid)
    }
}

/// The string form of a security identifier.
#[cfg(windows)]
fn sid_to_string(sid: windows::Win32::Security::PSID) -> Option<String> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;

    // Safe: the SID comes from a live token or a live security descriptor,
    // and the string the call allocates is freed before this returns.
    unsafe {
        let mut text = PWSTR::null();
        ConvertSidToStringSidW(sid, &mut text).ok()?;

        let value = text.to_string().ok();

        let _ = LocalFree(Some(HLOCAL(text.0 as *mut std::ffi::c_void)));
        value
    }
}

/// The account that owns a file, read off its security descriptor.
#[cfg(windows)]
fn owner_sid(path: &Path) -> Option<String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows::Win32::Security::{OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID};

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Safe: the path is null-terminated, and the descriptor the call fills in
    // is freed before this returns.
    unsafe {
        let mut owner: PSID = PSID(std::ptr::null_mut());
        let mut descriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR(std::ptr::null_mut());

        let status = GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        );

        if status != WIN32_ERROR(0) {
            if !descriptor.0.is_null() {
                let _ = LocalFree(Some(HLOCAL(descriptor.0)));
            }
            return None;
        }

        let account = sid_to_string(owner);

        if !descriptor.0.is_null() {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        account
    }
}

#[cfg(test)]
mod tests {
    use super::{allows, chain_is_trusted, mode_is_private, AccountId};
    /// An account for a test, spelled the way this platform spells accounts.
    fn account(n: u32) -> AccountId {
        #[cfg(unix)]
        {
            AccountId::Unix(n)
        }
        #[cfg(windows)]
        {
            AccountId::Windows(format!("S-1-5-21-{n}"))
        }
    }

    /// The service serves the account it was installed for, and nobody else.
    ///
    /// The whole point of the fix: a second local account holds a token of its
    /// own, and the service must refuse it all the same, because what it does
    /// with that token is machine-wide.
    #[test]
    fn the_installing_account_is_the_only_one_served() {
        let installer = account(1000);
        let other = account(1001);

        assert!(allows(Some(&installer), &installer, &installer));
        assert!(
            !allows(Some(&installer), &other, &other),
            "another account must not be served, even with a token of its own"
        );
        assert!(
            !allows(Some(&installer), &installer, &other),
            "a token belonging to another account must not be accepted"
        );
        assert!(!allows(Some(&installer), &other, &installer));
    }

    /// With no recorded installer the service falls back to requiring the peer
    /// to own the token it answered with. That still stops one account from
    /// using another's token.
    ///
    /// It does *not* stop an account from driving the service with a token of
    /// its own — which is exactly why the recorded installer matters, and why
    /// the service says so loudly when it has none.
    #[test]
    fn without_a_recorded_installer_the_peer_must_own_the_token() {
        let peer = account(1000);
        let other = account(1001);

        assert!(allows(None, &peer, &peer));
        assert!(
            !allows(None, &peer, &other),
            "a token belonging to another account must not be accepted"
        );
        assert!(
            allows(None, &other, &other),
            "the degraded mode serves any account that owns the token it read"
        );
    }

    /// An account is written down and read back as itself.
    #[test]
    fn an_account_survives_being_written_down() {
        let original = account(1000);

        let parsed = AccountId::parse(&original.to_text()).expect("the account reads back");

        assert_eq!(parsed, original);
    }

    /// A record that is not an account is not read as one. A tampered file
    /// must not become some other account.
    #[test]
    fn a_record_that_is_not_an_account_is_not_read_as_one() {
        assert!(AccountId::parse("").is_none());
        assert!(AccountId::parse("not an account").is_none());
    }

    /// A directory another account may write into is not one to read a secret
    /// from.
    #[test]
    fn a_directory_writable_by_others_is_not_private() {
        assert!(!mode_is_private(0o777));
        assert!(!mode_is_private(0o770));
        assert!(!mode_is_private(0o707));
        assert!(mode_is_private(0o700));
        assert!(mode_is_private(0o755));
        // Sticky does not make a directory private: `/tmp` is 1777.
        assert!(!mode_is_private(0o1777));
    }

    /// A world-writable directory anywhere in the chain lets another account
    /// replace the directories below it, so the chain is what has to be
    /// checked — and `/tmp` is the case that matters, because that is where a
    /// service with neither `HOME` nor `XDG_RUNTIME_DIR` ends up.
    #[test]
    fn a_world_writable_directory_in_the_chain_is_refused() {
        // An ordinary chain is fine: none of these is writable by others.
        assert!(chain_is_trusted(&[0o755, 0o755, 0o755]));
        assert!(chain_is_trusted(&[0o755, 0o700, 0o755]));
        // One world-writable directory in it is enough.
        assert!(!chain_is_trusted(&[0o755, 0o1777]));
        assert!(!chain_is_trusted(&[0o1777]));
        assert!(!chain_is_trusted(&[0o755, 0o777]));
    }

    /// The peer of the IPC socket is the account that connected to it.
    ///
    /// This is the answer the whole policy rests on, so it is checked against
    /// the transport the IPC really runs over rather than against a
    /// stand-in. A loopback TCP port cannot answer it at all: `SO_PEERCRED`
    /// succeeds on one and fills the uid in with `-1`, and `getpeereid` fails
    /// on one outright. A helper that had only ever been exercised against a
    /// stand-in would look right while refusing every caller in production.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_peer_of_the_ipc_socket_is_the_account_that_connected() {
        let (_client, server) = crate::service::ipc::connected_pair().await;

        let peer = AccountId::peer_of(&server).expect("the kernel names the peer");

        assert_eq!(
            peer,
            AccountId::current().expect("this process runs as an account"),
            "the peer of the IPC socket must be the account that connected to it"
        );
    }
}
