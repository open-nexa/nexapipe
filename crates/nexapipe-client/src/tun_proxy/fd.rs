//! The tunnel's file descriptors.
//!
//! On Android the tunnel is a device, and the device is a file descriptor
//! this process opens. The stack reads packets from one end of it and writes
//! them back to the other, so the descriptor is duplicated rather than shared:
//! a socket that both ends read from is a socket where the two halves race.

#[cfg(any(target_os = "android", test))]
use crate::ClientError;

#[cfg(any(target_os = "android", test))]
use std::os::fd::OwnedFd;
#[cfg(target_os = "android")]
use std::os::fd::RawFd;

/// The two dups of the TUN fd, closed unless the pumps take them over.
///
/// Android hands the fd over and it is closed straight after being dup'ed, so
/// every step between the dups and the pumps taking ownership can fail with
/// both dups still open — leaked for the life of the process, and the VPN
/// cannot be brought up again while they are. Each half is taken out as it is
/// handed to a pump; whatever is left here when this drops is closed.
///
/// Held as [`OwnedFd`] rather than as raw numbers, so that "closed exactly
/// once" is a property of the type rather than of every call site remembering
/// to close. The raw numbers come back out at the point where a descriptor
/// becomes a `File`, and that `File` takes the ownership over from there.
#[cfg(target_os = "android")]
pub(super) struct TunFds {
    pub(super) read: Option<OwnedFd>,
    pub(super) write: Option<OwnedFd>,
}

/// Duplicates a TUN descriptor into the read/write pair the stack needs.
///
/// The original is closed by this function, exactly once, on every path — the
/// successful one and the failing ones alike. That is the contract the caller
/// relies on: the descriptor has been handed over, so the caller must not
/// close it again, whether this returned the pair or an error.
///
/// The contract is worth stating because a descriptor closed twice is not a
/// harmless error. Between the two closes the number can be handed to
/// something else — a socket, a file, another TUN — and the second close then
/// closes that instead. On a phone that is an unrelated file in the process,
/// and the failure is silent.
///
/// Ownership is taken by type rather than by a call: the parameter is an
/// [`OwnedFd`], so it is closed when this returns, whichever way it returns,
/// with nothing left to remember.
#[cfg(any(target_os = "android", test))]
pub(super) fn dup_tun_fds(tun_fd: OwnedFd) -> Result<(OwnedFd, OwnedFd), ClientError> {
    dup_tun_fds_with(tun_fd, OwnedFd::try_clone)
}

/// [`dup_tun_fds`], with the duplication step passed in.
///
/// The duplication is the only thing here that can fail, and the failure is
/// the path that matters: it is where the original used to be left open for
/// the caller to close — and the caller closed it, which is the double close
/// this whole change is about. Passing the step in is what makes that path
/// testable, because there is no portable way to make `dup(2)` fail on
/// demand.
#[cfg(any(target_os = "android", test))]
pub(super) fn dup_tun_fds_with<F>(
    tun_fd: OwnedFd,
    mut duplicate: F,
) -> Result<(OwnedFd, OwnedFd), ClientError>
where
    F: FnMut(&OwnedFd) -> std::io::Result<OwnedFd>,
{
    let read = duplicate(&tun_fd)?;
    let write = duplicate(&tun_fd)?;
    Ok((read, write))
}

/// Put the fd into non-blocking mode.
#[cfg(target_os = "android")]
pub(super) fn set_nonblocking(fd: RawFd) -> Result<(), ClientError> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod fd_tests {
    use super::{dup_tun_fds, dup_tun_fds_with};
    use std::os::fd::{AsRawFd, OwnedFd};

    /// A descriptor to hand over. A socket pair stands in for the TUN
    /// descriptor: it is a real descriptor, and closing it is observable.
    fn a_descriptor() -> OwnedFd {
        let (one, _other) = std::os::unix::net::UnixStream::pair().expect("a socket pair");
        one.into()
    }

    /// Whether a descriptor number is still a live descriptor.
    ///
    /// `fcntl` on a closed descriptor fails with `EBADF`, which is the
    /// cheapest way to ask the question without touching whatever the
    /// number points at — and after a close the number may point at
    /// something else entirely.
    fn is_open(fd: std::os::fd::RawFd) -> bool {
        unsafe { libc::fcntl(fd, libc::F_GETFD) >= 0 }
    }

    /// What a descriptor number points at: the device and inode of the file
    /// behind it.
    ///
    /// `None` when the number is not a live descriptor.
    fn identity(fd: std::os::fd::RawFd) -> Option<(libc::dev_t, libc::ino_t)> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(fd, stat.as_mut_ptr()) } < 0 {
            return None;
        }
        let stat = unsafe { stat.assume_init() };
        Some((stat.st_dev, stat.st_ino))
    }

    /// Whether `fd` is still the descriptor it was when it was `was`.
    ///
    /// "Is this number still open" is not the same question. A closed
    /// descriptor's number is handed to the next `open`, so by the time the
    /// question is asked another thread may have taken the number — and then
    /// the number *is* open, pointing at something else entirely.
    ///
    /// That is not a failure of the code under test; it is the hazard the code
    /// under test is about, happening to the test itself. It is what made
    /// these tests fail at random when the test binary ran its tests side by
    /// side — every other test that opens a file or a socket is a candidate to
    /// take the number.
    ///
    /// What tells the two apart is *what* the number points at.
    fn is_the_same_descriptor(fd: std::os::fd::RawFd, was: (libc::dev_t, libc::ino_t)) -> bool {
        identity(fd) == Some(was)
    }

    /// The whole point of the change: the descriptor that was handed over is
    /// closed by the takeover, so the caller must not close it again.
    ///
    /// It used to be closed twice — once by the takeover and once by the
    /// caller, on the failure path — and a descriptor closed twice is not a
    /// harmless error: between the two closes the number can be handed to
    /// something else, and the second close then closes that instead.
    #[test]
    fn the_takeover_closes_the_original_descriptor() {
        let original = a_descriptor();
        let original_fd = original.as_raw_fd();
        let original_identity = identity(original_fd).expect("the descriptor is open");

        let (read, write) = dup_tun_fds(original).expect("the takeover");

        assert!(
            !is_the_same_descriptor(original_fd, original_identity),
            "the original descriptor is still open, so the caller would close it a second time"
        );
        assert!(is_open(read.as_raw_fd()), "the read duplicate is not open");
        assert!(
            is_open(write.as_raw_fd()),
            "the write duplicate is not open"
        );
    }

    /// The two duplicates have to be two different descriptors, or the read
    /// end and the write end of the TUN would be the same number.
    #[test]
    fn the_takeover_hands_back_two_distinct_descriptors() {
        let original = a_descriptor();
        let original_fd = original.as_raw_fd();

        let (read, write) = dup_tun_fds(original).expect("the takeover");

        assert_ne!(read.as_raw_fd(), write.as_raw_fd());
        assert_ne!(read.as_raw_fd(), original_fd);
        assert_ne!(write.as_raw_fd(), original_fd);
    }

    /// A takeover that fails still closes the original.
    ///
    /// This is the regression test for the double close. The original used to
    /// be closed by an explicit `close(2)` that only ran once both
    /// duplications had succeeded, so a failure left it open — and the caller
    /// closed it, on the assumption that it still owned it. Two closes of one
    /// number, and between them the number can be handed to something else.
    ///
    /// The duplication is the only step that can fail, so it is the one that
    /// is faked here: the second one is made to fail, which is the path the
    /// old code got wrong.
    #[test]
    fn a_failed_takeover_still_closes_the_original() {
        let original = a_descriptor();
        let original_fd = original.as_raw_fd();
        let original_identity = identity(original_fd).expect("the descriptor is open");

        let mut calls = 0;
        let result = dup_tun_fds_with(original, |fd| {
            calls += 1;
            if calls == 2 {
                return Err(std::io::Error::other("no descriptors left"));
            }
            fd.try_clone()
        });

        assert!(result.is_err(), "the takeover was supposed to fail");
        assert!(
            !is_the_same_descriptor(original_fd, original_identity),
            "the original descriptor is still open after a failed takeover, so the caller \
             would close it a second time"
        );
    }
}
