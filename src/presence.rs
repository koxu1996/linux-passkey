//! User presence, via a pinentry confirmation (plus, with
//! `LINUX_PASSKEY_UV=fprintd`, a fingerprint check after it; see [`UserCheck`]).
//!
//! OpenSK calls this only when user *verification* was NOT performed
//! (`has_valid_up` treats a performed UV as also satisfying presence). So on a
//! passkey registration where the browser skips UV, this is the one prompt; on
//! authentication UV runs instead (see `fingerprint.rs`) and this is skipped —
//! exactly one Confirm either way, never two.
//!
//! Polled model: OpenSK calls `wait_with_timeout(100ms)` in a loop and sends
//! keepalives between calls, so `check_init` starts the approval on a thread
//! ([`Pending`]) and we poll. While waiting we hand OpenSK the host's reports
//! (so it sees CTAPHID_CANCEL), and notice the host closing the device. When
//! the check ends for any reason, the dialog and fprintd are killed.

use opensk::api::connection::{RecvStatus, UsbEndpoint};
use opensk::api::user_presence::{
    UserPresence, UserPresenceError, UserPresenceWaitResult,
};
use crate::request::{self, Prompt};
use std::io;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// How the user approves a request: a pinentry dialog naming the site (and
/// account), then optionally a fingerprint check. Shared by user presence and
/// the fingerprint-backed user verification, so every path asks the same way.
#[derive(Clone)]
pub struct UserCheck {
    pub pinentry_bin: String,
    /// `fprintd-verify` binary when fingerprints are on (`LINUX_PASSKEY_UV=fprintd`).
    pub fprintd_verify: Option<String>,
}

/// How an approval ended. Kept apart because OpenSK treats them differently:
/// only a finger that does not match uses up a UV retry.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Outcome {
    Approved,
    /// Deny, or the dialog was closed.
    Denied,
    /// The fingerprint did not match.
    NoMatch,
    /// The dialog or the sensor could not be used.
    Error,
}

impl UserCheck {
    /// Dialog first; the finger only after a confirm, and only for requests that
    /// act on a credential (see [`request::wants_fingerprint`]).
    pub fn confirm(&self, req: Option<&request::Request>, abort: &Abort) -> Outcome {
        let mut prompt = Prompt::for_request(req);
        let finger = self.fprintd_verify.as_deref().filter(|_| request::wants_fingerprint(req));
        if finger.is_some() {
            prompt.description.push_str("\n\nAfter confirming, touch the fingerprint sensor.");
        }
        match crate::pinentry::confirm(&self.pinentry_bin, &prompt, abort) {
            Ok(crate::pinentry::Answer::Confirmed) => {}
            Ok(crate::pinentry::Answer::Denied) => {
                tracing::info!("request denied");
                return Outcome::Denied;
            }
            Err(e) => {
                if !abort.is_aborted() {
                    tracing::error!("confirm dialog ('{}') failed: {e}", self.pinentry_bin);
                }
                return Outcome::Error;
            }
        }
        match finger {
            Some(bin) => crate::fprintd::verify(bin, abort),
            None => Outcome::Approved,
        }
    }
}

/// Kills the process an approval is running (the dialog, then fprintd-verify)
/// when its request ends, and reaps it either way.
#[derive(Clone, Default)]
pub struct Abort(Arc<Mutex<AbortState>>);

#[derive(Default)]
struct AbortState {
    aborted: bool,
    child: Option<Child>,
}

/// The pipes of a process started with [`Abort::spawn`].
pub struct Pipes {
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}

impl Abort {
    fn state(&self) -> MutexGuard<'_, AbortState> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Kill the running process, and refuse to start more.
    pub fn abort(&self) {
        let mut st = self.state();
        st.aborted = true;
        if let Some(child) = st.child.as_mut() {
            let _ = child.kill();
        }
    }

    pub fn is_aborted(&self) -> bool {
        self.state().aborted
    }

    /// Start `cmd` (one at a time); [`Self::reap`] must follow.
    pub fn spawn(&self, cmd: &mut Command) -> io::Result<Pipes> {
        let mut st = self.state();
        if st.aborted {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "request ended"));
        }
        let mut child = cmd.spawn()?;
        let pipes = Pipes {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
        };
        st.child = Some(child);
        Ok(pipes)
    }

    /// Wait for the process from [`Self::spawn`] to exit.
    pub fn reap(&self) -> Option<ExitStatus> {
        let child = self.state().child.take();
        child.and_then(|mut c| c.wait().ok())
    }
}

/// An approval running on its own thread. Dropping it kills the approval.
pub struct Pending {
    rx: Receiver<Outcome>,
    abort: Abort,
    /// [`crate::uhid::closes`] when it started: a change means the host is gone.
    closes: u64,
}

pub enum Poll {
    Done(Outcome),
    /// The host closed the device: nobody waits for this request any more.
    HostGone,
    /// The caller's `interrupted` check fired.
    Interrupted,
    Waiting,
}

impl Pending {
    pub fn start(check: &UserCheck) -> Self {
        let (tx, rx) = mpsc::channel();
        let abort = Abort::default();
        let (check, req, job) = (check.clone(), request::current(), abort.clone());
        std::thread::spawn(move || {
            let _ = tx.send(check.confirm(req.as_ref(), &job));
        });
        Pending { rx, abort, closes: crate::uhid::closes() }
    }

    /// An approval that already has its answer.
    fn done(outcome: Outcome) -> Self {
        let (tx, rx) = mpsc::channel();
        let _ = tx.send(outcome);
        Pending { rx, abort: Abort::default(), closes: crate::uhid::closes() }
    }

    /// Wait up to `timeout` for the user, checking the host (and `interrupted`)
    /// every few milliseconds.
    pub fn poll(&self, timeout: Duration, mut interrupted: impl FnMut() -> bool) -> Poll {
        const TICK: Duration = Duration::from_millis(20);
        let deadline = Instant::now() + timeout;
        loop {
            if crate::uhid::closes() != self.closes {
                return Poll::HostGone;
            }
            if interrupted() {
                return Poll::Interrupted;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left.min(TICK)) {
                Ok(outcome) => return Poll::Done(outcome),
                Err(RecvTimeoutError::Disconnected) => return Poll::Done(Outcome::Error),
                Err(RecvTimeoutError::Timeout) if left <= TICK => return Poll::Waiting,
                Err(RecvTimeoutError::Timeout) => {}
            }
        }
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

pub struct PinentryPresence {
    check: UserCheck,
    pending: Option<Pending>,
}

impl PinentryPresence {
    pub fn new(check: UserCheck) -> Self {
        PinentryPresence {
            check,
            pending: None,
        }
    }
}

impl UserPresence for PinentryPresence {
    fn check_init(&mut self) {
        self.pending = Some(if request::presence_already_given() {
            // Duplicate registration: OpenSK re-checks presence before
            // rejecting it, but the user just confirmed this very request.
            Pending::done(Outcome::Approved)
        } else {
            Pending::start(&self.check)
        });
    }

    fn wait_with_timeout(
        &mut self,
        buf: &mut [u8; 64],
        timeout_ms: usize,
    ) -> UserPresenceWaitResult {
        let Some(pending) = &self.pending else {
            return Ok((Err(UserPresenceError::Timeout), RecvStatus::Timeout));
        };
        // A report from the host goes to OpenSK, which handles CTAPHID_CANCEL.
        let mut packet = None;
        let timeout = Duration::from_millis(timeout_ms as u64);
        let up = match pending.poll(timeout, || {
            packet = crate::uhid::take_packet();
            packet.is_some()
        }) {
            Poll::Done(Outcome::Approved) => {
                request::note_confirmed();
                Ok(())
            }
            Poll::Done(_) => Err(UserPresenceError::Declined),
            Poll::HostGone => {
                tracing::info!("host went away; closing the dialog");
                Err(UserPresenceError::Canceled)
            }
            Poll::Interrupted | Poll::Waiting => Err(UserPresenceError::Timeout), // keep waiting
        };
        match packet {
            Some(pkt) => {
                *buf = pkt;
                Ok((up, RecvStatus::Received(UsbEndpoint::MainHid)))
            }
            None => Ok((up, RecvStatus::Timeout)),
        }
    }

    fn check_complete(&mut self) {
        self.pending = None;
    }
}
