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
//! keepalives between calls, so we spawn pinentry in `check_init` and poll.

use opensk::api::connection::RecvStatus;
use opensk::api::user_presence::{
    UserPresence, UserPresenceError, UserPresenceWaitResult,
};
use crate::request::{self, Prompt};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

/// How the user approves a request: a pinentry dialog naming the site (and
/// account), then optionally a fingerprint check. Shared by user presence and
/// the fingerprint-backed user verification, so every path asks the same way.
#[derive(Clone)]
pub struct UserCheck {
    pub pinentry_bin: String,
    /// `fprintd-verify` binary when fingerprints are on (`LINUX_PASSKEY_UV=fprintd`).
    pub fprintd_verify: Option<String>,
}

impl UserCheck {
    /// Dialog first; the finger only after a confirm, and only for requests that
    /// act on a credential (see [`request::wants_fingerprint`]).
    pub fn confirm(&self, req: Option<&request::Request>) -> bool {
        let mut prompt = Prompt::for_request(req);
        let finger = self.fprintd_verify.as_deref().filter(|_| request::wants_fingerprint(req));
        if finger.is_some() {
            prompt.description.push_str("\n\nAfter confirming, touch the fingerprint sensor.");
        }
        if !pinentry_confirm(&self.pinentry_bin, &prompt) {
            return false;
        }
        match finger {
            Some(bin) => crate::fprintd::verify(bin),
            None => true,
        }
    }
}

pub struct PinentryPresence {
    check: UserCheck,
    pending: Option<Receiver<bool>>,
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
        let (tx, rx) = mpsc::channel();
        if request::presence_already_given() {
            // Duplicate registration: OpenSK re-checks presence before
            // rejecting it, but the user just confirmed this very request.
            let _ = tx.send(true);
            self.pending = Some(rx);
            return;
        }
        let check = self.check.clone();
        let req = request::current();
        std::thread::spawn(move || {
            let _ = tx.send(check.confirm(req.as_ref()));
        });
        self.pending = Some(rx);
    }

    fn wait_with_timeout(
        &mut self,
        _buf: &mut [u8; 64],
        timeout_ms: usize,
    ) -> UserPresenceWaitResult {
        let up = match &self.pending {
            Some(rx) => match rx.recv_timeout(Duration::from_millis(timeout_ms as u64)) {
                Ok(true) => {
                    request::note_confirmed();
                    Ok(())
                }
                Ok(false) => Err(UserPresenceError::Declined),
                Err(RecvTimeoutError::Timeout) => Err(UserPresenceError::Timeout), // keep waiting
                Err(RecvTimeoutError::Disconnected) => Err(UserPresenceError::Declined),
            },
            None => Err(UserPresenceError::Timeout),
        };
        Ok((up, RecvStatus::Timeout))
    }

    fn check_complete(&mut self) {
        self.pending = None;
    }
}

/// Show a pinentry Confirm/Deny dialog; returns true if confirmed. Shared by
/// user presence (here) and the fingerprint-backed user verification. The
/// wording names the operation and site of the request being processed.
pub fn pinentry_confirm(bin: &str, prompt: &Prompt) -> bool {
    use pinentry::ConfirmationDialog;
    match ConfirmationDialog::with_binary(bin) {
        None => {
            tracing::error!("pinentry binary '{bin}' not found");
            false
        }
        Some(mut dialog) => {
            dialog
                .with_title(&prompt.title)
                .with_ok(&prompt.ok)
                .with_cancel("Deny");
            matches!(dialog.confirm(&prompt.description), Ok(true))
        }
    }
}
