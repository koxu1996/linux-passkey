//! User presence, via a pinentry confirmation.
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
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

pub struct PinentryPresence {
    pinentry_bin: String,
    pending: Option<Receiver<bool>>,
}

impl PinentryPresence {
    pub fn new(pinentry_bin: String) -> Self {
        PinentryPresence {
            pinentry_bin,
            pending: None,
        }
    }
}

impl UserPresence for PinentryPresence {
    fn check_init(&mut self) {
        let (tx, rx) = mpsc::channel();
        let bin = self.pinentry_bin.clone();
        std::thread::spawn(move || {
            let _ = tx.send(pinentry_confirm(&bin));
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
                Ok(true) => Ok(()),
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
/// user presence (here) and the fingerprint-backed user verification.
pub fn pinentry_confirm(bin: &str) -> bool {
    use pinentry::ConfirmationDialog;
    match ConfirmationDialog::with_binary(bin) {
        None => {
            tracing::error!("pinentry binary '{bin}' not found");
            false
        }
        Some(mut dialog) => {
            dialog
                .with_title("tpm2-passkey")
                .with_ok("Confirm")
                .with_cancel("Deny");
            matches!(
                dialog.confirm("Confirm use of your TPM-backed passkey?"),
                Ok(true)
            )
        }
    }
}
