//! Built-in user verification, backed by a pinentry confirmation (and, with
//! `LINUX_PASSKEY_UV=fprintd`, a real fingerprint check after it).
//!
//! We present OpenSK with a "fingerprint sensor" whose single sample is a
//! pinentry Confirm/Deny click (then the finger, when enabled). With one template enrolled, the authenticator
//! advertises `uv:true`, so the browser performs built-in UV (this prompt)
//! instead of asking for a clientPIN. `check_fingerprint` is polled in a loop
//! by OpenSK (Timeout = keep waiting + keepalive), matching our poll model.

use opensk::api::fingerprint::{
    Ctap2EnrollFeedback, Fingerprint, FingerprintCheckError, FingerprintKind,
};
use opensk::ctap::status_code::CtapResult;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

/// The fixed template id for our single "enrolled finger".
// Kept from the tpm2-passkey days: it is stored in existing passkey stores.
pub const TEMPLATE_ID: &[u8] = b"tpm2-passkey-uv";

pub struct PinentryFingerprint {
    check: crate::presence::UserCheck,
    pending: Option<Receiver<bool>>,
}

impl PinentryFingerprint {
    pub fn new(check: crate::presence::UserCheck) -> Self {
        PinentryFingerprint {
            check,
            pending: None,
        }
    }
}

impl Fingerprint for PinentryFingerprint {
    fn prepare_enrollment(&mut self) -> CtapResult<()> {
        Ok(())
    }

    fn capture_sample(
        &mut self,
        _timeout_ms: Option<usize>,
    ) -> CtapResult<(Ctap2EnrollFeedback, usize, Option<Vec<u8>>)> {
        // One good sample completes enrollment.
        Ok((Ctap2EnrollFeedback::FpGood, 0, Some(TEMPLATE_ID.to_vec())))
    }

    fn cancel_enrollment(&mut self) -> CtapResult<()> {
        Ok(())
    }

    fn remove_enrollment(&mut self, _template_id: &[u8]) -> CtapResult<()> {
        Ok(())
    }

    fn check_fingerprint_init(&mut self) -> CtapResult<()> {
        let (tx, rx) = mpsc::channel();
        let check = self.check.clone();
        let req = crate::request::current();
        std::thread::spawn(move || {
            let _ = tx.send(check.confirm(req.as_ref()));
        });
        self.pending = Some(rx);
        Ok(())
    }

    fn check_fingerprint(&mut self, timeout_ms: usize) -> Result<(), FingerprintCheckError> {
        match &self.pending {
            Some(rx) => match rx.recv_timeout(Duration::from_millis(timeout_ms as u64)) {
                Ok(true) => {
                    crate::request::note_confirmed();
                    Ok(())
                }
                Ok(false) => Err(FingerprintCheckError::NoMatch),
                Err(RecvTimeoutError::Timeout) => Err(FingerprintCheckError::Timeout), // keep waiting
                Err(RecvTimeoutError::Disconnected) => Err(FingerprintCheckError::Other),
            },
            None => Err(FingerprintCheckError::Other),
        }
    }

    fn check_fingerprint_complete(&mut self) -> CtapResult<()> {
        self.pending = None;
        Ok(())
    }

    fn fingerprint_kind(&self) -> FingerprintKind {
        FingerprintKind::Touch
    }

    fn max_capture_samples_required_for_enroll(&self) -> usize {
        1
    }
}
