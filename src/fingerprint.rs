//! Built-in user verification, backed by a pinentry confirmation (and, with
//! `LINUX_PASSKEY_UV=fprintd`, a real fingerprint check after it).
//!
//! We present OpenSK with a "fingerprint sensor" whose single sample is a
//! pinentry Confirm/Deny click (then the finger, when enabled). With one template enrolled, the authenticator
//! advertises `uv:true`, so the browser performs built-in UV (this prompt)
//! instead of asking for a clientPIN. `check_fingerprint` is polled in a loop
//! by OpenSK (Timeout = keep waiting + keepalive), matching our poll model.
//!
//! Only a finger that does not match counts as a failed UV attempt. Deny, a
//! cancelled request and a broken dialog or sensor get their own outcomes
//! (`opensk-uv-outcomes.patch`), so they cost no retry and clients don't retry
//! them. OpenSK reads no HID while it waits here, so we look for the request's
//! CTAPHID_CANCEL ourselves.

use opensk::api::fingerprint::{
    Ctap2EnrollFeedback, Fingerprint, FingerprintCheckError, FingerprintKind,
};
use opensk::ctap::status_code::CtapResult;
use crate::presence::{Outcome, Pending, Poll};
use std::time::Duration;

/// The fixed template id for our single "enrolled finger".
// Kept from the tpm2-passkey days: it is stored in existing passkey stores.
pub const TEMPLATE_ID: &[u8] = b"tpm2-passkey-uv";

pub struct PinentryFingerprint {
    check: crate::presence::UserCheck,
    pending: Option<Pending>,
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
        self.pending = Some(Pending::start(&self.check));
        Ok(())
    }

    fn check_fingerprint(&mut self, timeout_ms: usize) -> Result<(), FingerprintCheckError> {
        let Some(pending) = &self.pending else {
            return Err(FingerprintCheckError::Unavailable);
        };
        let cid = crate::request::current_cid();
        let timeout = Duration::from_millis(timeout_ms as u64);
        match pending.poll(timeout, || crate::uhid::take_cancel(cid)) {
            Poll::Done(Outcome::Approved) => {
                crate::request::note_confirmed();
                Ok(())
            }
            Poll::Done(Outcome::Denied) => Err(FingerprintCheckError::Declined),
            Poll::Done(Outcome::NoMatch) => Err(FingerprintCheckError::NoMatch),
            Poll::Done(Outcome::Error) => Err(FingerprintCheckError::Unavailable),
            Poll::HostGone => {
                tracing::info!("host went away; closing the dialog");
                Err(FingerprintCheckError::Canceled)
            }
            Poll::Interrupted => {
                tracing::info!("request cancelled by the host; closing the dialog");
                Err(FingerprintCheckError::Canceled)
            }
            Poll::Waiting => Err(FingerprintCheckError::Timeout), // keep waiting
        }
    }

    fn check_fingerprint_complete(&mut self) -> CtapResult<()> {
        // Ends the approval: kills a dialog or fprintd still running.
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
