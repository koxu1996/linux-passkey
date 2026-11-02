//! Fingerprint check through fprintd (`LINUX_PASSKEY_UV=fprintd`).
//!
//! Runs `fprintd-verify` for the current user and accepts only `verify-match`:
//! the same check `sudo` does with pam_fprintd. On a Mac with the apple_sep
//! driver the match happens inside the Secure Enclave.

use crate::presence::{Abort, Outcome};
use std::io::Read;
use std::process::{Command, Stdio};

/// Ask fprintd to verify the user's finger. Only `verify-no-match` is a failed
/// match; anything else that is not a match (sensor error, no prints
/// enrolled, fprintd missing) is an [`Outcome::Error`].
pub fn verify(bin: &str, abort: &Abort) -> Outcome {
    let mut cmd = Command::new(bin);
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let pipes = match abort.spawn(&mut cmd) {
        Ok(pipes) => pipes,
        Err(e) => {
            if !abort.is_aborted() {
                tracing::error!("fingerprint check: could not run '{bin}': {e}");
            }
            return Outcome::Error;
        }
    };
    let (mut stdout, mut stderr) = (String::new(), String::new());
    if let Some(mut out) = pipes.stdout {
        let _ = out.read_to_string(&mut stdout);
    }
    if let Some(mut err) = pipes.stderr {
        let _ = err.read_to_string(&mut stderr);
    }
    let status = abort.reap();
    if abort.is_aborted() {
        tracing::info!("fingerprint check stopped: the request ended");
        return Outcome::Error;
    }
    let outcome = result(&stdout);
    if outcome == Outcome::Approved {
        tracing::info!("fingerprint verified");
        return outcome;
    }
    let last = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|l| !l.trim().is_empty())
        .last()
        .unwrap_or("no output");
    let status = status.map_or("killed".to_string(), |s| s.to_string());
    tracing::warn!("fingerprint not verified ({status}): {last}");
    outcome
}

/// fprintd-verify ends with `Verify result: verify-match (done)` on success and
/// `verify-no-match` for a finger it does not know.
fn result(stdout: &str) -> Outcome {
    let last = stdout.lines().filter(|l| l.contains("Verify result:")).last();
    match last {
        Some(l) if l.contains("verify-match") => Outcome::Approved,
        Some(l) if l.contains("verify-no-match") => Outcome::NoMatch,
        _ => Outcome::Error,
    }
}

#[cfg(test)]
mod tests {
    use super::result;
    use crate::presence::Outcome;

    #[test]
    fn only_a_match_counts() {
        assert_eq!(result("Verifying: right-index-finger\nVerify result: verify-match (done)\n"), Outcome::Approved);
        assert_eq!(result("Verify result: verify-no-match (done)\n"), Outcome::NoMatch);
        assert_eq!(result("Verify result: verify-retry-scan\nVerify result: verify-no-match (done)\n"), Outcome::NoMatch);
        assert_eq!(result("EnrollStart failed: GDBus.Error:...PermissionDenied\n"), Outcome::Error);
        assert_eq!(result("verify-match"), Outcome::Error); // not a result line
    }

    #[test]
    fn sensor_errors_are_not_a_failed_match() {
        // The Secure Enclave refusing to match (its own lockout) looks like this.
        assert_eq!(result("Verify result: verify-unknown-error (done)\n"), Outcome::Error);
        assert_eq!(result("Verify result: verify-disconnected (done)\n"), Outcome::Error);
    }
}
