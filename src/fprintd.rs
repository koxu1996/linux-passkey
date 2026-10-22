//! Fingerprint check through fprintd (`LINUX_PASSKEY_UV=fprintd`).
//!
//! Runs `fprintd-verify` for the current user and accepts only `verify-match`:
//! the same check `sudo` does with pam_fprintd. On a Mac with the apple_sep
//! driver the match happens inside the Secure Enclave.

use std::process::{Command, Stdio};

/// Ask fprintd to verify the user's finger; true only on a match.
pub fn verify(bin: &str) -> bool {
    let out = match Command::new(bin)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(out) => out,
        Err(e) => {
            tracing::error!("fingerprint check: could not run '{bin}': {e}");
            return false;
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    if matched(&stdout) {
        tracing::info!("fingerprint verified");
        return true;
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    let last = stdout
        .lines()
        .chain(stderr.lines())
        .filter(|l| !l.trim().is_empty())
        .last()
        .unwrap_or("no output");
    tracing::warn!("fingerprint not verified ({}): {last}", out.status);
    false
}

/// fprintd-verify prints `Verify result: verify-match (done)` on success.
fn matched(stdout: &str) -> bool {
    stdout
        .lines()
        .any(|l| l.contains("Verify result:") && l.contains("verify-match"))
}

#[cfg(test)]
mod tests {
    use super::matched;

    #[test]
    fn only_a_match_counts() {
        assert!(matched("Verifying: right-index-finger\nVerify result: verify-match (done)\n"));
        assert!(!matched("Verify result: verify-no-match (done)\n"));
        assert!(!matched("Verify result: verify-retry-scan\nVerify result: verify-no-match (done)\n"));
        assert!(!matched("EnrollStart failed: GDBus.Error:...PermissionDenied\n"));
        assert!(!matched("verify-match")); // not a result line
    }
}
