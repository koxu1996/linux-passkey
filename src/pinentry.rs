//! The Confirm/Deny dialog: a small pinentry (Assuan) client.
//!
//! Not the `pinentry` crate: it drops the pinentry process without waiting
//! for it (a zombie per prompt) and gives no handle to close a dialog whose
//! request is gone. Here the process runs under an [`Abort`], which can kill it,
//! and is always reaped.

use crate::presence::Abort;
use crate::request::Prompt;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

/// What the user did with the dialog.
#[derive(Debug, PartialEq)]
pub enum Answer {
    Confirmed,
    /// Deny, or the dialog was closed.
    Denied,
    /// The third button ([`Prompt::elsewhere`]): use another authenticator.
    Elsewhere,
}

/// GPG error codes (low 16 bits of an Assuan `ERR`) that mean "the user said no".
const GPG_ERR_CANCELED: u32 = 99;
const GPG_ERR_NOT_CONFIRMED: u32 = 114;

/// Show the dialog and wait for the user. Errors: pinentry missing or broken,
/// or the dialog was aborted.
pub fn confirm(bin: &str, prompt: &Prompt, abort: &Abort) -> io::Result<Answer> {
    let mut cmd = Command::new(bin);
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let pipes = abort.spawn(&mut cmd)?;
    let result = (|| {
        let mut input = pipes.stdin.expect("piped stdin");
        let mut output = BufReader::new(pipes.stdout.expect("piped stdout"));
        response(&mut output)?; // greeting
        for (command, value) in [
            ("SETTITLE", prompt.title.as_str()),
            ("SETDESC", prompt.description.as_str()),
            ("SETOK", prompt.ok.as_str()),
            ("SETCANCEL", "Deny"),
        ] {
            request(&mut input, &mut output, &format!("{command} {}", escape(value)))?;
        }
        // pinentry's "not OK" button: CONFIRM then fails with NOT_CONFIRMED,
        // while Deny (Cancel) and closing the window give CANCELED.
        if let Some(label) = &prompt.elsewhere {
            request(&mut input, &mut output, &format!("SETNOTOK {}", escape(label)))?;
        }
        let answer = match request(&mut input, &mut output, "CONFIRM") {
            Ok(()) => Answer::Confirmed,
            Err(Error::Assuan(code)) if code & 0xFFFF == GPG_ERR_NOT_CONFIRMED && prompt.elsewhere.is_some() => {
                Answer::Elsewhere
            }
            Err(Error::Assuan(code)) if matches!(code & 0xFFFF, GPG_ERR_CANCELED | GPG_ERR_NOT_CONFIRMED) => {
                Answer::Denied
            }
            Err(e) => return Err(e),
        };
        let _ = writeln!(input, "BYE");
        Ok(answer)
    })();
    abort.reap();
    result.map_err(|e| match e {
        Error::Io(e) => e,
        Error::Assuan(code) => io::Error::other(format!("pinentry error {code}")),
    })
}

enum Error {
    Io(io::Error),
    /// An `ERR <code>` reply.
    Assuan(u32),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

fn request(input: &mut impl Write, output: &mut impl BufRead, line: &str) -> Result<(), Error> {
    writeln!(input, "{line}")?;
    input.flush()?;
    response(output)
}

/// Read up to the `OK` or `ERR` that ends a reply (skipping comments, status
/// and data lines, which a Confirm dialog does not need).
fn response(output: &mut impl BufRead) -> Result<(), Error> {
    let mut line = String::new();
    loop {
        line.clear();
        if output.read_line(&mut line)? == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
        }
        let line = line.trim_end();
        if line == "OK" || line.starts_with("OK ") {
            return Ok(());
        }
        if let Some(rest) = line.strip_prefix("ERR ") {
            let code = rest.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(0);
            return Err(Error::Assuan(code));
        }
    }
}

/// Percent-escape an Assuan parameter, kept under the 1000-byte line limit.
fn escape(value: &str) -> String {
    const MAX: usize = 900;
    let mut out = String::new();
    for c in value.chars() {
        let piece = match c {
            '%' => "%25".to_string(),
            '\n' => "%0A".to_string(),
            '\r' => "%0D".to_string(),
            c => c.to_string(),
        };
        if out.len() + piece.len() > MAX {
            break;
        }
        out.push_str(&piece);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn escapes_assuan_specials() {
        assert_eq!(escape("50% off\r\nnext"), "50%25 off%0D%0Anext");
        assert!(escape(&"é".repeat(1000)).len() <= 900);
    }

    #[test]
    fn reads_replies() {
        let mut ok = Cursor::new("# comment\nS SOMETHING\nOK Pleased to meet you\n");
        assert!(response(&mut ok).is_ok());
        let mut cancel = Cursor::new("ERR 83886179 Operation cancelled <Pinentry>\n");
        assert!(matches!(response(&mut cancel), Err(Error::Assuan(c)) if c & 0xFFFF == GPG_ERR_CANCELED));
        let mut eof = Cursor::new("");
        assert!(matches!(response(&mut eof), Err(Error::Io(_))));
    }
}
