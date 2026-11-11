//! The approval agent: the program that shows the user what a request is
//! for and collects the answer. Like a polkit authentication agent, it only
//! draws; the daemon decides. linux-passkey-dialog (GTK4, `dialog/`) is the
//! default agent; pinentry is the fallback when none is configured.
//!
//! One agent process per request, JSON lines over its stdin/stdout:
//!
//! ```text
//! daemon -> agent  {"v":1,"type":"ask","op":"sign-in","rp":"google.com",
//!                   "origin":"https://accounts.google.com","app":"Brave",
//!                   "accounts":[{"id":"…","name":"you@gmail.com","displayName":"You"}],
//!                   "user":null,"elsewhere":true,"fingerprint":true}
//! agent -> daemon  {"answer":"approve","account":"…"} | {"answer":"deny"}
//!                  | {"answer":"elsewhere"}
//! daemon -> agent  {"v":1,"type":"fingerprint","state":"waiting"|"no-match"|"match"|"error"}
//! daemon -> agent  {"v":1,"type":"done"}, then EOF: the agent closes
//! ```
//!
//! `op` is one of register, already-registered, sign-in, select, reset,
//! u2f-register, u2f-sign-in, other. `accounts` (sign-in) lists our passkeys
//! for the site, newest first; empty when we can't list them (USB requests).
//! `origin` and `app` are only known for requests from the browser extension.
//!
//! For extension requests the agent runs *before* OpenSK sees the request
//! ([`preapprove`]), so the dialog can offer a choice of account; the
//! session then stays open and shows the fingerprint step, which OpenSK's
//! UV hook runs ([`preapproved_fingerprint`]).

use crate::presence::{Abort, Outcome};
use crate::request::Request;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const VERSION: u32 = 1;

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Account {
    /// Credential id, base64url.
    pub id: String,
    pub name: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Ask {
    pub op: &'static str,
    pub rp: String,
    pub origin: Option<String>,
    pub app: Option<String>,
    /// The account a registration is for.
    pub user: Option<Account>,
    pub accounts: Vec<Account>,
    pub elsewhere: bool,
    pub fingerprint: bool,
}

impl Ask {
    /// From what the request peek saw (USB requests, and the fallback).
    pub fn for_request(req: Option<&Request>, fingerprint: bool) -> Ask {
        let (op, rp, user) = match req {
            Some(Request::Register { rp, user, existing, .. }) => (
                if *existing { "already-registered" } else { "register" },
                rp.clone(),
                user.as_ref().map(|u| Account { id: String::new(), name: Some(u.clone()), display_name: None }),
            ),
            Some(Request::SignIn { rp }) => ("sign-in", rp.clone(), None),
            Some(Request::Reset) => ("reset", String::new(), None),
            Some(Request::Select) => ("select", String::new(), None),
            Some(Request::U2fRegister) => ("u2f-register", String::new(), None),
            Some(Request::U2fSignIn) => ("u2f-sign-in", String::new(), None),
            Some(Request::Other) | None => ("other", String::new(), None),
        };
        Ask { op, rp, origin: None, app: None, user, accounts: vec![], elsewhere: false, fingerprint }
    }
}

pub fn account_id(id: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(id)
}

#[derive(Debug, PartialEq)]
pub enum Answer {
    /// With the chosen account's credential id, when there was a choice.
    Approve(Option<Vec<u8>>),
    Deny,
    Elsewhere,
}

#[derive(Deserialize)]
struct RawAnswer {
    answer: String,
    account: Option<String>,
}

fn parse_answer(line: &str) -> io::Result<Answer> {
    let bad = |m: String| io::Error::new(io::ErrorKind::InvalidData, m);
    let raw: RawAnswer = serde_json::from_str(line).map_err(|e| bad(format!("agent answer: {e}")))?;
    match raw.answer.as_str() {
        "approve" => {
            let account = raw
                .account
                .map(|a| URL_SAFE_NO_PAD.decode(a).map_err(|e| bad(format!("agent account: {e}"))))
                .transpose()?;
            Ok(Answer::Approve(account))
        }
        "deny" => Ok(Answer::Deny),
        "elsewhere" => Ok(Answer::Elsewhere),
        other => Err(bad(format!("agent answer {other:?}"))),
    }
}

/// A running agent. Dropping it ends the dialog.
pub struct Session {
    child: Arc<Mutex<Child>>,
    input: ChildStdin,
    /// Its answer lines, read on a thread; None once it closed stdout.
    lines: Arc<Mutex<Receiver<Option<String>>>>,
}

impl Session {
    pub fn start(bin: &str) -> io::Result<Session> {
        let mut child = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().expect("piped stdin");
        let output = BufReader::new(child.stdout.take().expect("piped stdout"));
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in output.lines() {
                let Ok(line) = line else { break };
                if tx.send(Some(line)).is_err() {
                    return;
                }
            }
            let _ = tx.send(None);
        });
        Ok(Session { child: Arc::new(Mutex::new(child)), input, lines: Arc::new(Mutex::new(rx)) })
    }

    /// A handle that ends the dialog from another thread.
    pub fn killer(&self) -> Arc<Mutex<Child>> {
        self.child.clone()
    }

    fn send(&mut self, msg: serde_json::Value) -> io::Result<()> {
        writeln!(self.input, "{msg}")?;
        self.input.flush()
    }

    /// Show the request and wait for the user.
    pub fn ask(&mut self, ask: &Ask) -> io::Result<Answer> {
        let mut msg = serde_json::to_value(ask).map_err(io::Error::other)?;
        msg["v"] = VERSION.into();
        msg["type"] = "ask".into();
        self.send(msg)?;
        let lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        match lines.recv() {
            Ok(Some(line)) => parse_answer(line.trim()),
            // Closed without an answer: the window was closed.
            Ok(None) | Err(_) => Ok(Answer::Deny),
        }
    }

    pub fn fingerprint(&mut self, state: &str) {
        let _ = self.send(serde_json::json!({ "v": VERSION, "type": "fingerprint", "state": state }));
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.send(serde_json::json!({ "v": VERSION, "type": "done" }));
        let mut child = self.child.lock().unwrap_or_else(|e| e.into_inner());
        // Give it a moment to show the last state and exit by itself.
        let deadline = Instant::now() + Duration::from_millis(600);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

fn kill(child: &Arc<Mutex<Child>>) {
    let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
}

/// Run one approval in `session` for a USB request: the dialog, then the
/// finger in the same window. `abort` ends it when the request does.
pub fn approve(mut session: Session, ask: &Ask, finger: Option<&str>, abort: &Abort) -> Outcome {
    abort.adopt(session.killer());
    let answer = match session.ask(ask) {
        Ok(a) => a,
        Err(e) => {
            if !abort.is_aborted() {
                tracing::error!("approval dialog failed: {e}");
            }
            return Outcome::Error;
        }
    };
    match answer {
        Answer::Approve(_) => match finger {
            Some(bin) => fingerprint_in(&mut session, bin, abort),
            None => Outcome::Approved,
        },
        Answer::Deny => {
            tracing::info!("request denied");
            Outcome::Denied
        }
        Answer::Elsewhere => {
            crate::request::note_elsewhere();
            Outcome::Denied
        }
    }
}

fn fingerprint_in(session: &mut Session, bin: &str, abort: &Abort) -> Outcome {
    session.fingerprint("waiting");
    // Cancel (or closing the window) while we wait for the finger.
    let (stop, cancelled) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
    let watcher = {
        let (lines, abort, stop, cancelled) = (session.lines.clone(), abort.clone(), stop.clone(), cancelled.clone());
        std::thread::spawn(move || {
            let lines = lines.lock().unwrap_or_else(|e| e.into_inner());
            while !stop.load(Ordering::SeqCst) {
                let quit = match lines.recv_timeout(Duration::from_millis(100)) {
                    Ok(Some(line)) => parse_answer(line.trim()).is_ok_and(|a| a == Answer::Deny),
                    Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => true,
                    Err(mpsc::RecvTimeoutError::Timeout) => false,
                };
                if quit {
                    cancelled.store(true, Ordering::SeqCst);
                    abort.abort();
                    return;
                }
            }
        })
    };
    let outcome = crate::fprintd::verify(bin, abort);
    stop.store(true, Ordering::SeqCst);
    let _ = watcher.join();
    if cancelled.load(Ordering::SeqCst) {
        tracing::info!("fingerprint check cancelled in the dialog");
        return Outcome::Denied;
    }
    session.fingerprint(match outcome {
        Outcome::Approved => "match",
        Outcome::NoMatch => "no-match",
        _ => "error",
    });
    outcome
}

/// The session of the extension request being worked on, after the user
/// approved it ([`preapprove`]).
static PREAPPROVED: Mutex<Option<Session>> = Mutex::new(None);

pub fn is_preapproved() -> bool {
    PREAPPROVED.lock().map(|g| g.is_some()).unwrap_or(false)
}

/// OpenSK's UV for a preapproved request: only the finger is left, shown in
/// the open dialog.
pub fn preapproved_fingerprint(finger: Option<&str>, abort: &Abort) -> Outcome {
    let mut guard = PREAPPROVED.lock().unwrap_or_else(|e| e.into_inner());
    match (guard.as_mut(), finger) {
        (Some(session), Some(bin)) => fingerprint_in(session, bin, abort),
        _ => Outcome::Approved,
    }
}

/// The extension request is over: close its dialog.
pub fn finish() {
    let session = PREAPPROVED.lock().unwrap_or_else(|e| e.into_inner()).take();
    drop(session);
}

pub enum Pre {
    Approved(Option<Vec<u8>>),
    Denied,
    Elsewhere,
    /// Cancelled by the caller, or timed out.
    Cancelled,
    Failed,
}

/// Ask the user about an extension request before OpenSK runs it. Waits up
/// to `timeout`, and gives up when `cancelled` says so.
pub fn preapprove(bin: &str, ask: Ask, timeout: Duration, mut cancelled: impl FnMut() -> bool) -> Pre {
    let session = match Session::start(bin) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("could not start the approval dialog '{bin}': {e}");
            return Pre::Failed;
        }
    };
    let child = session.killer();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut session = session;
        let answer = session.ask(&ask);
        let _ = tx.send((session, answer));
    });
    let deadline = Instant::now() + timeout;
    loop {
        match rx.recv_timeout(Duration::from_millis(20)) {
            Ok((session, Ok(Answer::Approve(account)))) => {
                *PREAPPROVED.lock().unwrap_or_else(|e| e.into_inner()) = Some(session);
                return Pre::Approved(account);
            }
            Ok((_, Ok(Answer::Deny))) => return Pre::Denied,
            Ok((_, Ok(Answer::Elsewhere))) => return Pre::Elsewhere,
            Ok((_, Err(e))) => {
                tracing::error!("approval dialog failed: {e}");
                return Pre::Failed;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Pre::Failed,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if cancelled() || Instant::now() >= deadline {
            kill(&child);
            // The reader thread ends once the dialog is gone.
            let _ = rx.recv_timeout(Duration::from_secs(1));
            return Pre::Cancelled;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn answers() {
        assert_eq!(parse_answer(r#"{"answer":"approve"}"#).unwrap(), Answer::Approve(None));
        assert_eq!(parse_answer(r#"{"answer":"approve","account":"q80"}"#).unwrap(), Answer::Approve(Some(vec![0xAB, 0xCD])));
        assert_eq!(parse_answer(r#"{"answer":"deny"}"#).unwrap(), Answer::Deny);
        assert_eq!(parse_answer(r#"{"answer":"elsewhere"}"#).unwrap(), Answer::Elsewhere);
        assert!(parse_answer(r#"{"answer":"maybe"}"#).is_err());
        assert!(parse_answer("not json").is_err());
    }

    #[test]
    fn ask_from_usb_request() {
        let reg = Request::Register { rp: "example.com".into(), user: Some("andrew".into()), exclude: vec![], has_uv: true, existing: false };
        let ask = Ask::for_request(Some(&reg), true);
        assert_eq!(ask.op, "register");
        assert_eq!(ask.user.unwrap().name.as_deref(), Some("andrew"));
        assert_eq!(Ask::for_request(Some(&Request::Select), false).op, "select");
        let json = serde_json::to_value(Ask::for_request(None, false)).unwrap();
        assert_eq!(json["op"], "other");
        assert!(json.get("displayName").is_none());
    }
}
