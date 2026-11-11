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
//! An agent can also be a running program that listens on
//! `$XDG_RUNTIME_DIR/linux-passkey-agent.sock` (the Quickshell bar does): the
//! daemon connects there first, with the same messages, and starts the dialog
//! program only when nobody listens. Only programs from an allowed package
//! (`LINUX_PASSKEY_AGENTS`, store paths) count: whoever answers there can
//! approve requests, so the daemon checks the peer's executable.
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
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
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

/// Where approval agents come from.
#[derive(Clone, Default)]
pub struct Agents {
    /// The program to start when no agent listens (linux-passkey-dialog).
    pub dialog: Option<String>,
    /// Packages (store paths) whose programs may answer on the agent socket.
    pub allowed: Vec<String>,
}

impl Agents {
    /// Is there any agent to ask (otherwise pinentry asks)?
    pub fn available(&self) -> bool {
        self.dialog.is_some() || (!self.allowed.is_empty() && socket_path().is_some_and(|p| p.exists()))
    }
}

pub fn socket_path() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("linux-passkey-agent.sock"))
}

/// Ends a session from another thread (kills the dialog, or hangs up on the
/// listening agent).
#[derive(Clone)]
pub struct Killer(Arc<dyn Fn() + Send + Sync>);

impl Killer {
    pub fn kill(&self) {
        (self.0)()
    }
}

enum End {
    Child(Arc<Mutex<Child>>),
    Socket(UnixStream),
}

/// A running agent. Dropping it ends the dialog.
pub struct Session {
    end: End,
    input: Box<dyn Write + Send>,
    /// Its answer lines, read on a thread; None once it closed its side.
    lines: Arc<Mutex<Receiver<Option<String>>>>,
}

fn read_lines(output: impl Read + Send + 'static) -> Receiver<Option<String>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(output).lines() {
            let Ok(line) = line else { break };
            if tx.send(Some(line)).is_err() {
                return;
            }
        }
        let _ = tx.send(None);
    });
    rx
}

/// The process on the other end of a Unix socket, and its uid.
fn peer(stream: &UnixStream) -> Option<(i32, u32)> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: SO_PEERCRED fills a ucred of the given length on this socket.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some((cred.pid, cred.uid))
}

impl Session {
    /// The listening agent if there is an allowed one, else the dialog program.
    pub fn start(agents: &Agents) -> io::Result<Session> {
        if let Some(session) = Self::connect(agents) {
            return Ok(session);
        }
        let bin = agents
            .dialog
            .as_deref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no approval agent"))?;
        let mut child = Command::new(bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let input = child.stdin.take().expect("piped stdin");
        let lines = read_lines(child.stdout.take().expect("piped stdout"));
        Ok(Session {
            end: End::Child(Arc::new(Mutex::new(child))),
            input: Box::new(input),
            lines: Arc::new(Mutex::new(lines)),
        })
    }

    fn connect(agents: &Agents) -> Option<Session> {
        if agents.allowed.is_empty() {
            return None;
        }
        let path = socket_path()?;
        let stream = UnixStream::connect(&path).ok()?;
        let (pid, uid) = peer(&stream)?;
        // SAFETY: getuid has no preconditions.
        let ours = uid == unsafe { libc::getuid() };
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        if !ours || !agents.allowed.iter().any(|p| exe.starts_with(p)) {
            tracing::warn!("ignoring the agent on {}: {} is not an allowed agent", path.display(), exe.display());
            return None;
        }
        let input = stream.try_clone().ok()?;
        let output = stream.try_clone().ok()?;
        Some(Session {
            end: End::Socket(stream),
            input: Box::new(input),
            lines: Arc::new(Mutex::new(read_lines(output))),
        })
    }

    /// A handle that ends the dialog from another thread.
    pub fn killer(&self) -> Killer {
        match &self.end {
            End::Child(child) => {
                let child = child.clone();
                Killer(Arc::new(move || {
                    let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
                }))
            }
            End::Socket(stream) => {
                let stream = stream.try_clone().ok();
                Killer(Arc::new(move || {
                    if let Some(s) = &stream {
                        let _ = s.shutdown(std::net::Shutdown::Both);
                    }
                }))
            }
        }
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
        let child = match &self.end {
            End::Socket(stream) => {
                let _ = stream.shutdown(std::net::Shutdown::Both);
                return;
            }
            End::Child(child) => child,
        };
        let mut child = child.lock().unwrap_or_else(|e| e.into_inner());
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
pub fn preapprove(agents: &Agents, ask: Ask, timeout: Duration, mut cancelled: impl FnMut() -> bool) -> Pre {
    let session = match Session::start(agents) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("could not start the approval dialog: {e}");
            return Pre::Failed;
        }
    };
    let killer = session.killer();
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
            killer.kill();
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
