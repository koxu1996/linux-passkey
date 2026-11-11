//! The D-Bus front-end: WebAuthn requests from the browser extension's native
//! host (`native_host.rs`), with the full request in hand, instead of CTAP
//! over the virtual USB key. See docs/design/browser-extension.md.
//!
//! The interface follows credentialsd's Gateway (origin as an argument,
//! `top_origin` and `public_key` in the options, JSON in and out), under our
//! own name until that API settles:
//!
//! ```text
//! io.github.koxu1996.LinuxPasskey  /io/github/koxu1996/LinuxPasskey
//! io.github.koxu1996.LinuxPasskey.Gateway1
//!   CreateCredential(s parent_window, s origin, s type, a{sv} options) -> a{sv}
//!   GetCredential(s parent_window, s origin, a{sv} options) -> a{sv}
//!   GetClientCapabilities() -> a{sb}
//!   Cancel(u request_id)
//! ```
//!
//! Requests are checked and encoded here (`webauthn.rs`), then queued for the
//! main loop, which owns OpenSK: one ceremony at a time, USB and D-Bus alike.

use crate::webauthn::{Caller, Ceremony, Error};
use futures_channel::oneshot;
use std::collections::HashMap;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use zbus::message::Header;
use zbus::zvariant::{OwnedValue, Value};

pub const BUS_NAME: &str = "io.github.koxu1996.LinuxPasskey";
pub const OBJECT_PATH: &str = "/io/github/koxu1996/LinuxPasskey";
pub const INTERFACE: &str = "io.github.koxu1996.LinuxPasskey.Gateway1";

/// Who asked: the caller's unique bus name and its request id (for Cancel).
pub type CallId = (String, u32);

/// A ceremony for the main loop.
pub struct Job {
    pub ceremony: Ceremony,
    pub call: CallId,
    /// The app asking, for the dialog ("Brave").
    pub app: Option<String>,
    pub reply: oneshot::Sender<Result<String, Error>>,
}

#[derive(Default)]
struct Calls {
    /// The call OpenSK is working on.
    running: Option<CallId>,
    /// Cancelled before they started.
    cancelled: Vec<CallId>,
}

static CALLS: Mutex<Calls> = Mutex::new(Calls { running: None, cancelled: Vec::new() });

fn calls() -> std::sync::MutexGuard<'static, Calls> {
    CALLS.lock().unwrap_or_else(|e| e.into_inner())
}

/// The main loop starts `call`: false if it was cancelled while queued.
pub fn start(call: &CallId) -> bool {
    let mut c = calls();
    if let Some(i) = c.cancelled.iter().position(|x| x == call) {
        c.cancelled.swap_remove(i);
        return false;
    }
    c.running = Some(call.clone());
    true
}

/// The main loop is done with the running call.
pub fn finish() {
    calls().running = None;
    // A cancel that came too late must not hit the next D-Bus request.
    crate::uhid::take_cancel(crate::request::INTERNAL_CID);
}

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "io.github.koxu1996.LinuxPasskey.Error")]
pub enum GatewayError {
    #[zbus(error)]
    ZBus(zbus::Error),
    NotAllowed(String),
    InvalidState(String),
    Security(String),
    NotSupported(String),
    Type(String),
    Abort(String),
    /// Not a DOMException: the caller should try other authenticators.
    NoCredential(String),
    Unknown(String),
}

impl From<Error> for GatewayError {
    fn from(e: Error) -> Self {
        let m = e.message();
        match e {
            Error::NotAllowed(_) => GatewayError::NotAllowed(m),
            Error::InvalidState(_) => GatewayError::InvalidState(m),
            Error::Security(_) => GatewayError::Security(m),
            Error::NotSupported(_) => GatewayError::NotSupported(m),
            Error::Type(_) => GatewayError::Type(m),
            Error::Abort => GatewayError::Abort(m),
            Error::NoCredential => GatewayError::NoCredential(m),
            Error::Unknown(_) => GatewayError::Unknown(m),
        }
    }
}

pub struct Gateway {
    jobs: Mutex<Sender<Job>>,
}

fn option_str(options: &HashMap<String, OwnedValue>, key: &str) -> Option<String> {
    options.get(key).and_then(|v| String::try_from(v.clone()).ok())
}

fn reply(kind: &str, key: &str, json: String) -> Result<HashMap<String, OwnedValue>, GatewayError> {
    let owned = |v: Value<'_>| OwnedValue::try_from(v).map_err(|e| GatewayError::ZBus(e.into()));
    Ok(HashMap::from([
        ("type".to_string(), owned(Value::from(kind.to_string()))?),
        (key.to_string(), owned(Value::from(json))?),
    ]))
}

impl Gateway {
    async fn run(
        &self,
        conn: &zbus::Connection,
        header: &Header<'_>,
        origin: String,
        options: &HashMap<String, OwnedValue>,
        prepare: fn(&Caller, &str) -> Result<Ceremony, Error>,
    ) -> Result<String, GatewayError> {
        let caller = Caller { origin, top_origin: option_str(options, "top_origin") };
        let public_key = option_str(options, "public_key")
            .ok_or_else(|| GatewayError::Type("options.public_key (JSON) is missing".into()))?;
        let ceremony = prepare(&caller, &public_key)?;
        let sender = header.sender().map(|s| s.to_string()).unwrap_or_default();
        let request_id = options.get("request_id").and_then(|v| u32::try_from(v.clone()).ok()).unwrap_or(0);
        tracing::info!(origin = %caller.origin, rp = %ceremony.rp_id, kind = ?ceremony.kind, "D-Bus request");
        let app = caller_app(conn, &sender).await;
        let (tx, rx) = oneshot::channel();
        let job = Job { ceremony, call: (sender, request_id), app, reply: tx };
        self.jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(job)
            .map_err(|_| GatewayError::Unknown("authenticator is shutting down".into()))?;
        crate::uhid::wake();
        let result = rx.await.map_err(|_| GatewayError::Unknown("request dropped".into()))?;
        Ok(result?)
    }
}

#[zbus::interface(name = "io.github.koxu1996.LinuxPasskey.Gateway1")]
impl Gateway {
    async fn create_credential(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        _parent_window: String,
        origin: String,
        r#type: String,
        options: HashMap<String, OwnedValue>,
    ) -> Result<HashMap<String, OwnedValue>, GatewayError> {
        if r#type != "publicKey" {
            return Err(GatewayError::NotSupported(format!("credential type {type:?}")));
        }
        let json = self.run(conn, &header, origin, &options, Ceremony::create).await?;
        reply("publicKey", "registration_response_json", json)
    }

    async fn get_credential(
        &self,
        #[zbus(connection)] conn: &zbus::Connection,
        #[zbus(header)] header: Header<'_>,
        _parent_window: String,
        origin: String,
        options: HashMap<String, OwnedValue>,
    ) -> Result<HashMap<String, OwnedValue>, GatewayError> {
        let json = self.run(conn, &header, origin, &options, Ceremony::get).await?;
        reply("publicKey", "authentication_response_json", json)
    }

    /// WebAuthn L3 client capabilities this authenticator adds.
    async fn get_client_capabilities(&self) -> HashMap<String, bool> {
        HashMap::from([
            ("userVerifyingPlatformAuthenticator".to_string(), true),
            ("passkeyPlatformAuthenticator".to_string(), true),
            ("conditionalCreate".to_string(), false),
            ("conditionalGet".to_string(), false),
        ])
    }

    /// Cancel one of the caller's own requests (by its `request_id`).
    async fn cancel(&self, #[zbus(header)] header: Header<'_>, request_id: u32) {
        let call = (header.sender().map(|s| s.to_string()).unwrap_or_default(), request_id);
        let mut c = calls();
        if c.running.as_ref() == Some(&call) {
            tracing::info!("D-Bus request cancelled; closing the dialog");
            crate::uhid::push_cancel(crate::request::INTERNAL_CID);
        } else {
            // Usually a request that is still queued; keep only recent ones.
            if c.cancelled.len() >= 64 {
                c.cancelled.remove(0);
            }
            c.cancelled.push(call);
        }
    }
}

/// The app behind a caller, for the dialog: the browser that started the
/// native host (its parent process), named by its executable. Looked up by
/// us from the bus, not taken from the caller. Display only.
async fn caller_app(conn: &zbus::Connection, sender: &str) -> Option<String> {
    let dbus = zbus::fdo::DBusProxy::new(conn).await.ok()?;
    let name = zbus::names::BusName::try_from(sender).ok()?;
    let pid = dbus.get_connection_unix_process_id(name).await.ok()?;
    let mut pid = parent(pid)?;
    // Skip a shell or wrapper between the browser and the host.
    for _ in 0..3 {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let base = exe.file_name()?.to_string_lossy().trim_start_matches('.').trim_end_matches("-wrapped").to_string();
        if !matches!(base.as_str(), "sh" | "bash" | "dash" | "zsh" | "env") {
            return Some(app_name(&base));
        }
        pid = parent(pid)?;
    }
    None
}

fn parent(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // pid (comm) state ppid ...; comm may contain spaces and parentheses.
    stat.rsplit_once(')')?.1.split_whitespace().nth(1)?.parse().ok()
}

fn app_name(exe: &str) -> String {
    match exe {
        "brave" => "Brave".into(),
        "chrome" | "google-chrome" => "Chrome".into(),
        "chromium" => "Chromium".into(),
        "librewolf" => "LibreWolf".into(),
        "firefox" => "Firefox".into(),
        "msedge" => "Edge".into(),
        "vivaldi-bin" => "Vivaldi".into(),
        other => other.to_string(),
    }
}

/// Own the bus name and serve the gateway. The connection must stay alive.
pub fn serve(jobs: Sender<Job>) -> zbus::Result<zbus::blocking::Connection> {
    zbus::blocking::connection::Builder::session()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, Gateway { jobs: Mutex::new(jobs) })?
        .build()
}
