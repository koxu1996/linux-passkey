//! Native messaging host for the browser extension: the browser starts it
//! (one process per extension connection) and talks JSON over stdio, each
//! message prefixed with its length (u32, native byte order). We forward to
//! the daemon's D-Bus gateway (`gateway.rs`) and hold no state of our own.
//!
//! From the extension (`id` is unique per connection):
//!   {"id": 1, "op": "create" | "get", "origin": "...", "topOrigin": "...",
//!    "publicKey": {...WebAuthn options JSON...}}
//!   {"id": 2, "op": "cancel", "target": 1}
//!   {"id": 3, "op": "capabilities"}
//! To the extension:
//!   {"id": 1, "ok": true, "response": {...credential JSON...}}
//!   {"id": 3, "ok": true, "capabilities": {...}}
//!   {"id": 1, "ok": false, "error": "NotAllowedError", "message": "..."}
//! `error` is a DOMException name, or `NoCredential` / `Unavailable`, which
//! tell the extension to use the browser's own WebAuthn instead.
//!
//! The extension takes `origin` from the browser (the sender of the page's
//! message), never from the page.

use crate::gateway::{BUS_NAME, INTERFACE, OBJECT_PATH};
use serde_json::{json, Value as Json};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedValue, Value};

/// Browsers cap messages to the host at 4 GiB and from it at 1 MiB; WebAuthn
/// requests are a few KiB.
const MAX_MESSAGE: usize = 1 << 20;

fn read_message(input: &mut impl Read) -> io::Result<Option<Json>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        r => r?,
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message too large"));
    }
    let mut buf = vec![0u8; len];
    input.read_exact(&mut buf)?;
    serde_json::from_slice(&buf).map(Some).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn write_message(out: &Mutex<io::Stdout>, msg: &Json) {
    let body = msg.to_string();
    let mut out = out.lock().unwrap_or_else(|e| e.into_inner());
    let _ = out.write_all(&(body.len() as u32).to_ne_bytes());
    let _ = out.write_all(body.as_bytes());
    let _ = out.flush();
}

fn failure(id: u64, error: &str, message: impl Into<String>) -> Json {
    json!({ "id": id, "ok": false, "error": error, "message": message.into() })
}

/// A D-Bus error from the gateway, as the extension's error name.
fn error_name(e: &zbus::Error) -> (&'static str, String) {
    const DOM: [(&str, &str); 8] = [
        ("NotAllowed", "NotAllowedError"),
        ("InvalidState", "InvalidStateError"),
        ("Security", "SecurityError"),
        ("NotSupported", "NotSupportedError"),
        ("Type", "TypeError"),
        ("Abort", "AbortError"),
        ("NoCredential", "NoCredential"),
        ("Unknown", "UnknownError"),
    ];
    if let zbus::Error::MethodError(name, message, _) = e {
        let message = message.clone().unwrap_or_default();
        if let Some(ours) = name.as_str().strip_prefix("io.github.koxu1996.LinuxPasskey.Error.") {
            if let Some((_, dom)) = DOM.iter().find(|(n, _)| *n == ours) {
                return (dom, message);
            }
        }
        // ServiceUnknown, NameHasNoOwner, ...: the daemon isn't running.
        return ("Unavailable", format!("{name}: {message}"));
    }
    ("Unavailable", e.to_string())
}

fn call(conn: &Connection, method: &str, body: &(impl serde::Serialize + zbus::zvariant::DynamicType)) -> zbus::Result<zbus::Message> {
    conn.call_method(Some(BUS_NAME), OBJECT_PATH, Some(INTERFACE), method, body)
}

fn ceremony(conn: &Connection, id: u64, msg: &Json) -> Json {
    let op = msg["op"].as_str().unwrap_or_default();
    let Some(origin) = msg["origin"].as_str() else {
        return failure(id, "SecurityError", "no origin");
    };
    // Options as a JSON string (the extension may send an object).
    let public_key = match &msg["publicKey"] {
        Json::String(s) => s.clone(),
        Json::Null => return failure(id, "TypeError", "no publicKey options"),
        other => other.to_string(),
    };
    let mut options: HashMap<&str, Value<'_>> = HashMap::from([
        ("public_key", Value::from(public_key)),
        ("request_id", Value::from(id as u32)),
    ]);
    if let Some(top) = msg["topOrigin"].as_str() {
        options.insert("top_origin", Value::from(top.to_string()));
    }
    let (result, key) = if op == "create" {
        (call(conn, "CreateCredential", &("", origin, "publicKey", options)), "registration_response_json")
    } else {
        (call(conn, "GetCredential", &("", origin, options)), "authentication_response_json")
    };
    let reply = result.and_then(|m| m.body().deserialize::<HashMap<String, OwnedValue>>());
    match reply {
        Ok(map) => {
            let json = map
                .get(key)
                .and_then(|v| String::try_from(v.clone()).ok())
                .and_then(|s| serde_json::from_str::<Json>(&s).ok());
            match json {
                Some(response) => json!({ "id": id, "ok": true, "response": response }),
                None => failure(id, "UnknownError", "malformed reply from linux-passkey"),
            }
        }
        Err(e) => {
            let (name, message) = error_name(&e);
            failure(id, name, message)
        }
    }
}

fn capabilities(conn: &Connection, id: u64) -> Json {
    match call(conn, "GetClientCapabilities", &()).and_then(|m| m.body().deserialize::<HashMap<String, bool>>()) {
        Ok(caps) => json!({ "id": id, "ok": true, "capabilities": caps }),
        Err(e) => {
            let (name, message) = error_name(&e);
            failure(id, name, message)
        }
    }
}

pub fn run() -> anyhow::Result<()> {
    let out = Arc::new(Mutex::new(io::stdout()));
    let conn = match Connection::session() {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("linux-passkey-native-host: no session bus: {e}");
            None
        }
    };
    // Ceremonies still waiting for the daemon (ids), cancelled if the browser
    // goes away.
    let inflight: Arc<Mutex<HashSet<u64>>> = Arc::default();
    let mut stdin = io::stdin().lock();
    while let Some(msg) = read_message(&mut stdin)? {
        let id = msg["id"].as_u64().unwrap_or(0);
        let Some(conn) = conn.clone() else {
            write_message(&out, &failure(id, "Unavailable", "no D-Bus session bus"));
            continue;
        };
        match msg["op"].as_str() {
            Some("create" | "get") => {
                let (out, inflight) = (out.clone(), inflight.clone());
                inflight.lock().unwrap_or_else(|e| e.into_inner()).insert(id);
                std::thread::spawn(move || {
                    let reply = ceremony(&conn, id, &msg);
                    inflight.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    write_message(&out, &reply);
                });
            }
            Some("cancel") => {
                if let Some(target) = msg["target"].as_u64() {
                    std::thread::spawn(move || {
                        let _ = call(&conn, "Cancel", &(target as u32,));
                    });
                }
            }
            Some("capabilities") => {
                let out = out.clone();
                std::thread::spawn(move || write_message(&out, &capabilities(&conn, id)));
            }
            other => write_message(&out, &failure(id, "NotSupportedError", format!("unknown op {other:?}"))),
        }
    }
    // The browser closed the connection: nobody waits for the open requests.
    if let Some(conn) = &conn {
        for id in inflight.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            let _ = call(conn, "Cancel", &(*id as u32,));
        }
    }
    Ok(())
}
