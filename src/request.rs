//! What is the host asking for? Lets the pinentry prompt say *which* operation
//! and *which* site ("Register a passkey for example.com?") instead of a generic
//! confirm.
//!
//! OpenSK's UserPresence/Fingerprint hooks get no context, so we peek at the
//! traffic ourselves: every HID report is fed through a CTAPHID reassembler
//! before OpenSK sees it, and complete CBOR requests are decoded just far
//! enough to pull out the command, rp id and user name. The result is kept in a
//! process-wide slot that the prompt reads when it is shown.
//!
//! Everything here is display-only: OpenSK still parses and validates the
//! request itself, so a malformed message just leaves the prompt generic.
//!
//! Already registered: a makeCredential's excludeList names the credentials the
//! site already has for this account. OpenSK rejects the request if one of them
//! is ours, but only after a presence gesture (anti-probing), and after the UV
//! prompt if UV was asked for — two dialogs both saying "Create a passkey".
//! `already_registered` runs OpenSK's own match up front, so the (single)
//! prompt can say so, and the follow-up presence check for that same request is
//! answered by the gesture already given.

use opensk::api::key_store::KeyStore;
use opensk::ctap::data_formats::CredentialProtectionPolicy;
use opensk::env::Env;
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

const CTAPHID_MSG: u8 = 0x83;
const CTAPHID_CBOR: u8 = 0x90;
const INIT_DATA: usize = 64 - 7;
const CONT_DATA: usize = 64 - 5;
/// CTAPHID's largest message (128 continuation packets).
const MAX_MSG: usize = INIT_DATA + 128 * CONT_DATA;

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Register {
        rp: String,
        user: Option<String>,
        /// Credential ids from the excludeList.
        exclude: Vec<Vec<u8>>,
        /// UV requested (options.uv) or a pinUvAuthParam supplied.
        has_uv: bool,
        /// One of `exclude` is ours: the site already has this authenticator.
        existing: bool,
    },
    SignIn { rp: String },
    Reset,
    Select,
    U2fRegister,
    U2fSignIn,
    Other,
}

static CURRENT: Mutex<Option<Request>> = Mutex::new(None);
/// The user already confirmed a dialog for the current request.
static CONFIRMED: AtomicBool = AtomicBool::new(false);

/// The request the authenticator is currently working on, if known.
pub fn current() -> Option<Request> {
    CURRENT.lock().ok().and_then(|g| g.clone())
}

/// Record that the user confirmed a dialog for the current request.
pub fn note_confirmed() {
    CONFIRMED.store(true, Ordering::SeqCst);
}

/// True when a presence check can be answered without another dialog: the
/// current registration is a duplicate and the user already confirmed it once.
/// (OpenSK asks for presence again before rejecting excluded credentials.)
pub fn presence_already_given() -> bool {
    CONFIRMED.load(Ordering::SeqCst)
        && matches!(current(), Some(Request::Register { existing: true, .. }))
}

fn mark_existing() {
    if let Ok(mut g) = CURRENT.lock() {
        if let Some(Request::Register { existing, .. }) = g.as_mut() {
            *existing = true;
        }
    }
}

/// Mirror OpenSK's excludeList check (ctap/mod.rs, process_make_credential):
/// a listed id that is one of our resident credentials, or a wrapped
/// credential for this rp, excludes the request — unless it is credProtect
/// UV-required and this request has no UV. Marks the current request.
pub fn check_already_registered<E: Env>(env: &mut E) {
    let Some(Request::Register { rp, exclude, has_uv, .. }) = current() else {
        return;
    };
    let usable = |p: Option<CredentialProtectionPolicy>| {
        has_uv || p != Some(CredentialProtectionPolicy::UserVerificationRequired)
    };
    let rp_hash = Sha256::digest(rp.as_bytes());
    let ours = exclude.iter().any(|id| {
        let resident = opensk::ctap::storage::find_credential(env, &rp, id)
            .ok()
            .flatten()
            .is_some_and(|c| usable(c.cred_protect_policy));
        resident
            || env
                .key_store()
                .unwrap_credential(id, &rp_hash)
                .ok()
                .flatten()
                .is_some_and(|c| usable(c.cred_protect_policy))
    });
    if ours {
        tracing::info!(%rp, "excludeList matches one of our credentials: already registered");
        mark_existing();
    }
}

/// Reassembles CTAPHID messages from 64-byte reports (one in flight at a time,
/// which is all a browser does).
#[derive(Default)]
pub struct Reassembler {
    cid: [u8; 4],
    cmd: u8,
    len: usize,
    next_seq: u8,
    data: Vec<u8>,
    active: bool,
}

impl Reassembler {
    /// Feed one HID report; on a completed message, records what it asks for
    /// and returns true.
    pub fn feed(&mut self, pkt: &[u8; 64]) -> bool {
        let cid: [u8; 4] = pkt[0..4].try_into().unwrap();
        if pkt[4] & 0x80 != 0 {
            // Init packet: starts a new message (and abandons any partial one).
            let len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
            if len > MAX_MSG {
                self.active = false;
                return false;
            }
            self.cid = cid;
            self.cmd = pkt[4];
            self.len = len;
            self.next_seq = 0;
            self.data.clear();
            self.data
                .extend_from_slice(&pkt[7..7 + len.min(INIT_DATA)]);
            self.active = true;
        } else {
            // Continuation packet: must follow in order on the same channel.
            if !self.active || cid != self.cid || pkt[4] != self.next_seq {
                self.active = false;
                return false;
            }
            self.next_seq += 1;
            let take = (self.len - self.data.len()).min(CONT_DATA);
            self.data.extend_from_slice(&pkt[5..5 + take]);
        }
        if self.active && self.data.len() == self.len {
            self.active = false;
            if let Some(req) = classify(self.cmd, &self.data) {
                tracing::debug!(?req, "incoming request");
                CONFIRMED.store(false, Ordering::SeqCst);
                if let Ok(mut g) = CURRENT.lock() {
                    *g = Some(req);
                }
                return true;
            }
        }
        false
    }
}

/// Map a complete CTAPHID message to a Request. Returns None for messages
/// that never need a gesture (ping, init, getInfo, …) so they don't clobber
/// the context of the one that does.
fn classify(cmd: u8, data: &[u8]) -> Option<Request> {
    match cmd {
        CTAPHID_CBOR => {
            let (&ctap_cmd, body) = data.split_first()?;
            match ctap_cmd {
                0x01 => Some(make_credential(body).unwrap_or(Request::Other)),
                0x02 => Some(get_assertion(body).unwrap_or(Request::Other)),
                0x04 => None, // getInfo
                0x06 => client_pin(body),
                0x07 => Some(Request::Reset),
                0x0B => Some(Request::Select),
                _ => Some(Request::Other),
            }
        }
        // U2F APDU: CLA INS ...; INS 0x01 = register, 0x02 = authenticate.
        CTAPHID_MSG => match data.get(1) {
            Some(0x01) => Some(Request::U2fRegister),
            Some(0x02) => Some(Request::U2fSignIn),
            _ => None,
        },
        _ => None,
    }
}

fn cbor_map(body: &[u8]) -> Option<Vec<(sk_cbor::Value, sk_cbor::Value)>> {
    sk_cbor::read(body).ok()?.extract_map()
}

/// Look up an integer key in a CTAP request map.
fn take_int(map: &mut Vec<(sk_cbor::Value, sk_cbor::Value)>, key: i64) -> Option<sk_cbor::Value> {
    let i = map
        .iter()
        .position(|(k, _)| k.clone().extract_integer() == Some(key))?;
    Some(map.swap_remove(i).1)
}

/// Look up a text key in a nested map (rp / user entities).
fn take_text(map: &mut Vec<(sk_cbor::Value, sk_cbor::Value)>, key: &str) -> Option<String> {
    let i = map
        .iter()
        .position(|(k, _)| k.clone().extract_text_string().as_deref() == Some(key))?;
    map.swap_remove(i).1.extract_text_string()
}

// authenticatorMakeCredential: 0x02 = rp {id, name}, 0x03 = user {id, name,
// displayName}, 0x05 = excludeList [{type, id}], 0x07 = options {uv, …},
// 0x08 = pinUvAuthParam.
fn make_credential(body: &[u8]) -> Option<Request> {
    let mut map = cbor_map(body)?;
    let mut rp = take_int(&mut map, 0x02)?.extract_map()?;
    let rp = take_text(&mut rp, "id")?;
    let user = take_int(&mut map, 0x03)
        .and_then(|u| u.extract_map())
        .and_then(|mut u| take_text(&mut u, "name").or_else(|| take_text(&mut u, "displayName")));
    let exclude = take_int(&mut map, 0x05)
        .and_then(|l| l.extract_array())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|d| {
            let mut d = d.extract_map()?;
            let i = d
                .iter()
                .position(|(k, _)| k.clone().extract_text_string().as_deref() == Some("id"))?;
            d.swap_remove(i).1.extract_byte_string()
        })
        .collect();
    let uv_option = take_int(&mut map, 0x07)
        .and_then(|o| o.extract_map())
        .and_then(|mut o| {
            let i = o
                .iter()
                .position(|(k, _)| k.clone().extract_text_string().as_deref() == Some("uv"))?;
            o.swap_remove(i).1.extract_bool()
        })
        .unwrap_or(false);
    let has_uv = uv_option || take_int(&mut map, 0x08).is_some();
    Some(Request::Register { rp, user, exclude, has_uv, existing: false })
}

// authenticatorGetAssertion: 0x01 = rpId.
fn get_assertion(body: &[u8]) -> Option<Request> {
    let mut map = cbor_map(body)?;
    let rp = take_int(&mut map, 0x01)?.extract_text_string()?;
    Some(Request::SignIn { rp })
}

// authenticatorClientPin: 0x02 = subCommand, 0x09 = permissions, 0x0A = rpId.
// Only getPinUvAuthTokenUsingUvWithPermissions (0x06) asks for a gesture: the
// browser verifies the user there, before the makeCredential/getAssertion
// that the token is for, so the dialog needs the site from this request. The
// other subcommands (getKeyAgreement, getRetries, ...) keep the context.
fn client_pin(body: &[u8]) -> Option<Request> {
    const GET_UV_TOKEN: i64 = 0x06;
    const MC: i64 = 0x01;
    const GA: i64 = 0x02;
    let Some(mut map) = cbor_map(body) else {
        return Some(Request::Other);
    };
    if take_int(&mut map, 0x02)?.extract_integer()? != GET_UV_TOKEN {
        return None;
    }
    let permissions = take_int(&mut map, 0x09)
        .and_then(|p| p.extract_integer())
        .unwrap_or(0);
    let rp = take_int(&mut map, 0x0A).and_then(|r| r.extract_text_string());
    Some(match rp {
        Some(rp) if permissions & MC != 0 => Request::Register {
            rp,
            user: None,
            exclude: vec![],
            has_uv: true,
            existing: false,
        },
        Some(rp) if permissions & GA != 0 => Request::SignIn { rp },
        _ => Request::Other,
    })
}

/// Make site-supplied text safe and short for a dialog.
fn clean(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '<' | '>' | '&'))
        .take(64)
        .collect();
    if s.chars().count() > 64 {
        out.push('…');
    }
    out
}

/// Dialog wording for a request: (title, description, OK-button label).
/// Whether a confirmed request also needs the fingerprint (when enabled): yes
/// for anything that creates, uses or deletes credentials; no for the
/// informational "already registered" answer and the browser's key selection.
pub fn wants_fingerprint(req: Option<&Request>) -> bool {
    !matches!(
        req,
        Some(Request::Register { existing: true, .. }) | Some(Request::Select)
    )
}

pub struct Prompt {
    pub title: String,
    pub description: String,
    pub ok: String,
}

impl Prompt {
    pub fn for_request(req: Option<&Request>) -> Prompt {
        let p = |title: &str, description: String, ok: &str| Prompt {
            title: title.to_string(),
            description,
            ok: ok.to_string(),
        };
        match req {
            Some(Request::Register { rp, user, existing: true, .. }) => p(
                "linux-passkey — Already registered",
                match user {
                    Some(u) => format!(
                        "{} already has a passkey from this device for \"{}\". \
                         Nothing new will be created; OK lets the site know.",
                        clean(rp),
                        clean(u)
                    ),
                    None => format!(
                        "{} already has a passkey from this device. \
                         Nothing new will be created; OK lets the site know.",
                        clean(rp)
                    ),
                },
                "OK",
            ),
            Some(Request::Register { rp, user, .. }) => p(
                "linux-passkey — Register",
                match user {
                    Some(u) => format!(
                        "Create a passkey for {} as \"{}\"?",
                        clean(rp),
                        clean(u)
                    ),
                    None => format!("Create a passkey for {}?", clean(rp)),
                },
                "Register",
            ),
            Some(Request::SignIn { rp }) => p(
                "linux-passkey — Sign in",
                format!("Sign in to {} with your passkey?", clean(rp)),
                "Sign in",
            ),
            Some(Request::Reset) => p(
                "linux-passkey — RESET",
                "Reset the authenticator? This permanently deletes ALL passkeys.".to_string(),
                "Reset",
            ),
            Some(Request::Select) => p(
                "linux-passkey",
                "Use this passkey authenticator?".to_string(),
                "Select",
            ),
            Some(Request::U2fRegister) => p(
                "linux-passkey — Register (U2F)",
                "Register this security key with a site (legacy U2F)?".to_string(),
                "Register",
            ),
            Some(Request::U2fSignIn) => p(
                "linux-passkey — Sign in (U2F)",
                "Sign in with this security key (legacy U2F)?".to_string(),
                "Sign in",
            ),
            Some(Request::Other) | None => p(
                "linux-passkey",
                "Confirm use of your TPM-backed passkey?".to_string(),
                "Confirm",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_only_for_credential_operations() {
        let reg = |existing| Request::Register {
            rp: "example.com".into(),
            user: None,
            exclude: vec![],
            has_uv: true,
            existing,
        };
        assert!(wants_fingerprint(Some(&reg(false))));
        assert!(wants_fingerprint(Some(&Request::SignIn { rp: "example.com".into() })));
        assert!(wants_fingerprint(Some(&Request::Reset)));
        assert!(wants_fingerprint(Some(&Request::U2fSignIn)));
        assert!(wants_fingerprint(None));
        assert!(!wants_fingerprint(Some(&reg(true))), "already registered is informational");
        assert!(!wants_fingerprint(Some(&Request::Select)), "key selection is not an approval");
    }
    use sk_cbor::{cbor_array, cbor_map};

    // Tests share the process-wide CURRENT slot.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn packets(cmd: u8, payload: &[u8]) -> Vec<[u8; 64]> {
        let cid = [1, 2, 3, 4];
        let mut out = Vec::new();
        let mut p = [0u8; 64];
        p[..4].copy_from_slice(&cid);
        p[4] = cmd;
        p[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let n = payload.len().min(INIT_DATA);
        p[7..7 + n].copy_from_slice(&payload[..n]);
        out.push(p);
        for (seq, chunk) in payload[n..].chunks(CONT_DATA).enumerate() {
            let mut p = [0u8; 64];
            p[..4].copy_from_slice(&cid);
            p[4] = seq as u8;
            p[5..5 + chunk.len()].copy_from_slice(chunk);
            out.push(p);
        }
        out
    }

    fn cbor_req(cmd: u8, v: sk_cbor::Value) -> Vec<u8> {
        let mut b = vec![cmd];
        sk_cbor::write(v, &mut b).unwrap();
        b
    }

    #[test]
    fn make_credential_spanning_packets() {
        let _g = SERIAL.lock().unwrap();
        let req = cbor_req(
            0x01,
            cbor_map! {
                0x01 => sk_cbor::cbor_bytes!(vec![0xAA; 32]),
                0x02 => cbor_map! { "id" => "webauthn.io", "name" => "WebAuthn.io" },
                0x03 => cbor_map! { "id" => sk_cbor::cbor_bytes!(vec![1; 16]), "name" => "andrew" },
            },
        );
        assert!(req.len() > INIT_DATA, "test should span packets");
        let mut r = Reassembler::default();
        for p in packets(CTAPHID_CBOR, &req) {
            r.feed(&p);
        }
        assert_eq!(
            current(),
            Some(Request::Register {
                rp: "webauthn.io".into(),
                user: Some("andrew".into()),
                exclude: vec![],
                has_uv: false,
                existing: false,
            })
        );
    }

    #[test]
    fn uv_token_request_names_the_site() {
        let _g = SERIAL.lock().unwrap();
        let mut r = Reassembler::default();
        let mut feed = |req: &[u8]| {
            for p in packets(CTAPHID_CBOR, req) {
                r.feed(&p);
            }
        };
        // getPinUvAuthTokenUsingUvWithPermissions, mc permission.
        feed(&cbor_req(
            0x06,
            cbor_map! { 0x01 => 2, 0x02 => 0x06, 0x09 => 0x01, 0x0A => "webauthn.io" },
        ));
        let register = Request::Register {
            rp: "webauthn.io".into(),
            user: None,
            exclude: vec![],
            has_uv: true,
            existing: false,
        };
        assert_eq!(current(), Some(register.clone()));
        // getKeyAgreement doesn't need a gesture and keeps the context.
        feed(&cbor_req(0x06, cbor_map! { 0x01 => 2, 0x02 => 0x02 }));
        assert_eq!(current(), Some(register));
        // ga permission.
        feed(&cbor_req(
            0x06,
            cbor_map! { 0x01 => 2, 0x02 => 0x06, 0x09 => 0x02, 0x0A => "google.com" },
        ));
        assert_eq!(current(), Some(Request::SignIn { rp: "google.com".into() }));
        // No rpId (e.g. credential management): generic prompt.
        feed(&cbor_req(0x06, cbor_map! { 0x01 => 2, 0x02 => 0x06, 0x09 => 0x04 }));
        assert_eq!(current(), Some(Request::Other));
    }

    #[test]
    fn make_credential_exclude_list_and_uv() {
        let _g = SERIAL.lock().unwrap();
        let req = cbor_req(
            0x01,
            cbor_map! {
                0x01 => sk_cbor::cbor_bytes!(vec![0xAA; 32]),
                0x02 => cbor_map! { "id" => "webauthn.io" },
                0x03 => cbor_map! { "id" => sk_cbor::cbor_bytes!(vec![1; 16]), "displayName" => "Andrew" },
                0x05 => cbor_array! [
                    cbor_map! { "id" => sk_cbor::cbor_bytes!(vec![7; 20]), "type" => "public-key" },
                    cbor_map! { "id" => sk_cbor::cbor_bytes!(vec![8; 20]), "type" => "public-key" },
                ],
                0x07 => cbor_map! { "rk" => true, "uv" => true },
            },
        );
        let mut r = Reassembler::default();
        let done: Vec<bool> = packets(CTAPHID_CBOR, &req).iter().map(|p| r.feed(p)).collect();
        assert_eq!(done.iter().filter(|d| **d).count(), 1);
        assert!(*done.last().unwrap());
        let Some(Request::Register { user, exclude, has_uv, existing, .. }) = current() else {
            panic!("not a register request");
        };
        assert_eq!(user.as_deref(), Some("Andrew"));
        assert_eq!(exclude, vec![vec![7; 20], vec![8; 20]]);
        assert!(has_uv);
        assert!(!existing);
        // Not a duplicate (yet), so presence is never auto-answered.
        note_confirmed();
        assert!(!presence_already_given());
        mark_existing();
        assert!(presence_already_given());
        let prompt = Prompt::for_request(current().as_ref());
        assert_eq!(prompt.ok, "OK");
        assert!(prompt.description.starts_with("webauthn.io already has a passkey"));
    }

    #[test]
    fn get_assertion_and_clean() {
        let _g = SERIAL.lock().unwrap();
        let req = cbor_req(0x02, cbor_map! { 0x01 => "evil<b>.example\n" });
        let mut r = Reassembler::default();
        for p in packets(CTAPHID_CBOR, &req) {
            r.feed(&p);
        }
        let got = current().unwrap();
        assert_eq!(got, Request::SignIn { rp: "evil<b>.example\n".into() });
        let prompt = Prompt::for_request(Some(&got));
        assert_eq!(prompt.description, "Sign in to evilb.example with your passkey?");
    }
}
