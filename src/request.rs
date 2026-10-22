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

use std::sync::Mutex;

const CTAPHID_MSG: u8 = 0x83;
const CTAPHID_CBOR: u8 = 0x90;
const INIT_DATA: usize = 64 - 7;
const CONT_DATA: usize = 64 - 5;
/// CTAPHID's largest message (128 continuation packets).
const MAX_MSG: usize = INIT_DATA + 128 * CONT_DATA;

#[derive(Clone, Debug, PartialEq)]
pub enum Request {
    Register { rp: String, user: Option<String> },
    SignIn { rp: String },
    Reset,
    Select,
    U2fRegister,
    U2fSignIn,
    Other,
}

static CURRENT: Mutex<Option<Request>> = Mutex::new(None);

/// The request the authenticator is currently working on, if known.
pub fn current() -> Option<Request> {
    CURRENT.lock().ok().and_then(|g| g.clone())
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
    /// Feed one HID report; on a completed message, records what it asks for.
    pub fn feed(&mut self, pkt: &[u8; 64]) {
        let cid: [u8; 4] = pkt[0..4].try_into().unwrap();
        if pkt[4] & 0x80 != 0 {
            // Init packet: starts a new message (and abandons any partial one).
            let len = u16::from_be_bytes([pkt[5], pkt[6]]) as usize;
            if len > MAX_MSG {
                self.active = false;
                return;
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
                return;
            }
            self.next_seq += 1;
            let take = (self.len - self.data.len()).min(CONT_DATA);
            self.data.extend_from_slice(&pkt[5..5 + take]);
        }
        if self.active && self.data.len() == self.len {
            self.active = false;
            if let Some(req) = classify(self.cmd, &self.data) {
                tracing::debug!(?req, "incoming request");
                if let Ok(mut g) = CURRENT.lock() {
                    *g = Some(req);
                }
            }
        }
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

// authenticatorMakeCredential: 0x02 = rp {id, name}, 0x03 = user {id, name, displayName}.
fn make_credential(body: &[u8]) -> Option<Request> {
    let mut map = cbor_map(body)?;
    let mut rp = take_int(&mut map, 0x02)?.extract_map()?;
    let rp = take_text(&mut rp, "id")?;
    let user = take_int(&mut map, 0x03)
        .and_then(|u| u.extract_map())
        .and_then(|mut u| take_text(&mut u, "name").or_else(|| take_text(&mut u, "displayName")));
    Some(Request::Register { rp, user })
}

// authenticatorGetAssertion: 0x01 = rpId.
fn get_assertion(body: &[u8]) -> Option<Request> {
    let mut map = cbor_map(body)?;
    let rp = take_int(&mut map, 0x01)?.extract_text_string()?;
    Some(Request::SignIn { rp })
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
            Some(Request::Register { rp, user }) => p(
                "tpm2-passkey — Register",
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
                "tpm2-passkey — Sign in",
                format!("Sign in to {} with your passkey?", clean(rp)),
                "Sign in",
            ),
            Some(Request::Reset) => p(
                "tpm2-passkey — RESET",
                "Reset the authenticator? This permanently deletes ALL passkeys.".to_string(),
                "Reset",
            ),
            Some(Request::Select) => p(
                "tpm2-passkey",
                "Use this TPM passkey authenticator?".to_string(),
                "Select",
            ),
            Some(Request::U2fRegister) => p(
                "tpm2-passkey — Register (U2F)",
                "Register this security key with a site (legacy U2F)?".to_string(),
                "Register",
            ),
            Some(Request::U2fSignIn) => p(
                "tpm2-passkey — Sign in (U2F)",
                "Sign in with this security key (legacy U2F)?".to_string(),
                "Sign in",
            ),
            Some(Request::Other) | None => p(
                "tpm2-passkey",
                "Confirm use of your TPM-backed passkey?".to_string(),
                "Confirm",
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sk_cbor::cbor_map;

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
            Some(Request::Register { rp: "webauthn.io".into(), user: Some("andrew".into()) })
        );
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
