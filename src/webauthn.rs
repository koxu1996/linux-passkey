//! WebAuthn on top of CTAP2, for the D-Bus front-end (`gateway.rs`): the
//! browser hands us the WebAuthn request as JSON (WebAuthn L3
//! `PublicKeyCredentialCreationOptionsJSON` / `…RequestOptionsJSON`) plus the
//! caller's origin, and gets `RegistrationResponseJSON` /
//! `AuthenticationResponseJSON` back.
//!
//! Here we do the WebAuthn client's part: check the rp id against the
//! origin, build and hash `clientDataJSON`, encode the CTAP2 command
//! (canonical CBOR, always `uv`), and turn OpenSK's answer into the response
//! JSON (attestation `none`, attachment `platform`, transport `internal`).

use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value as Json};
use sha2::{Digest, Sha256};
use sk_cbor::{cbor_array_vec, cbor_bytes, cbor_map, cbor_map_options};
use sk_cbor::Value as Cbor;

const MAKE_CREDENTIAL: u8 = 0x01;
const GET_ASSERTION: u8 = 0x02;
/// COSE ES256: the only algorithm our backends sign with.
const ES256: i64 = -7;

/// How a ceremony failed, named after the DOMException a page sees.
/// `NoCredential` never reaches the page: the extension then hands the
/// request to the browser's own WebAuthn (USB keys, phones).
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    NotAllowed(String),
    InvalidState(String),
    Security(String),
    NotSupported(String),
    Type(String),
    Abort,
    NoCredential,
    Unknown(String),
}

impl Error {
    /// DOMException name; `NoCredential` is ours.
    pub fn name(&self) -> &'static str {
        match self {
            Error::NotAllowed(_) => "NotAllowedError",
            Error::InvalidState(_) => "InvalidStateError",
            Error::Security(_) => "SecurityError",
            Error::NotSupported(_) => "NotSupportedError",
            Error::Type(_) => "TypeError",
            Error::Abort => "AbortError",
            Error::NoCredential => "NoCredential",
            Error::Unknown(_) => "UnknownError",
        }
    }

    pub fn message(&self) -> String {
        match self {
            Error::NotAllowed(m)
            | Error::InvalidState(m)
            | Error::Security(m)
            | Error::NotSupported(m)
            | Error::Type(m)
            | Error::Unknown(m) => m.clone(),
            Error::Abort => "The operation was aborted.".into(),
            Error::NoCredential => "No passkey for this request on this device.".into(),
        }
    }

    /// From a CTAP2 status byte.
    pub fn from_ctap(status: u8) -> Error {
        match status {
            0x19 => Error::InvalidState("This device is already registered with this site.".into()),
            0x26 => Error::NotSupported("None of the requested algorithms is supported.".into()),
            0x2E => Error::NoCredential,
            // OPERATION_DENIED, KEEPALIVE_CANCEL, USER_ACTION_TIMEOUT, PIN/UV blocked or invalid.
            0x27 | 0x2D | 0x2F | 0x31 | 0x32 | 0x34 | 0x3C | 0x3F => {
                Error::NotAllowed("The request was denied, cancelled or timed out.".into())
            }
            s => Error::Unknown(format!("authenticator error 0x{s:02X}")),
        }
    }
}

/// Bytes in WebAuthn JSON: base64url, padding optional on input.
#[derive(Debug, Clone, PartialEq)]
struct B64(Vec<u8>);

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = if s.ends_with('=') { URL_SAFE.decode(&s) } else { URL_SAFE_NO_PAD.decode(&s) };
        bytes.map(B64).map_err(serde::de::Error::custom)
    }
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreationOptions {
    rp: RpEntity,
    user: UserEntity,
    challenge: B64,
    #[serde(default)]
    pub_key_cred_params: Vec<CredParam>,
    #[serde(default)]
    exclude_credentials: Vec<Descriptor>,
    #[serde(default)]
    extensions: Option<Json>,
}

#[derive(Deserialize)]
struct RpEntity {
    id: Option<String>,
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserEntity {
    id: B64,
    name: String,
    display_name: String,
}

#[derive(Deserialize)]
struct CredParam {
    #[serde(rename = "type")]
    kind: String,
    alg: i64,
}

#[derive(Deserialize)]
struct Descriptor {
    #[serde(rename = "type")]
    kind: String,
    id: B64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RequestOptions {
    challenge: B64,
    rp_id: Option<String>,
    #[serde(default)]
    allow_credentials: Vec<Descriptor>,
    #[serde(default)]
    extensions: Option<Json>,
}

/// Where a request comes from: the caller's origin, and the top-level origin
/// when it was made from a cross-origin frame.
#[derive(Debug, Clone)]
pub struct Caller {
    pub origin: String,
    pub top_origin: Option<String>,
}

/// A validated request, ready for OpenSK.
#[derive(Debug, Clone)]
pub struct Ceremony {
    pub kind: Kind,
    pub rp_id: String,
    /// The caller's origin, serialized (for the dialog).
    pub origin: String,
    /// The account a registration is for: (name, display name).
    pub user: Option<(String, String)>,
    client_data_hash: Vec<u8>,
    /// The CTAP2 command: command byte, then CBOR.
    pub command: Vec<u8>,
    client_data_json: String,
    /// getAssertion's allowList (credential ids); empty = discoverable.
    pub allow: Vec<Vec<u8>>,
    /// The site asked for `credProps`.
    cred_props: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    Create,
    Get,
}

/// Serialized origin (`scheme://host[:port]`) and host of a caller origin;
/// only secure contexts (https, or http on localhost).
fn parse_origin(origin: &str) -> Result<(String, String), Error> {
    let url = url::Url::parse(origin).map_err(|_| Error::Security(format!("bad origin {origin:?}")))?;
    let host = match url.host() {
        Some(url::Host::Domain(d)) => d.to_ascii_lowercase(),
        _ => return Err(Error::Security(format!("origin {origin:?} has no domain"))),
    };
    let secure = url.scheme() == "https" || (url.scheme() == "http" && host == "localhost");
    if !secure {
        return Err(Error::Security(format!("origin {origin:?} is not a secure context")));
    }
    Ok((url.origin().ascii_serialization(), host))
}

/// WebAuthn's rp id rule: the origin's host, or a registrable suffix of it
/// (not a public suffix like `com` or `github.io`).
fn check_rp_id(host: &str, rp_id: &str) -> Result<(), Error> {
    let rp = rp_id.to_ascii_lowercase();
    let suffix_of_host = host == rp || host.ends_with(&format!(".{rp}"));
    let registrable = rp == "localhost" || psl::domain(rp.as_bytes()).is_some();
    if suffix_of_host && registrable && rp == rp_id {
        Ok(())
    } else {
        Err(Error::Security(format!("rp id {rp_id:?} is not valid for {host}")))
    }
}

/// `CollectedClientData`, serialized the way WebAuthn L3 §5.8.1.1 specifies
/// (fixed member order, `topOrigin` only for cross-origin calls).
fn client_data_json(kind: Kind, challenge: &[u8], origin: &str, top_origin: Option<&str>) -> String {
    let s = |v: &str| Json::String(v.into()).to_string();
    let ty = match kind {
        Kind::Create => "webauthn.create",
        Kind::Get => "webauthn.get",
    };
    let mut out = format!(
        "{{\"type\":{},\"challenge\":{},\"origin\":{},\"crossOrigin\":{}",
        s(ty),
        s(&b64(challenge)),
        s(origin),
        top_origin.is_some()
    );
    if let Some(top) = top_origin {
        out.push_str(&format!(",\"topOrigin\":{}", s(top)));
    }
    out.push('}');
    out
}

fn wants_cred_props(extensions: &Option<Json>) -> bool {
    extensions.as_ref().and_then(|e| e.get("credProps")).and_then(Json::as_bool) == Some(true)
}

fn encode(cmd: u8, map: Cbor) -> Vec<u8> {
    let mut out = vec![cmd];
    sk_cbor::write(map, &mut out).expect("CBOR encoding of a request");
    out
}

fn descriptors(list: &[Descriptor]) -> Vec<Cbor> {
    list.iter()
        .filter(|d| d.kind == "public-key")
        .map(|d| cbor_map! { "id" => cbor_bytes!(d.id.0.clone()), "type" => "public-key" })
        .collect()
}

fn get_assertion(rp_id: &str, client_data_hash: &[u8], allow: &[Vec<u8>]) -> Vec<u8> {
    let allow_list: Vec<Cbor> = allow
        .iter()
        .map(|id| cbor_map! { "id" => cbor_bytes!(id.clone()), "type" => "public-key" })
        .collect();
    encode(
        GET_ASSERTION,
        cbor_map_options! {
            0x01 => rp_id.to_string(),
            0x02 => cbor_bytes!(client_data_hash.to_vec()),
            0x03 => (!allow_list.is_empty()).then(|| cbor_array_vec!(allow_list)),
            0x05 => cbor_map! { "up" => true, "uv" => true },
        },
    )
}

fn checked_top_origin(caller: &Caller) -> Result<Option<String>, Error> {
    caller.top_origin.as_deref().map(|t| parse_origin(t).map(|(o, _)| o)).transpose()
}

impl Ceremony {
    /// `navigator.credentials.create({publicKey})`.
    pub fn create(caller: &Caller, options_json: &str) -> Result<Ceremony, Error> {
        let opts: CreationOptions = serde_json::from_str(options_json)
            .map_err(|e| Error::Type(format!("bad creation options: {e}")))?;
        let (origin, host) = parse_origin(&caller.origin)?;
        let top_origin = checked_top_origin(caller)?;
        let rp_id = opts.rp.id.clone().unwrap_or_else(|| host.clone());
        check_rp_id(&host, &rp_id)?;
        if opts.user.id.0.is_empty() || opts.user.id.0.len() > 64 {
            return Err(Error::Type("user.id must be 1 to 64 bytes".into()));
        }
        // No parameters means "ES256 or RS256" (WebAuthn §5.1.3); we do ES256.
        let params = if opts.pub_key_cred_params.is_empty() {
            vec![CredParam { kind: "public-key".into(), alg: ES256 }]
        } else {
            opts.pub_key_cred_params
        };
        let params: Vec<Cbor> = params
            .iter()
            .filter(|p| p.kind == "public-key")
            .map(|p| cbor_map! { "alg" => p.alg, "type" => "public-key" })
            .collect();
        let client_data_json =
            client_data_json(Kind::Create, &opts.challenge.0, &origin, top_origin.as_deref());
        let exclude = descriptors(&opts.exclude_credentials);
        let (user_name, user_display_name) = (opts.user.name, opts.user.display_name);
        // Always discoverable and always user-verified, like the built-in
        // authenticators of Windows and macOS.
        let command = encode(
            MAKE_CREDENTIAL,
            cbor_map_options! {
                0x01 => cbor_bytes!(Sha256::digest(client_data_json.as_bytes()).to_vec()),
                0x02 => cbor_map! { "id" => rp_id.clone(), "name" => opts.rp.name },
                0x03 => cbor_map! {
                    "id" => cbor_bytes!(opts.user.id.0),
                    "name" => user_name.clone(),
                    "displayName" => user_display_name.clone(),
                },
                0x04 => cbor_array_vec!(params),
                0x05 => (!exclude.is_empty()).then(|| cbor_array_vec!(exclude)),
                0x07 => cbor_map! { "rk" => true, "uv" => true },
            },
        );
        Ok(Ceremony {
            kind: Kind::Create,
            rp_id,
            origin,
            user: Some((user_name, user_display_name)),
            client_data_hash: Sha256::digest(client_data_json.as_bytes()).to_vec(),
            command,
            client_data_json,
            allow: vec![],
            cred_props: wants_cred_props(&opts.extensions),
        })
    }

    /// `navigator.credentials.get({publicKey})`.
    pub fn get(caller: &Caller, options_json: &str) -> Result<Ceremony, Error> {
        let opts: RequestOptions = serde_json::from_str(options_json)
            .map_err(|e| Error::Type(format!("bad request options: {e}")))?;
        let (origin, host) = parse_origin(&caller.origin)?;
        let top_origin = checked_top_origin(caller)?;
        let rp_id = opts.rp_id.clone().unwrap_or_else(|| host.clone());
        check_rp_id(&host, &rp_id)?;
        let client_data_json =
            client_data_json(Kind::Get, &opts.challenge.0, &origin, top_origin.as_deref());
        let _ = &opts.extensions; // none supported yet (prf, largeBlob: later)
        let allow: Vec<Vec<u8>> = opts
            .allow_credentials
            .into_iter()
            .filter(|d| d.kind == "public-key")
            .map(|d| d.id.0)
            .collect();
        let client_data_hash = Sha256::digest(client_data_json.as_bytes()).to_vec();
        Ok(Ceremony {
            kind: Kind::Get,
            command: get_assertion(&rp_id, &client_data_hash, &allow),
            rp_id,
            origin,
            user: None,
            client_data_hash,
            client_data_json,
            allow,
            cred_props: false,
        })
    }

    /// Sign in with this credential only: the account the user picked.
    pub fn restrict_to(&mut self, credential_id: Vec<u8>) {
        self.allow = vec![credential_id];
        self.command = get_assertion(&self.rp_id, &self.client_data_hash, &self.allow);
    }

    /// Turn OpenSK's reply (status byte, then CBOR) into the response JSON.
    pub fn response(&self, reply: &[u8]) -> Result<String, Error> {
        let (&status, body) = reply
            .split_first()
            .ok_or_else(|| Error::Unknown("empty reply from the authenticator".into()))?;
        if status != 0 {
            return Err(Error::from_ctap(status));
        }
        let bad = || Error::Unknown("malformed reply from the authenticator".into());
        let mut map = sk_cbor::read(body).ok().and_then(Cbor::extract_map).ok_or_else(bad)?;
        let json = match self.kind {
            Kind::Create => self.registration(&mut map).ok_or_else(bad)?,
            Kind::Get => self.authentication(&mut map).ok_or_else(bad)?,
        };
        Ok(json.to_string())
    }

    // makeCredential reply: 0x01 fmt, 0x02 authData, 0x03 attStmt.
    fn registration(&self, map: &mut Vec<(Cbor, Cbor)>) -> Option<Json> {
        let auth_data = take(map, 0x02)?.extract_byte_string()?;
        let attested = AttestedCredential::parse(&auth_data)?;
        // Attestation "none": we have no attestation key, and the AAGUID
        // (in authData) names us anyway.
        let mut attestation_object = Vec::new();
        sk_cbor::write(
            cbor_map! {
                "fmt" => "none",
                "attStmt" => cbor_map! {},
                "authData" => cbor_bytes!(auth_data.clone()),
            },
            &mut attestation_object,
        )
        .ok()?;
        let mut extensions = json!({});
        if self.cred_props {
            extensions["credProps"] = json!({ "rk": true });
        }
        let mut response = json!({
            "clientDataJSON": b64(self.client_data_json.as_bytes()),
            "authenticatorData": b64(&auth_data),
            "transports": ["internal"],
            "publicKeyAlgorithm": attested.alg,
            "attestationObject": b64(&attestation_object),
        });
        if let Some(spki) = attested.spki() {
            response["publicKey"] = json!(b64(&spki));
        }
        Some(json!({
            "id": b64(&attested.credential_id),
            "rawId": b64(&attested.credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": response,
            "clientExtensionResults": extensions,
        }))
    }

    // getAssertion reply: 0x01 credential, 0x02 authData, 0x03 signature,
    // 0x04 user, 0x05 numberOfCredentials.
    fn authentication(&self, map: &mut Vec<(Cbor, Cbor)>) -> Option<Json> {
        let credential_id = match take(map, 0x01) {
            Some(c) => {
                let mut c = c.extract_map()?;
                let i = c.iter().position(|(k, _)| k.clone().extract_text_string().as_deref() == Some("id"))?;
                c.swap_remove(i).1.extract_byte_string()?
            }
            // May be left out when the allowList had exactly one entry.
            None if self.allow.len() == 1 => self.allow[0].clone(),
            None => return None,
        };
        let auth_data = take(map, 0x02)?.extract_byte_string()?;
        let signature = take(map, 0x03)?.extract_byte_string()?;
        let user_handle = take(map, 0x04).and_then(Cbor::extract_map).and_then(|mut u| {
            let i = u.iter().position(|(k, _)| k.clone().extract_text_string().as_deref() == Some("id"))?;
            u.swap_remove(i).1.extract_byte_string()
        });
        Some(json!({
            "id": b64(&credential_id),
            "rawId": b64(&credential_id),
            "type": "public-key",
            "authenticatorAttachment": "platform",
            "response": {
                "clientDataJSON": b64(self.client_data_json.as_bytes()),
                "authenticatorData": b64(&auth_data),
                "signature": b64(&signature),
                "userHandle": user_handle.map(|h| b64(&h)),
            },
            "clientExtensionResults": {},
        }))
    }
}

fn take(map: &mut Vec<(Cbor, Cbor)>, key: i64) -> Option<Cbor> {
    let i = map.iter().position(|(k, _)| k.clone().extract_integer() == Some(key))?;
    Some(map.swap_remove(i).1)
}

/// The attested credential data inside a registration's authenticator data.
struct AttestedCredential {
    credential_id: Vec<u8>,
    alg: i64,
    /// COSE EC2 coordinates, for ES256.
    xy: Option<(Vec<u8>, Vec<u8>)>,
}

impl AttestedCredential {
    // rpIdHash(32) flags(1) signCount(4) aaguid(16) idLen(2) id coseKey [extensions]
    fn parse(auth_data: &[u8]) -> Option<Self> {
        const AT: u8 = 0x40;
        const ED: u8 = 0x80;
        let flags = *auth_data.get(32)?;
        if flags & AT == 0 {
            return None;
        }
        let len = u16::from_be_bytes([*auth_data.get(53)?, *auth_data.get(54)?]) as usize;
        let credential_id = auth_data.get(55..55 + len)?.to_vec();
        let rest = &auth_data[55 + len..];
        // sk-cbor reads a whole buffer only; with extensions after the key,
        // find where the key ends.
        let key = if flags & ED == 0 {
            sk_cbor::read(rest).ok()?
        } else {
            (1..=rest.len()).find_map(|n| sk_cbor::read(&rest[..n]).ok())?
        };
        let mut key = key.extract_map()?;
        let alg = take(&mut key, 3)?.extract_integer()?;
        let x = take(&mut key, -2).and_then(Cbor::extract_byte_string);
        let y = take(&mut key, -3).and_then(Cbor::extract_byte_string);
        Some(AttestedCredential { credential_id, alg, xy: x.zip(y) })
    }

    /// The public key as DER SubjectPublicKeyInfo (`getPublicKey()`), for P-256.
    fn spki(&self) -> Option<Vec<u8>> {
        // SEQUENCE { SEQUENCE { id-ecPublicKey, prime256v1 }, BIT STRING 04||x||y }
        const PREFIX: [u8; 27] = [
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06,
            0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
        ];
        let (x, y) = self.xy.as_ref().filter(|(x, y)| self.alg == ES256 && x.len() == 32 && y.len() == 32)?;
        Some([&PREFIX[..], x, y].concat())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(origin: &str) -> Caller {
        Caller { origin: origin.into(), top_origin: None }
    }

    #[test]
    fn rp_id_rules() {
        assert!(check_rp_id("login.example.com", "example.com").is_ok());
        assert!(check_rp_id("example.com", "example.com").is_ok());
        assert!(check_rp_id("localhost", "localhost").is_ok());
        assert!(check_rp_id("example.com", "com").is_err(), "public suffix");
        assert!(check_rp_id("foo.github.io", "github.io").is_err(), "public suffix");
        assert!(check_rp_id("badexample.com", "example.com").is_err(), "not a dot boundary");
        assert!(check_rp_id("example.com", "other.com").is_err());
        assert!(check_rp_id("example.com", "Example.com").is_err(), "rp id must be lowercase");
    }

    #[test]
    fn origins() {
        assert_eq!(parse_origin("https://Example.com:443").unwrap().0, "https://example.com");
        assert_eq!(parse_origin("http://localhost:8080").unwrap().0, "http://localhost:8080");
        assert!(parse_origin("http://example.com").is_err());
        assert!(parse_origin("https://127.0.0.1").is_err());
        assert!(parse_origin("null").is_err());
    }

    #[test]
    fn client_data_layout() {
        assert_eq!(
            client_data_json(Kind::Get, b"hi", "https://a.example", None),
            r#"{"type":"webauthn.get","challenge":"aGk","origin":"https://a.example","crossOrigin":false}"#
        );
        assert_eq!(
            client_data_json(Kind::Create, b"hi", "https://a.example", Some("https://top.example")),
            r#"{"type":"webauthn.create","challenge":"aGk","origin":"https://a.example","crossOrigin":true,"topOrigin":"https://top.example"}"#
        );
    }

    const CREATE: &str = r#"{
        "rp": {"id": "example.com", "name": "Example"},
        "user": {"id": "AQID", "name": "andrew", "displayName": "Andrew"},
        "challenge": "Y2hhbGxlbmdl",
        "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}],
        "excludeCredentials": [{"type": "public-key", "id": "qrvM"}],
        "authenticatorSelection": {"residentKey": "preferred"},
        "extensions": {"credProps": true}
    }"#;

    #[test]
    fn create_encodes_canonical_ctap() {
        let c = Ceremony::create(&caller("https://login.example.com"), CREATE).unwrap();
        assert_eq!(c.rp_id, "example.com");
        assert_eq!(c.command[0], MAKE_CREDENTIAL);
        let mut map = sk_cbor::read(&c.command[1..]).unwrap().extract_map().unwrap();
        let keys: Vec<_> = map.iter().map(|(k, _)| k.clone().extract_integer().unwrap()).collect();
        assert_eq!(keys, [1, 2, 3, 4, 5, 7]);
        let hash = take(&mut map, 1).unwrap().extract_byte_string().unwrap();
        assert_eq!(hash, Sha256::digest(c.client_data_json.as_bytes()).to_vec());
        // Canonical option order (Firefox bug 2090860 was the reverse).
        let mut opts = Vec::new();
        sk_cbor::write(take(&mut map, 7).unwrap(), &mut opts).unwrap();
        assert_eq!(opts, [0xA2, 0x62, b'r', b'k', 0xF5, 0x62, b'u', b'v', 0xF5]);
    }

    #[test]
    fn create_rejects_foreign_rp() {
        let err = Ceremony::create(&caller("https://evil.test"), CREATE).unwrap_err();
        assert!(matches!(err, Error::Security(_)));
    }

    #[test]
    fn get_defaults_rp_id_to_host() {
        let c = Ceremony::get(&caller("https://webauthn.io"), r#"{"challenge":"AAAA"}"#).unwrap();
        assert_eq!(c.rp_id, "webauthn.io");
        assert!(c.allow.is_empty());
        let mut map = sk_cbor::read(&c.command[1..]).unwrap().extract_map().unwrap();
        assert!(take(&mut map, 3).is_none(), "no empty allowList");
        let mut opts = Vec::new();
        sk_cbor::write(take(&mut map, 5).unwrap(), &mut opts).unwrap();
        assert_eq!(opts, [0xA2, 0x62, b'u', b'p', 0xF5, 0x62, b'u', b'v', 0xF5]);
    }

    #[test]
    fn restrict_to_one_account() {
        let mut c = Ceremony::get(&caller("https://webauthn.io"), r#"{"challenge":"AAAA"}"#).unwrap();
        let before = c.command.clone();
        c.restrict_to(vec![1, 2, 3]);
        assert_eq!(c.allow, vec![vec![1, 2, 3]]);
        let mut map = sk_cbor::read(&c.command[1..]).unwrap().extract_map().unwrap();
        let list = take(&mut map, 3).unwrap().extract_array().unwrap();
        assert_eq!(list.len(), 1);
        // Same client data: the signature still covers what the site sent.
        let mut old = sk_cbor::read(&before[1..]).unwrap().extract_map().unwrap();
        assert_eq!(take(&mut map, 2), take(&mut old, 2));
    }

    fn auth_data_with_key(id: &[u8]) -> Vec<u8> {
        let mut key = Vec::new();
        sk_cbor::write(
            cbor_map! { 1 => 2, 3 => ES256, -1 => 1, -2 => cbor_bytes!(vec![7; 32]), -3 => cbor_bytes!(vec![9; 32]) },
            &mut key,
        )
        .unwrap();
        let mut ad = vec![0u8; 32];
        ad.push(0x45); // UP | UV | AT
        ad.extend([0, 0, 0, 1]);
        ad.extend([0x47; 16]);
        ad.extend((id.len() as u16).to_be_bytes());
        ad.extend(id);
        ad.extend(key);
        ad
    }

    #[test]
    fn registration_response() {
        let c = Ceremony::create(&caller("https://example.com"), CREATE).unwrap();
        let mut reply = vec![0];
        sk_cbor::write(
            cbor_map! {
                0x01 => "packed",
                0x02 => cbor_bytes!(auth_data_with_key(&[0xAB, 0xCD])),
                0x03 => cbor_map! {},
            },
            &mut reply,
        )
        .unwrap();
        let json: Json = serde_json::from_str(&c.response(&reply).unwrap()).unwrap();
        assert_eq!(json["id"], "q80");
        assert_eq!(json["authenticatorAttachment"], "platform");
        assert_eq!(json["response"]["transports"], json!(["internal"]));
        assert_eq!(json["response"]["publicKeyAlgorithm"], ES256);
        assert_eq!(json["clientExtensionResults"]["credProps"]["rk"], true);
        let spki = URL_SAFE_NO_PAD.decode(json["response"]["publicKey"].as_str().unwrap()).unwrap();
        assert_eq!(spki.len(), 91);
        let att = URL_SAFE_NO_PAD.decode(json["response"]["attestationObject"].as_str().unwrap()).unwrap();
        let mut att = sk_cbor::read(&att).unwrap().extract_map().unwrap();
        let fmt = att.iter().position(|(k, _)| k.clone().extract_text_string().as_deref() == Some("fmt")).unwrap();
        assert_eq!(att.swap_remove(fmt).1.extract_text_string().unwrap(), "none");
    }

    #[test]
    fn errors_map_to_dom_exceptions() {
        let c = Ceremony::get(&caller("https://webauthn.io"), r#"{"challenge":"AAAA"}"#).unwrap();
        assert_eq!(c.response(&[0x27]).unwrap_err().name(), "NotAllowedError");
        assert_eq!(c.response(&[0x2E]).unwrap_err(), Error::NoCredential);
        assert_eq!(c.response(&[0x19]).unwrap_err().name(), "InvalidStateError");
    }
}
