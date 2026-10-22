//! A `Crypto` for OpenSK where credential signing is hardware-backed.
//!
//! Only `Ecdsa` (the credential signing keys) goes to the hardware backend (see
//! [`crate::backend`]); AES/SHA/HMAC/HKDF/ECDH reuse OpenSK's software
//! implementations (they protect PIN/wrapping state, not the credential private
//! keys).

use opensk::api::crypto::Crypto;
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::crypto::software_crypto::{
    SoftwareAes256, SoftwareEcdh, SoftwareHkdf256, SoftwareHmac256, SoftwareSha256,
};
use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::rng::Rng;

pub struct HwCrypto;

impl Crypto for HwCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = HwEcdsa;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = SoftwareHkdf256;
}

pub struct HwEcdsa;

impl Ecdsa for HwEcdsa {
    type SecretKey = HwSecretKey;
    type PublicKey = HwPublicKey;
    type Signature = HwSignature;
}

/// A credential signing key, held as the backend's wrapped key material (opaque
/// here; only the backend that created it can use it).
pub struct HwSecretKey {
    key: Vec<u8>,
}

pub struct HwPublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

pub struct HwSignature {
    raw: [u8; 64],
}

impl EcSecretKey for HwSecretKey {
    type PublicKey = HwPublicKey;
    type Signature = HwSignature;

    fn random(_rng: &mut impl Rng) -> Self {
        // The hardware generates the key; `_rng` is unused. The trait can't return
        // an error, so a backend failure here is fatal (the daemon can't function).
        let key = crate::backend::get()
            .create_key()
            .expect("backend create_key failed");
        HwSecretKey { key }
    }

    fn public_key(&self) -> HwPublicKey {
        let (x, y) = crate::backend::get()
            .public_coords(&self.key)
            .expect("backend public_coords failed");
        HwPublicKey { x, y }
    }

    fn sign(&self, message: &[u8]) -> HwSignature {
        let raw = crate::backend::get()
            .sign(&self.key, message)
            .expect("backend sign failed");
        HwSignature { raw }
    }

    fn export(&self) -> Vec<u8> {
        // The backend's wrapped material, as created: safe to persist on disk.
        self.key.clone()
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        Some(HwSecretKey { key: bytes.to_vec() })
    }
}

impl EcPublicKey for HwPublicKey {
    type Signature = HwSignature;

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        x.copy_from_slice(&self.x);
        y.copy_from_slice(&self.y);
    }
}

impl EcSignature for HwSignature {
    fn to_der(&self) -> Vec<u8> {
        der_encode_ecdsa(&self.raw)
    }
}

/// DER-encode a raw 64-byte P-256 ECDSA signature (r || s).
fn der_encode_ecdsa(raw: &[u8; 64]) -> Vec<u8> {
    let r = der_integer(&raw[..32]);
    let s = der_integer(&raw[32..]);
    let mut out = Vec::with_capacity(2 + r.len() + s.len());
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

fn der_integer(n: &[u8]) -> Vec<u8> {
    let start = n.iter().position(|&b| b != 0).unwrap_or(n.len());
    let trimmed = &n[start..];
    let trimmed: &[u8] = if trimmed.is_empty() { &[0] } else { trimmed };
    let pad = (trimmed[0] & 0x80) != 0;
    let mut out = Vec::with_capacity(2 + trimmed.len() + pad as usize);
    out.push(0x02);
    out.push((trimmed.len() + pad as usize) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
    out
}
