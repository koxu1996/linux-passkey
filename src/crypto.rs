//! A `Crypto` for OpenSK where credential signing is TPM-backed.
//!
//! Only `Ecdsa` (the credential signing keys) goes to the TPM; AES/SHA/HMAC/
//! HKDF/ECDH reuse OpenSK's software implementations (they protect PIN/wrapping
//! state, not the credential private keys).

use opensk::api::crypto::Crypto;
use opensk::api::crypto::ec_signing::{EcPublicKey, EcSecretKey, EcSignature, Ecdsa};
use opensk::api::crypto::software_crypto::{
    SoftwareAes256, SoftwareEcdh, SoftwareHkdf256, SoftwareHmac256, SoftwareSha256,
};
use opensk::api::crypto::EC_FIELD_SIZE;
use opensk::api::rng::Rng;

pub struct TpmCrypto;

impl Crypto for TpmCrypto {
    type Aes256 = SoftwareAes256;
    type Ecdh = SoftwareEcdh;
    type Ecdsa = TpmEcdsa;
    type Sha256 = SoftwareSha256;
    type Hmac256 = SoftwareHmac256;
    type Hkdf256 = SoftwareHkdf256;
}

pub struct TpmEcdsa;

impl Ecdsa for TpmEcdsa {
    type SecretKey = TpmSecretKey;
    type PublicKey = TpmPublicKey;
    type Signature = TpmSignature;
}

/// A credential signing key, stored as its TPM-wrapped (private, public) blobs.
pub struct TpmSecretKey {
    private_blob: Vec<u8>,
    public_blob: Vec<u8>,
}

pub struct TpmPublicKey {
    x: [u8; 32],
    y: [u8; 32],
}

pub struct TpmSignature {
    raw: [u8; 64],
}

impl EcSecretKey for TpmSecretKey {
    type PublicKey = TpmPublicKey;
    type Signature = TpmSignature;

    fn random(_rng: &mut impl Rng) -> Self {
        // The TPM generates the key; `_rng` is unused. The trait can't return an
        // error, so a TPM failure here is fatal (the daemon can't function).
        let (private_blob, public_blob) =
            crate::tpm::create_key().expect("TPM create_key failed");
        TpmSecretKey {
            private_blob,
            public_blob,
        }
    }

    fn public_key(&self) -> TpmPublicKey {
        let (x, y) =
            crate::tpm::public_coords(&self.public_blob).expect("TPM public_coords failed");
        TpmPublicKey { x, y }
    }

    fn sign(&self, message: &[u8]) -> TpmSignature {
        let raw = crate::tpm::sign(&self.private_blob, &self.public_blob, message)
            .expect("TPM sign failed");
        TpmSignature { raw }
    }

    fn export(&self) -> Vec<u8> {
        // Deterministic: [u16 BE private_len][private][public]. The blobs are
        // TPM-wrapped, so this is safe to persist on disk.
        let mut out = Vec::with_capacity(2 + self.private_blob.len() + self.public_blob.len());
        out.extend_from_slice(&(self.private_blob.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.private_blob);
        out.extend_from_slice(&self.public_blob);
        out
    }

    fn import(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 2 {
            return None;
        }
        let plen = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
        if bytes.len() < 2 + plen {
            return None;
        }
        Some(TpmSecretKey {
            private_blob: bytes[2..2 + plen].to_vec(),
            public_blob: bytes[2 + plen..].to_vec(),
        })
    }
}

impl EcPublicKey for TpmPublicKey {
    type Signature = TpmSignature;

    fn to_coordinates(&self, x: &mut [u8; EC_FIELD_SIZE], y: &mut [u8; EC_FIELD_SIZE]) {
        x.copy_from_slice(&self.x);
        y.copy_from_slice(&self.y);
    }
}

impl EcSignature for TpmSignature {
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
