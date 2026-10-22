//! The hardware that holds the credential keys and protects the store.
//!
//! OpenSK's `EcSecretKey::{random, sign, import}` take no context argument, so
//! the backend is a process-global chosen once at startup ([`init`]) and reached
//! through [`get`]. A backend owns two things:
//!
//! - **Credential keys.** `create_key` returns opaque key material that is safe
//!   to persist (it is wrapped by the hardware); `public_coords` and `sign` take
//!   it back. OpenSK stores it as the credential's key.
//! - **The store cipher.** `store_cipher` encrypts/decrypts the credential store
//!   file with a key the hardware protects; how (unseal into memory, or keep the
//!   key in the kernel) is the backend's business.

use anyhow::{anyhow, Result};
use std::path::Path;
use std::sync::OnceLock;

pub trait Backend: Send + Sync {
    /// Short name for logs, e.g. "TPM".
    fn name(&self) -> &'static str;
    /// A new P-256 credential key; returns its persistable (wrapped) material.
    fn create_key(&self) -> Result<Vec<u8>>;
    /// The key's public point as (x, y).
    fn public_coords(&self, key: &[u8]) -> Result<([u8; 32], [u8; 32])>;
    /// ECDSA-P256 over SHA-256(`message`), as raw r || s.
    fn sign(&self, key: &[u8], message: &[u8]) -> Result<[u8; 64]>;
    /// The cipher for the store in `dir` (created on first use).
    fn store_cipher(&self, dir: &Path) -> Result<Box<dyn StoreCipher>>;
}

/// Encrypts the credential store file as one blob.
pub trait StoreCipher: Send {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

static BACKEND: OnceLock<Box<dyn Backend>> = OnceLock::new();

/// Install the process-global backend. Call once, before any key or store use.
pub fn init(backend: Box<dyn Backend>) -> Result<()> {
    BACKEND
        .set(backend)
        .map_err(|_| anyhow!("backend already initialized"))
}

/// The installed backend. Panics if [`init`] was not called (a startup bug).
pub fn get() -> &'static dyn Backend {
    BACKEND
        .get()
        .expect("backend not initialized; call backend::init at startup")
        .as_ref()
}

/// Shared checks any backend must pass, used by each backend's hardware test.
#[cfg(test)]
pub(crate) mod conformance {
    use super::Backend;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::EncodedPoint;

    fn verifying_key(b: &dyn Backend, key: &[u8]) -> VerifyingKey {
        let (x, y) = b.public_coords(key).expect("public_coords");
        VerifyingKey::from_encoded_point(&EncodedPoint::from_affine_coordinates(
            &x.into(),
            &y.into(),
            false,
        ))
        .expect("public point is on the curve")
    }

    /// Two keys differ; a signature verifies (ECDSA-P256 over SHA-256) with its own
    /// key only; a tampered message fails; exported material round-trips.
    pub(crate) fn check(b: &dyn Backend) {
        let k1 = b.create_key().expect("create_key");
        let k2 = b.create_key().expect("create_key");
        assert_ne!(k1, k2, "two creates must give two keys");

        let msg = b"linux-passkey backend conformance";
        let sig = Signature::from_slice(&b.sign(&k1, msg).expect("sign")).expect("raw r||s");
        verifying_key(b, &k1)
            .verify(msg, &sig)
            .expect("signature verifies with its own key");
        assert!(
            verifying_key(b, &k2).verify(msg, &sig).is_err(),
            "signature must not verify with another key"
        );
        assert!(
            verifying_key(b, &k1).verify(b"tampered", &sig).is_err(),
            "signature must not verify a different message"
        );

        // OpenSK persists exactly the bytes create_key returned; signing with a copy works.
        let copy = k1.clone();
        let sig2 = Signature::from_slice(&b.sign(&copy, msg).expect("sign")).expect("raw r||s");
        verifying_key(b, &k1).verify(msg, &sig2).expect("copied key material signs");
    }
}
