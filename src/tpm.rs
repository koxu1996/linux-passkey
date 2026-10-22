//! Process-global TPM 2.0 backend.
//!
//! OpenSK's `EcSecretKey::{random, sign}` take no context argument, so the TPM
//! connection lives in a process-global initialized once at startup via
//! [`init`]. Credential signing keys are created as P-256 children of a primary
//! under the Owner hierarchy; `create_key` returns the TPM-wrapped
//! (private, public) blobs that OpenSK stores as the credential's key material.
//! tss-esapi calls adapted from fidorium (same 8.0.0-alpha.1).

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::convert::{TryFrom, TryInto};
use std::sync::{Mutex, OnceLock};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::handles::{KeyHandle, ObjectHandle};
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::reserved_handles::Hierarchy;
use tss_esapi::structures::{
    Digest as TpmDigest, EccPoint, EccScheme, HashScheme, HashcheckTicket, KeyedHashScheme,
    Private, Public, PublicBuilder, PublicEccParametersBuilder, PublicKeyedHashParameters,
    SensitiveData, Signature, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::{Context, TctiNameConf};

struct Backend {
    ctx: Mutex<Context>,
    primary: KeyHandle,
}

static BACKEND: OnceLock<Backend> = OnceLock::new();

/// Initialize the global TPM backend. `tcti` is a tss-esapi TCTI string, e.g.
/// "device:/dev/tpmrm0" (real TPM) or a swtpm/mssim config for dev.
pub fn init(tcti: &str) -> Result<()> {
    let conf = tcti
        .parse::<TctiNameConf>()
        .map_err(|e| anyhow!("invalid TCTI {tcti:?}: {e}"))?;
    let mut ctx = Context::new(conf).map_err(|e| anyhow!("TPM context: {e}"))?;
    let primary = create_primary(&mut ctx)?;
    BACKEND
        .set(Backend {
            ctx: Mutex::new(ctx),
            primary,
        })
        .map_err(|_| anyhow!("TPM backend already initialized"))?;
    Ok(())
}

fn with_ctx<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut Context, KeyHandle) -> Result<T>,
{
    let b = BACKEND.get().ok_or_else(|| anyhow!("TPM not initialized"))?;
    let mut ctx = b.ctx.lock().map_err(|_| anyhow!("TPM mutex poisoned"))?;
    f(&mut ctx, b.primary)
}

fn create_primary(ctx: &mut Context) -> Result<KeyHandle> {
    let ecc_params = PublicEccParametersBuilder::new_restricted_decryption_key(
        SymmetricDefinitionObject::AES_128_CFB,
        EccCurve::NistP256,
    )
    .build()
    .map_err(|e| anyhow!("primary ecc params: {e}"))?;

    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|e| anyhow!("primary attrs: {e}"))?;

    let template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| anyhow!("primary template: {e}"))?;

    let result = ctx
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map_err(|e| anyhow!("create_primary: {e}"))?;
    Ok(result.key_handle)
}

/// Create a new P-256 ECDSA signing key under the primary.
/// Returns the TPM-wrapped (private_blob, public_blob).
pub fn create_key() -> Result<(Vec<u8>, Vec<u8>)> {
    with_ctx(|ctx, primary| {
        let scheme = EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256));
        let ecc_params =
            PublicEccParametersBuilder::new_unrestricted_signing_key(scheme, EccCurve::NistP256)
                .build()
                .map_err(|e| anyhow!("child ecc params: {e}"))?;

        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_sensitive_data_origin(true)
            .with_user_with_auth(true)
            .with_sign_encrypt(true)
            .with_no_da(true)
            .build()
            .map_err(|e| anyhow!("child attrs: {e}"))?;

        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::Ecc)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_ecc_parameters(ecc_params)
            .with_ecc_unique_identifier(EccPoint::default())
            .build()
            .map_err(|e| anyhow!("child template: {e}"))?;

        let result = ctx
            .execute_with_nullauth_session(|ctx| ctx.create(primary, template, None, None, None, None))
            .map_err(|e| anyhow!("create child key: {e}"))?;

        let private_blob = result.out_private.as_bytes().to_vec();
        let public_blob = result
            .out_public
            .marshall()
            .map_err(|e| anyhow!("marshall public: {e}"))?;
        Ok((private_blob, public_blob))
    })
}

/// Sign `message` (SHA-256 hashed internally) with the given wrapped key.
/// Returns raw r||s, each zero-padded to 32 bytes (64 bytes total).
pub fn sign(private_blob: &[u8], public_blob: &[u8], message: &[u8]) -> Result<[u8; 64]> {
    with_ctx(|ctx, primary| {
        let private =
            Private::try_from(private_blob.to_vec()).map_err(|e| anyhow!("private blob: {e}"))?;
        let public = Public::unmarshall(public_blob).map_err(|e| anyhow!("public blob: {e}"))?;
        let handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| anyhow!("load key: {e}"))?;

        let digest_bytes: [u8; 32] = Sha256::digest(message).into();
        let digest =
            TpmDigest::try_from(digest_bytes.to_vec()).map_err(|e| anyhow!("digest: {e}"))?;
        let validation: HashcheckTicket = TPMT_TK_HASHCHECK {
            tag: TPM2_ST_HASHCHECK,
            hierarchy: TPM2_RH_NULL,
            digest: Default::default(),
        }
        .try_into()
        .map_err(|e| anyhow!("hashcheck: {e}"))?;

        let sig_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.sign(handle, digest, SignatureScheme::Null, validation)
            })
            .map_err(|e| anyhow!("sign: {e}"));
        let _ = ctx.flush_context(ObjectHandle::from(handle));
        let signature = sig_result?;

        match signature {
            Signature::EcDsa(ecc) => {
                let r = ecc.signature_r().as_bytes();
                let s = ecc.signature_s().as_bytes();
                let mut out = [0u8; 64];
                let rl = r.len().min(32);
                let sl = s.len().min(32);
                out[32 - rl..32].copy_from_slice(&r[r.len() - rl..]);
                out[64 - sl..].copy_from_slice(&s[s.len() - sl..]);
                Ok(out)
            }
            _ => Err(anyhow!("expected ECDSA signature")),
        }
    })
}

/// Create a TPM-sealed object wrapping a fresh random 32-byte key.
/// Returns (private_blob, public_blob, key_plaintext). The blobs are stored on
/// disk; the key is recoverable only via [`unseal_key`] on this TPM.
pub fn seal_new_key() -> Result<(Vec<u8>, Vec<u8>, [u8; 32])> {
    use rand::RngCore;
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);

    with_ctx(|ctx, primary| {
        let sensitive =
            SensitiveData::try_from(key.to_vec()).map_err(|e| anyhow!("sensitive: {e}"))?;
        let attrs = ObjectAttributesBuilder::new()
            .with_fixed_tpm(true)
            .with_fixed_parent(true)
            .with_user_with_auth(true)
            .with_no_da(true)
            .build()
            .map_err(|e| anyhow!("seal attrs: {e}"))?;
        let template = PublicBuilder::new()
            .with_public_algorithm(PublicAlgorithm::KeyedHash)
            .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
            .with_object_attributes(attrs)
            .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
            .with_keyed_hash_unique_identifier(Default::default())
            .build()
            .map_err(|e| anyhow!("seal template: {e}"))?;
        let result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(primary, template, None, Some(sensitive), None, None)
            })
            .map_err(|e| anyhow!("create sealed object: {e}"))?;
        let private_blob = result.out_private.as_bytes().to_vec();
        let public_blob = result
            .out_public
            .marshall()
            .map_err(|e| anyhow!("marshall sealed public: {e}"))?;
        Ok((private_blob, public_blob, key))
    })
}

/// Unseal a 32-byte key previously created with [`seal_new_key`].
pub fn unseal_key(private_blob: &[u8], public_blob: &[u8]) -> Result<[u8; 32]> {
    with_ctx(|ctx, primary| {
        let private =
            Private::try_from(private_blob.to_vec()).map_err(|e| anyhow!("private: {e}"))?;
        let public = Public::unmarshall(public_blob).map_err(|e| anyhow!("public: {e}"))?;
        let handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| anyhow!("load sealed: {e}"))?;
        let sensitive = ctx
            .execute_with_nullauth_session(|ctx| ctx.unseal(ObjectHandle::from(handle)));
        let _ = ctx.flush_context(ObjectHandle::from(handle));
        let sensitive = sensitive.map_err(|e| anyhow!("unseal: {e}"))?;
        let bytes = sensitive.as_bytes();
        if bytes.len() != 32 {
            return Err(anyhow!("sealed key wrong size: {}", bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(key)
    })
}

/// Extract (x, y) from a marshalled TPM2B_PUBLIC blob (no TPM round-trip).
pub fn public_coords(public_blob: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    let public = Public::unmarshall(public_blob).map_err(|e| anyhow!("public blob: {e}"))?;
    match public {
        Public::Ecc { unique, .. } => {
            let xb = unique.x().as_bytes();
            let yb = unique.y().as_bytes();
            let mut x = [0u8; 32];
            let mut y = [0u8; 32];
            let xl = xb.len().min(32);
            let yl = yb.len().min(32);
            x[32 - xl..].copy_from_slice(&xb[xb.len() - xl..]);
            y[32 - yl..].copy_from_slice(&yb[yb.len() - yl..]);
            Ok((x, y))
        }
        _ => Err(anyhow!("not an ECC public key")),
    }
}

// --- Backend --------------------------------------------------------------------

/// [`crate::backend::Backend`] over this module's process-global TPM context
/// ([`init`] first). Key material keeps the v0.1.0 export format,
/// `[u16 BE private_len][TPM2B_PRIVATE][TPM2B_PUBLIC]`, so existing stores load.
pub struct TpmBackend;

impl crate::backend::Backend for TpmBackend {
    fn name(&self) -> &'static str {
        "TPM"
    }

    fn create_key(&self) -> Result<Vec<u8>> {
        let (private_blob, public_blob) = create_key()?;
        let mut out = Vec::with_capacity(2 + private_blob.len() + public_blob.len());
        out.extend_from_slice(&(private_blob.len() as u16).to_be_bytes());
        out.extend_from_slice(&private_blob);
        out.extend_from_slice(&public_blob);
        Ok(out)
    }

    fn public_coords(&self, key: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let (_, public_blob) = split_key(key)?;
        public_coords(public_blob)
    }

    fn sign(&self, key: &[u8], message: &[u8]) -> Result<[u8; 64]> {
        let (private_blob, public_blob) = split_key(key)?;
        sign(private_blob, public_blob, message)
    }

    /// `dir/seal.blob` holds the TPM-sealed AES-256 key,
    /// `[u16 LE priv_len][TPM2B_PRIVATE][TPM2B_PUBLIC]`; it is unsealed into memory
    /// and the store is encrypted in software.
    fn store_cipher(&self, dir: &std::path::Path) -> Result<Box<dyn crate::backend::StoreCipher>> {
        let seal_path = dir.join("seal.blob");
        let key = if seal_path.exists() {
            let (priv_b, pub_b) = split_seal_blob(&std::fs::read(&seal_path)?)?;
            unseal_key(&priv_b, &pub_b)?
        } else {
            let (priv_b, pub_b, key) = seal_new_key()?;
            std::fs::write(&seal_path, join_seal_blob(&priv_b, &pub_b))?;
            tracing::info!("sealed a fresh store key to the TPM");
            key
        };
        Ok(Box::new(crate::store::SoftwareGcm::new(key)))
    }
}

/// Split credential key material into (private, public) TPM blobs.
fn split_key(key: &[u8]) -> Result<(&[u8], &[u8])> {
    if key.len() < 2 {
        return Err(anyhow!("key material too short"));
    }
    let plen = u16::from_be_bytes([key[0], key[1]]) as usize;
    if key.len() < 2 + plen {
        return Err(anyhow!("key material truncated"));
    }
    Ok((&key[2..2 + plen], &key[2 + plen..]))
}

// seal.blob framing: [u16 LE priv_len][priv][pub]
fn join_seal_blob(private_blob: &[u8], public_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + private_blob.len() + public_blob.len());
    out.extend_from_slice(&(private_blob.len() as u16).to_le_bytes());
    out.extend_from_slice(private_blob);
    out.extend_from_slice(public_blob);
    out
}

fn split_seal_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if blob.len() < 2 {
        return Err(anyhow!("seal blob too short"));
    }
    let plen = u16::from_le_bytes([blob[0], blob[1]]) as usize;
    if blob.len() < 2 + plen {
        return Err(anyhow!("seal blob truncated"));
    }
    Ok((blob[2..2 + plen].to_vec(), blob[2 + plen..].to_vec()))
}

#[cfg(test)]
mod tests {
    /// Real TPM operations, so opt-in: run against swtpm (see README, Development)
    /// with `LINUX_PASSKEY_TEST_TCTI=swtpm:host=localhost,port=2321 cargo test`.
    #[test]
    fn tpm_backend_conformance() {
        let Ok(tcti) = std::env::var("LINUX_PASSKEY_TEST_TCTI") else {
            eprintln!("skipped: set LINUX_PASSKEY_TEST_TCTI (a swtpm TCTI) to run");
            return;
        };
        super::init(&tcti).expect("TPM init");
        crate::backend::conformance::check(&super::TpmBackend);
    }
}
