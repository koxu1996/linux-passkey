//! Persistent credential store: an OpenSK key/value map serialized to one file,
//! AES-256-GCM encrypted with a key that is TPM-sealed. Survives daemon restart
//! and (placed in /persist) the impermanence root rollback.
//!
//! Layout in `dir`:
//!   seal.blob   — [u16 priv_len][TPM2B_PRIVATE][TPM2B_PUBLIC] of the sealed AES key
//!   store.enc   — [12-byte nonce][AES-256-GCM ciphertext of the serialized map]

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use rand::RngCore;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub struct FileStore {
    dir: PathBuf,
    aes_key: [u8; 32],
    map: BTreeMap<usize, Vec<u8>>,
    /// Exclusive lock on `dir/lock` for writers (the daemon, `delete`): the
    /// daemon keeps the map in memory and rewrites the whole file, so a second
    /// writer's changes would be silently lost. None for read-only opens.
    _lock: Option<std::fs::File>,
}

impl FileStore {
    /// Open (or initialize) the store in `dir`. Creates+seals a fresh AES key on
    /// first run; otherwise unseals it and decrypts the existing store.
    /// `writer` takes the exclusive lock and fails if another writer holds it.
    pub fn open(dir: PathBuf, writer: bool) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        let lock = if writer {
            let f = std::fs::File::create(dir.join("lock"))?;
            f.try_lock().map_err(|_| {
                anyhow!(
                    "store {} is in use (is the linux-passkey daemon running? stop it first)",
                    dir.display()
                )
            })?;
            Some(f)
        } else {
            None
        };

        let seal_path = dir.join("seal.blob");
        let aes_key = if seal_path.exists() {
            let (priv_b, pub_b) = split_blob(&std::fs::read(&seal_path)?)?;
            crate::tpm::unseal_key(&priv_b, &pub_b)?
        } else {
            let (priv_b, pub_b, key) = crate::tpm::seal_new_key()?;
            std::fs::write(&seal_path, join_blob(&priv_b, &pub_b))?;
            tracing::info!("sealed a fresh store key to the TPM");
            key
        };

        let store_path = dir.join("store.enc");
        let map = if store_path.exists() {
            let plain = decrypt(&aes_key, &std::fs::read(&store_path)?)?;
            let map = deserialize(&plain)?;
            tracing::info!(entries = map.len(), "loaded encrypted store");
            map
        } else {
            BTreeMap::new()
        };

        Ok(FileStore { dir, aes_key, map, _lock: lock })
    }

    fn persist(&self) -> Result<()> {
        if self._lock.is_none() {
            return Err(anyhow!("store opened read-only"));
        }
        let data = encrypt(&self.aes_key, &serialize(&self.map))?;
        let tmp = self.dir.join("store.enc.tmp");
        std::fs::write(&tmp, &data)?;
        std::fs::rename(&tmp, self.dir.join("store.enc"))?; // atomic replace
        Ok(())
    }

    pub fn get(&self, key: usize) -> Option<Vec<u8>> {
        self.map.get(&key).cloned()
    }

    pub fn insert(&mut self, key: usize, value: Vec<u8>) -> Result<()> {
        self.map.insert(key, value);
        self.persist()
    }

    pub fn remove(&mut self, key: usize) -> Result<()> {
        self.map.remove(&key);
        self.persist()
    }

    pub fn keys(&self) -> Vec<usize> {
        self.map.keys().copied().collect()
    }
}

// --- serialization: [u32 count]{[u64 key][u32 len][bytes]}* --------------------
fn serialize(map: &BTreeMap<usize, Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    for (k, v) in map {
        out.extend_from_slice(&(*k as u64).to_le_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

fn deserialize(bytes: &[u8]) -> Result<BTreeMap<usize, Vec<u8>>> {
    let mut map = BTreeMap::new();
    let mut p = 0usize;
    let rd = |b: &[u8], p: &mut usize, n: usize| -> Result<Vec<u8>> {
        if *p + n > b.len() {
            return Err(anyhow!("store truncated"));
        }
        let s = b[*p..*p + n].to_vec();
        *p += n;
        Ok(s)
    };
    let count = u32::from_le_bytes(rd(bytes, &mut p, 4)?.try_into().unwrap());
    for _ in 0..count {
        let key = u64::from_le_bytes(rd(bytes, &mut p, 8)?.try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(rd(bytes, &mut p, 4)?.try_into().unwrap()) as usize;
        let val = rd(bytes, &mut p, len)?;
        map.insert(key, val);
    }
    Ok(map)
}

// --- AES-256-GCM: [12 nonce][ciphertext] --------------------------------------
fn encrypt(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("aes key: {e}"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plain)
        .map_err(|e| anyhow!("encrypt: {e}"))?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 {
        return Err(anyhow!("store file too short"));
    }
    let (nonce_bytes, ct) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| anyhow!("aes key: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ct).map_err(|e| anyhow!("decrypt: {e}"))
}

// --- seal.blob framing: [u16 priv_len][priv][pub] -----------------------------
fn join_blob(private_blob: &[u8], public_blob: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + private_blob.len() + public_blob.len());
    out.extend_from_slice(&(private_blob.len() as u16).to_le_bytes());
    out.extend_from_slice(private_blob);
    out.extend_from_slice(public_blob);
    out
}

fn split_blob(blob: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    if blob.len() < 2 {
        return Err(anyhow!("seal blob too short"));
    }
    let plen = u16::from_le_bytes([blob[0], blob[1]]) as usize;
    if blob.len() < 2 + plen {
        return Err(anyhow!("seal blob truncated"));
    }
    Ok((blob[2..2 + plen].to_vec(), blob[2 + plen..].to_vec()))
}
