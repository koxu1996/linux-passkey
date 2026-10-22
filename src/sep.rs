//! Apple Secure Enclave backend (Apple Silicon Macs running the aurora-silicon
//! `apple_sep` driver).
//!
//! **Credential keys.** `SEP_BIO_KEY_CREATE` on `/dev/sep-bio` has the enclave
//! create a P-256 key pair and return the public point plus the private key
//! wrapped by the enclave; `SEP_BIO_KEY_SIGN` signs a digest with such a blob.
//! The private key never leaves the enclave, and a blob is useless anywhere else.
//! Key material: `[1][65-byte public point 04||X||Y][enclave blob]`.
//!
//! **Store cipher.** The AES-256 store key is a kernel *trusted key* sealed by the
//! enclave (`trusted.source=applesep`). Its sealed form is kept in
//! `dir/sep-seal.hex`; at startup it is loaded into this process's keyring, and
//! the store is encrypted with `gcm(aes)` inside the kernel (AF_ALG, keyed by
//! the keyring entry), so the AES key is never in this process's memory.
//! `store.enc` keeps the [`crate::store::SoftwareGcm`] layout:
//! `[12-byte nonce][ciphertext || 16-byte tag]`.

use anyhow::{anyhow, bail, Context as _, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::sync::{Mutex, OnceLock};

// --- /dev/sep-bio ABI (drivers/soc/apple/sep-bio.h) ------------------------------

const PUB_LEN: usize = 65;
const DIGEST_LEN: usize = 32;
const SIG_MAX: usize = 72;
const KEY_BLOB_MAX: usize = 1024;

#[repr(C)]
struct KeyCreate {
    blob_len: u32,
    public: [u8; PUB_LEN],
    reserved: [u8; 3],
    blob: [u8; KEY_BLOB_MAX],
}

#[repr(C)]
struct KeySign {
    blob_len: u32,
    sig_len: u32,
    digest: [u8; DIGEST_LEN],
    signature: [u8; SIG_MAX],
    blob: [u8; KEY_BLOB_MAX],
}

const _: () = assert!(std::mem::size_of::<KeyCreate>() == 1096);
const _: () = assert!(std::mem::size_of::<KeySign>() == 1136);

const fn ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << 30) | ((size as u64) << 16) | (0xB1 << 8) | nr
}
const IOC_READ: u64 = 2;
const IOC_RW: u64 = 3;
const SEP_BIO_KEY_CREATE: u64 = ioc(IOC_READ, 0x0b, std::mem::size_of::<KeyCreate>());
const SEP_BIO_KEY_SIGN: u64 = ioc(IOC_RW, 0x0c, std::mem::size_of::<KeySign>());

const KEY_VERSION: u8 = 1;

static DEVICE: OnceLock<Mutex<File>> = OnceLock::new();

/// Open the enclave device (default `/dev/sep-bio`). Call once at startup.
pub fn init(device: &str) -> Result<()> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(device)
        .with_context(|| format!("open {device} (Secure Enclave; needs access to the device)"))?;
    DEVICE
        .set(Mutex::new(f))
        .map_err(|_| anyhow!("Secure Enclave backend already initialized"))
}

fn ioctl<T>(request: u64, arg: &mut T) -> Result<()> {
    let dev = DEVICE
        .get()
        .ok_or_else(|| anyhow!("Secure Enclave backend not initialized"))?
        .lock()
        .map_err(|_| anyhow!("Secure Enclave device lock poisoned"))?;
    // SAFETY: `arg` is the #[repr(C)] struct whose size is encoded in `request`.
    let rc = unsafe { libc::ioctl(dev.as_raw_fd(), request as _, arg as *mut T) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub struct SepBackend;

impl crate::backend::Backend for SepBackend {
    fn name(&self) -> &'static str {
        "Secure Enclave"
    }

    fn create_key(&self) -> Result<Vec<u8>> {
        let mut req = KeyCreate {
            blob_len: 0,
            public: [0; PUB_LEN],
            reserved: [0; 3],
            blob: [0; KEY_BLOB_MAX],
        };
        ioctl(SEP_BIO_KEY_CREATE, &mut req).context("enclave key create")?;
        let n = req.blob_len as usize;
        if n == 0 || n > KEY_BLOB_MAX || req.public[0] != 0x04 {
            bail!("enclave returned a malformed key (blob {n} bytes)");
        }
        let mut out = Vec::with_capacity(1 + PUB_LEN + n);
        out.push(KEY_VERSION);
        out.extend_from_slice(&req.public);
        out.extend_from_slice(&req.blob[..n]);
        Ok(out)
    }

    fn public_coords(&self, key: &[u8]) -> Result<([u8; 32], [u8; 32])> {
        let (public, _) = split_key(key)?;
        Ok((public[1..33].try_into()?, public[33..65].try_into()?))
    }

    fn sign(&self, key: &[u8], message: &[u8]) -> Result<[u8; 64]> {
        let (_, blob) = split_key(key)?;
        let mut req = KeySign {
            blob_len: blob.len() as u32,
            sig_len: 0,
            digest: Sha256::digest(message).into(),
            signature: [0; SIG_MAX],
            blob: [0; KEY_BLOB_MAX],
        };
        req.blob[..blob.len()].copy_from_slice(blob);
        ioctl(SEP_BIO_KEY_SIGN, &mut req).context("enclave sign")?;
        let n = (req.sig_len as usize).min(SIG_MAX);
        der_signature_to_raw(&req.signature[..n])
    }

    fn store_cipher(&self, dir: &Path) -> Result<Box<dyn crate::backend::StoreCipher>> {
        let seal_path = dir.join("sep-seal.hex");
        let serial = if seal_path.exists() {
            let hex = std::fs::read_to_string(&seal_path)?;
            add_trusted_key(&format!("load {}", hex.trim()))
                .context("unseal the store key through the Secure Enclave")?
        } else {
            let serial = add_trusted_key("new 32").context("create the store key")?;
            std::fs::write(&seal_path, read_key(serial)?)?;
            tracing::info!("sealed a fresh store key to the Secure Enclave");
            serial
        };
        Ok(Box::new(KernelGcm { serial }))
    }
}

/// Split key material into (public point, enclave blob).
fn split_key(key: &[u8]) -> Result<(&[u8], &[u8])> {
    match key {
        [KEY_VERSION, rest @ ..] if rest.len() > PUB_LEN && rest.len() - PUB_LEN <= KEY_BLOB_MAX => {
            Ok(rest.split_at(PUB_LEN))
        }
        [v, ..] if *v != KEY_VERSION => bail!("unknown Secure Enclave key version {v}"),
        _ => bail!("Secure Enclave key material is malformed"),
    }
}

/// DER `SEQUENCE { INTEGER r, INTEGER s }` to raw 32-byte big-endian r || s.
fn der_signature_to_raw(der: &[u8]) -> Result<[u8; 64]> {
    fn integer(b: &[u8]) -> Result<(&[u8], &[u8])> {
        match b {
            [0x02, len, rest @ ..] if rest.len() >= *len as usize => {
                Ok(rest.split_at(*len as usize))
            }
            _ => bail!("signature: expected a DER INTEGER"),
        }
    }
    let body = match der {
        [0x30, len, rest @ ..] if rest.len() == *len as usize => rest,
        _ => bail!("signature: expected a DER SEQUENCE"),
    };
    let (r, rest) = integer(body)?;
    let (s, rest) = integer(rest)?;
    if !rest.is_empty() {
        bail!("signature: trailing bytes");
    }
    let mut out = [0u8; 64];
    let (out_r, out_s) = out.split_at_mut(32);
    for (src, dst) in [(r, out_r), (s, out_s)] {
        let src = match src.iter().position(|&b| b != 0) {
            Some(i) => &src[i..],
            None => &[][..],
        };
        if src.len() > 32 {
            bail!("signature: integer longer than 32 bytes");
        }
        dst[32 - src.len()..].copy_from_slice(src);
    }
    Ok(out)
}

// --- kernel keyring: the enclave-sealed store key --------------------------------

/// Add a `trusted` key to this process's keyring; returns its serial. Each call
/// gets its own description: adding under an existing one would be an update,
/// which trusted keys refuse.
fn add_trusted_key(payload: &str) -> Result<i32> {
    static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let ktype = CString::new("trusted")?;
    let desc = CString::new(format!("linux-passkey-store-{n}"))?;
    // SAFETY: valid NUL-terminated strings and a payload slice for its length.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            ktype.as_ptr(),
            desc.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            libc::KEY_SPEC_PROCESS_KEYRING,
        )
    };
    if serial < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(serial as i32)
}

/// A trusted key's sealed form (hex, as the kernel prints it).
fn read_key(serial: i32) -> Result<String> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: `buf` is writable for its length.
    let n = unsafe {
        libc::syscall(libc::SYS_keyctl, libc::KEYCTL_READ, serial, buf.as_mut_ptr(), buf.len())
    };
    if n < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if n as usize > buf.len() {
        bail!("sealed store key larger than expected ({n} bytes)");
    }
    buf.truncate(n as usize);
    Ok(String::from_utf8(buf)?)
}

// --- AES-256-GCM in the kernel (AF_ALG), keyed by the trusted key -----------------

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

struct KernelGcm {
    serial: i32,
}

impl crate::backend::StoreCipher for KernelGcm {
    fn encrypt(&self, plain: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = kernel_gcm(self.serial, libc::ALG_OP_ENCRYPT, &nonce, plain, plain.len() + TAG_LEN)?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < NONCE_LEN + TAG_LEN {
            bail!("store file too short");
        }
        let (nonce, ct) = data.split_at(NONCE_LEN);
        kernel_gcm(self.serial, libc::ALG_OP_DECRYPT, nonce.try_into()?, ct, ct.len() - TAG_LEN)
            .map_err(|e| anyhow!("decrypt store: {e}"))
    }
}

fn check(rc: libc::c_int, what: &str) -> Result<()> {
    if rc < 0 {
        return Err(anyhow!("{what}: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

/// One AEAD operation (no associated data). Encrypt: `input` = plaintext, output
/// = ciphertext || tag. Decrypt: `input` = ciphertext || tag, output = plaintext;
/// a wrong key or tampered data fails with EBADMSG.
fn kernel_gcm(
    serial: i32,
    op: libc::c_int,
    nonce: &[u8; NONCE_LEN],
    input: &[u8],
    out_len: usize,
) -> Result<Vec<u8>> {
    // SAFETY: plain socket syscalls on fds we own; every pointer refers to a live
    // local buffer of the length passed with it.
    unsafe {
        let tfm = libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC, 0);
        check(tfm, "AF_ALG socket")?;
        let tfm = OwnedFd::from_raw_fd(tfm);

        let mut sa: libc::sockaddr_alg = std::mem::zeroed();
        sa.salg_family = libc::AF_ALG as u16;
        sa.salg_type[..4].copy_from_slice(b"aead");
        sa.salg_name[..8].copy_from_slice(b"gcm(aes)");
        check(
            libc::bind(
                tfm.as_raw_fd(),
                &sa as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_alg>() as u32,
            ),
            "bind gcm(aes)",
        )?;
        check(
            libc::setsockopt(
                tfm.as_raw_fd(),
                libc::SOL_ALG,
                libc::ALG_SET_KEY_BY_KEY_SERIAL,
                &serial as *const i32 as *const libc::c_void,
                4,
            ),
            "set the trusted key on gcm(aes)",
        )?;
        check(
            libc::setsockopt(
                tfm.as_raw_fd(),
                libc::SOL_ALG,
                libc::ALG_SET_AEAD_AUTHSIZE,
                std::ptr::null(),
                TAG_LEN as u32,
            ),
            "set the GCM tag size",
        )?;
        let opfd = libc::accept(tfm.as_raw_fd(), std::ptr::null_mut(), std::ptr::null_mut());
        check(opfd, "AF_ALG accept")?;
        let opfd = OwnedFd::from_raw_fd(opfd);

        // Control messages: the operation, the IV (u32 length + bytes), assoclen 0.
        let op_len = std::mem::size_of::<u32>();
        let iv_len = std::mem::size_of::<u32>() + NONCE_LEN;
        let assoc_len = std::mem::size_of::<u32>();
        let space = libc::CMSG_SPACE(op_len as u32)
            + libc::CMSG_SPACE(iv_len as u32)
            + libc::CMSG_SPACE(assoc_len as u32);
        let mut cbuf = vec![0u8; space as usize];

        let mut iov = libc::iovec {
            iov_base: input.as_ptr() as *mut libc::c_void,
            iov_len: input.len(),
        };
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;

        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_ALG;
        (*c).cmsg_type = libc::ALG_SET_OP;
        (*c).cmsg_len = libc::CMSG_LEN(op_len as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut u32, op as u32);

        let c = libc::CMSG_NXTHDR(&msg, c);
        (*c).cmsg_level = libc::SOL_ALG;
        (*c).cmsg_type = libc::ALG_SET_IV;
        (*c).cmsg_len = libc::CMSG_LEN(iv_len as u32) as _;
        let d = libc::CMSG_DATA(c);
        std::ptr::write_unaligned(d as *mut u32, NONCE_LEN as u32);
        std::ptr::copy_nonoverlapping(nonce.as_ptr(), d.add(4), NONCE_LEN);

        let c = libc::CMSG_NXTHDR(&msg, c);
        (*c).cmsg_level = libc::SOL_ALG;
        (*c).cmsg_type = libc::ALG_SET_AEAD_ASSOCLEN;
        (*c).cmsg_len = libc::CMSG_LEN(assoc_len as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(c) as *mut u32, 0);

        let sent = libc::sendmsg(opfd.as_raw_fd(), &msg, 0);
        if sent < 0 {
            bail!("AF_ALG sendmsg: {}", std::io::Error::last_os_error());
        }
        if sent as usize != input.len() {
            bail!("AF_ALG took {sent} of {} bytes (store too large for one operation)", input.len());
        }

        let mut out = vec![0u8; out_len];
        let got = libc::read(opfd.as_raw_fd(), out.as_mut_ptr() as *mut libc::c_void, out_len);
        if got < 0 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EBADMSG) {
                bail!("authentication failed (wrong key or tampered data)");
            }
            bail!("AF_ALG read: {e}");
        }
        if got as usize != out_len {
            bail!("AF_ALG returned {got} of {out_len} bytes");
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Backend;

    #[test]
    fn der_to_raw_pads_and_strips() {
        // r with a leading 0x00 (high bit set), s short (needs left padding).
        let mut der = vec![0x30, 0];
        der.extend_from_slice(&[0x02, 33, 0x00]);
        der.extend(std::iter::repeat(0xAB).take(32));
        der.extend_from_slice(&[0x02, 2, 0x01, 0x02]);
        der[1] = (der.len() - 2) as u8;
        let raw = der_signature_to_raw(&der).unwrap();
        assert_eq!(&raw[..32], &[0xAB; 32]);
        assert_eq!(&raw[32..62], &[0u8; 30]);
        assert_eq!(&raw[62..], &[0x01, 0x02]);
        assert!(der_signature_to_raw(&der[..der.len() - 1]).is_err());
    }

    #[test]
    fn key_material_layout() {
        let mut key = vec![KEY_VERSION, 0x04];
        key.extend(1..=64u8);
        key.extend_from_slice(&[0xEE; 258]);
        let (public, blob) = split_key(&key).unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(blob, &[0xEE; 258][..]);
        let (x, y) = SepBackend.public_coords(&key).unwrap();
        assert_eq!(x[0], 1);
        assert_eq!(y[31], 64);
        assert!(split_key(&[2, 0x04]).is_err());
        assert!(split_key(&key[..60]).is_err());
    }

    /// Real enclave operations, so opt-in: on an Apple Silicon Mac with the
    /// apple_sep key ioctls, `LINUX_PASSKEY_TEST_SEP=/dev/sep-bio cargo test`
    /// (as a user with access to the device).
    #[test]
    fn sep_backend_conformance() {
        let Ok(device) = std::env::var("LINUX_PASSKEY_TEST_SEP") else {
            eprintln!("skipped: set LINUX_PASSKEY_TEST_SEP=/dev/sep-bio to run");
            return;
        };
        init(&device).expect("open the enclave device");
        crate::backend::conformance::check(&SepBackend);

        // Store cipher: seal a fresh key, round-trip, reload from the sealed form.
        let dir = std::env::temp_dir().join(format!("linux-passkey-sep-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let c1 = SepBackend.store_cipher(&dir).expect("store cipher (new)");
        let blob = c1.encrypt(b"passkeys").unwrap();
        assert_eq!(c1.decrypt(&blob).unwrap(), b"passkeys");
        let c2 = SepBackend.store_cipher(&dir).expect("store cipher (reload)");
        assert_eq!(c2.decrypt(&blob).unwrap(), b"passkeys", "reloaded key decrypts");
        let mut bad = blob.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(c2.decrypt(&bad).is_err(), "tampered store is rejected");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
