//! The OpenSK `Env` for our Linux daemon: software crypto (M1) + an in-memory
//! credential store, wired to the uhid transport and pinentry user-presence.
//! Later milestones swap `Crypto` to TPM and the store to a TPM-sealed file.

use opensk::api::customization::{CustomizationImpl, DEFAULT_CUSTOMIZATION};
use opensk::api::key_store;
use opensk::api::persist::{Persist, PersistIter};
use opensk::ctap::status_code::{Ctap2StatusCode, CtapResult};
use opensk::env::Env;
use std::path::PathBuf;

use crate::clock::RealClock;
use crate::crypto::TpmCrypto;
use crate::fingerprint::PinentryFingerprint;
use crate::presence::PinentryPresence;
use crate::rng::AppRng;
use crate::store::FileStore;
use crate::uhid::UhidConnection;

/// Routes CTAP debug output to `tracing`.
pub struct LogWrite;
impl core::fmt::Write for LogWrite {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        tracing::debug!(target: "ctap", "{}", s.trim_end());
        Ok(())
    }
}

pub struct AppEnv {
    rng: AppRng,
    user_presence: PinentryPresence,
    fingerprint: PinentryFingerprint,
    hid: UhidConnection,
    clock: RealClock,
    customization: CustomizationImpl,
    store: FileStore,
}

impl AppEnv {
    /// `writer`: hold the store's exclusive lock (daemon, `delete`); false for
    /// read-only CLI use alongside a running daemon (`list`).
    pub fn new(
        hid: UhidConnection,
        pinentry_bin: String,
        data_dir: PathBuf,
        writer: bool,
    ) -> anyhow::Result<Self> {
        Ok(AppEnv {
            rng: AppRng::new(),
            user_presence: PinentryPresence::new(pinentry_bin.clone()),
            fingerprint: PinentryFingerprint::new(pinentry_bin),
            hid,
            clock: RealClock,
            customization: DEFAULT_CUSTOMIZATION,
            store: FileStore::open(data_dir, writer)?,
        })
    }

    /// Attach the real device (the store is opened first, see main).
    pub fn with_hid(mut self, hid: UhidConnection) -> Self {
        self.hid = hid;
        self
    }
}

// --- Persist: file-backed, AES-256-GCM encrypted, key TPM-sealed (M3) --------
impl Persist for AppEnv {
    fn find(&self, key: usize) -> CtapResult<Option<Vec<u8>>> {
        Ok(self.store.get(key))
    }
    fn insert(&mut self, key: usize, value: &[u8]) -> CtapResult<()> {
        self.store.insert(key, value.to_vec()).map_err(|e| {
            tracing::error!("store write failed (key {key}): {e:#}");
            Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR
        })
    }
    fn remove(&mut self, key: usize) -> CtapResult<()> {
        self.store.remove(key).map_err(|e| {
            tracing::error!("store write failed (remove key {key}): {e:#}");
            Ctap2StatusCode::CTAP2_ERR_VENDOR_INTERNAL_ERROR
        })
    }
    fn iter(&self) -> CtapResult<PersistIter<'_>> {
        Ok(Box::new(self.store.keys().into_iter().map(Ok)))
    }
}

// Default credential-wrapping KeyStore (AES master key from Persist).
impl key_store::Helper for AppEnv {}

impl Env for AppEnv {
    type Rng = AppRng;
    type UserPresence = PinentryPresence;
    type Fingerprint = PinentryFingerprint;
    type Persist = Self;
    type KeyStore = Self;
    type Clock = RealClock;
    type Write = LogWrite;
    type Customization = CustomizationImpl;
    type HidConnection = UhidConnection;
    type Crypto = TpmCrypto;

    fn rng(&mut self) -> &mut Self::Rng {
        &mut self.rng
    }
    fn user_presence(&mut self) -> &mut Self::UserPresence {
        &mut self.user_presence
    }
    fn fingerprint(&mut self) -> &mut Self::Fingerprint {
        &mut self.fingerprint
    }
    fn persist(&mut self) -> &mut Self {
        self
    }
    fn key_store(&mut self) -> &mut Self {
        self
    }
    fn clock(&mut self) -> &mut Self::Clock {
        &mut self.clock
    }
    fn write(&mut self) -> Self::Write {
        LogWrite
    }
    fn customization(&self) -> &Self::Customization {
        &self.customization
    }
    fn hid_connection(&mut self) -> &mut Self::HidConnection {
        &mut self.hid
    }
    fn boots_after_soft_reset(&self) -> bool {
        false
    }
}
