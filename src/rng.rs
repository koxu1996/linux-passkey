//! RNG for the CTAP core. OpenSK's `Rng` is a marker over `rand_core`'s
//! `CryptoRng + RngCore`; we can't impl it on a foreign type, so wrap `OsRng`.

use opensk::api::rng::Rng;
use rand::rngs::OsRng;
use rand::{CryptoRng, RngCore};

pub struct AppRng(OsRng);

impl AppRng {
    pub fn new() -> Self {
        AppRng(OsRng)
    }
}

impl RngCore for AppRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl CryptoRng for AppRng {}
impl Rng for AppRng {}
