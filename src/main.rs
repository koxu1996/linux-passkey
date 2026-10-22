// tpm2-passkey — a FIDO2/CTAP2 authenticator daemon built on OpenSK.
// M1: real uhid transport + pinentry user-presence + software crypto.
// Loop: recv a 64-byte HID report -> ctap.process_hid_packet -> send outputs.

// sk-cbor's macros expand to `::alloc::…` paths.
extern crate alloc;

mod clock;
mod crypto;
mod env;
mod fingerprint;
mod presence;
mod request;
mod rng;
mod store;
mod tpm;
mod uhid;

use anyhow::Result;
use opensk::Ctap;
use opensk::Transport;
use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::env::Env;

use env::AppEnv;
use uhid::UhidConnection;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let pinentry_bin =
        std::env::var("TPM2_PASSKEY_PINENTRY").unwrap_or_else(|_| "pinentry".to_string());
    let tcti =
        std::env::var("TPM2_PASSKEY_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_string());
    let data_dir = std::env::var("TPM2_PASSKEY_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            std::path::PathBuf::from(home).join(".local/share/tpm2-passkey")
        });

    tracing::info!("tpm2-passkey starting (OpenSK core, TPM-backed keys + sealed store — M3)");
    tpm::init(&tcti)?;
    tracing::info!("TPM backend ready ({tcti})");
    let hid = UhidConnection::create()?;
    tracing::info!("uhid FIDO2 device created; waiting for the host");

    let env = AppEnv::new(hid, pinentry_bin, data_dir)?;
    let mut ctap = Ctap::new(env);

    // Enroll one built-in-UV "template" so the authenticator advertises uv:true
    // and the browser performs built-in UV (our pinentry) instead of a clientPIN.
    {
        use opensk::api::persist::Persist;
        let env = ctap.env();
        let already = env
            .template_infos()
            .map(|t| !t.is_empty())
            .unwrap_or(false);
        if !already {
            if let Err(e) = env.store_template_id(fingerprint::TEMPLATE_ID.to_vec()) {
                tracing::warn!("could not enroll built-in UV template: {:?}", e);
            } else {
                tracing::info!("enrolled built-in UV template (uv:true, no clientPIN)");
            }
        }
    }

    let mut buf = [0u8; 64];
    let mut requests = request::Reassembler::default();
    loop {
        match ctap.env().hid_connection().recv(&mut buf, 60_000) {
            Ok(RecvStatus::Received(_endpoint)) => {
                // Note what is being asked (op + site) for the confirm prompt.
                if requests.feed(&buf) {
                    request::check_already_registered(ctap.env());
                }
                let out = ctap.process_hid_packet(&buf, Transport::MainHid);
                // Collect to drop the &mut ctap borrow before sending.
                let packets: Vec<_> = out.collect();
                for pkt in packets {
                    if let Err(e) = ctap
                        .env()
                        .hid_connection()
                        .send(&pkt, UsbEndpoint::MainHid)
                    {
                        tracing::error!("HID send error: {:?}", e);
                    }
                }
            }
            Ok(RecvStatus::Timeout) => {}
            Err(e) => {
                tracing::error!("HID recv error: {:?}; shutting down", e);
                break;
            }
        }
    }
    Ok(())
}
