// tpm2-passkey — a FIDO2/CTAP2 authenticator daemon built on OpenSK.
// Loop: recv a 64-byte HID report -> ctap.process_hid_packet -> send outputs.

// sk-cbor's macros expand to `::alloc::…` paths.
extern crate alloc;

mod cli;
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

const USAGE: &str = "\
tpm2-passkey — TPM 2.0-backed FIDO2/CTAP2 authenticator

USAGE:
  tpm2-passkey [serve]                 run the authenticator (virtual USB key)
  tpm2-passkey list [--rp SITE]        list stored passkeys
  tpm2-passkey delete [--yes] ID-PREFIX...
  tpm2-passkey delete [--yes] --rp SITE [--keep-newest]
                                       delete passkeys (daemon must be stopped)

ENVIRONMENT:
  TPM2_PASSKEY_DATA_DIR   store dir (default ~/.local/share/tpm2-passkey)
  TPM2_PASSKEY_TCTI       TPM (default device:/dev/tpmrm0)
  TPM2_PASSKEY_PINENTRY   pinentry binary for the confirm dialog";

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

    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("serve");
    if matches!(command, "-h" | "--help" | "help") {
        println!("{USAGE}");
        return Ok(());
    }
    if !matches!(command, "serve" | "list" | "delete") {
        anyhow::bail!("unknown command '{command}'\n\n{USAGE}");
    }

    tpm::init(&tcti)?;
    match command {
        "list" => {
            let rp = match args.get(1).map(String::as_str) {
                Some("--rp") => Some(args.get(2).map(String::as_str).ok_or_else(|| anyhow::anyhow!("--rp needs a site"))?),
                Some(other) => anyhow::bail!("unknown option {other}"),
                None => None,
            };
            return cli::list(data_dir, rp);
        }
        "delete" => return cli::delete(data_dir, &args[1..]),
        _ => {}
    }

    tracing::info!("tpm2-passkey starting (OpenSK core, TPM-backed keys + sealed store)");
    tracing::info!("TPM backend ready ({tcti})");
    // Take the store lock before creating the device, so a second daemon
    // fails cleanly instead of fighting over the same store.
    let env = AppEnv::new(UhidConnection::detached(), pinentry_bin, data_dir, true)?;
    let env = env.with_hid(UhidConnection::create()?);
    tracing::info!("uhid FIDO2 device created; waiting for the host");

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
