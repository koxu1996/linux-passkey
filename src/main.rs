// linux-passkey — a FIDO2/CTAP2 authenticator daemon built on OpenSK.
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
linux-passkey — TPM 2.0-backed FIDO2/CTAP2 authenticator

USAGE:
  linux-passkey [serve]                 run the authenticator (virtual USB key)
  linux-passkey list [--rp SITE]        list stored passkeys
  linux-passkey delete [--yes] ID-PREFIX...
  linux-passkey delete [--yes] --rp SITE [--keep-newest]
                                       delete passkeys (daemon must be stopped)

ENVIRONMENT:
  LINUX_PASSKEY_DATA_DIR   store dir (default ~/.local/share/linux-passkey)
  LINUX_PASSKEY_TCTI       TPM (default device:/dev/tpmrm0)
  LINUX_PASSKEY_PINENTRY   pinentry binary for the confirm dialog";

/// `LINUX_PASSKEY_<name>`, falling back to the pre-rename `TPM2_PASSKEY_<name>`.
fn env_var(name: &str) -> Option<String> {
    std::env::var(format!("LINUX_PASSKEY_{name}"))
        .or_else(|_| std::env::var(format!("TPM2_PASSKEY_{name}")))
        .ok()
}

/// The project was called tpm2-passkey: on first start, copy the store from
/// its old default location. Copy, not move: on impermanence systems both
/// directories are bind mounts that can't be renamed, and the old copy is a
/// free backup. Only the default location is migrated.
fn migrate_store(old: &std::path::Path, new: &std::path::Path) -> Result<()> {
    const FILES: [&str; 2] = ["seal.blob", "store.enc"];
    if new.join("seal.blob").exists() || !old.join("seal.blob").exists() {
        return Ok(());
    }
    std::fs::create_dir_all(new)?;
    for f in FILES {
        let src = old.join(f);
        if src.exists() {
            std::fs::copy(&src, new.join(f))?;
        }
    }
    eprintln!(
        "linux-passkey: copied the passkey store from {} to {} (the old copy is left in place)",
        old.display(),
        new.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let pinentry_bin = env_var("PINENTRY").unwrap_or_else(|| "pinentry".to_string());
    let tcti = env_var("TCTI").unwrap_or_else(|| "device:/dev/tpmrm0".to_string());
    let data_dir = match env_var("DATA_DIR") {
        Some(dir) => std::path::PathBuf::from(dir),
        None => {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            let share = std::path::PathBuf::from(home).join(".local/share");
            let dir = share.join("linux-passkey");
            migrate_store(&share.join("tpm2-passkey"), &dir)?;
            dir
        }
    };

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

    tracing::info!("linux-passkey starting (OpenSK core, TPM-backed keys + sealed store)");
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
