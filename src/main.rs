// linux-passkey — a FIDO2/CTAP2 authenticator daemon built on OpenSK.
// Loop: recv a 64-byte HID report -> ctap.process_hid_packet -> send outputs.

// sk-cbor's macros expand to `::alloc::…` paths.
extern crate alloc;

mod backend;
mod cli;
mod clock;
mod crypto;
mod env;
mod fingerprint;
mod agent;
mod fprintd;
mod gateway;
mod native_host;
mod pinentry;
mod presence;
mod request;
mod rng;
mod sep;
mod store;
mod tpm;
mod uhid;
mod webauthn;

use anyhow::Result;
use opensk::Ctap;
use opensk::Transport;
use opensk::api::connection::{HidConnection, RecvStatus, UsbEndpoint};
use opensk::ctap::Channel;
use opensk::env::Env;

use env::AppEnv;
use uhid::UhidConnection;

/// linux-passkey's AAGUID (random v4 UUID, see README).
const AAGUID: [u8; 16] = [
    0x47, 0x90, 0x68, 0x8c, 0x58, 0x23, 0x40, 0xb0, 0x90, 0x2a, 0x27, 0x24, 0xc6, 0xd7, 0xbb, 0xad,
];

const USAGE: &str = "\
linux-passkey — TPM 2.0-backed FIDO2/CTAP2 authenticator

USAGE:
  linux-passkey [serve]                 run the authenticator (virtual USB key + D-Bus)
  linux-passkey native-host             browser native messaging host (started by the
                                       browser extension; also as linux-passkey-native-host)
  linux-passkey list [--rp SITE]        list stored passkeys
  linux-passkey delete [--yes] ID-PREFIX...
  linux-passkey delete [--yes] --rp SITE [--keep-newest]
                                       delete passkeys (daemon must be stopped)
  linux-passkey unblock                 clear failed-approval lockout (PIN_BLOCKED;
                                       daemon must be stopped)

ENVIRONMENT:
  LINUX_PASSKEY_DATA_DIR   store dir (default ~/.local/share/linux-passkey)
  LINUX_PASSKEY_TCTI       TPM (default device:/dev/tpmrm0)
  LINUX_PASSKEY_DIALOG     approval dialog (linux-passkey-dialog); pinentry without it
  LINUX_PASSKEY_PINENTRY   pinentry binary for the confirm dialog
  LINUX_PASSKEY_BACKEND    hardware behind the keys: tpm (default) or sep
  LINUX_PASSKEY_SEP_DEVICE Secure Enclave key device (default /dev/sep-key)
  LINUX_PASSKEY_UV         approval: pinentry (dialog, default) or fprintd (dialog, then finger)
  LINUX_PASSKEY_FPRINTD_VERIFY  fprintd-verify binary (default fprintd-verify)";

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
    // Browsers start the native host with their own arguments (the manifest
    // path, or the extension's origin), so it is picked by program name too.
    let program = std::env::args().next().unwrap_or_default();
    if program.ends_with("linux-passkey-native-host")
        || std::env::args().nth(1).as_deref() == Some("native-host")
    {
        return native_host::run();
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let pinentry_bin = env_var("PINENTRY").unwrap_or_else(|| "pinentry".to_string());
    // How requests are approved: the pinentry dialog, then (fprintd) the finger.
    let fprintd_verify = match env_var("UV").as_deref().unwrap_or("pinentry") {
        "pinentry" => None,
        "fprintd" => Some(env_var("FPRINTD_VERIFY").unwrap_or_else(|| "fprintd-verify".to_string())),
        other => anyhow::bail!("unknown LINUX_PASSKEY_UV '{other}' (supported: pinentry, fprintd)"),
    };
    let dialog_bin = env_var("DIALOG").filter(|d| !d.is_empty());
    let check = presence::UserCheck { dialog_bin, pinentry_bin, fprintd_verify };
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
    if !matches!(command, "serve" | "list" | "delete" | "unblock") {
        anyhow::bail!("unknown command '{command}'\n\n{USAGE}");
    }

    // The hardware behind the keys and the store.
    let backend_name = env_var("BACKEND").unwrap_or_else(|| "tpm".into());
    match backend_name.as_str() {
        "tpm" => {
            tpm::init(&tcti)?;
            backend::init(Box::new(tpm::TpmBackend))?;
        }
        "sep" => {
            let device = env_var("SEP_DEVICE").unwrap_or_else(|| "/dev/sep-key".into());
            sep::init(&device)?;
            backend::init(Box::new(sep::SepBackend))?;
        }
        other => anyhow::bail!("unknown LINUX_PASSKEY_BACKEND '{other}' (supported: tpm, sep)"),
    }
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
        "unblock" => return cli::unblock(data_dir),
        _ => {}
    }

    let hw = backend::get().name();
    tracing::info!("linux-passkey starting (OpenSK core, {hw}-backed keys + sealed store)");
    if backend_name == "tpm" {
        tracing::info!("TPM backend ready ({tcti})");
    }
    // Take the store lock before creating the device, so a second daemon
    // fails cleanly instead of fighting over the same store.
    let env = AppEnv::new(UhidConnection::detached(), check.clone(), data_dir, true)?;
    let env = env.with_hid(UhidConnection::create()?);
    tracing::info!("uhid FIDO2 device created; waiting for the host");

    let mut ctap = Ctap::new(env);

    // The browser extension's front-end (gateway.rs). Without a session bus
    // the USB key still works.
    let (jobs_tx, jobs) = std::sync::mpsc::channel();
    let _bus = match gateway::serve(jobs_tx) {
        Ok(bus) => {
            tracing::info!("D-Bus gateway ready ({})", gateway::BUS_NAME);
            Some(bus)
        }
        Err(e) => {
            tracing::warn!("no D-Bus gateway ({e}); browsers can use the USB key only");
            None
        }
    };

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

    // Our AAGUID (4790688c-5823-40b0-902a-2724c6d7bbad), so sites can name the
    // authenticator. Only new registrations carry it; existing passkeys are
    // unaffected. Kept across authenticatorReset (a persistent OpenSK key).
    {
        use opensk::api::persist::Persist;
        let env = ctap.env();
        if env.aaguid().ok() != Some(AAGUID) {
            if let Err(e) = env.set_aaguid(&AAGUID) {
                tracing::warn!("could not set AAGUID: {:?}", e);
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
        while let Ok(job) = jobs.try_recv() {
            run_job(&mut ctap, &check, job);
        }
    }
    Ok(())
}

/// One WebAuthn ceremony from D-Bus, on the same OpenSK state as the USB key.
fn run_job(ctap: &mut Ctap<AppEnv>, check: &presence::UserCheck, mut job: gateway::Job) {
    if !gateway::start(&job.call) {
        let _ = job.reply.send(Err(webauthn::Error::Abort));
        return;
    }
    let result = ceremony(ctap, check, &mut job);
    agent::finish();
    gateway::finish();
    let c = &job.ceremony;
    if let Err(e) = &result {
        tracing::info!(rp = %c.rp_id, "D-Bus request ended: {}", e.name());
    }
    let _ = job.reply.send(result);
}

/// How long the user has to answer the dialog of an extension request
/// (OpenSK's own 30 s then cover only the finger).
const DIALOG_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
/// Fingerprint attempts per sign-in or registration; each failed one uses up
/// one of OpenSK's UV retries.
const FINGER_ATTEMPTS: usize = 3;

fn ceremony(ctap: &mut Ctap<AppEnv>, check: &presence::UserCheck, job: &mut gateway::Job) -> Result<String, webauthn::Error> {
    use webauthn::{Error, Kind};
    let c = &mut job.ceremony;
    if c.kind == Kind::Get && !request::has_credential(ctap.env(), &c.rp_id, &c.allow) {
        // Nothing to sign with: the browser asks its own authenticators.
        return Err(Error::NoCredential);
    }
    request::begin_internal(&c.command);
    request::check_already_registered(ctap.env());

    // With the dialog agent, the user answers before OpenSK runs: they can
    // pick the account, and OpenSK's UV is left with the finger only.
    if let Some(bin) = &check.dialog_bin {
        let existing = matches!(request::current(), Some(request::Request::Register { existing: true, .. }));
        let accounts = if c.kind == Kind::Get { request::accounts(ctap.env(), &c.rp_id, &c.allow) } else { vec![] };
        let ask = agent::Ask {
            op: match (c.kind, existing) {
                (Kind::Create, false) => "register",
                (Kind::Create, true) => "already-registered",
                (Kind::Get, _) => "sign-in",
            },
            rp: c.rp_id.clone(),
            origin: Some(c.origin.clone()),
            app: job.app.clone(),
            user: c.user.as_ref().map(|(name, display)| agent::Account {
                id: String::new(),
                name: Some(name.clone()),
                display_name: Some(display.clone()),
            }),
            accounts,
            elsewhere: !existing,
            fingerprint: check.fprintd_verify.is_some() && !existing,
        };
        let cancelled = || crate::uhid::take_cancel(request::INTERNAL_CID);
        match agent::preapprove(bin, ask, DIALOG_TIMEOUT, cancelled) {
            agent::Pre::Approved(account) => {
                if let Some(id) = account {
                    c.restrict_to(id);
                    request::begin_internal(&c.command);
                }
                request::note_confirmed();
            }
            agent::Pre::Denied => return Err(Error::NotAllowed("The request was denied.".into())),
            agent::Pre::Elsewhere => return Err(Error::NoCredential),
            agent::Pre::Cancelled => return Err(Error::NotAllowed("The request was cancelled or timed out.".into())),
            // Without a working dialog, OpenSK's hooks fall back to pinentry.
            agent::Pre::Failed => {}
        }
    }

    let mut attempt = 1;
    loop {
        let reply = ctap.process_command(&c.command, Channel::MainHid(request::INTERNAL_CID));
        const UV_INVALID: u8 = 0x3F;
        // A finger that didn't match: try again in the same dialog.
        if reply.first() == Some(&UV_INVALID) && agent::is_preapproved() && attempt < FINGER_ATTEMPTS {
            attempt += 1;
            continue;
        }
        return match c.response(&reply) {
            Err(Error::NotAllowed(_)) if request::chose_elsewhere() => Err(Error::NoCredential),
            r => r,
        };
    }
}
