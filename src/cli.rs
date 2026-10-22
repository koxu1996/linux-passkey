//! Local credential management: `linux-passkey list` / `linux-passkey delete`.
//!
//! CTAP's own credential management (browser settings, `fido2-token -L`) needs
//! a pinUvAuthToken, i.e. a clientPIN, which this authenticator deliberately
//! does not have. These commands read the TPM-sealed store directly instead.
//! Only discoverable credentials (passkeys) are stored; non-discoverable ones
//! live wrapped inside the site's credential id and cannot be listed.

use crate::env::AppEnv;
use crate::uhid::UhidConnection;
use anyhow::{anyhow, bail, Result};
use opensk::ctap::data_formats::PublicKeyCredentialSource;
use opensk::ctap::storage;
use std::io::Write;
use std::path::PathBuf;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn open(data_dir: PathBuf, writer: bool) -> Result<AppEnv> {
    // No uhid device and no prompts: the Env is only used for its store.
    AppEnv::new(UhidConnection::detached(), String::new(), data_dir, writer)
}

fn credentials(env: &mut AppEnv) -> Result<Vec<PublicKeyCredentialSource>> {
    let mut result = Ok(());
    let mut creds: Vec<_> = storage::iter_credentials(env, &mut result)
        .map_err(|e| anyhow!("reading credentials: {e:?}"))?
        .map(|(_, c)| c)
        .collect();
    result.map_err(|e| anyhow!("reading credentials: {e:?}"))?;
    creds.sort_by_key(|c| c.creation_order);
    Ok(creds)
}

fn describe(c: &PublicKeyCredentialSource) -> String {
    let user = c
        .user_name
        .as_deref()
        .or(c.user_display_name.as_deref())
        .unwrap_or("-");
    format!(
        "{:<16}  #{:<4} {:<28} {}",
        &hex(&c.credential_id)[..16.min(c.credential_id.len() * 2)],
        c.creation_order,
        c.rp_id,
        user
    )
}

/// `list [--rp RP]`: print stored passkeys, oldest first.
pub fn list(data_dir: PathBuf, rp: Option<&str>) -> Result<()> {
    let mut env = open(data_dir, false)?;
    let creds: Vec<_> = credentials(&mut env)?
        .into_iter()
        .filter(|c| rp.is_none_or(|rp| c.rp_id == rp))
        .collect();
    println!("{:<16}  {:<5} {:<28} USER", "ID", "ORDER", "SITE");
    for c in &creds {
        println!("{}", describe(c));
    }
    let left = storage::remaining_credentials(&mut env).unwrap_or(0);
    println!("\n{} passkey(s) shown, {} free slot(s)", creds.len(), left);
    Ok(())
}

/// `delete [--yes] (ID-PREFIX... | --rp RP [--keep-newest])`.
pub fn delete(data_dir: PathBuf, args: &[String]) -> Result<()> {
    let mut yes = false;
    let mut rp = None;
    let mut keep_newest = false;
    let mut prefixes = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--yes" | "-y" => yes = true,
            "--rp" => rp = Some(it.next().ok_or_else(|| anyhow!("--rp needs a site"))?.clone()),
            "--keep-newest" => keep_newest = true,
            p if p.starts_with('-') => bail!("unknown option {p}"),
            p => {
                if p.len() < 4 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
                    bail!("'{p}' is not an id prefix (at least 4 hex chars, see `list`)");
                }
                prefixes.push(p.to_ascii_lowercase());
            }
        }
    }
    if rp.is_none() && prefixes.is_empty() {
        bail!("nothing selected: give id prefixes from `list`, or --rp SITE");
    }

    let mut env = open(data_dir, true)?;
    let all = credentials(&mut env)?;
    let mut chosen: Vec<_> = all
        .iter()
        .filter(|c| {
            let id = hex(&c.credential_id);
            rp.as_deref().is_some_and(|rp| c.rp_id == rp)
                || prefixes.iter().any(|p| id.starts_with(p.as_str()))
        })
        .collect();
    for p in &prefixes {
        let n = all.iter().filter(|c| hex(&c.credential_id).starts_with(p.as_str())).count();
        if n == 0 {
            bail!("no passkey with id prefix {p}");
        }
        if n > 1 {
            bail!("id prefix {p} is ambiguous ({n} matches); use more characters");
        }
    }
    if keep_newest {
        // `all` is sorted oldest first, so the last chosen one is the newest.
        chosen.pop();
    }
    if chosen.is_empty() {
        println!("nothing to delete");
        return Ok(());
    }

    println!("Deleting {} passkey(s):", chosen.len());
    for c in &chosen {
        println!("  {}", describe(c));
    }
    if !yes {
        print!("This cannot be undone. Continue? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            println!("aborted");
            return Ok(());
        }
    }
    let ids: Vec<Vec<u8>> = chosen.iter().map(|c| c.credential_id.clone()).collect();
    for id in ids {
        storage::delete_credential(&mut env, &id)
            .map_err(|e| anyhow!("deleting {}: {e:?}", hex(&id)))?;
    }
    println!("done. (The site may still list this key; remove it there too.)");
    Ok(())
}
