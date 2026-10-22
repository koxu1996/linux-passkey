# tpm2-passkey

A **TPM 2.0-backed FIDO2/CTAP2 passkey authenticator for Linux**, in Rust.

It shows up in the browser as a normal USB security key, but the "key" is a
daemon: every passkey's private key is generated inside the machine's TPM and
can never leave it. One pinentry dialog per registration or sign-in replaces
the touch and the PIN.

Works today with **webauthn.io** and **Google** (passwordless sign-in), from
Brave/Chromium.

```
browser ──WebAuthn──▶ /dev/hidraw (virtual FIDO HID key, via /dev/uhid)
                              │ CTAPHID
                              ▼
                     tpm2-passkey daemon
              ┌───────────────┼─────────────────────────┐
              ▼               ▼                         ▼
       OpenSK CTAP2 core   TPM (tss-esapi)          pinentry-qt
       (patched, 3 tiny    P-256 keys created +     one Confirm dialog =
        patches)           signed in the TPM;       user presence + user
              │            store key TPM-sealed     verification
              ▼
   ~/.local/share/tpm2-passkey/  (AES-256-GCM store; key sealed to the TPM)
```

## Why

| Tool | What it does | Gap |
|---|---|---|
| `tpm-fido` | TPM-backed U2F | CTAP1/**U2F only**: no passkeys, sites say "your device can't be used" |
| `libwebauthn` / `credentialsd` | Linux platform-authenticator plumbing | TPM authenticator planned, not built |
| Password-manager passkeys (KeePassXC, …) | software passkeys | key is a file you can copy |
| **tpm2-passkey** | CTAP 2.1 passkeys, keys in the TPM | — |

## Features

- **CTAP 2.1** (`FIDO_2_0`, `FIDO_2_1`, `U2F_V2`), ES256, discoverable
  credentials (passkeys), credProtect, hmac-secret, largeBlobs.
- **Keys in the TPM.** Each credential gets its own P-256 key, created by the
  TPM under a primary key (`fixed_tpm`, `fixed_parent`,
  `sensitive_data_origin`). We only ever hold the TPM-encrypted blob; signing
  happens inside the TPM. Copying the files to another machine gets you
  nothing.
- **No PIN, one dialog.** User verification is OpenSK's built-in-UV
  ("fingerprint") path, backed by a pinentry Confirm. A performed UV also
  counts as user presence, so every operation is exactly **one** click.
- **The dialog says what is happening and for whom:**
  - *Register*: "Create a passkey for google.com as "you@gmail.com"?" `[Register]`
  - *Sign in*: "Sign in to webauthn.io with your passkey?" `[Sign in]`
  - *Already registered*: "webauthn.io already has a passkey from this device …"
  - *Reset*: an explicit "deletes ALL passkeys" warning.

  Site-supplied text is stripped of control characters and `<>&` and capped at
  64 characters.
- **UV on registration**, so the UV flag is set and sites treat it as a real
  passkey, not a second factor (see [Google](#google)).
- **Duplicate detection.** When a site already has this authenticator (its
  `excludeList` contains one of our credentials), you get one honest
  "already registered" dialog instead of one or two "Create a passkey" ones.
- **Local management** with `list` / `delete` (CTAP credential management
  needs a PIN, which we don't have).
- **Encrypted, TPM-sealed store.** The credential database is AES-256-GCM
  encrypted; the AES key is sealed to the TPM.

## Build and run

Nix (recommended; fetches and patches OpenSK itself):

```sh
nix build            # → ./result/bin/tpm2-passkey
```

Cargo, for development: needs `../OpenSK` next to this repo (Google's OpenSK at
`a93efdb2a94a01607a8df2813fe06c3f6fb58292`, with `patches/*.patch` applied).
Then:

```sh
nix develop -c cargo build --release
nix develop -c cargo test
```

Run in your graphical session (the dialog needs the display):

```sh
TPM2_PASSKEY_PINENTRY=$(command -v pinentry-qt) ./result/bin/tpm2-passkey
```

| Variable | Default | |
|---|---|---|
| `TPM2_PASSKEY_PINENTRY` | `pinentry` | pinentry binary for the dialog (`pinentry-qt` works under Hyprland; `pinentry-gnome3` silently fails there) |
| `TPM2_PASSKEY_DATA_DIR` | `~/.local/share/tpm2-passkey` | credential store |
| `TPM2_PASSKEY_TCTI` | `device:/dev/tpmrm0` | TPM; use `swtpm:…` for a software TPM |
| `RUST_LOG` | `info` | `tpm2_passkey::request=debug` logs every request (op, site, user, UV) |

Requirements: a TPM 2.0 (Intel PTT / AMD fTPM enabled in firmware), access to
`/dev/tpmrm0` (`tss` group) and `/dev/uhid` (see the module's udev rule), and
the `uhid` kernel module.

### NixOS module

```nix
# flake input:  tpm2-passkey.url = "path:/home/you/…/tpm2-passkey";
imports = [ tpm2-passkey.nixosModules.default ];
services.tpm2-passkey = { enable = true; user = "andrew"; };
```

This enables the TPM stack, loads `uhid`, adds the udev rule and the `tss`
group, and runs a `systemd --user` service bound to `graphical-session.target`.
It stays inert until `/dev/tpmrm0` exists.

> **Impermanence / ephemeral home:** persist the store directory, or every
> reboot wipes your passkeys:
> `users.<you>.directories = [ ".local/share/tpm2-passkey" ];`

> **Don't run `tpm-fido` alongside it.** The browser sends every request to
> every key, so you get two dialogs, and tpm-fido (U2F-only) is what triggers
> "your device can't be used with this site".

## Managing passkeys

```sh
tpm2-passkey list                    # all passkeys, oldest first
tpm2-passkey list --rp webauthn.io
tpm2-passkey delete c99c38e8         # by id prefix from `list` (asks first)
tpm2-passkey delete --rp webauthn.io --keep-newest
tpm2-passkey delete --yes …          # no confirmation
```

```
ID                ORDER SITE                         USER
c99c38e89f37a57b  #4    webauthn.io                  test22oct2026
98990478c10f7ead  #5    google.com                   you@gmail.com

2 passkey(s) shown, 148 free slot(s)
```

`list` is read-only and works while the daemon runs. `delete` needs the daemon
**stopped**: the store holds an exclusive lock, because the daemon keeps it in
memory and would overwrite the change. Deleting here doesn't tell the site;
remove the key in the site's settings too.

Only discoverable credentials are listed. Non-discoverable ones (e.g. Google
"2-Step Verification" keys) are stored wrapped inside the site's credential ID,
so there's nothing local to list.

## Limits

- The TPM itself is not a limit. No key is kept inside the TPM's NV memory;
  each key is loaded into a transient slot, used, and flushed.
- **150 passkeys** (OpenSK `DEFAULT_CUSTOMIZATION.max_supported_resident_keys`).
  Raising it to 300 is a one-line customization change; above 300 needs
  OpenSK's storage key ranges (`CREDENTIALS = 1700..2000`) patched.
  For comparison, a YubiKey with firmware 5.7+ holds 100 (older ones 25).
- Registering the same account on the same site again **replaces** the old
  passkey.
- Non-discoverable credentials: unlimited.

## Google

Google needs two extra steps on Linux:

1. **"A passkey can't be created on this device."** Google's page asks the
   browser whether a built-in (platform) authenticator exists. On Linux the
   answer is always no, so the page refuses to start. The **"create a passkey
   on another device"** link is a trap: it enrolls a *2-Step Verification
   security key* (no UV), which later fails with *"Your key requires a password
   to sign in"*.

   → Load [`browser/passkey-platform-shim`](browser/passkey-platform-shim) (an
   unpacked extension, `*.google.com` only). It answers "yes" to that check and
   strips platform-only constraints from `navigator.credentials.create()`, so
   Brave offers the USB key. It is needed **only for creating** the passkey;
   sign-in works without it.

2. **UV on registration.** Credentials registered without the UV flag are filed
   as 2SV-only keys. OpenSK used to advertise `makeCredUvNotRqd: true`, which
   lets browsers skip UV whenever a site only *prefers* it.
   `patches/opensk-uv-on-register.patch` fixes that, so it is handled.

Steps: load the shim → `g.co/passkeys` → **Create a passkey** (not "another
device") → *USB security key* → confirm the dialog. Sign out, then sign in with
the passkey: no password.

If you already enrolled this key as a 2SV security key, delete that entry under
*2-Step Verification → Security keys* first. Google lists it in the
`excludeList`, so the new registration would be stopped as "already
registered".

## Security model

- **Not extractable.** Private keys exist in plaintext only inside the TPM.
  The disk holds TPM-wrapped blobs that only this TPM can load.
- **Bound to this TPM.** Clearing the TPM (firmware reset, some BIOS updates,
  `tpm2_clear`) destroys every passkey, permanently. Register a second
  authenticator or recovery method on important accounts.
- **Not hardware-attested.** Attestation is `none` and the AAGUID is all zeros.
  Sites can't tell this from a software passkey, and sites that require
  attested hardware keys (some enterprise policies) won't accept it.
- **The dialog is the gesture.** Anything that can click your pinentry, or run
  as your user and talk to `/dev/tpmrm0` and the store, can use the passkeys.
  This is the same trust boundary as `gpg-agent`. There is no separate PIN;
  OS login is the user verification.
- **Roaming, not platform.** Browsers see a USB security key, which is why
  Google needs the shim. Hybrid/phone flows are unaffected.
- **Anti-probing kept.** Duplicate detection still requires your confirm
  before telling a site "already registered".

## OpenSK patches

Applied by the flake (`patches/`) on top of OpenSK `a93efdb`:

| Patch | Why |
|---|---|
| `opensk-pinuvauthtoken.patch` | Advertise `pinUvAuthToken` only when a clientPIN is set. Otherwise browsers take the token path, which OpenSK only allows with a PIN (`PIN_NOT_SET`, "operation timed out"). |
| `opensk-pub-storage.patch` | `mod storage` → `pub mod storage`, for duplicate detection and `list`/`delete`. |
| `opensk-uv-on-register.patch` | `makeCredUvNotRqd: false` when built-in UV is enrolled, so registrations carry the UV flag (Google: real passkey, not 2SV). |

## Code map

| File | |
|---|---|
| `src/main.rs` | CLI dispatch; daemon loop: HID report → request peek → `Ctap::process_hid_packet` → send |
| `src/uhid.rs` | virtual FIDO HID device (usage page `0xF1D0`) over `/dev/uhid` |
| `src/env.rs` | OpenSK `Env`: wires TPM crypto, store, prompts, clock, RNG |
| `src/crypto.rs`, `src/tpm.rs` | OpenSK `Ecdsa` backed by TPM2 Create/Load/Sign; seal/unseal |
| `src/store.rs` | AES-256-GCM file store, TPM-sealed key, writer lock |
| `src/presence.rs` | user presence = pinentry Confirm |
| `src/fingerprint.rs` | built-in UV = pinentry Confirm (one enrolled "template") |
| `src/request.rs` | CTAPHID reassembly + CBOR peek: dialog wording, duplicate detection |
| `src/cli.rs` | `list` / `delete` |
| `nix/module.nix` | `services.tpm2-passkey` |
| `browser/passkey-platform-shim/` | Google passkey-creation shim (extension) |

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Two dialogs, one says "FIDO Confirm Register" | `tpm-fido` is running too: `systemctl --user stop tpm-fido`, remove it from your config |
| "Your device can't be used with this site" | a U2F-only key answered (tpm-fido), or the site needs something not advertised; check `brave://device-log` |
| Google: "A passkey can't be created on this device" | expected on Linux; use the [shim](#google) |
| Google: "Your key requires a password … 2-Step Verification only" | enrolled via "another device", or before the UV patch; delete it in 2SV settings and re-create via the shim |
| "store … is in use" | daemon running; stop it for `delete`, or don't start a second daemon |
| Passkeys gone after reboot | store dir not persisted (impermanence) |
| No dialog appears | wrong `TPM2_PASSKEY_PINENTRY`, or no `WAYLAND_DISPLAY`/`DISPLAY` in the daemon's environment |

Inspect what the key advertises:

```sh
nix shell nixpkgs#libfido2 -c fido2-token -I /dev/hidrawN   # N: grep tpm2-passkey /sys/class/hidraw/*/device/uevent
# expect: FIDO_2_1 … options: rk, up, uv, noclientPin, nopinUvAuthToken, nomakeCredUvNotRqd
```

## Development

Use a software TPM (`swtpm`) so the real one is never touched. `nix develop`
provides Rust, tpm2-tss, swtpm and tpm2-tools; then set
`TPM2_PASSKEY_TCTI=swtpm:…` and a scratch `TPM2_PASSKEY_DATA_DIR`.

`cargo test` covers request parsing: multi-packet reassembly, excludeList/UV
parsing, dialog wording, and text cleaning.

## License

Apache-2.0 (same as OpenSK).
