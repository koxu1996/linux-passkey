# linux-passkey

A **TPM 2.0-backed FIDO2/CTAP2 passkey authenticator for Linux**, in Rust.

It shows up in the browser as a normal USB security key, but the "key" is a
daemon: every passkey's private key is generated inside the machine's TPM and
can never leave it. One pinentry dialog per registration or sign-in replaces
the touch and the PIN.

Works today with **webauthn.io** and **Google** (passwordless sign-in), from
Brave/Chromium.

> **Renamed from `tpm2-passkey`** (more backends are coming: Apple Secure
> Enclave on Apple Silicon Linux is in progress). On first start the daemon
> copies an existing store from `~/.local/share/tpm2-passkey` to
> `~/.local/share/linux-passkey` and leaves the old copy in place;
> `TPM2_PASSKEY_*` variables and `services.tpm2-passkey` still work as aliases.
> On impermanence systems, persist the new directory **before** switching, or
> keep the old one persisted until the first start has copied it.

```
browser ──WebAuthn──▶ /dev/hidraw (virtual FIDO HID key, via /dev/uhid)
                              │ CTAPHID
                              ▼
                     linux-passkey daemon
              ┌───────────────┼─────────────────────────┐
              ▼               ▼                         ▼
       OpenSK CTAP2 core   TPM (tss-esapi)          pinentry-qt
       (patched, 3 tiny    P-256 keys created +     one Confirm dialog =
        patches)           signed in the TPM;       user presence + user
              │            store key TPM-sealed     verification
              ▼
   ~/.local/share/linux-passkey/  (AES-256-GCM store; key sealed to the TPM)
```

## Why

| Tool | What it does | Gap |
|---|---|---|
| `tpm-fido` | TPM-backed U2F | CTAP1/**U2F only**: no passkeys, sites say "your device can't be used" |
| `libwebauthn` / `credentialsd` | Linux platform-authenticator plumbing | TPM authenticator planned, not built |
| Password-manager passkeys (KeePassXC, …) | software passkeys | key is a file you can copy |
| **linux-passkey** | CTAP 2.1 passkeys, keys in the TPM | — |

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
nix build            # → ./result/bin/linux-passkey
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
LINUX_PASSKEY_PINENTRY=$(command -v pinentry-qt) ./result/bin/linux-passkey
```

| Variable | Default | |
|---|---|---|
| `LINUX_PASSKEY_PINENTRY` | `pinentry` | pinentry binary for the dialog (`pinentry-qt` works under Hyprland; `pinentry-gnome3` silently fails there) |
| `LINUX_PASSKEY_DATA_DIR` | `~/.local/share/linux-passkey` | credential store |
| `LINUX_PASSKEY_BACKEND` | `tpm` | hardware behind the keys and the store: `tpm`, or `sep` (Apple Secure Enclave, see below) |
| `LINUX_PASSKEY_SEP_DEVICE` | `/dev/sep-bio` | Secure Enclave device (`sep` backend) |
| `LINUX_PASSKEY_UV` | `pinentry` | how requests are approved: `pinentry` (the dialog), or `fprintd` (the dialog, then a fingerprint check) |
| `LINUX_PASSKEY_FPRINTD_VERIFY` | `fprintd-verify` | fprintd client used for the fingerprint check |
| `LINUX_PASSKEY_TCTI` | `device:/dev/tpmrm0` | TPM; use `swtpm:…` for a software TPM |
| `RUST_LOG` | `info` | `linux_passkey::request=debug` logs every request (op, site, user, UV) |

Requirements: a TPM 2.0 (Intel PTT / AMD fTPM enabled in firmware), access to
`/dev/tpmrm0` (`tss` group) and `/dev/uhid` (see the module's udev rule), and
the `uhid` kernel module.

### NixOS module

```nix
# flake.nix
inputs.linux-passkey.url = "github:koxu1996/linux-passkey";
inputs.linux-passkey.inputs.nixpkgs.follows = "nixpkgs";

# in your NixOS configuration
imports = [ linux-passkey.nixosModules.default ];
services.linux-passkey = { enable = true; user = "you"; };
```

This enables the TPM stack, loads `uhid`, adds the udev rule and the `tss`
group, and runs a `systemd --user` service bound to `graphical-session.target`.
It stays inert until `/dev/tpmrm0` exists.

> **Impermanence / ephemeral home:** persist the store directory, or every
> reboot wipes your passkeys:
> `users.<you>.directories = [ ".local/share/linux-passkey" ];`

> **Don't run `tpm-fido` alongside it.** The browser sends every request to
> every key, so you get two dialogs, and tpm-fido (U2F-only) is what triggers
> "your device can't be used with this site".

## Apple Silicon (Secure Enclave backend)

`LINUX_PASSKEY_BACKEND=sep` keeps the credential keys in the Mac's Secure
Enclave instead of a TPM: each passkey gets its own enclave key, created and
used inside the enclave; only the enclave-wrapped blob (258 bytes) is stored.
The store key is a kernel trusted key sealed by the enclave, and the store is
encrypted inside the kernel, so the AES key never enters the daemon.

Requires the aurora-silicon `apple_sep` driver (Touch ID working, xART writes
on, `trusted.source=applesep`) plus the `SEP_BIO_KEY_CREATE`/`SEP_BIO_KEY_SIGN`
ioctls, currently a patch on top of it:
[apple-sep-key-ioctls.patch](https://gitlab.com/andrzej1_1/nixos-config/-/blob/master/hosts/nixAir/touchid/apple-sep-key-ioctls.patch).
Tested on a MacBook Air M2 (J413) with webauthn.io. Only ES256, like the TPM
backend.

With `LINUX_PASSKEY_UV=fprintd` every registration and sign-in is the dialog
(site and account), then the fingerprint, matched inside the enclave by the
same Touch ID stack `sudo` uses. `/dev/sep-bio` admits one opener at a time and
fprintd needs it for the match, so the backend opens it only per operation.

## Managing passkeys

```sh
linux-passkey list                    # all passkeys, oldest first
linux-passkey list --rp webauthn.io
linux-passkey delete c99c38e8         # by id prefix from `list` (asks first)
linux-passkey delete --rp webauthn.io --keep-newest
linux-passkey delete --yes …          # no confirmation
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

Every credential is listed. Sites that ask for a non-discoverable credential
(e.g. 2-Step Verification keys, `pamu2fcfg` without `-r`) get a discoverable
one: OpenSK would wrap the key into the credential ID, but a TPM-wrapped key
doesn't fit its fixed size, so it's stored locally instead
(`opensk-resident-fallback.patch`; Windows Hello does the same).

## Limits

- The TPM itself is not a limit. No key is kept inside the TPM's NV memory;
  each key is loaded into a transient slot, used, and flushed.
- **300 passkeys**, OpenSK's whole `CREDENTIALS = 1700..2000` storage key range
  (its default is 150). More would need that range patched.
  For comparison, a YubiKey with firmware 5.7+ holds 100 (older ones 25).
- Registering the same account on the same site again **replaces** the old
  passkey.
- Non-discoverable requests count against the 300 too (see above).

## sudo / PAM

`pam_u2f` works with it: the Confirm dialog replaces the password for sudo,
su or polkit (`sufficient`, before `pam_unix`, so Deny falls back to the
password). Register with `pamu2fcfg -r -u $USER -o pam://$HOST -i pam://$HOST`
and put the line in a root-owned authfile. Screen unlock and login can't use
it: the daemon lives in the graphical session, and a locked session can't show
the dialog.

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
- **Not hardware-attested.** Attestation is `none`. The AAGUID
  `4790688c-5823-40b0-902a-2724c6d7bbad` names linux-passkey (registrations
  from before v0.1.0 carry all zeros), but it's self-asserted: sites can't
  tell this from a software passkey, and sites that require
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
| `opensk-resident-fallback.patch` | Store a non-discoverable credential as discoverable when the wrapped key doesn't fit in the fixed-size credential ID (instead of `VENDOR_INTERNAL_ERROR`). |
| `opensk-uv-on-register.patch` | `makeCredUvNotRqd: false` when built-in UV is enrolled, so registrations carry the UV flag (Google: real passkey, not 2SV). |

## Code map

| File | |
|---|---|
| `src/main.rs` | CLI dispatch; daemon loop: HID report → request peek → `Ctap::process_hid_packet` → send |
| `src/uhid.rs` | virtual FIDO HID device (usage page `0xF1D0`) over `/dev/uhid` |
| `src/env.rs` | OpenSK `Env`: wires TPM crypto, store, prompts, clock, RNG |
| `src/backend.rs` | `Backend` trait (credential keys + store cipher), process-global; shared conformance test |
| `src/crypto.rs` | OpenSK `Ecdsa` over the backend's wrapped key material |
| `src/tpm.rs` | TPM backend: TPM2 Create/Load/Sign; store key sealed to the TPM |
| `src/sep.rs` | Secure Enclave backend: enclave key create/sign ioctls; store key is an enclave-sealed kernel trusted key, AES-GCM in the kernel (AF_ALG) |
| `src/store.rs` | AES-256-GCM file store, TPM-sealed key, writer lock |
| `src/presence.rs` | user presence = pinentry Confirm |
| `src/fingerprint.rs` | built-in UV = the approval (one enrolled "template") |
| `src/fprintd.rs` | fingerprint check via `fprintd-verify` (`LINUX_PASSKEY_UV=fprintd`) |
| `src/request.rs` | CTAPHID reassembly + CBOR peek: dialog wording, duplicate detection |
| `src/cli.rs` | `list` / `delete` |
| `nix/module.nix` | `services.linux-passkey` |
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
| No dialog appears | wrong `LINUX_PASSKEY_PINENTRY`, or no `WAYLAND_DISPLAY`/`DISPLAY` in the daemon's environment |

Inspect what the key advertises:

```sh
nix shell nixpkgs#libfido2 -c fido2-token -I /dev/hidrawN   # N: grep linux-passkey /sys/class/hidraw/*/device/uevent
# expect: FIDO_2_1 … options: rk, up, uv, noclientPin, nopinUvAuthToken, nomakeCredUvNotRqd
```

## Development

Use a software TPM (`swtpm`) so the real one is never touched. `nix develop`
provides Rust, tpm2-tss, swtpm and tpm2-tools; then set
`LINUX_PASSKEY_TCTI=swtpm:…` and a scratch `LINUX_PASSKEY_DATA_DIR`.

`cargo test` covers request parsing: multi-packet reassembly, excludeList/UV
parsing, dialog wording, and text cleaning. The backend conformance test (keys
differ, signatures verify with their own key only) needs real hardware, so it is
opt-in; against swtpm:

```sh
swtpm socket --tpm2 --tpmstate dir=/tmp/swtpm --server type=tcp,port=2321 \
  --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --daemon
LINUX_PASSKEY_TEST_TCTI=swtpm:host=localhost,port=2321 cargo test
```

On an Apple Silicon Mac with the Secure Enclave key ioctls (see below):
`LINUX_PASSKEY_TEST_SEP=/dev/sep-bio cargo test sep_backend_conformance`
(as a user with access to the device).

## License

Apache-2.0 (same as OpenSK).
