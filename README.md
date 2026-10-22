# tpm2-passkey

A **TPM 2.0-backed FIDO2/CTAP2 authenticator for Linux**, in Rust.

The goal: real **passkeys** (discoverable FIDO2 credentials, with user
verification) whose private keys are sealed in the machine's TPM — usable in the
browser today via a virtual USB-HID device, and later as a factor for OS/PAM
login. This is the thing that existing tools can't do yet:

- `tpm-fido` → CTAP1/**U2F only** (no passkeys / discoverable creds).
- `libwebauthn`/`credentialsd` → TPM platform authenticator **planned, unbuilt**.

## Status: WIP / MVP in progress

Architecture and base crate are being finalized from research (OpenSK CTAP2 core
vs. `passkey-authenticator`/`fido-authenticator`, + `tss-esapi` for the TPM, +
`uhid` for the CTAPHID transport). See `docs/` once populated.

## Design (target)

```
browser ──WebAuthn──> CTAPHID over /dev/uhid ──> CTAP2 state machine
                                                      │
                                   ┌──────────────────┼───────────────────┐
                                   ▼                   ▼                   ▼
                          TPM crypto (tss-esapi)   discoverable-cred    user verification
                          P-256 keygen/sign        store (sealed blob)  (local PIN / prompt)
```

- **Keys**: per-credential P-256 keys created under a TPM primary, TPM-wrapped.
- **Discoverable creds**: metadata (rpId, userHandle, wrapped key) in an
  encrypted blob **sealed to the TPM** on disk — survives impermanence (nothing
  in plaintext, nothing that must be persisted beyond the sealed blob).
- **Attestation**: `none` for the MVP (browsers/webauthn.io accept it).
- **Transport**: emulate a FIDO HID device via `/dev/uhid` (usage page 0xF1D0),
  so browsers see a normal roaming security key — no browser/portal support
  needed.

## Dev

Develop against a **software TPM** (`swtpm`) so the real PTT is never touched:

```sh
nix develop            # Rust + tpm2-tss + swtpm + tpm2-tools
# then follow the swtpm snippet printed by the shell hook
```

MVP acceptance: register + authenticate **one discoverable passkey on
webauthn.io** from Brave, keys living in the (simulated, then real) TPM.
