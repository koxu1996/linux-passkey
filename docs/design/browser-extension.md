# Design: linux-passkey as a platform authenticator in the browser

Status: Phase 1 implemented 2026-11-11 (D-Bus gateway, native host, extension; tested on webauthn.io and Google in Brave 155 and LibreWolf 158). Phase 2 implemented 2026-11-11 (approval agent, GTK4 dialog).

## Problem

Browsers see linux-passkey as a USB security key (`/dev/uhid`, CTAP2 over
CTAPHID). That works, but it is the wrong shape for a built-in authenticator:

- **Sites think there is no passkey on this device.**
  `isUserVerifyingPlatformAuthenticatorAvailable()` is always false on Linux.
  Google refuses to start (hence `browser/passkey-platform-shim`), others
  hide their "Create a passkey" button or offer only "use another device".
- **The browser's USB flow gets in the way.** We see an "insert your security
  key" sheet, then our own dialog. The browser can fetch a pinUvAuthToken
  before we see the account, unless we hide it
  (`opensk-pinuvauthtoken.patch`, not spec compliant).
- **The browser's CTAP encoder is in the path.** Bug
  [2090860](https://bugzilla.mozilla.org/show_bug.cgi?id=2090860) (Firefox
  encoded getAssertion options non-canonically) broke every Firefox sign-in.
- **No passkey autofill.** `mediation: "conditional"` lists only platform
  and synced credentials, never a USB key.
- **The credential is reported as roaming.** Sites store
  `transports: ["usb"]` and `authenticatorAttachment: "cross-platform"`. That
  is wrong for a key that lives in this machine's TPM or Secure Enclave.

Windows and macOS solve this by putting the authenticator behind an OS API
(`webauthn.dll`, `ASAuthorization`) that the browser calls with the full
WebAuthn request. Linux has no such API yet.

## Goal

Make linux-passkey a platform authenticator in Firefox/LibreWolf and
Chromium/Brave **without patching the browser**, and shape it so that a later
browser patch (or a standard xdg portal) needs no daemon change.

In scope:
- `navigator.credentials.create/get` for `publicKey`, routed to the daemon
  with the full request.
- Correct platform answers: `isUserVerifyingPlatformAuthenticatorAvailable`,
  `getClientCapabilities`, `authenticatorAttachment: "platform"`,
  `transports: ["internal"]`.
- Fall back to the browser's own WebAuthn (USB keys, phone/hybrid) when our
  authenticator can't or shouldn't answer.
- One store: a passkey created over USB is usable through the extension, and
  the reverse.

Out of scope:
- Removing the USB front-end. `pam_u2f` (sudo), `ssh -sk` keys, pkee and
  browsers without the extension keep using `/dev/uhid`.
- Synced passkeys (BE/BS stay 0: device-bound).
- Attestation (stays `none`).
- Phase 1 leaves out passkey autofill (`conditional`); see Phase 3.

## Prior art

- **credentialsd** ([linux-credentials/credentialsd](https://github.com/linux-credentials/credentialsd)):
  a D-Bus service and proposed xdg portal for WebAuthn on Linux. It ships the
  same front-end shape: an MV3 extension overrides `navigator.credentials`,
  a native messaging host (`xyz.iinuwa.credentialsd_helper`) forwards to the
  D-Bus "Gateway" (`CreateCredential` / `GetCredential`). An experimental
  Firefox build calls it directly. Today it only talks to USB and hybrid
  authenticators. A provider interface for third-party authenticators is a
  stated goal but not defined yet. Its API is pre-1.0 (0.1.0, Aug 2025).
- **Password managers** (Bitwarden, 1Password, KeePassXC-Browser): extensions
  that replace `navigator.credentials` and return their own
  `PublicKeyCredential`-like objects. The page-side technique is proven at
  scale.

**Decision:** speak credentialsd's Gateway shape on our D-Bus API (origin as
an argument, `top_origin` option, WebAuthn options and responses as the
standard JSON serialization). Then:
1. our extension and native host are small and could be shared,
2. linux-passkey can become a credentialsd *provider* once that interface
   exists, and we can help define it from a working implementation,
3. a browser patch targeting the portal reaches us with no change here.

## Architecture

```
 page JS
   │  navigator.credentials.create/get           (wrapped)
 ┌─▼──────────────────────────┐
 │ content script, MAIN world │  inject.js: wraps the API, builds
 └─▲──────────────────────────┘  PublicKeyCredential-shaped results
   │  window.postMessage (same frame)
 ┌─▼──────────────────────────┐
 │ content script, ISOLATED   │  relay.js: forwards, adds nothing
 └─▲──────────────────────────┘
   │  runtime.sendMessage
 ┌─▼──────────────────────────┐
 │ background (service worker)│  takes origin + frame from `sender`
 └─▲──────────────────────────┘  (browser-supplied, not page-supplied)
   │  native messaging (JSON over stdio, length-prefixed)
 ┌─▼──────────────────────────┐
 │ linux-passkey native-host  │  same binary, `native-host` subcommand;
 └─▲──────────────────────────┘  started by the browser per connection
   │  D-Bus, session bus
 ┌─▼──────────────────────────────────────────────┐
 │ linux-passkey daemon (one process, one Ctap)   │◄── /dev/uhid (USB front-end,
 │ dialog · fprintd · store · TPM / SEP backend   │     unchanged)
 └────────────────────────────────────────────────┘
```

The daemon stays the single owner of the store (writer lock), the OpenSK
state and the dialog. The native host is a stateless translator. It exists
because browsers can only start a native messaging process, not call D-Bus.

### Components

| Component | Where | Job |
|---|---|---|
| `inject.js` | `browser/platform-extension/`, MAIN world, `document_start`, `all_frames` | Wrap `navigator.credentials.create/get` and the `PublicKeyCredential` statics; serialize options with `toJSON` semantics; rebuild results; fall back to the originals |
| `relay.js` | ISOLATED world | Accept messages only from `event.source === window`, forward to background, return the reply. Holds no logic, so the page can't reach extension APIs through it |
| `background.js` | service worker / event page | Take `origin`, `frameId` and top-level origin from `runtime.MessageSender`; keep one native port; map aborts to `Cancel` |
| `native-host` | `src/native_host.rs` | Native messaging framing ↔ D-Bus calls |
| D-Bus service | `src/dbus.rs` in the daemon | Validate, build `clientDataJSON`, run the ceremony on the shared `Ctap`, return JSON |

The existing `passkey-platform-shim` becomes unnecessary once the extension
answers the availability checks itself. Keep it until the extension ships.

## D-Bus API (daemon)

Bus name `io.github.koxu1996.LinuxPasskey`, object `/io/github/koxu1996/LinuxPasskey`,
interface `io.github.koxu1996.LinuxPasskey.Gateway1`. We use our own
name because credentialsd's API is still changing. Arguments and fields
follow its Gateway, so moving to the portal later is a rename:

```
CreateCredential(IN  s parent_window,   # "wayland:<handle>" | "x11:<xid>" | ""
                 IN  s origin,          # "https://login.example.com"
                 IN  s type,            # "publicKey"
                 IN  a{sv} options,     # top_origin: s, public_key: s (JSON),
                                        # request_id: u, activation_token: s
                 OUT a{sv} response)    # type: s, registration_response_json: s

GetCredential   (IN  s parent_window,
                 IN  s origin,
                 IN  a{sv} options,     # same keys, public_key = request JSON
                 OUT a{sv} response)    # type: s, authentication_response_json: s

GetClientCapabilities(OUT a{sb})         # WebAuthn L3 capability names

Cancel(IN u request_id)
```

- `public_key` is `PublicKeyCredentialCreationOptionsJSON` /
  `PublicKeyCredentialRequestOptionsJSON` (WebAuthn L3: camelCase,
  base64url without padding). Responses are `RegistrationResponseJSON` /
  `AuthenticationResponseJSON`. Pages can parse them with
  `PublicKeyCredential.parseCreationOptionsFromJSON` and its siblings.
- Errors are D-Bus errors named after DOMException:
  `…Error.NotAllowed` (denied, timeout, cancel),
  `…Error.InvalidState` (excluded credential: already registered),
  `…Error.Security` (bad origin/rpId), `…Error.NotSupported`,
  `…Error.Abort`.
  `…Error.NoCredential` is ours: no credential for this request. The extension
  turns it into a fallback to the browser, never into a page-visible error.
- One ceremony at a time across D-Bus and USB. A second request waits until
  the first finishes, or fails at once with `NotAllowed` if a dialog is
  already open. It never opens two dialogs.

### Who builds clientDataJSON

The daemon builds it, from `type`, `challenge`, `origin`, `crossOrigin`
(`top_origin` set) and `topOrigin`. Then it hashes it and passes the hash to
OpenSK. It returns the JSON inside the response.

Why the daemon: it keeps the origin check and the signed origin in one place.
That matches the portal model, where the portal (not the app) is trusted with
the origin. A caller that supplied a ready hash could sign anything. If a
browser integration later wants to build clientData itself (like CTAP does),
add a `client_data_hash` option for privileged callers only.

### Origin and rpId checks (daemon)

- `origin` must be `https://`, or `http://localhost` (WebAuthn allows it).
- `rp.id` (create), or `rpId` (get, default: origin host), must equal the
  origin's host or be a registrable suffix of it. Use the Public Suffix List
  (the `psl` crate, pinned in the Nix build). `rp.id = "com"` is a
  `Security` error.
- `top_origin` set: the request is cross-origin. The extension sends it only
  for iframes that the page allowed (see below).
- Related origins (`/.well-known/webauthn`) are a later phase: answer
  `Security` until then.

## Extension details

### Wrapping the page API

```js
const native = { create: navigator.credentials.create.bind(navigator.credentials),
                 get: navigator.credentials.get.bind(navigator.credentials) };
navigator.credentials.create = async (opts) =>
  opts?.publicKey ? ours("create", opts).catch(fallbackTo(native.create, opts))
                  : native.create(opts);
```

- Only `publicKey` requests are ours. Password and federated credentials go to
  the original API.
- `opts.signal`: on abort, send `Cancel(request_id)` and reject with the
  signal's reason. Reject at once if the signal is already aborted.
- Timeouts are left to the daemon. OpenSK's 30 s covers the dialog and the
  finger; see `TODO-from-pkee.md`.
- `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable` returns
  true only while the native host answers a ping. With no daemon running it
  stays false, so sites don't offer a dead option.
- `getClientCapabilities`: merge the browser's answer with ours:
  `userVerifyingPlatformAuthenticator`, `passkeyPlatformAuthenticator`, and
  `conditionalGet` only once Phase 3 lands.

### Returning credentials

A real `PublicKeyCredential` can't be constructed from script. Build an object
with `PublicKeyCredential.prototype` and `AuthenticatorAttestationResponse.prototype`
(or `AuthenticatorAssertionResponse.prototype`) as prototypes, and give it
*own* properties that shadow the prototype getters. The getters themselves
would throw "illegal invocation" on our object. Provide:
`id`, `rawId`, `type`, `authenticatorAttachment: "platform"`,
`response.{clientDataJSON, attestationObject | authenticatorData, signature,
userHandle}`, `getTransports() → ["internal"]`, `getAuthenticatorData()`,
`getPublicKey()`, `getPublicKeyAlgorithm()`, `getClientExtensionResults()`,
`toJSON()`. `instanceof PublicKeyCredential` then holds. Bitwarden ships the
same approach.

ArrayBuffers are created in the page's realm (decode base64url inside
`inject.js`), so `instanceof ArrayBuffer` holds in the page.

### When to fall back to the browser

The extension prefers us, but must not hide other authenticators:

| Request | Behaviour |
|---|---|
| `create`, `hints` contains `security-key` or `hybrid` only, or `authenticatorAttachment: "cross-platform"` | browser |
| `create`, otherwise | us. The dialog has a **"Use another device"** button → `NoCredential` → browser |
| `get` with `allowCredentials`, none of them ours | browser, without a dialog. The daemon checks credential IDs against the store silently, before any prompt (no user-visible probing) |
| `get` with `allowCredentials` that include ours | us, same "Use another device" button |
| `get` without `allowCredentials` (discoverable) | us if we have one for the rpId, else browser |
| daemon not reachable | browser |

**Probing:** "is any of these IDs ours?" answered without a gesture is a
privacy leak only if the page can see the answer. It can't tell a silent
fallback from us apart from timing, and USB security keys leak the same thing
in CTAP2.1 preflight (`up=false`). Accepted for Phase 1.

### Frames

- Content scripts run in all frames. For a frame that isn't top-level, the
  background sets `top_origin` from the tab's top frame. The extension accepts
  the request only if the frame is same-origin with the top, or the page
  allowed it with `allow="publickey-credentials-create|get"`. Check this
  in-frame with `document.featurePolicy?.allowsFeature(...)` (Chromium), or
  read the frame element's `allow` from the parent (Firefox). If we can't tell,
  fall back to the browser, which enforces the policy itself.
- `sandbox`ed frames with opaque origins: always the browser.

### User activation

WebAuthn requires transient activation for `create` in cross-origin iframes,
and browsers rate-limit dialogs. Read `navigator.userActivation.isActive` from
the original getter, captured at `document_start`. Without activation, fall
back to the browser and let it decide. The daemon's one-ceremony-at-a-time rule
caps dialog spam.

### Packaging

| Browser | Extension | Native host manifest |
|---|---|---|
| LibreWolf / Firefox | MV3, `browser_specific_settings.gecko.id = "linux-passkey@koxu1996"`, unsigned is fine on LibreWolf; Firefox needs AMO (unlisted) signing | `programs.librewolf.nativeMessagingHosts` (home-manager re-links it on every activation, so the boot wipe of `~/.librewolf` is fine), or system-wide `/usr/lib/mozilla/native-messaging-hosts/` |
| Brave / Chromium | MV3 with a fixed `key` so the extension ID is stable; force-install by policy (`ExtensionInstallForcelist`), or load unpacked | `/etc/chromium/native-messaging-hosts/` and `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts/`, `allowed_origins: ["chrome-extension://<id>/"]` |

Needs MV3 `content_scripts[].world = "MAIN"`: Chromium 111+, Firefox 128+.
The package ships both host manifests (`lib/mozilla/native-messaging-hosts`,
`etc/chromium/native-messaging-hosts`) and `.#browser-extension` builds one
manifest per browser; home-manager wires them in (README, "Browser
extension").

## Daemon internals

Reuse OpenSK instead of reimplementing WebAuthn. The D-Bus handler turns the
JSON request into a CTAP2 `authenticatorMakeCredential` / `GetAssertion`
CBOR message, encoded by us (canonical, `uv: true`, `up: true`). It feeds the
message to the same `Ctap` instance through an in-process channel, not HID.
Then:

- one code path for keys, store, UV retries and `PIN_BLOCKED`,
- credentials stay interchangeable between both front-ends,
- the dialog gets its context directly (`request::Request` set from the parsed
  JSON, no CTAPHID peek), including `user.displayName`, the exclude match, and
  the requesting browser (from `parent_window` / the host's parent PID).

The daemon then turns the CTAP response into WebAuthn JSON. It builds the
attestationObject (`fmt: "none"`) and fills `authenticatorAttachment` and
transports.

Concurrency: today the HID loop owns `Ctap`. Move it to a ceremony thread that
takes requests from a queue (HID messages and D-Bus calls). The HID side keeps
its keepalive and cancel semantics. A D-Bus `Cancel` maps to the same `Abort`
that `presence.rs` already uses.

Several credentials for one rpId (discoverable get): the dialog is an account
picker (Phase 2). It runs before OpenSK, on the store's list of our passkeys
for the rp id; the chosen one becomes the only allowList entry. OpenSK still
returns the user handle for it, so usernameless sign-in keeps working.

### Approval agent (Phase 2)

The dialog is an *agent*, in the polkit sense: a separate program that only
draws and reports the answer, so desktops (or a shell like Quickshell) can
bring their own. The daemon starts one per request (`LINUX_PASSKEY_DIALOG`)
and speaks JSON lines over its stdin/stdout (`src/agent.rs`): an `ask` with
the operation, rp id, origin, requesting app, accounts and whether the finger
follows; the answer `approve` (with the chosen account), `deny` or
`elsewhere`; then `fingerprint` states and `done`. During the finger, a
`deny` from the agent stops fprintd.

For extension requests the agent runs before OpenSK (`preapprove`, 60 s,
cancellable over D-Bus) and the session stays open; OpenSK's UV hook then
only runs the finger in it. A finger that doesn't match is retried in the same
dialog (3 attempts, each one an OpenSK UV failure). USB requests run the agent
from the hook as before. pinentry stays as the fallback.

The requesting app is looked up by the daemon: the D-Bus caller's pid is the
native host, its parent the browser, named by its executable. Display only.

A desktop-provided agent registering itself over D-Bus (polkit's
`RegisterAuthenticationAgent`) would carry the same messages; not built.

Once this path is the browser default, `opensk-pinuvauthtoken.patch` stops
mattering to browsers. Keep it for CTAP clients that still want the full
request in the dialog.

## Security

- **Origin trust.** The daemon believes the `origin` its caller passes. With
  the extension, the browser supplies it (`MessageSender.origin`), so a page
  can't lie about it. But any process running as the user can call the D-Bus
  method with any origin. **This is no worse than today**: any such process
  can already open our hidraw node and ask for an assertion with any rpId hash.
  It is the same boundary as `gpg-agent`, and every request still needs the
  dialog (and the finger on nixAir). The fix is caller identity, which is a
  portal problem: see below.
- **Native host allow-list.** Chromium enforces `allowed_origins`, Firefox
  `allowed_extensions`. Only our extension can start the host.
- **Page isolation.** All decisions happen in the background script and the
  daemon. The MAIN-world script is untrusted: the page can tamper with it, and
  the only effect is on that page's own requests.
- **No extension permissions beyond** `nativeMessaging` and content scripts on
  `https://*/*` plus `http://localhost/*`. No `tabs`, no host permissions for
  fetch.
- **The dialog is the security UI.** It must show the origin that will be
  signed into `clientDataJSON`, taken from the daemon's own copy. Never show a
  page-supplied display string alone.

## Toward a standard

What stays fixed as the stack moves from extension to browser patch to portal:

1. **The wire format.** WebAuthn L3 JSON for options and responses, plus
   `origin`, `top_origin` and `parent_window`. That is already credentialsd's
   Gateway shape. Browsers have JSON (de)serializers for these types, because
   `toJSON` / `parse*FromJSON` are in the spec.
2. **The daemon API.** Our Gateway1 is a subset of credentialsd's Gateway.
   When the portal (`org.freedesktop.portal.Credentials`?) is defined, the
   daemon either implements it directly or registers as a provider behind
   credentialsd.

What we can push on, with a working implementation as evidence:

- **A provider interface for credentialsd**: how a platform authenticator
  (TPM/SEP-backed, like us) or a password manager registers and receives
  requests. It doesn't exist yet. Our D-Bus API is a concrete proposal for its
  shape: the same JSON in and out, plus `HasCredentials(rp_id, ids)` for the
  silent fallback check.
- **Caller identity for origins**: a portal knows the caller's app id
  (Flatpak/Snap, or an allow-list of browser binaries for host apps). Proposal:
  only privileged callers (browsers) may assert arbitrary web origins. Other
  apps get origins tied to their app id, like Android asset links or Apple
  associated domains. This is what closes the "any user process" gap above.
- **Browser patches**: a Linux backend in Firefox `dom/webauthn` (next to
  `WinWebAuthnService` / `MacOSWebAuthnService`) and in Chromium
  `device/fido` (next to `win/` and `mac/`) that call the portal. Through the
  JSON API they reach credentialsd, us, or both. The extension is then
  dropped. credentialsd's experimental Firefox patch is the starting point on
  the Firefox side.

## Phases

1. **Extension + native host + D-Bus Gateway1**: create/get, fallback rules,
   availability checks, LibreWolf and Brave packaging, NixOS option. Done
   when: webauthn.io, Google (without the shim) and GitHub register and sign
   in on both browsers, and USB-created passkeys still sign in.
2. **Real dialog** (done): account picker, "Use another device", requesting
   browser shown, fingerprint step inside the dialog, 60 s to answer.
   Not yet: Wayland parenting / activation token (the native host has no
   window handle to pass).
3. **Passkey autofill**: `mediation: "conditional"`. The extension shows its
   own suggestion popup on `input[autocomplete~="webauthn"]`, fed by a
   gesture-free `ListCredentials(rp_id)` that returns user names only. The
   popup must be extension UI (a top-layer element in a closed shadow root
   outside the page's reach, or `browser.action` popup), so the page can't
   read the account list.
4. **Upstream**: propose the provider interface to credentialsd, and prototype
   the Firefox backend against it.

## Open questions

- Firefox: can the background reliably learn an iframe's `allow` policy, or do
  we always fall back for cross-origin frames in Phase 1?
- `largeBlob`, `prf` (hmac-secret) and `credProps` extensions: map through to
  CTAP. pkee uses hmac-secret over USB, and websites asking for `prf` would
  want it here too.
- Should `NoCredential` fallback use the browser's sheet directly, or first
  say "no passkey on this device" in our dialog?
- Does credentialsd plan to handle the dialog itself, with providers being
  headless? The agent split keeps our dialog replaceable either way.
