# passkey-platform-shim

A tiny unpacked browser extension (Brave/Chromium, MV3) that lets **Google**
create a passkey on a USB/virtual FIDO2 key (linux-passkey) on Linux.

**Problem.** Before it starts, Google's passkey page calls
`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()`. Linux
has no platform authenticator, so the answer is `false`, and Google shows
*"A passkey can't be created on this device"*. Its "another device" fallback
enrolls a 2-Step-Verification-only security key instead of a passkey.

**What the shim does** (only on `https://*.google.com/*`, injected at
`document_start` into the page's own JS world):

1. `isUserVerifyingPlatformAuthenticatorAvailable()` → `true`, and
   `getClientCapabilities()` reports `userVerifyingPlatformAuthenticator` /
   `passkeyPlatformAuthenticator`.
2. Wraps `navigator.credentials.create()` to drop
   `authenticatorAttachment: "platform"` and the `client-device` hint, so the
   browser offers the USB security key.
3. Logs Google's request options and the result to the console
   (`[passkey-shim]`), for debugging.

It changes nothing about the credential itself: the authenticator, the user
verification and the server-side checks are all real.

**Use.** `brave://extensions` → Developer mode → *Load unpacked* → this
directory. Then `g.co/passkeys` → *Create a passkey* → *USB security key*. You
only need it while **creating** the passkey; disable it afterwards if you like,
because sign-in doesn't need it.
