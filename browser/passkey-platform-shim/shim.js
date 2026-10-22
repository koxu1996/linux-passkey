// Runs in the page's own JS world before Google's scripts.
(() => {
  const tag = "[passkey-shim]";
  const PKC = window.PublicKeyCredential;
  if (!PKC || !navigator.credentials) return;

  // 1. Linux has no built-in (platform) authenticator, so Google refuses to
  //    even start. Claim one exists.
  PKC.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
  if (PKC.getClientCapabilities) {
    const orig = PKC.getClientCapabilities.bind(PKC);
    PKC.getClientCapabilities = async () => ({
      ...(await orig()),
      userVerifyingPlatformAuthenticator: true,
      passkeyPlatformAuthenticator: true,
    });
  }

  // 2. Don't let the request insist on a platform authenticator, so the
  //    browser offers the USB security key (our tpm2-passkey).
  const create = navigator.credentials.create.bind(navigator.credentials);
  navigator.credentials.create = async (options) => {
    const pk = options && options.publicKey;
    if (pk) {
      console.info(tag, "create() options from site:", JSON.parse(JSON.stringify(pk, (k, v) =>
        v instanceof ArrayBuffer || ArrayBuffer.isView(v) ? `<${v.byteLength} bytes>` : v)));
      const sel = pk.authenticatorSelection || (pk.authenticatorSelection = {});
      if (sel.authenticatorAttachment === "platform") {
        delete sel.authenticatorAttachment;
        console.info(tag, "dropped authenticatorAttachment=platform");
      }
      if (Array.isArray(pk.hints)) {
        pk.hints = pk.hints.filter((h) => h !== "client-device");
      }
    }
    try {
      const cred = await create(options);
      console.info(tag, "create() succeeded");
      return cred;
    } catch (e) {
      console.warn(tag, "create() failed:", e && e.name, e && e.message);
      throw e;
    }
  };
  console.info(tag, "active on", location.host);
})();
