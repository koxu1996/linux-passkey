// Runs in the page's own JS world (MAIN), before the page's scripts: wraps
// navigator.credentials so passkey requests go to linux-passkey as a
// platform authenticator, and builds PublicKeyCredential-shaped results.
// Untrusted by design: the origin comes from the browser (background.js),
// not from here, so a page tampering with this only affects itself.
(() => {
  const PKC = window.PublicKeyCredential;
  const creds = navigator.credentials;
  if (!PKC || !creds || window.isSecureContext === false) return;

  const browserApi = {
    create: creds.create.bind(creds),
    get: creds.get.bind(creds),
    uvpaa: PKC.isUserVerifyingPlatformAuthenticatorAvailable?.bind(PKC),
    capabilities: PKC.getClientCapabilities?.bind(PKC),
  };
  // Captured before the page can replace them.
  const { Object, JSON, Promise, Uint8Array, ArrayBuffer, DOMException, TypeError, Map, String, atob, btoa } = window;
  const AttestationResponse = window.AuthenticatorAttestationResponse;
  const AssertionResponse = window.AuthenticatorAssertionResponse;
  const toString = Object.prototype.toString;

  // --- The channel to relay.js (isolated world) ---------------------------
  // relay.js answers "ready" with a MessagePort; the first one wins.
  let port = null;
  const queued = [];
  const pending = new Map();
  let nextId = 1;
  window.addEventListener("message", (e) => {
    if (port || e.source !== window || e.data?.linuxPasskey !== "port" || !e.ports?.[0]) return;
    port = e.ports[0];
    port.onmessage = (m) => {
      const done = pending.get(m.data?.id);
      if (done) {
        pending.delete(m.data.id);
        done(m.data);
      }
    };
    queued.splice(0).forEach((send) => send());
  });
  window.postMessage({ linuxPasskey: "ready" }, "*");

  const UNAVAILABLE = { ok: false, error: "Unavailable", message: "linux-passkey extension not connected" };

  // Send a request; resolves with the host's reply. `id` is for cancel().
  function ask(msg) {
    const id = nextId++;
    const reply = new Promise((resolve) => {
      pending.set(id, resolve);
      const send = () => port.postMessage({ ...msg, id });
      if (port) send();
      else queued.push(send);
      // No relay in this frame (e.g. about:blank): give up quickly.
      setTimeout(() => {
        if (!port && pending.delete(id)) resolve(UNAVAILABLE);
      }, 1000);
    });
    return { id, reply };
  }

  function cancel(id) {
    if (port && pending.has(id)) port.postMessage({ op: "cancel", target: id });
  }

  // --- base64url and WebAuthn JSON -----------------------------------------
  function b64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function unb64(s) {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  // Options -> WebAuthn L3 JSON: every BufferSource becomes base64url.
  function toJSON(v) {
    const tag = toString.call(v);
    if (tag === "[object ArrayBuffer]") return b64(new Uint8Array(v));
    if (ArrayBuffer.isView(v)) return b64(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
    if (Array.isArray(v)) return v.map(toJSON);
    if (v && typeof v === "object") {
      const out = {};
      for (const k of Object.keys(v)) if (v[k] !== undefined) out[k] = toJSON(v[k]);
      return out;
    }
    return v;
  }

  const copy = (json) => JSON.parse(JSON.stringify(json));
  const fixed = (value) => ({ value, enumerable: true });
  const method = (value) => ({ value });

  // A PublicKeyCredential from response JSON. Real ones can't be constructed
  // from script, so: the right prototypes, with own properties that shadow
  // the prototype's getters (which would throw on this object).
  function credential(json, kind) {
    const r = json.response;
    let response;
    if (kind === "create") {
      const authData = unb64(r.authenticatorData);
      const publicKey = r.publicKey ? unb64(r.publicKey) : null;
      response = Object.create(AttestationResponse.prototype, {
        clientDataJSON: fixed(unb64(r.clientDataJSON)),
        attestationObject: fixed(unb64(r.attestationObject)),
        getTransports: method(() => [...(r.transports || [])]),
        getAuthenticatorData: method(() => authData.slice(0)),
        getPublicKey: method(() => (publicKey ? publicKey.slice(0) : null)),
        getPublicKeyAlgorithm: method(() => r.publicKeyAlgorithm),
        toJSON: method(() => copy(r)),
      });
    } else {
      response = Object.create(AssertionResponse.prototype, {
        clientDataJSON: fixed(unb64(r.clientDataJSON)),
        authenticatorData: fixed(unb64(r.authenticatorData)),
        signature: fixed(unb64(r.signature)),
        userHandle: fixed(r.userHandle ? unb64(r.userHandle) : null),
        toJSON: method(() => copy(r)),
      });
    }
    const extensions = json.clientExtensionResults || {};
    return Object.create(PKC.prototype, {
      id: fixed(json.id),
      rawId: fixed(unb64(json.rawId)),
      type: fixed("public-key"),
      authenticatorAttachment: fixed(json.authenticatorAttachment),
      response: fixed(response),
      getClientExtensionResults: method(() => copy(extensions)),
      toJSON: method(() => copy(json)),
    });
  }

  // A failed reply as the exception the page sees.
  function exception(reply) {
    if (reply.error === "TypeError") return new TypeError(reply.message);
    return new DOMException(reply.message || "The operation failed.", reply.error || "UnknownError");
  }

  // --- When the browser's own WebAuthn should answer -----------------------
  function wantsOtherAuthenticator(pk, kind) {
    const hints = Array.isArray(pk.hints) ? pk.hints : [];
    if (hints.length && !hints.includes("client-device")) return true; // security-key / hybrid
    return kind === "create" && pk.authenticatorSelection?.authenticatorAttachment === "cross-platform";
  }

  async function ceremony(kind, options) {
    const fallback = () => browserApi[kind](options);
    const pk = options?.publicKey;
    if (!pk || options.mediation === "conditional" || wantsOtherAuthenticator(pk, kind)) return fallback();
    const signal = options.signal;
    if (signal?.aborted) throw signal.reason ?? new DOMException("The operation was aborted.", "AbortError");

    const { id, reply } = ask({ op: kind, publicKey: toJSON(pk) });
    let onAbort;
    const aborted = new Promise((_, reject) => {
      onAbort = () => {
        cancel(id);
        reject(signal.reason ?? new DOMException("The operation was aborted.", "AbortError"));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
    });
    let result;
    try {
      result = await Promise.race([reply, aborted]);
    } finally {
      signal?.removeEventListener("abort", onAbort);
    }
    if (result.ok) return credential(result.response, kind);
    // Not ours to answer (no passkey here, "Use another device", daemon down).
    if (result.error === "NoCredential" || result.error === "Unavailable") return fallback();
    throw exception(result);
  }

  // --- Platform authenticator availability ---------------------------------
  let ours = null;
  const ourCapabilities = () =>
    (ours ??= ask({ op: "capabilities" }).reply.then((r) => (r.ok ? r.capabilities : null)));

  creds.create = function create(options) {
    return ceremony("create", options);
  };
  creds.get = function get(options) {
    return ceremony("get", options);
  };
  PKC.isUserVerifyingPlatformAuthenticatorAvailable = async function isUserVerifyingPlatformAuthenticatorAvailable() {
    if ((await ourCapabilities())?.userVerifyingPlatformAuthenticator) return true;
    return browserApi.uvpaa ? browserApi.uvpaa() : false;
  };
  if (browserApi.capabilities) {
    PKC.getClientCapabilities = async function getClientCapabilities() {
      const merged = { ...(await browserApi.capabilities()) };
      for (const [k, v] of Object.entries((await ourCapabilities()) || {})) if (v) merged[k] = true;
      return merged;
    };
  }
})();
