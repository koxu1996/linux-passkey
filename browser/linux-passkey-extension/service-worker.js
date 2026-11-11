// Background (service worker on Chromium, event page on Firefox): takes the
// caller's origin from the browser (the message sender), never from the page,
// and forwards requests to the native host, which talks to linux-passkey over
// D-Bus. One native connection, started on first use.
const api = globalThis.browser ?? globalThis.chrome;
const HOST = "io.github.koxu1996.linux_passkey";

let native = null;
let nextId = 1;
const waiting = new Map(); // native id -> reply callback

// Armed passkey autofill, by token (known to relay.js and suggest.html only):
// { port, relayId, origin, publicKey, accounts, nativeId }.
const autofill = new Map();

function host() {
  if (native) return native;
  native = api.runtime.connectNative(HOST);
  native.onMessage.addListener((m) => {
    const done = waiting.get(m.id);
    if (done) {
      waiting.delete(m.id);
      done(m);
    }
  });
  native.onDisconnect.addListener(() => {
    const message = api.runtime.lastError?.message || "native host exited";
    native = null;
    for (const [id, done] of waiting) done({ id, ok: false, error: "Unavailable", message });
    waiting.clear();
  });
  return native;
}

function send(msg, done) {
  const id = nextId++;
  waiting.set(id, done);
  try {
    host().postMessage({ ...msg, id });
  } catch (e) {
    waiting.delete(id);
    done({ id, ok: false, error: "Unavailable", message: String(e) });
  }
  return id;
}

// The host doesn't answer cancels.
function cancel(target) {
  try {
    host().postMessage({ op: "cancel", target, id: nextId++ });
  } catch {
    // Host gone: its requests are over anyway.
  }
}

function senderOrigin(sender) {
  try {
    return sender.origin || new URL(sender.url).origin;
  } catch {
    return "null";
  }
}

function post(port, msg) {
  try {
    port.postMessage(msg);
  } catch {
    // The frame is gone.
  }
}

function token() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  return [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

api.runtime.onConnect.addListener((port) => {
  if (port.name !== "linux-passkey") return;
  const sender = port.sender;
  const inflight = new Map(); // relay id -> native id
  const armed = new Map(); // relay id -> autofill token
  const answer = (id, reply) => post(port, { ...reply, id });

  port.onMessage.addListener((m) => {
    if (m.op === "cancel") {
      const t = armed.get(m.target);
      if (t) {
        // A conditional request the page gave up (or replaced by a modal one).
        const a = autofill.get(t);
        autofill.delete(t);
        armed.delete(m.target);
        if (a?.nativeId) cancel(a.nativeId);
        return answer(m.target, { ok: false, error: "AbortError", message: "The operation was aborted." });
      }
      const target = inflight.get(m.target);
      if (target) cancel(target);
      return;
    }
    const msg = { op: m.op };
    if (m.op === "create" || m.op === "get" || m.op === "conditional") {
      const origin = senderOrigin(sender);
      if (origin === "null") {
        return answer(m.id, { ok: false, error: "Unavailable", message: "opaque origin" });
      }
      // Cross-origin iframes go to the browser, which enforces the
      // publickey-credentials permissions policy itself.
      if (sender.frameId !== 0 && !m.sameOriginWithTop) {
        return answer(m.id, { ok: false, error: "Unavailable", message: "cross-origin frame" });
      }
      msg.origin = origin;
      msg.publicKey = m.publicKey;
    }
    if (m.op === "conditional") {
      // Autofill: which of our passkeys could sign in here? No dialog.
      send({ ...msg, op: "list" }, (reply) => {
        if (!reply.ok || !reply.accounts?.length) {
          return answer(m.id, reply.ok ? { ok: false, error: "NoCredential", message: "no passkey here" } : reply);
        }
        const t = token();
        autofill.set(t, { port, relayId: m.id, origin: msg.origin, publicKey: m.publicKey, accounts: reply.accounts });
        armed.set(m.id, t);
        post(port, { id: m.id, type: "armed", token: t, count: reply.accounts.length });
      });
      return;
    }
    const nativeId = send(msg, (reply) => {
      inflight.delete(m.id);
      answer(m.id, reply);
    });
    inflight.set(m.id, nativeId);
  });

  // Tab closed or navigated away: nobody waits for its requests.
  port.onDisconnect.addListener(() => {
    for (const target of inflight.values()) cancel(target);
    inflight.clear();
    for (const t of armed.values()) {
      const a = autofill.get(t);
      if (a?.nativeId) cancel(a.nativeId);
      autofill.delete(t);
    }
    armed.clear();
  });
});

// The suggestion list (suggest.html, our own page in an iframe).
api.runtime.onMessage.addListener((m, sender, respond) => {
  if (sender.id !== api.runtime.id || !sender.url?.startsWith(api.runtime.getURL("suggest.html"))) return;
  const a = autofill.get(m.token);
  if (!a) return;
  if (m.op === "accounts") {
    respond(a.accounts);
    return;
  }
  if (m.op === "dismiss") return post(a.port, { type: "hide" });
  if (m.op === "refocus") return post(a.port, { type: "refocus" });
  if (m.op === "pick" && !a.nativeId && a.accounts.some((x) => x.id === m.account)) {
    post(a.port, { id: a.relayId, type: "picked" });
    // Sign in with that passkey only; the dialog then names that account.
    const publicKey = { ...a.publicKey, allowCredentials: [{ type: "public-key", id: m.account }] };
    a.nativeId = send({ op: "get", origin: a.origin, publicKey }, (reply) => {
      a.nativeId = null;
      // Denied or timed out: offer the passkeys again, as browsers keep a
      // conditional request open until it succeeds or the page aborts it.
      if (!reply.ok && reply.error === "NotAllowedError" && autofill.has(m.token)) {
        return post(a.port, { id: a.relayId, type: "armed", token: m.token, count: a.accounts.length });
      }
      autofill.delete(m.token);
      post(a.port, { ...reply, id: a.relayId });
    });
  }
});
