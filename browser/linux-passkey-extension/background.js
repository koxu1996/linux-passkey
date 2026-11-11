// Background (service worker on Chromium, event page on Firefox): takes the
// caller's origin from the browser (the message sender), never from the page,
// and forwards requests to the native host, which talks to linux-passkey over
// D-Bus. One native connection, started on first use.
const api = globalThis.browser ?? globalThis.chrome;
const HOST = "io.github.koxu1996.linux_passkey";

let native = null;
let nextId = 1;
const waiting = new Map(); // native id -> reply callback

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

api.runtime.onConnect.addListener((port) => {
  if (port.name !== "linux-passkey") return;
  const sender = port.sender;
  const inflight = new Map(); // relay id -> native id
  const answer = (id, reply) => {
    try {
      port.postMessage({ ...reply, id });
    } catch {
      // The frame is gone.
    }
  };

  port.onMessage.addListener((m) => {
    if (m.op === "cancel") {
      const target = inflight.get(m.target);
      if (target) cancel(target);
      return;
    }
    const msg = { op: m.op };
    if (m.op === "create" || m.op === "get") {
      const origin = senderOrigin(sender);
      if (origin === "null") {
        return answer(m.id, { ok: false, error: "Unavailable", message: "opaque origin" });
      }
      // Phase 1: cross-origin iframes go to the browser, which enforces
      // the publickey-credentials permissions policy itself.
      if (sender.frameId !== 0 && !m.sameOriginWithTop) {
        return answer(m.id, { ok: false, error: "Unavailable", message: "cross-origin frame" });
      }
      msg.origin = origin;
      msg.publicKey = m.publicKey;
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
  });
});
