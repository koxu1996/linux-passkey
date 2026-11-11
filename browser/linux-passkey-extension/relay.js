// Runs in the extension's isolated world: passes messages between inject.js
// (the page's world) and background.js. Holds no logic, so a page can't
// reach extension APIs through it. Also tells the background whether this
// frame is same-origin with the top frame; the page can't fake that here.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  let background = null;
  // Our request id -> the page-side port and its id.
  const routes = new Map();
  let nextId = 1;

  function sameOriginWithTop() {
    try {
      return window.top === window || window.top.location.origin === location.origin;
    } catch {
      return false; // cross-origin: reading top's location throws
    }
  }

  function connect() {
    if (background) return background;
    background = api.runtime.connect({ name: "linux-passkey" });
    background.onMessage.addListener((m) => {
      const route = routes.get(m.id);
      if (!route) return;
      routes.delete(m.id);
      route.port.postMessage({ ...m, id: route.id });
    });
    background.onDisconnect.addListener(() => {
      background = null;
      for (const [id, route] of routes) {
        route.port.postMessage({ id: route.id, ok: false, error: "Unavailable", message: "extension restarted" });
        routes.delete(id);
      }
    });
    return background;
  }

  function offerPort() {
    const channel = new MessageChannel();
    const pageIds = new Map(); // page id -> our id, for cancel
    channel.port1.onmessage = (e) => {
      const m = e.data || {};
      if (m.op === "cancel") {
        const target = pageIds.get(m.target);
        if (target) connect().postMessage({ op: "cancel", target });
        return;
      }
      const id = nextId++;
      pageIds.set(m.id, id);
      routes.set(id, { port: channel.port1, id: m.id });
      connect().postMessage({ op: m.op, publicKey: m.publicKey, id, sameOriginWithTop: sameOriginWithTop() });
    };
    window.postMessage({ linuxPasskey: "port" }, "*", [channel.port2]);
  }

  window.addEventListener("message", (e) => {
    if (e.source === window && e.data?.linuxPasskey === "ready") offerPort();
  });
})();
