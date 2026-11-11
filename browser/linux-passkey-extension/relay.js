// Runs in the extension's isolated world: passes messages between inject.js
// (the page's world) and service-worker.js. Holds no logic, so a page can't
// reach extension APIs through it. Also tells the background whether this
// frame is same-origin with the top frame; the page can't fake that here.
//
// Passkey autofill: while a conditional request is armed, a focused field
// with autocomplete="… webauthn" gets the suggestion list under it, in an
// iframe with our extension page (suggest.html), which the page can't read.
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

  // --- Passkey autofill ------------------------------------------------------
  let armed = null; // { token, count }
  let frame = null;
  let field = null;

  function wantsPasskeys(el) {
    return (
      el instanceof HTMLInputElement &&
      (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/).includes("webauthn")
    );
  }

  function place() {
    if (!frame || !field) return;
    const r = field.getBoundingClientRect();
    const height = 34 + 52 * Math.min(armed?.count || 1, 5) + 2;
    Object.assign(frame.style, {
      top: `${r.bottom + 2}px`,
      left: `${r.left}px`,
      width: `${Math.max(r.width, 280)}px`,
      height: `${height}px`,
      borderRadius: "8px",
      boxShadow: "0 4px 14px rgba(0, 0, 0, 0.18)",
    });
  }

  function show(el) {
    if (!armed) return;
    field = el;
    if (!frame) {
      frame = document.createElement("iframe");
      frame.src = api.runtime.getURL("suggest.html") + "#" + armed.token;
      frame.setAttribute("allowtransparency", "true");
      Object.assign(frame.style, {
        position: "fixed",
        zIndex: "2147483647",
        border: "0",
        background: "transparent",
        colorScheme: "normal",
        display: "block",
        margin: "0",
        padding: "0",
      });
      (document.body || document.documentElement).append(frame);
    }
    place();
  }

  function hide() {
    frame?.remove();
    frame = null;
    field = null;
  }

  function disarm() {
    armed = null;
    hide();
  }

  document.addEventListener(
    "focusin",
    (e) => {
      if (e.target === frame) return;
      if (armed && wantsPasskeys(e.target)) show(e.target);
      else hide();
    },
    true,
  );
  document.addEventListener(
    "focusout",
    (e) => {
      if (e.target !== field) return;
      // Focus moving into the list (a click on it) keeps it open.
      setTimeout(() => {
        if (document.activeElement !== frame && document.activeElement !== field) hide();
      }, 0);
    },
    true,
  );
  document.addEventListener(
    "keydown",
    (e) => {
      if (!frame || e.target !== field) return;
      if (e.key === "Escape") hide();
      else if (e.key === "ArrowDown") {
        frame.focus();
        frame.contentWindow?.postMessage("linux-passkey:focus", "*");
        e.preventDefault();
      }
    },
    true,
  );
  window.addEventListener("scroll", place, true);
  window.addEventListener("resize", place);

  // --- Messages ---------------------------------------------------------------
  function connect() {
    if (background) return background;
    background = api.runtime.connect({ name: "linux-passkey" });
    background.onMessage.addListener((m) => {
      // Autofill steps for the background, not answers for the page.
      if (m.type === "hide") return hide();
      if (m.type === "refocus") return field?.focus();
      const route = routes.get(m.id);
      if (!route) return;
      if (m.type === "armed") {
        armed = { token: m.token, count: m.count };
        if (wantsPasskeys(document.activeElement)) show(document.activeElement);
        return;
      }
      if (m.type === "picked") return disarm();
      routes.delete(m.id);
      if (route.conditional) disarm();
      route.port.postMessage({ ...m, id: route.id });
    });
    background.onDisconnect.addListener(() => {
      background = null;
      disarm();
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
      routes.set(id, { port: channel.port1, id: m.id, conditional: m.op === "conditional" });
      connect().postMessage({ op: m.op, publicKey: m.publicKey, id, sameOriginWithTop: sameOriginWithTop() });
    };
    window.postMessage({ linuxPasskey: "port" }, "*", [channel.port2]);
  }

  window.addEventListener("message", (e) => {
    if (e.source === window && e.data?.linuxPasskey === "ready") offerPort();
  });
})();
