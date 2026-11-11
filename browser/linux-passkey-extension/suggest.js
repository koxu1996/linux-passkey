// The suggestion list (an extension page in an iframe, see relay.js). Gets
// the accounts from service-worker.js by the token in its URL; a pick goes back
// the same way. The site never sees either.
const api = globalThis.browser ?? globalThis.chrome;
const token = location.hash.slice(1);
const list = document.getElementById("list");

// A key icon, drawn here rather than loaded.
const SVG = "http://www.w3.org/2000/svg";
function keyIcon() {
  const svg = document.createElementNS(SVG, "svg");
  svg.setAttribute("class", "icon");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  const path = document.createElementNS(SVG, "path");
  path.setAttribute(
    "d",
    "M10.5 1a4.5 4.5 0 0 0-4.36 5.62L1 11.76V15h3.24l.76-.76V13h1.24l.76-.76V11h1.24l1.14-1.14A4.5 4.5 0 1 0 10.5 1zm1 2.5a1 1 0 1 1 0 2 1 1 0 0 1 0-2z",
  );
  svg.append(path);
  return svg;
}

function row(account) {
  const button = document.createElement("button");
  button.setAttribute("role", "option");
  button.append(keyIcon());
  const text = document.createElement("span");
  text.className = "text";
  const name = document.createElement("span");
  name.className = "name";
  name.textContent = account.name || account.displayName || "Passkey";
  text.append(name);
  if (account.displayName && account.displayName !== account.name) {
    const sub = document.createElement("span");
    sub.className = "sub";
    sub.textContent = account.displayName;
    text.append(sub);
  }
  button.append(text);
  button.addEventListener("click", () => api.runtime.sendMessage({ op: "pick", token, account: account.id }));
  return button;
}

function buttons() {
  return [...list.querySelectorAll("button")];
}

document.addEventListener("keydown", (e) => {
  const all = buttons();
  const i = all.indexOf(document.activeElement);
  if (e.key === "ArrowDown") all[Math.min(i + 1, all.length - 1)]?.focus();
  else if (e.key === "ArrowUp") {
    // Up from the first entry: back to the field.
    if (i <= 0) api.runtime.sendMessage({ op: "refocus", token });
    else all[i - 1].focus();
  } else if (e.key === "Escape") api.runtime.sendMessage({ op: "dismiss", token });
  else return;
  e.preventDefault();
});

// relay.js asks for keyboard focus (ArrowDown in the field). Only that: the
// page can post here too, and it must not be able to pick for the user.
window.addEventListener("message", (e) => {
  if (e.data === "linux-passkey:focus") buttons()[0]?.focus();
});

api.runtime.sendMessage({ op: "accounts", token }).then((accounts) => {
  for (const a of accounts || []) list.append(row(a));
});
