/**
 * Utilitaires DOM sécurisés : aucune injection innerHTML sur des données dynamiques.
 * Garantit l'immunité structurelle contre les attaques XSS stockées ou réfléchies.
 */

export function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, val] of Object.entries(attrs)) {
    if (val === null || val === undefined) continue;
    if (key === "class") {
      node.className = val;
    } else if (key.startsWith("on") && typeof val === "function") {
      node.addEventListener(key.slice(2).toLowerCase(), val);
    } else if (key === "dataset" && typeof val === "object") {
      for (const [dk, dv] of Object.entries(val)) {
        node.dataset[dk] = dv;
      }
    } else {
      node.setAttribute(key, String(val));
    }
  }
  const items = Array.isArray(children) ? children : [children];
  for (const child of items) {
    if (child === null || child === undefined) continue;
    if (typeof child === "string" || typeof child === "number") {
      node.appendChild(document.createTextNode(String(child)));
    } else {
      node.appendChild(child);
    }
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

export function badge(text, variant = "neutral") {
  return el("span", { class: `badge badge-${variant}` }, text);
}

export function formatSla(remainingSec, state) {
  if (state === "MET") return badge("SLA RESPECTÉ", "MET");
  if (state === "BREACHED") {
    const mins = Math.abs(Math.floor(remainingSec / 60));
    return badge(`DÉPASSÉ -${mins}m`, "BREACHED");
  }
  const hrs = Math.floor(remainingSec / 3600);
  const mins = Math.floor((remainingSec % 3600) / 60);
  const label = hrs > 0 ? `${hrs}h ${mins}m` : `${mins} min`;
  return badge(label, state);
}

export function showToast(message, isError = false) {
  const container = document.getElementById("toast-container");
  if (!container) return;
  const item = el("div", { class: `toast${isError ? " error" : ""}` }, message);
  container.appendChild(item);
  setTimeout(() => item.remove(), 4200);
}
