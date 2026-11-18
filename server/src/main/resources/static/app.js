"use strict";

// Every value shown comes from the network (host names, mDNS names) and may be hostile:
// the page builds nodes with textContent only and never uses innerHTML.

const TRUST = {
  unset: "Statut à choisir",
  owned: "Mon réseau",
  authorized: "Réseau autorisé",
  ignored: "Ne pas surveiller",
};
const STATUS = {
  new: "Nouveau",
  approved: "Approuvé",
  guest: "Invité",
  suspect: "Suspect",
  ignored: "Ignoré",
};
const TYPE = {
  phone: "Téléphone",
  computer: "Ordinateur",
  printer: "Imprimante",
  tv: "Téléviseur ou diffuseur",
  iot: "Objet connecté",
  unknown: "Inconnu",
};
const SOURCE = { arp: "ARP", dhcp: "DHCP", mdns: "mDNS", arp_scan: "Balayage ARP" };
const CATEGORIES = ["Famille", "Travail", "Invités", "Multimédia", "Domotique", "Réseau", "Autre"];

const view = document.getElementById("view");

// --- DOM helpers -------------------------------------------------------------------------

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === undefined || value === null || value === false) continue;
    if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key === "class") node.className = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function link(path, ...children) {
  return el("a", { href: path, "data-link": true }, ...children);
}

function chip(text, kind) {
  return el("span", { class: "chip " + (kind || "") }, text);
}

function show(...nodes) {
  view.replaceChildren(...nodes);
}

let toastTimer;
function toast(message, error) {
  const box = document.getElementById("toast");
  box.textContent = message;
  box.className = error ? "error" : "";
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (box.hidden = true), error ? 6000 : 2500);
}

// --- Formatting --------------------------------------------------------------------------

const dateFormat = new Intl.DateTimeFormat("fr-CA", { dateStyle: "medium", timeStyle: "short" });

function when(iso) {
  return iso ? dateFormat.format(new Date(iso)) : "—";
}

function ago(iso) {
  if (!iso) return "—";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return "à l'instant";
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `il y a ${hours} h`;
  return `il y a ${Math.round(hours / 24)} j`;
}

function deviceName(d) {
  return d.displayName || d.hostname || vendorOf(d) || d.mac;
}

function vendorOf(d) {
  return d.randomized ? "Adresse privée" : d.vendor || "";
}

function networkName(n) {
  return n.label || n.subnet;
}

function monitoring(n) {
  if (n.trust !== "owned" && n.trust !== "authorized") return "Non surveillé";
  if (n.learningUntil && new Date(n.learningUntil) > new Date()) {
    return `Surveillé · apprentissage jusqu'au ${when(n.learningUntil)} (pas d'alerte d'appareil)`;
  }
  return "Surveillé";
}

// --- Server access -----------------------------------------------------------------------

let csrf = null;

async function csrfToken(refresh) {
  if (!csrf || refresh) {
    const response = await fetch("/ui/csrf", { credentials: "same-origin" });
    csrf = await response.json();
  }
  return csrf;
}

async function api(method, path, body) {
  const send = async (refresh) => {
    const headers = { Accept: "application/json" };
    if (method !== "GET") {
      const token = await csrfToken(refresh);
      headers[token.headerName] = token.token;
    }
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  };
  let response = await send(false);
  // The session holding the token ends when the server restarts: fetch a new one, once.
  if (response.status === 403 && method !== "GET") response = await send(true);
  if (!response.ok) {
    let detail = `Erreur ${response.status}`;
    try {
      const problem = await response.json();
      if (problem.detail) detail = problem.detail;
    } catch (ignored) {
      // Not a problem document.
    }
    throw new Error(detail);
  }
  return response.status === 204 ? null : response.json();
}

async function run(action, success) {
  try {
    const result = await action();
    if (success) toast(success);
    return result;
  } catch (e) {
    toast(e.message, true);
    return undefined;
  }
}

// --- Views -------------------------------------------------------------------------------

async function networksView() {
  const networks = await api("GET", "/ui/networks");
  document.title = "Réseaux · NetLedger";
  if (networks.length === 0) {
    return show(
      el("h1", {}, "Réseaux"),
      el("p", { class: "empty" }, "Aucun réseau. Lancez l'agent : le réseau courant apparaîtra ici."),
    );
  }
  show(
    el("h1", {}, "Réseaux"),
    el(
      "p",
      { class: "sub" },
      "NetLedger ne capture rien sur un réseau tant que vous ne l'avez pas déclaré comme le vôtre ou autorisé par son administrateur.",
    ),
    el("div", { class: "cards" }, networks.map(networkCard)),
  );
}

function networkCard(n) {
  const trust = el(
    "select",
    {
      "aria-label": "Statut du réseau",
      onchange: async (e) => {
        const value = e.target.value;
        if (value === "authorized" && !confirm("Avez-vous l'accord de l'administrateur de ce réseau pour y surveiller les appareils ?")) {
          e.target.value = n.trust;
          return;
        }
        const ok = await run(() => api("PATCH", `/ui/networks/${n.id}`, { trust: value }), "Statut enregistré");
        if (ok === undefined) e.target.value = n.trust;
        route();
      },
    },
    Object.entries(TRUST).map(([value, label]) => el("option", { value, selected: value === n.trust }, label)),
  );
  return el(
    "div",
    { class: "card" + (n.trust === "unset" ? " attention" : "") },
    el(
      "div",
      { class: "card-head" },
      el(
        "div",
        {},
        el("h3", {}, link(`/networks/${n.id}`, networkName(n))),
        el("div", { class: "muted mono" }, `${n.subnet} · passerelle ${n.gatewayMac}`),
      ),
      trust,
    ),
    el("p", {}, monitoring(n)),
    el(
      "div",
      { class: "muted" },
      `${n.devices} appareil(s), dont ${n.newDevices} nouveau(x) · vu ${ago(n.lastSeen)}`,
    ),
    n.trust === "unset"
      ? el("p", {}, "Choisissez son statut : sans réponse, rien n'est capturé sur ce réseau.")
      : null,
    el(
      "div",
      { class: "actions" },
      link(`/networks/${n.id}`, "Appareils"),
      link(`/events?network=${n.id}`, "Chronologie"),
      el("a", { href: `/ui/networks/${n.id}/inventory.csv`, download: true }, "Export CSV"),
      el("a", { href: `/ui/networks/${n.id}/inventory.json`, download: true }, "Export JSON"),
      el(
        "button",
        {
          type: "button",
          onclick: async () => {
            const label = prompt("Nom du réseau (vide pour effacer)", n.label || "");
            if (label === null) return;
            await run(() => api("PATCH", `/ui/networks/${n.id}`, { label }), "Nom enregistré");
            route();
          },
        },
        "Renommer",
      ),
      el(
        "button",
        {
          type: "button",
          class: "danger",
          onclick: async () => {
            if (!confirm(`Supprimer « ${networkName(n)} » et tout son historique (${n.devices} appareil(s)) ? C'est définitif.`)) return;
            await run(() => api("DELETE", `/ui/networks/${n.id}`), "Réseau supprimé");
            route();
          },
        },
        "Supprimer",
      ),
    ),
  );
}

async function networkView(id) {
  const [network, devices] = await Promise.all([
    api("GET", `/ui/networks/${id}`),
    api("GET", `/ui/networks/${id}/devices`),
  ]);
  document.title = `${networkName(network)} · NetLedger`;
  const search = el("input", { type: "search", placeholder: "Nom, fabricant, IP ou MAC", "aria-label": "Rechercher" });
  const status = el(
    "select",
    { "aria-label": "Filtrer par statut" },
    el("option", { value: "" }, "Tous les statuts"),
    Object.entries(STATUS).map(([value, label]) => el("option", { value }, label)),
  );
  const type = el(
    "select",
    { "aria-label": "Filtrer par type" },
    el("option", { value: "" }, "Tous les types"),
    Object.entries(TYPE).map(([value, label]) => el("option", { value }, label)),
  );
  const body = el("tbody");
  const count = el("p", { class: "muted" });

  const refresh = () => {
    const q = search.value.trim().toLowerCase();
    const rows = devices.filter(
      (d) =>
        (!status.value || d.status === status.value) &&
        (!type.value || d.type === type.value) &&
        (!q ||
          [d.displayName, d.hostname, vendorOf(d), d.lastIp, d.mac, d.category]
            .filter(Boolean)
            .some((v) => v.toLowerCase().includes(q))),
    );
    count.textContent = `${rows.length} appareil(s) sur ${devices.length}`;
    body.replaceChildren(
      ...rows.map((d) =>
        el(
          "tr",
          {
            class: "clickable",
            onclick: (e) => {
              if (!e.target.closest("a")) navigate(`/devices/${d.id}`);
            },
          },
          el("td", {}, link(`/devices/${d.id}`, deviceName(d)), d.category ? el("div", { class: "muted" }, d.category) : null),
          el("td", {}, vendorOf(d) || "—"),
          el("td", {}, TYPE[d.type] || "—"),
          el("td", { class: "mono" }, d.lastIp || "—"),
          el("td", { class: "mono" }, d.mac),
          el("td", {}, chip(STATUS[d.status] || d.status, d.status)),
          el("td", { title: when(d.lastSeen) }, ago(d.lastSeen)),
        ),
      ),
    );
  };
  search.addEventListener("input", refresh);
  status.addEventListener("change", refresh);
  type.addEventListener("change", refresh);
  refresh();

  show(
    el("p", {}, link("/networks", "← Réseaux")),
    el("h1", {}, networkName(network), " ", chip(TRUST[network.trust], network.trust)),
    el("p", { class: "sub" }, `${network.subnet} · ${monitoring(network)}`),
    el("div", { class: "filters" }, search, status, type),
    count,
    devices.length === 0
      ? el("p", { class: "empty" }, "Aucun appareil observé sur ce réseau.")
      : el(
          "div",
          { class: "table-wrap" },
          el(
            "table",
            {},
            el(
              "thead",
              {},
              el("tr", {}, ["Appareil", "Fabricant", "Type", "IP", "MAC", "Statut", "Vu"].map((h) => el("th", {}, h))),
            ),
            body,
          ),
        ),
  );
}

async function deviceView(id) {
  const detail = await api("GET", `/ui/devices/${id}`);
  const d = detail.device;
  document.title = `${deviceName(d)} · NetLedger`;

  const name = el("input", { value: d.displayName || "", maxlength: 64, placeholder: d.hostname || "" });
  const category = el("input", { value: d.category || "", maxlength: 32, list: "categories" });
  const save = el(
    "form",
    {
      class: "inline",
      onsubmit: async (e) => {
        e.preventDefault();
        await run(
          () => api("PATCH", `/ui/devices/${id}`, { displayName: name.value, category: category.value }),
          "Fiche enregistrée",
        );
        route();
      },
    },
    el("label", {}, "Nom", name),
    el("label", {}, "Catégorie", category),
    el("datalist", { id: "categories" }, CATEGORIES.map((c) => el("option", { value: c }))),
    el("button", { type: "submit", class: "primary" }, "Enregistrer"),
  );

  const statusButtons = el(
    "div",
    { class: "actions" },
    [
      ["approved", "Approuver"],
      ["guest", "Invité"],
      ["suspect", "Suspect"],
      ["ignored", "Ignorer"],
      ["new", "Nouveau"],
    ].map(([value, label]) =>
      el(
        "button",
        {
          type: "button",
          "aria-pressed": String(d.status === value),
          onclick: async () => {
            await run(() => api("PATCH", `/ui/devices/${id}`, { status: value }), `Statut : ${STATUS[value]}`);
            route();
          },
        },
        label,
      ),
    ),
  );

  const candidates = [...detail.mergeCandidates].sort(
    (a, b) => (b.status === "approved") - (a.status === "approved") || deviceName(a).localeCompare(deviceName(b)),
  );
  const target = el(
    "select",
    { "aria-label": "Appareil connu" },
    el("option", { value: "" }, "Choisir l'appareil connu…"),
    candidates.map((c) => el("option", { value: c.id }, `${deviceName(c)} · ${STATUS[c.status]} · ${c.mac}`)),
  );
  const merge = el(
    "form",
    {
      class: "inline",
      onsubmit: async (e) => {
        e.preventDefault();
        if (!target.value) return;
        const chosen = candidates.find((c) => String(c.id) === target.value);
        if (!confirm(`Fusionner cette fiche dans « ${deviceName(chosen)} » ? Son historique y sera rattaché et cette fiche disparaîtra.`)) return;
        const kept = await run(() => api("POST", `/ui/devices/${id}/merge`, { into: Number(target.value) }), "Fiches fusionnées");
        if (kept) navigate(`/devices/${kept.id}`);
      },
    },
    target,
    el("button", { type: "submit" }, "Fusionner"),
  );

  show(
    el("p", {}, link(`/networks/${d.networkId}`, `← ${networkName(detail.network)}`)),
    el("h1", {}, deviceName(d), " ", chip(STATUS[d.status] || d.status, d.status)),
    el("p", { class: "sub" }, `${TYPE[d.type] || "Type inconnu"} · ${vendorOf(d) || "fabricant inconnu"}`),
    el(
      "div",
      { class: "grid2" },
      el(
        "div",
        { class: "card" },
        el(
          "dl",
          { class: "facts" },
          fact("Adresse MAC", d.mac, true),
          fact("Fabricant", vendorOf(d) || "—"),
          fact("Type probable", TYPE[d.type] || "—"),
          fact("Dernière IP", d.lastIp || "—", true),
          fact("Nom d'hôte", d.hostname || "—"),
          fact("Empreinte DHCP", d.dhcpFingerprint || "—", true),
          fact("Vu la première fois", when(d.firstSeen)),
          fact("Vu la dernière fois", `${when(d.lastSeen)} (${ago(d.lastSeen)})`),
        ),
      ),
      el(
        "div",
        { class: "card" },
        save,
        el("h2", {}, "Statut"),
        statusButtons,
        el("h2", {}, "Même appareil qu'une autre fiche ?"),
        el("p", { class: "muted" }, "Un téléphone qui change d'adresse privée crée une nouvelle fiche : fusionnez-la avec l'appareil connu."),
        candidates.length ? merge : el("p", { class: "muted" }, "Aucune autre fiche sur ce réseau."),
      ),
    ),
    el("h2", {}, "Adresses IP"),
    table(["IP", "Première fois", "Dernière fois"], detail.ips, (ip) => [mono(ip.ip), when(ip.firstSeen), when(ip.lastSeen)]),
    el("h2", {}, "Services mDNS"),
    table(["Type", "Nom", "Port", "Vu"], detail.services, (s) => [mono(s.type), s.name || "—", s.port ?? "—", ago(s.lastSeen)]),
    el("h2", {}, "Événements"),
    timeline(detail.events, false),
    el("h2", {}, `Observations récentes (${detail.observations.length} au plus récent)`),
    table(["Source", "IP", "Détail", "Moment"], detail.observations, (o) => [
      SOURCE[o.source] || o.source,
      mono(o.ip || "—"),
      observationDetail(o.detail),
      when(o.observedAt),
    ]),
  );
}

function fact(label, value, monospace) {
  return [el("dt", {}, label), el("dd", { class: monospace ? "mono" : "" }, value)];
}

function mono(text) {
  return el("span", { class: "mono" }, text);
}

function table(headers, rows, cells) {
  if (!rows.length) return el("p", { class: "muted" }, "Rien pour l'instant.");
  return el(
    "div",
    { class: "table-wrap" },
    el(
      "table",
      {},
      el("thead", {}, el("tr", {}, headers.map((h) => el("th", {}, h)))),
      el("tbody", {}, rows.map((r) => el("tr", {}, cells(r).map((c) => el("td", {}, c))))),
    ),
  );
}

function observationDetail(json) {
  if (!json) return "—";
  try {
    const d = JSON.parse(json);
    const parts = [];
    if (d.hostname) parts.push(`nom ${d.hostname}`);
    if (d.vendorClass) parts.push(`classe ${d.vendorClass}`);
    if (d.dhcpFingerprint) parts.push(`empreinte ${d.dhcpFingerprint}`);
    if (d.services) parts.push(d.services.map((s) => s.type).join(", "));
    return parts.join(" · ") || "—";
  } catch (ignored) {
    return "—";
  }
}

function timeline(events, withNetwork) {
  if (!events.length) return el("p", { class: "muted" }, "Aucun événement.");
  return el(
    "ul",
    { class: "timeline card" },
    events.map((e) =>
      el(
        "li",
        {},
        el("span", { class: "muted" }, when(e.occurredAt)),
        el(
          "div",
          {},
          el("div", { class: "title" }, e.title),
          el("div", {}, e.message),
          e.deviceId ? el("div", {}, link(`/devices/${e.deviceId}`, e.deviceLabel || "Voir l'appareil")) : null,
          withNetwork ? el("div", { class: "muted" }, link(`/networks/${e.networkId}`, `Réseau ${e.networkId}`)) : null,
        ),
      ),
    ),
  );
}

async function eventsView(params) {
  const network = params.get("network");
  const [events, networks] = await Promise.all([
    api("GET", "/ui/events" + (network ? `?network=${encodeURIComponent(network)}` : "")),
    api("GET", "/ui/networks"),
  ]);
  document.title = "Chronologie · NetLedger";
  const filter = el(
    "select",
    {
      "aria-label": "Réseau",
      onchange: (e) => navigate(e.target.value ? `/events?network=${e.target.value}` : "/events"),
    },
    el("option", { value: "" }, "Tous les réseaux"),
    networks.map((n) => el("option", { value: n.id, selected: String(n.id) === network }, networkName(n))),
  );
  show(
    el("h1", {}, "Chronologie"),
    el("p", { class: "sub" }, "Alertes et événements, du plus récent au plus ancien."),
    el("div", { class: "filters" }, filter),
    timeline(events, !network),
  );
}

// --- Routing -----------------------------------------------------------------------------

function navigate(path) {
  history.pushState(null, "", path);
  route();
}

async function route() {
  const url = new URL(location.href);
  const parts = url.pathname.split("/").filter(Boolean);
  try {
    if (parts.length === 0 || (parts[0] === "networks" && parts.length === 1)) await networksView();
    else if (parts[0] === "networks" && /^\d+$/.test(parts[1])) await networkView(parts[1]);
    else if (parts[0] === "devices" && /^\d+$/.test(parts[1])) await deviceView(parts[1]);
    else if (parts[0] === "events") await eventsView(url.searchParams);
    else show(el("p", { class: "empty" }, "Page introuvable."));
  } catch (e) {
    show(el("p", { class: "empty" }, `Impossible de charger la page : ${e.message}`));
  }
}

document.addEventListener("click", (e) => {
  const a = e.target.closest("a[data-link]");
  if (!a || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
  e.preventDefault();
  navigate(a.getAttribute("href"));
});
window.addEventListener("popstate", route);
route();
