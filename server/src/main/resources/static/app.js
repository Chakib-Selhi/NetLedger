"use strict";

// Every value shown comes from the network (host names, mDNS names) and may be hostile:
// the page builds nodes with textContent only and never uses innerHTML.

const TRUST = {
  unset: "Statut à choisir",
  owned: "Mon réseau",
  authorized: "Réseau autorisé",
  ignored: "Ne pas surveiller",
};
const VISA = {
  new: "à viser",
  approved: "approuvé",
  guest: "invité",
  suspect: "suspect",
  ignored: "ignoré",
};
const STAMPS = [
  ["approved", "Approuvé"],
  ["guest", "Invité"],
  ["suspect", "Suspect"],
  ["ignored", "Ignoré"],
  ["new", "À viser"],
];
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
  for (const child of children.flat(Infinity)) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function link(path, ...children) {
  return el("a", { href: path, "data-link": true }, ...children);
}

function textButton(label, onclick, danger) {
  return el("button", { type: "button", class: "textbtn" + (danger ? " danger" : ""), onclick }, label);
}

function visa(status) {
  return el("span", { class: "visa " + status }, VISA[status] || status);
}

function mono(text) {
  return el("span", { class: "mono" }, text);
}

function show(...nodes) {
  view.replaceChildren(...nodes.flat(Infinity).filter((n) => n !== null && n !== undefined && n !== false));
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

const dateTime = new Intl.DateTimeFormat("fr-CA", { dateStyle: "medium", timeStyle: "short" });
const shortDate = new Intl.DateTimeFormat("fr-CA", { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
const dayTitle = new Intl.DateTimeFormat("fr-CA", { weekday: "long", day: "numeric", month: "long", year: "numeric" });
const clock = new Intl.DateTimeFormat("fr-CA", { hour: "2-digit", minute: "2-digit" });

const when = (iso) => (iso ? dateTime.format(new Date(iso)) : "—");
const short = (iso) => (iso ? shortDate.format(new Date(iso)) : "—");

function ago(iso) {
  if (!iso) return "—";
  const minutes = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return "à l'instant";
  if (minutes < 60) return `il y a ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `il y a ${hours} h`;
  return `il y a ${Math.round(hours / 24)} j`;
}

const pad = (n, width) => String(n).padStart(width, "0");
const vendorOf = (d) => (d.randomized ? "Adresse privée" : d.vendor || "");
const deviceName = (d) => d.displayName || d.hostname || vendorOf(d) || d.mac;
const networkName = (n) => n.label || n.subnet;

function monitoring(n) {
  if (n.trust !== "owned" && n.trust !== "authorized") return "Rien n'est capturé sur ce réseau.";
  if (n.learningUntil && new Date(n.learningUntil) > new Date()) {
    return `Surveillé. Apprentissage jusqu'au ${when(n.learningUntil)} : pas d'alerte d'appareil d'ici là.`;
  }
  return "Surveillé.";
}

/** Entry numbers in order of first appearance, like the lines of a ledger. */
function entryNumbers(devices) {
  const ordered = [...devices].sort((a, b) => a.firstSeen.localeCompare(b.firstSeen) || a.id - b.id);
  return new Map(ordered.map((d, i) => [d.id, i + 1]));
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

// --- Registers (networks) ----------------------------------------------------------------

async function networksView() {
  const networks = await api("GET", "/ui/networks");
  document.title = "Registres · NetLedger";
  const intro = el(
    "p",
    { class: "warning" },
    "NetLedger ne capture rien sur un réseau tant que vous ne l'avez pas déclaré comme le vôtre, ou autorisé par son administrateur.",
  );
  if (networks.length === 0) {
    return show(
      el("h1", {}, "Registres"),
      intro,
      el("p", { class: "empty" }, "Aucun réseau pour l'instant. Lancez l'agent : le réseau courant s'inscrira ici."),
    );
  }
  show(
    el("p", { class: "folio" }, `${networks.length} registre(s)`),
    el("h1", {}, "Registres"),
    intro,
    el("h2", { class: "section" }, "Réseaux rencontrés"),
    el("div", { class: "entries" }, networks.map(networkEntry)),
  );
}

function networkEntry(n) {
  const trust = el(
    "select",
    {
      id: `trust-${n.id}`,
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
    "section",
    { class: "entry" + (n.trust === "unset" ? " pending" : "") },
    el("div", { class: "num", "aria-label": `Folio ${n.id}` }, pad(n.id, 2)),
    el(
      "div",
      {},
      el("h3", {}, link(`/networks/${n.id}`, networkName(n))),
      el("p", { class: "mono muted" }, `${n.subnet} · passerelle ${n.gatewayMac}`),
      el("p", {}, monitoring(n)),
      el(
        "p",
        { class: "muted" },
        `${n.devices} inscription(s)`,
        n.newDevices ? el("span", { class: "red" }, ` · ${n.newDevices} à viser`) : null,
        ` · vu ${ago(n.lastSeen)}`,
      ),
      n.trust === "unset" ? el("p", { class: "red" }, "Choisissez un statut : rien n'est capturé d'ici là.") : null,
      el(
        "div",
        { class: "actions" },
        link(`/networks/${n.id}`, "Ouvrir le registre"),
        link(`/events?network=${n.id}`, "Journal"),
        el("a", { href: `/ui/networks/${n.id}/inventory.csv`, download: true }, "Export CSV"),
        el("a", { href: `/ui/networks/${n.id}/inventory.json`, download: true }, "Export JSON"),
        textButton("Renommer", async () => {
          const label = prompt("Nom du registre (vide pour effacer)", n.label || "");
          if (label === null) return;
          await run(() => api("PATCH", `/ui/networks/${n.id}`, { label }), "Nom enregistré");
          route();
        }),
        textButton(
          "Supprimer",
          async () => {
            if (!confirm(`Supprimer « ${networkName(n)} » et tout son historique (${n.devices} inscription(s)) ? C'est définitif.`)) return;
            await run(() => api("DELETE", `/ui/networks/${n.id}`), "Registre supprimé");
            route();
          },
          true,
        ),
      ),
    ),
    el("div", { class: "status" }, el("label", { for: `trust-${n.id}` }, "statut"), trust),
  );
}

// --- One register: address plan and ledger ---------------------------------------------------

const ipToInt = (ip) => ip.split(".").reduce((acc, part) => acc * 256 + Number(part), 0);
const intToIp = (n) => [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join(".");

/** One square per address, for subnets up to /22 (1024 addresses); null for larger ones. */
function addressPlan(subnet, devices) {
  const [base, bits] = subnet.split("/");
  const prefix = Number(bits);
  if (!(prefix >= 22 && prefix <= 30)) return null;
  const start = ipToInt(base);
  const size = 2 ** (32 - prefix);
  const used = new Map();
  for (const d of devices) {
    if (!d.lastIp) continue;
    const offset = ipToInt(d.lastIp) - start;
    if (offset >= 0 && offset < size) used.set(offset, d);
  }
  const cells = [];
  for (let i = 0; i < size; i++) {
    const ip = intToIp(start + i);
    const d = used.get(i);
    cells.push(
      d
        ? el("a", { class: `cell ${d.status}`, href: `/devices/${d.id}`, "data-link": true, title: `${ip} · ${deviceName(d)} · ${VISA[d.status]}` })
        : el("span", { class: "cell", title: `${ip} · libre` }),
    );
  }
  const grid = el("div", { class: "grid" }, cells);
  // Set through the CSSOM: the Content Security Policy forbids inline style attributes.
  grid.style.gridTemplateColumns = `repeat(${Math.min(32, size)}, 1fr)`;
  const legend = [
    ["approved", "approuvé"],
    ["guest", "invité"],
    ["new", "à viser"],
    ["suspect", "suspect"],
    ["", "libre"],
  ];
  return el(
    "div",
    { class: "plan" },
    el("h2", { class: "section" }, "Plan d'adressage"),
    el("p", { class: "mono muted" }, `${intToIp(start)} → ${intToIp(start + size - 1)} · ${used.size} adresse(s) occupée(s) sur ${size}`),
    grid,
    el("div", { class: "legend" }, legend.map(([status, label]) => el("span", {}, el("span", { class: "cell " + status }), label))),
  );
}

async function networkView(id) {
  const [network, devices] = await Promise.all([
    api("GET", `/ui/networks/${id}`),
    api("GET", `/ui/networks/${id}/devices`),
  ]);
  document.title = `${networkName(network)} · NetLedger`;
  const numbers = entryNumbers(devices);
  const search = el("input", { type: "search", placeholder: "nom, fabricant, IP ou MAC", "aria-label": "Rechercher" });
  const status = el(
    "select",
    { "aria-label": "Visa" },
    el("option", { value: "" }, "tous les visas"),
    Object.entries(VISA).map(([value, label]) => el("option", { value }, label)),
  );
  const type = el(
    "select",
    { "aria-label": "Type" },
    el("option", { value: "" }, "tous les types"),
    Object.entries(TYPE).map(([value, label]) => el("option", { value }, label.toLowerCase())),
  );
  const body = el("tbody");
  const count = el("span", { class: "muted" });

  const refresh = () => {
    const q = search.value.trim().toLowerCase();
    const rows = devices
      .filter(
        (d) =>
          (!status.value || d.status === status.value) &&
          (!type.value || d.type === type.value) &&
          (!q ||
            [d.displayName, d.hostname, vendorOf(d), d.lastIp, d.mac, d.category]
              .filter(Boolean)
              .some((v) => v.toLowerCase().includes(q))),
      )
      .sort((a, b) => numbers.get(b.id) - numbers.get(a.id));
    count.textContent = `${rows.length} inscription(s) sur ${devices.length}`;
    body.replaceChildren(
      ...rows.map((d) =>
        el(
          "tr",
          {
            class: "row",
            onclick: (e) => {
              if (!e.target.closest("a")) navigate(`/devices/${d.id}`);
            },
          },
          el("td", { class: "no" }, pad(numbers.get(d.id), 3)),
          el(
            "td",
            {},
            el("div", { class: "name" }, link(`/devices/${d.id}`, deviceName(d))),
            d.category ? el("div", { class: "note" }, d.category) : null,
          ),
          el("td", {}, vendorOf(d) || "—"),
          el("td", {}, TYPE[d.type] || "—"),
          el("td", {}, mono(d.lastIp || "—")),
          el("td", {}, mono(d.mac)),
          el("td", {}, mono(short(d.firstSeen))),
          el("td", { title: when(d.lastSeen), class: "nowrap" }, ago(d.lastSeen)),
          el("td", {}, visa(d.status)),
        ),
      ),
    );
  };
  search.addEventListener("input", refresh);
  status.addEventListener("change", refresh);
  type.addEventListener("change", refresh);
  refresh();

  show(
    el("p", { class: "back" }, link("/networks", "← Registres")),
    el("p", { class: "folio" }, `Folio ${pad(network.id, 2)} · ${TRUST[network.trust]}`),
    el("h1", {}, `Registre — ${networkName(network)}`),
    el("p", { class: "sub" }, `${network.subnet}. ${monitoring(network)}`),
    addressPlan(network.subnet, devices),
    el("h2", { class: "section" }, "Inscriptions"),
    devices.length === 0
      ? el("p", { class: "empty" }, "Aucun appareil inscrit sur ce réseau.")
      : [
          el("div", { class: "filters" }, search, status, type, count),
          el(
            "div",
            { class: "scroll" },
            el(
              "table",
              { class: "ledger" },
              el(
                "thead",
                {},
                el(
                  "tr",
                  {},
                  el("th", { class: "no" }, "n°"),
                  ["Appareil", "Fabricant", "Type", "Adresse IP", "MAC", "Inscrit le", "Vu", "Visa"].map((h) => el("th", {}, h)),
                ),
              ),
              body,
            ),
          ),
        ],
  );
}

// --- One entry (device) -------------------------------------------------------------------

function fact(label, value, monospace) {
  return el(
    "div",
    { class: "fact" },
    el("span", { class: "k" }, label),
    el("span", { class: "dots", "aria-hidden": "true" }),
    el("span", { class: "v" + (monospace ? " mono" : "") }, value),
  );
}

function ledgerTable(headers, rows, cells) {
  if (!rows.length) return el("p", { class: "empty" }, "Rien pour l'instant.");
  return el(
    "div",
    { class: "scroll" },
    el(
      "table",
      { class: "ledger" },
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

async function deviceView(id) {
  const detail = await api("GET", `/ui/devices/${id}`);
  const d = detail.device;
  const number = entryNumbers([d, ...detail.mergeCandidates]).get(d.id);
  document.title = `${deviceName(d)} · NetLedger`;

  const name = el("input", { id: "name", value: d.displayName || "", maxlength: 64, placeholder: d.hostname || "" });
  const category = el("input", { id: "category", value: d.category || "", maxlength: 32, list: "categories" });
  const fields = el(
    "form",
    {
      class: "fields",
      onsubmit: async (e) => {
        e.preventDefault();
        await run(() => api("PATCH", `/ui/devices/${id}`, { displayName: name.value, category: category.value }), "Inscription mise à jour");
        route();
      },
    },
    el("label", { for: "name" }, "nom", name),
    el("label", { for: "category" }, "catégorie", category),
    el("datalist", { id: "categories" }, CATEGORIES.map((c) => el("option", { value: c }))),
    el("button", { type: "submit", class: "textbtn" }, "Enregistrer"),
  );

  const stamps = el(
    "div",
    { class: "stamps" },
    STAMPS.map(([value, label]) =>
      el(
        "button",
        {
          type: "button",
          class: "stamp " + value,
          "aria-pressed": String(d.status === value),
          onclick: async () => {
            await run(() => api("PATCH", `/ui/devices/${id}`, { status: value }), `Visa : ${VISA[value]}`);
            route();
          },
        },
        el("span", {}, label),
      ),
    ),
  );

  const candidates = [...detail.mergeCandidates].sort(
    (a, b) => (b.status === "approved") - (a.status === "approved") || deviceName(a).localeCompare(deviceName(b)),
  );
  const target = el(
    "select",
    { "aria-label": "Inscription à garder" },
    el("option", { value: "" }, "choisir l'appareil connu…"),
    candidates.map((c) => el("option", { value: c.id }, `${deviceName(c)} · ${VISA[c.status]} · ${c.mac}`)),
  );
  const merge = el(
    "form",
    {
      class: "fields",
      onsubmit: async (e) => {
        e.preventDefault();
        if (!target.value) return;
        const chosen = candidates.find((c) => String(c.id) === target.value);
        if (!confirm(`Reporter cette inscription sur « ${deviceName(chosen)} » ? Son historique y sera rattaché et celle-ci sera rayée.`)) return;
        const kept = await run(() => api("POST", `/ui/devices/${id}/merge`, { into: Number(target.value) }), "Inscriptions fusionnées");
        if (kept) navigate(`/devices/${kept.id}`);
      },
    },
    target,
    el("button", { type: "submit", class: "textbtn" }, "Fusionner"),
  );

  show(
    el("p", { class: "back" }, link(`/networks/${d.networkId}`, `← Registre — ${networkName(detail.network)}`)),
    el("p", { class: "folio" }, `Inscription n° ${pad(number, 3)} · folio ${pad(d.networkId, 2)}`),
    el("h1", {}, deviceName(d), " ", visa(d.status)),
    el("p", { class: "sub" }, `${TYPE[d.type] || "Type inconnu"} · ${vendorOf(d) || "fabricant inconnu"}`),
    el(
      "div",
      { class: "columns" },
      el(
        "div",
        {},
        el("h2", { class: "section" }, "Signalement"),
        fact("Adresse MAC", d.mac, true),
        fact("Fabricant", vendorOf(d) || "—"),
        fact("Type probable", TYPE[d.type] || "—"),
        fact("Dernière adresse IP", d.lastIp || "—", true),
        fact("Nom d'hôte", d.hostname || "—"),
        fact("Empreinte DHCP", d.dhcpFingerprint || "—", true),
        fact("Inscrit le", when(d.firstSeen)),
        fact("Vu pour la dernière fois", `${when(d.lastSeen)} (${ago(d.lastSeen)})`),
      ),
      el(
        "div",
        {},
        el("h2", { class: "section" }, "Annotations"),
        fields,
        el("h2", { class: "section" }, "Visa"),
        stamps,
        el("h2", { class: "section" }, "Même appareil qu'une autre inscription ?"),
        el("p", { class: "muted" }, "Un téléphone qui change d'adresse privée s'inscrit une seconde fois : reportez cette inscription sur l'appareil connu."),
        candidates.length ? merge : el("p", { class: "empty" }, "Aucune autre inscription sur ce réseau."),
      ),
    ),
    el("h2", { class: "section" }, "Adresses IP"),
    ledgerTable(["Adresse", "Première fois", "Dernière fois"], detail.ips, (ip) => [mono(ip.ip), when(ip.firstSeen), when(ip.lastSeen)]),
    el("h2", { class: "section" }, "Services annoncés"),
    ledgerTable(["Type", "Nom", "Port", "Vu"], detail.services, (s) => [mono(s.type), s.name || "—", mono(s.port ?? "—"), ago(s.lastSeen)]),
    el("h2", { class: "section" }, "Journal de l'appareil"),
    journal(detail.events, false),
    el("h2", { class: "section" }, `Observations récentes (${detail.observations.length})`),
    ledgerTable(["Source", "Adresse", "Détail", "Moment"], detail.observations, (o) => [
      SOURCE[o.source] || o.source,
      mono(o.ip || "—"),
      observationDetail(o.detail),
      mono(short(o.observedAt)),
    ]),
  );
}

// --- Journal (events) -----------------------------------------------------------------------

function journal(events, withNetwork) {
  if (!events.length) return el("p", { class: "empty" }, "Aucun événement.");
  const days = new Map();
  for (const e of events) {
    const day = dayTitle.format(new Date(e.occurredAt));
    if (!days.has(day)) days.set(day, []);
    days.get(day).push(e);
  }
  return [...days].map(([day, list]) => [
    el("h3", { class: "day" }, day),
    el(
      "ul",
      { class: "journal" },
      list.map((e) =>
        el(
          "li",
          {},
          el("span", { class: "time" }, clock.format(new Date(e.occurredAt))),
          el(
            "div",
            {},
            el("div", { class: "title" }, e.title),
            el("div", {}, e.message),
            el(
              "div",
              { class: "meta" },
              e.deviceId ? link(`/devices/${e.deviceId}`, e.deviceLabel || "voir l'inscription") : null,
              e.deviceId && withNetwork ? " · " : null,
              withNetwork ? link(`/networks/${e.networkId}`, `folio ${pad(e.networkId, 2)}`) : null,
            ),
          ),
        ),
      ),
    ),
  ]);
}

async function eventsView(params) {
  const network = params.get("network");
  const [events, networks] = await Promise.all([
    api("GET", "/ui/events" + (network ? `?network=${encodeURIComponent(network)}` : "")),
    api("GET", "/ui/networks"),
  ]);
  document.title = "Journal · NetLedger";
  const filter = el(
    "select",
    {
      "aria-label": "Registre",
      onchange: (e) => navigate(e.target.value ? `/events?network=${e.target.value}` : "/events"),
    },
    el("option", { value: "" }, "tous les registres"),
    networks.map((n) => el("option", { value: n.id, selected: String(n.id) === network }, networkName(n))),
  );
  show(
    el("p", { class: "folio" }, `${events.length} entrée(s)`),
    el("h1", {}, "Journal"),
    el("p", { class: "sub" }, "Alertes et événements, du plus récent au plus ancien."),
    el("div", { class: "filters" }, filter),
    journal(events, !network),
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
