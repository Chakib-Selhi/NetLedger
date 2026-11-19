# Changelog

## 1.1.0 — 2026-11-19

### Dashboard

- New ledger design: cream paper and ruled lines, numbered entries, red ink for devices to review, rubber-stamp statuses, serif and monospace type, automatic dark theme.
- Address plan: one square per address of the subnet (up to /22), colored by status, each linking to its device.
- Journal grouped by day.

## 1.0.0 — 2026-11-19

First release.

### Agent (macOS)

- Passive capture of ARP, DHCP and mDNS with pcap4j, through the `access_bpf` group (no administrator rights), only on networks marked "owned" or "authorized".
- Current network recognized by gateway MAC and subnet; sleep and network changes detected.
- Bounded buffer (10,000 observations, 60-second deduplication), batches, backoff while the server is down.
- Optional ARP sweep, off by default, limited to "owned" networks.
- Alerts over Server-Sent Events, macOS notifications, menu bar icon with pause, recent alerts and dashboard link.
- Setup assistant: BPF access, local network access, keychain token, server.
- Packaged as `NetLedger.app` and `.dmg`; the agent runs as a per-user `launchd` job, without start at login.

### Server (Docker)

- Agent API protected by a shared bearer token; port published on `127.0.0.1` only.
- Correlation into devices with IP history and mDNS services; SQLite with Flyway; raw observations kept 30 days.
- Vendor from the IEEE registry, refreshed monthly; probable type from deterministic rules; private address detection.
- Alerts: new network, new device, known device with a new address, suspect device back, IP conflict; 24-hour learning period; no repeat within an hour.
- Dashboard: networks and trust, filterable device list, device page (name, category, status, merge), timeline, CSV and JSON export.
- Dashboard security: CSRF, Host check against DNS rebinding, strict Content Security Policy, CSV formula neutralization.
- Hardened container: non-root, read-only, no capabilities, `no-new-privileges`, memory limit.
