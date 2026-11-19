# Security policy

NetLedger is a defensive tool: it listens passively to ARP, DHCP and mDNS on networks its user owns or is authorized to monitor. A flaw that would let it capture without that authorization, leak what it collects, or let someone else drive it is a security issue.

## Reporting

Please report vulnerabilities privately through GitHub: **Security › Report a vulnerability** on this repository. Do not open a public issue. You will get an answer within a week.

## In scope

- Capture starting on a network whose status is not "owned" or "authorized".
- Anything that reaches the server from another machine (the port is meant to be published on `127.0.0.1` only).
- Agent API authentication (shared bearer token), request size limits, error responses.
- Dashboard: CSRF, DNS rebinding (`Host` check), content security policy, rendering or exporting hostile host names and mDNS names.
- Packet decoders fed with malformed or hostile frames (name compression loops, truncated options, oversized fields).
- Token storage in the macOS keychain and in `.env`.

## Out of scope

- Attacks requiring code execution as the same macOS user: such an attacker can already read the keychain item and the `.env` file.
- Gatekeeper warnings: the app is not signed with an Apple developer account (see the README).
- Denial of service by flooding the local network with broadcast traffic: the agent deduplicates and bounds its buffer, but a saturated network is not something it can fix.

## Design notes

The threat model and the reasoning behind each protection are in [docs/architecture.md](docs/architecture.md#threat-model).
