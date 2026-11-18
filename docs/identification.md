# Device identification

How the server derives a device's vendor and probable type. Everything is deterministic: no
machine learning, no external service. Code: `server/.../identification/`.

## Vendor (EF-08)

The IEEE assigns MAC address blocks of three sizes, identified by the first bits of the address:

| Registry | Prefix | Addresses | File |
| --- | --- | --- | --- |
| MA-L ("OUI") | 24 bits (6 hex digits) | 16 M | `oui/oui.csv` |
| MA-M | 28 bits (7 hex digits) | 1 M | `oui28/mam.csv` |
| MA-S | 36 bits (9 hex digits) | 4096 | `oui36/oui36.csv` |

MA-M and MA-S blocks are carved out of MA-L blocks registered to "IEEE Registration Authority",
so the **longest matching prefix wins**. Blocks registered as "Private" give no vendor.

The Docker image ships a copy of the three files, so identification works offline. When
`NETLEDGER_OUI_UPDATE=true` (the default in the image), the server downloads the registry into
the data volume when it is missing or older than 30 days. A download replaces the files only
after they parse and contain at least 1,000 entries.

## Private (randomized) addresses (EF-09)

Bit 1 of the first octet (the U/L bit) marks *locally administered* addresses. Phones and
computers use such random addresses per Wi-Fi network. They belong to no vendor, so the vendor
stays empty, `mac_randomized = 1`, and the dashboard shows "Adresse privée".

## Probable type (EF-10)

Rules are evaluated in this order; the first match wins.

| # | Clue | Type |
| --- | --- | --- |
| 1 | mDNS service `_ipp` or `_printer` | `printer` |
| 2 | `_googlecast` or `_airplay`, without `_companion-link` | `tv` |
| 3 | DHCP fingerprint of iOS or Android, and a private address | `phone` |
| 4 | `_ssh` or `_smb`, or DHCP fingerprint of macOS, Windows or Linux | `computer` |
| 5 | Vendor in the IoT vendor list | `iot` |
| 6 | Nothing above | `unknown` |

Rule 2 excludes `_companion-link` because Apple phones, tablets and Macs announce it next to
AirPlay, while Apple TVs and AirPlay speakers are the targets of a cast.

### Proxies

Some devices answer service type enumerations (`_services._dns-sd._udp.local`) for the whole
network: DNS-SD discovery proxies (RFC 8766, service `_dnssd-server._udp`) and Bonjour sleep
proxies (`_sleep-proxy._udp`). An Amazon Echo acting as a Thread border router was seen listing
25 service types, including the printer's and a computer's. For a device announcing one of these
two services, the rules only consider services it backs with an instance of its own (a name and
a port), not bare enumerated types. Such a device is more often "unknown" than wrong.

### Data files

Both live in `server/src/main/resources/identification/` and can be edited without code changes.

- `dhcp-fingerprints.csv`: DHCP option 55 lists (comma separated, in order) and the operating
  system family that sends them. Only fingerprints observed on real devices are listed, with
  their source. Option 55 is the list of parameters a client requests; its content and order
  depend on the DHCP client of the operating system, which makes it a fingerprint.
- `iot-vendors.txt`: IEEE organization names (case-insensitive substring) of vendors that mostly
  make connected objects. Vendors that also make phones, computers or TVs are left out.

## Limits

- Fingerprints are only known for systems actually observed; others stay unidentified.
- A Bonjour sleep proxy answers for sleeping devices with its own MAC address, so some records
  can be attributed to the proxy.
- Types are a best guess. The user can always rename a device and set its category.
