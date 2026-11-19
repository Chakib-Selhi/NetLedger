# Protocols

NetLedger learns about devices from three protocols that are broadcast or multicast on purpose, so a single machine on a switched or Wi-Fi network receives them without any interception. This page shows what each frame looks like on the wire and which fields NetLedger keeps.

The kernel filter given to libpcap is:

```
arp or (udp and (port 67 or port 68 or port 5353))
```

Everything else is dropped by the kernel before the agent sees it. Frames are decoded in memory and discarded: no full packet is ever stored or sent to the server.

## ARP (RFC 826)

ARP maps an IPv4 address to a MAC address on the local link. Every device that joins the network or talks to another one sends ARP, which makes it the most reliable presence signal.

```
offset  size  field
 0      2     hardware type        1 = Ethernet
 2      2     protocol type        0x0800 = IPv4
 4      1     hardware length      6
 5      1     protocol length      4
 6      2     operation            1 = request, 2 = reply
 8      6     sender MAC  ◀── kept
14      4     sender IPv4 ◀── kept
18      6     target MAC
24      4     target IPv4
```

The sender pair is what a device says about itself, so it becomes the observation.

- **Probe (RFC 5227).** Sender IPv4 `0.0.0.0`: a device asks "is this address free?" before using it. Only its presence is recorded, not the address.
- **Gratuitous ARP.** Sender IPv4 equal to target IPv4: a device announces its address. It is kept.
- **Spoofing.** An IP the gateway or an approved device used in the last 24 hours, announced by another MAC, raises an "IP conflict" alert: that is the visible part of an ARP spoofing (man in the middle) attack.

## DHCP (RFC 2131)

A device joining a network asks for an address with DHCP (Discover, Offer, Request, Ack). Its requests are broadcast from UDP port 68 to port 67 and say a lot about the device.

```
offset  size  field
  0     1     op        1 = BOOTREQUEST (client) ◀── only client messages are decoded
  1     1     htype     1 = Ethernet
  2     1     hlen      6
  3     1     hops
  4     4     xid       transaction id
  8     2     secs
 10     2     flags
 12     4     ciaddr    client address (renewal)
 16     4     yiaddr
 20     4     siaddr
 24     4     giaddr
 28    16     chaddr    client MAC
 44    64     sname
108   128     file
236     4     magic cookie  99.130.83.99
240     …     options: code (1 byte), length (1 byte), value; 0 = pad, 255 = end
```

NetLedger decodes Discover and Request messages (option 53 = 1 or 3) and keeps:

| Option | Meaning | Use |
| --- | --- | --- |
| 12 | Host name | device name |
| 50 | Requested IP | address, else `ciaddr` |
| 53 | Message type | Discover or Request only |
| 55 | Parameter request list | **fingerprint**: each OS asks for options in its own order |
| 60 | Vendor class | e.g. `android-dhcp-14` |
| 61 | Client identifier | presence |

The parameter request list is a well known passive OS fingerprint. macOS, for example, asks for `1,121,3,6,15,108,114,119,162,252,95,44,46`. Fingerprints observed on real devices are listed in `server/src/main/resources/identification/dhcp-fingerprints.csv`.

Limitation: an iPhone returning to a network it knows may skip DHCP entirely and reuse its address after checking the gateway (DNAv4, RFC 4436). ARP and mDNS still see it.

## mDNS and DNS-SD (RFC 6762, RFC 6763)

Multicast DNS lets devices resolve `.local` names and announce services without a DNS server, on `224.0.0.251`, UDP port 5353. DNS-SD builds service discovery on top: printers, AirPlay receivers and Chromecasts announce themselves this way.

A message is a regular DNS message:

```
offset  size  field
 0      2     id         0 in mDNS
 2      2     flags      bit 15: response
 4      2     questions
 6      2     answers
 8      2     authority records
10      2     additional records
12      …     questions, then resource records
```

A name is a sequence of labels (length byte, then bytes) ending with 0. To save space, a name may end with a **compression pointer**: two bytes starting with bits `11`, holding the offset of the rest of the name earlier in the message.

| Record | Example | What NetLedger learns |
| --- | --- | --- |
| A / AAAA | `printer.local → 192.168.1.40` | host name |
| PTR | `_ipp._tcp.local → Brother HL-L2350._ipp._tcp.local` | a service instance |
| PTR | `_services._dns-sd._udp.local → _airplay._tcp.local` | a service type the device offers |
| SRV | `Brother HL-L2350._ipp._tcp.local → port 631, printer.local` | service port and host |
| PTR | `40.1.168.192.in-addr.arpa → printer.local` | reverse mapping, another host name |

In resource records, the top bit of the class field is the **cache-flush** bit, masked before the class is read; in questions the same bit is the **QU** bit (unicast response wanted). A query (not a response) only proves the sender is present.

**Hostile input.** Anyone on the network can send mDNS, so the parser assumes the worst:

- compression pointers may only point backward, which rules out loops;
- at most 16 pointer jumps and 255 bytes per name;
- every read is bounds-checked; a malformed message is rejected, never half-parsed;
- control characters are stripped from names before they are stored.

**Active query.** On monitored networks the agent sends one mDNS question for `_services._dns-sd._udp.local` every 15 minutes, then asks for the instances of a few identifying types (`_airplay._tcp`, `_raop._tcp`, `_googlecast._tcp`, `_ipp._tcp`, `_printer._tcp`). It never announces anything itself.

**Proxies.** An Apple TV or HomePod (Bonjour sleep proxy) and Thread border routers (DNS-SD discovery proxy, RFC 8766) answer for other devices. Their bare service type lists are ignored for identification; only services backed by an instance of their own count.

## MAC addresses

The first three bytes of a MAC address are the vendor's Organizationally Unique Identifier. NetLedger looks them up in the IEEE registry (MA-L, then MA-M and MA-S for the longer 28- and 36-bit blocks), always taking the longest matching prefix.

The second-lowest bit of the first byte is the **locally administered** bit. Phones and computers set it for their private Wi-Fi addresses (`3a:…`, `7a:…`): such an address carries no vendor, so NetLedger shows "Adresse privée". A device can be recognized across a new private address by its host name and DHCP fingerprint, and the dashboard can merge the two records.
