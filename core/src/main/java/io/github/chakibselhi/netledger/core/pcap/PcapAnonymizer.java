package io.github.chakibselhi.netledger.core.pcap;

import io.github.chakibselhi.netledger.core.decode.DhcpMessage;
import io.github.chakibselhi.netledger.core.decode.DnsMessage;
import io.github.chakibselhi.netledger.core.decode.DnsName;
import io.github.chakibselhi.netledger.core.decode.MalformedPacketException;
import io.github.chakibselhi.netledger.core.decode.PacketLayout;
import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Anonymizes capture files so they can be published as test fixtures, while keeping every packet
 * structurally valid (same lengths, valid UDP checksums):
 *
 * <ul>
 *   <li>MAC addresses keep their first 3 bytes (OUI, the vendor, needed by identification tests)
 *       and get new last 3 bytes. Randomized (locally administered) addresses are fully replaced.
 *   <li>Device names (DNS labels, DHCP host name) become placeholders of the same byte length.
 *   <li>TXT values become {@code x} characters; keys are kept.
 *   <li>IPv6 unicast addresses are replaced: link-local ones keep fe80::/64, others move to the
 *       documentation prefix 2001:db8::/32, since a global prefix reveals the subscriber.
 * </ul>
 *
 * <p>Replacements are derived from a random per-run salt, so they are consistent within one run
 * (the same device keeps the same new address across files) but cannot be reversed.
 */
public final class PcapAnonymizer {

  private static final Set<String> STRUCTURAL_LABELS = Set.of("local", "arpa", "in-addr", "ip6");
  private static final int MIN_LEAK_CHECK_LENGTH = 3;
  private static final HexFormat HEX = HexFormat.of();

  private final byte[] salt;
  private final Map<String, byte[]> macs = new LinkedHashMap<>();
  private final Map<String, byte[]> ipv6Addresses = new LinkedHashMap<>();
  private final Map<String, String> names = new LinkedHashMap<>();

  public PcapAnonymizer(byte[] salt) {
    this.salt = salt.clone();
  }

  public static void main(String[] args) throws IOException {
    if (args.length != 2) {
      System.err.println("Usage: PcapAnonymizer <input dir> <output dir>");
      System.exit(64);
    }
    Path input = Path.of(args[0]);
    Path output = Path.of(args[1]);
    List<Path> paths;
    try (Stream<Path> listing = Files.list(input)) {
      paths = listing.filter(p -> p.toString().endsWith(".pcap")).sorted().toList();
    }
    var originals = new ArrayList<PcapFile>();
    for (Path path : paths) {
      originals.add(PcapReader.read(path));
    }
    var salt = new byte[32];
    new SecureRandom().nextBytes(salt);
    var anonymizer = new PcapAnonymizer(salt);
    List<PcapFile> anonymized = anonymizer.anonymize(originals);
    List<String> leaks = anonymizer.findLeaks(anonymized);
    if (!leaks.isEmpty()) {
      System.err.println("Refusing to write: " + leaks.size() + " original value(s) still present");
      System.exit(1);
    }
    Files.createDirectories(output);
    for (int i = 0; i < paths.size(); i++) {
      PcapWriter.write(output.resolve(paths.get(i).getFileName()), anonymized.get(i));
    }
    System.out.printf(
        "%d file(s): %d MAC, %d IPv6 address(es) and %d name(s) replaced, no leak found.%n",
        paths.size(),
        anonymizer.macs.size(),
        anonymizer.ipv6Addresses.size(),
        anonymizer.names.size());
  }

  /** Anonymizes all files with one consistent mapping. */
  public List<PcapFile> anonymize(List<PcapFile> files) {
    files.forEach(f -> f.records().forEach(r -> collect(r.data())));
    return files.stream()
        .map(
            f ->
                new PcapFile(
                    f.linkType(),
                    f.snapLength(),
                    f.records().stream()
                        .map(
                            r ->
                                new PcapRecord(
                                    r.timestamp(), rewrite(r.data().clone()), r.originalLength()))
                        .toList()))
        .toList();
  }

  /** Describes every original MAC, IPv6 address or name still found in the given files. */
  public List<String> findLeaks(List<PcapFile> files) {
    var leaks = new ArrayList<String>();
    for (PcapFile file : files) {
      for (PcapRecord record : file.records()) {
        byte[] data = record.data();
        macs.keySet().stream()
            .filter(mac -> indexOf(data, HEX.parseHex(mac), 0) >= 0)
            .forEach(mac -> leaks.add("MAC " + mac));
        ipv6Addresses.keySet().stream()
            .filter(address -> indexOf(data, HEX.parseHex(address), 0) >= 0)
            .forEach(address -> leaks.add("IPv6 " + address));
        // Names travel length-prefixed (DNS labels, DHCP option 12); a bare substring match would
        // flag unrelated text, such as a short host name inside an Apple TXT key.
        names.keySet().stream()
            .map(PcapAnonymizer::lengthPrefixed)
            .filter(bytes -> bytes.length > MIN_LEAK_CHECK_LENGTH && indexOf(data, bytes, 0) >= 0)
            .forEach(bytes -> leaks.add("name of " + (bytes.length - 1) + " bytes"));
      }
    }
    return leaks;
  }

  Map<String, String> names() {
    return names;
  }

  private void collect(byte[] frame) {
    if (frame.length >= 12) {
      addMac(frame, 0);
      addMac(frame, 6);
    }
    try {
      PacketLayout layout = PacketLayout.parse(frame);
      if (layout.etherType() == PacketLayout.ETHERTYPE_ARP
          && frame.length >= layout.payloadOffset() + 28) {
        addMac(frame, layout.payloadOffset() + 8);
        addMac(frame, layout.payloadOffset() + 18);
      }
      if (layout.etherType() == PacketLayout.ETHERTYPE_IPV6) {
        addIpv6(frame, layout.payloadOffset() + 8);
        addIpv6(frame, layout.payloadOffset() + 24);
      }
      PacketLayout.Udp udp = layout.udp();
      if (udp == null) {
        return;
      }
      if (isDhcp(udp)) {
        DhcpMessage.parse(frame, udp.payloadOffset(), udp.payloadLength())
            .ifPresent(
                message -> {
                  addMac(frame, message.clientMacOffset());
                  message
                      .option(DhcpMessage.OPTION_HOST_NAME)
                      .ifPresent(
                          o ->
                              addName(
                                  new String(
                                      frame, o.valueOffset(), o.length(), StandardCharsets.UTF_8)));
                });
      } else if (isMdns(udp)) {
        DnsMessage message = DnsMessage.parse(frame, udp.payloadOffset(), udp.payloadLength());
        message.questions().forEach(q -> addLabels(q.name()));
        for (DnsMessage.ResourceRecord record : message.records()) {
          addLabels(record.name());
          if (record.target() != null) {
            addLabels(record.target());
          }
          if (record.type() == DnsMessage.TYPE_AAAA) {
            addIpv6(frame, record.rdataOffset());
          }
        }
      }
    } catch (MalformedPacketException e) {
      // Undecodable frames still get their Ethernet addresses replaced.
    }
  }

  private byte[] rewrite(byte[] frame) {
    PacketLayout.Udp udp = null;
    try {
      udp = PacketLayout.parse(frame).udp();
      if (udp != null && isMdns(udp)) {
        maskTxtValues(frame, DnsMessage.parse(frame, udp.payloadOffset(), udp.payloadLength()));
      }
    } catch (MalformedPacketException e) {
      udp = null;
    }
    macs.forEach((original, replacement) -> replaceAll(frame, HEX.parseHex(original), replacement));
    ipv6Addresses.forEach(
        (original, replacement) -> replaceAll(frame, HEX.parseHex(original), replacement));
    if (udp != null) {
      int start = udp.payloadOffset();
      int end = start + udp.payloadLength();
      for (Map.Entry<String, String> name : names.entrySet()) {
        replaceLengthPrefixed(frame, start, end, name.getKey(), name.getValue());
      }
      UdpChecksum.update(frame, udp);
    }
    return frame;
  }

  private void addMac(byte[] data, int offset) {
    if (offset + MacAddresses.LENGTH > data.length || !MacAddresses.isUnicast(data, offset)) {
      return;
    }
    String key = HEX.formatHex(data, offset, offset + MacAddresses.LENGTH);
    macs.computeIfAbsent(
        key,
        k -> {
          byte[] original = HEX.parseHex(k);
          byte[] hash = hash(original);
          byte[] replacement = original.clone();
          if (MacAddresses.isLocallyAdministered(original, 0)) {
            replacement[0] = (byte) ((hash[0] & 0xFC) | 0x02);
            replacement[1] = hash[1];
            replacement[2] = hash[2];
          }
          replacement[3] = hash[3];
          replacement[4] = hash[4];
          replacement[5] = hash[5];
          return replacement;
        });
  }

  private void addIpv6(byte[] data, int offset) {
    if (offset + 16 > data.length) {
      return;
    }
    int first = data[offset] & 0xFF;
    boolean unspecified = true;
    for (int i = 0; i < 16; i++) {
      unspecified &= data[offset + i] == 0;
    }
    if (first == 0xFF || unspecified) {
      return;
    }
    String key = HEX.formatHex(data, offset, offset + 16);
    ipv6Addresses.computeIfAbsent(
        key,
        k -> {
          byte[] original = HEX.parseHex(k);
          byte[] hash = hash(original);
          byte[] replacement = new byte[16];
          boolean linkLocal = first == 0xFE && (original[1] & 0xC0) == 0x80;
          if (linkLocal) {
            System.arraycopy(original, 0, replacement, 0, 8);
            System.arraycopy(hash, 0, replacement, 8, 8);
          } else {
            replacement[0] = 0x20;
            replacement[1] = 0x01;
            replacement[2] = 0x0D;
            replacement[3] = (byte) 0xB8;
            System.arraycopy(hash, 0, replacement, 4, 12);
          }
          return replacement;
        });
  }

  private void addLabels(DnsName name) {
    name.labels().forEach(this::addName);
  }

  private void addName(String label) {
    if (isPersonal(label)) {
      names.computeIfAbsent(label, this::placeholder);
    }
  }

  static boolean isPersonal(String label) {
    if (label.isEmpty() || label.startsWith("_")) {
      return false;
    }
    if (STRUCTURAL_LABELS.contains(label.toLowerCase(Locale.ROOT))) {
      return false;
    }
    // Reverse lookup components: IPv4 octets ("192") and IPv6 nibbles ("a").
    return !label.matches("[0-9]{1,3}|[0-9a-fA-F]");
  }

  /** ASCII placeholder with exactly the byte length of the original, unique in this run. */
  private String placeholder(String original) {
    int length = original.getBytes(StandardCharsets.UTF_8).length;
    int counter = names.size() + 1;
    while (true) {
      String base = "host" + counter;
      String candidate =
          base.length() >= length
              ? base.substring(base.length() - length)
              : base + "x".repeat(length - base.length());
      if (!names.containsValue(candidate) && !names.containsKey(candidate)) {
        return candidate;
      }
      counter++;
    }
  }

  private static void maskTxtValues(byte[] frame, DnsMessage message) {
    for (DnsMessage.ResourceRecord record : message.records()) {
      if (record.type() != DnsMessage.TYPE_TXT) {
        continue;
      }
      int position = record.rdataOffset();
      int end = position + record.rdataLength();
      while (position < end) {
        int length = frame[position] & 0xFF;
        boolean value = false;
        for (int i = position + 1; i <= position + length; i++) {
          if (value) {
            frame[i] = 'x';
          } else if (frame[i] == '=') {
            value = true;
          }
        }
        position += 1 + length;
      }
    }
  }

  private static void replaceLengthPrefixed(
      byte[] frame, int start, int end, String original, String replacement) {
    if (original.getBytes(StandardCharsets.UTF_8).length > 255) {
      return;
    }
    byte[] pattern = lengthPrefixed(original);
    byte[] to = replacement.getBytes(StandardCharsets.US_ASCII);
    int at = indexOf(frame, pattern, start);
    while (at >= 0 && at + pattern.length <= end) {
      System.arraycopy(to, 0, frame, at + 1, to.length);
      at = indexOf(frame, pattern, at + pattern.length);
    }
  }

  private static byte[] lengthPrefixed(String text) {
    byte[] bytes = text.getBytes(StandardCharsets.UTF_8);
    var prefixed = new byte[bytes.length + 1];
    prefixed[0] = (byte) bytes.length;
    System.arraycopy(bytes, 0, prefixed, 1, bytes.length);
    return prefixed;
  }

  private static void replaceAll(byte[] data, byte[] from, byte[] to) {
    int at = indexOf(data, from, 0);
    while (at >= 0) {
      System.arraycopy(to, 0, data, at, to.length);
      at = indexOf(data, from, at + from.length);
    }
  }

  static int indexOf(byte[] data, byte[] pattern, int from) {
    outer:
    for (int i = Math.max(from, 0); i <= data.length - pattern.length; i++) {
      for (int j = 0; j < pattern.length; j++) {
        if (data[i + j] != pattern[j]) {
          continue outer;
        }
      }
      return i;
    }
    return -1;
  }

  private byte[] hash(byte[] value) {
    try {
      var digest = MessageDigest.getInstance("SHA-256");
      digest.update(salt);
      return digest.digest(value);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is always available", e);
    }
  }

  private static boolean isDhcp(PacketLayout.Udp udp) {
    return udp.ipVersion() == 4 && (udp.destinationPort() == 67 || udp.sourcePort() == 67);
  }

  private static boolean isMdns(PacketLayout.Udp udp) {
    return udp.sourcePort() == 5353 || udp.destinationPort() == 5353;
  }
}
