package io.github.chakibselhi.netledger.server.identification;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Deterministic type rules from the PRD, evaluated in order; the first match wins. Documented in
 * docs/identification.md. The data they use lives in two editable files: known DHCP fingerprints
 * per operating system and IoT vendor names.
 */
@Component
public class DeviceTypeRules {

  private static final Set<String> MOBILE_OS = Set.of("ios", "android");
  private static final Set<String> DESKTOP_OS = Set.of("macos", "windows", "linux");

  /**
   * Discovery proxies (RFC 8766) and sleep proxies answer service type enumerations for the whole
   * network: an Amazon Echo acting as a Thread border router lists the printer's and the NAS's
   * service types. For them, only services backed by an instance of their own count.
   */
  private static final Set<String> PROXY_MARKERS = Set.of("_dnssd-server", "_sleep-proxy");

  private final Map<String, String> osByFingerprint;
  private final List<String> iotVendors;

  public DeviceTypeRules() {
    this(
        loadFingerprints(resource("identification/dhcp-fingerprints.csv")),
        loadLines(resource("identification/iot-vendors.txt")));
  }

  DeviceTypeRules(Map<String, String> osByFingerprint, List<String> iotVendors) {
    this.osByFingerprint = Map.copyOf(osByFingerprint);
    this.iotVendors = iotVendors.stream().map(v -> v.toLowerCase(Locale.ROOT)).toList();
  }

  public DeviceType guess(DeviceFacts facts) {
    Set<String> announced = baseNames(facts.serviceTypes());
    Set<String> services =
        announced.stream().anyMatch(PROXY_MARKERS::contains)
            ? baseNames(facts.instanceServiceTypes())
            : announced;
    Optional<String> os = operatingSystem(facts.dhcpFingerprint());

    if (services.contains("_ipp") || services.contains("_printer")) {
      return DeviceType.PRINTER;
    }
    if ((services.contains("_googlecast") || services.contains("_airplay"))
        && (!services.contains("_companion-link") || services.contains("_sleep-proxy"))) {
      return DeviceType.TV;
    }
    if (os.filter(MOBILE_OS::contains).isPresent() && facts.randomizedMac()) {
      return DeviceType.PHONE;
    }
    if (services.contains("_ssh")
        || services.contains("_smb")
        || os.filter(DESKTOP_OS::contains).isPresent()) {
      return DeviceType.COMPUTER;
    }
    if (facts.vendor() != null && isIotVendor(facts.vendor())) {
      return DeviceType.IOT;
    }
    return DeviceType.UNKNOWN;
  }

  /** Operating system family of a known DHCP fingerprint. */
  public Optional<String> operatingSystem(String fingerprint) {
    return fingerprint == null
        ? Optional.empty()
        : Optional.ofNullable(osByFingerprint.get(fingerprint));
  }

  private boolean isIotVendor(String vendor) {
    String lower = vendor.toLowerCase(Locale.ROOT);
    return iotVendors.stream().anyMatch(lower::contains);
  }

  /** {@code _airplay._tcp} -> {@code _airplay}, as the PRD rules name services. */
  private static Set<String> baseNames(Set<String> serviceTypes) {
    var names = new java.util.HashSet<String>();
    for (String type : serviceTypes) {
      int dot = type.indexOf('.');
      names.add((dot < 0 ? type : type.substring(0, dot)).toLowerCase(Locale.ROOT));
    }
    return names;
  }

  private static InputStream resource(String name) {
    InputStream in = DeviceTypeRules.class.getClassLoader().getResourceAsStream(name);
    if (in == null) {
      throw new IllegalStateException("Missing resource " + name);
    }
    return in;
  }

  /** {@code fingerprint;os;source} lines; {@code #} starts a comment. */
  static Map<String, String> loadFingerprints(InputStream in) {
    var map = new HashMap<String, String>();
    for (String line : loadLines(in)) {
      String[] parts = line.split(";");
      if (parts.length >= 2) {
        map.put(parts[0].strip(), parts[1].strip().toLowerCase(Locale.ROOT));
      }
    }
    return map;
  }

  static List<String> loadLines(InputStream in) {
    var lines = new ArrayList<String>();
    try (var reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
      String line;
      while ((line = reader.readLine()) != null) {
        String trimmed = line.strip();
        if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
          lines.add(trimmed);
        }
      }
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return lines;
  }
}
