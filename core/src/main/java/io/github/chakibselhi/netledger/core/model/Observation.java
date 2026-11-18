package io.github.chakibselhi.netledger.core.model;

import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * One normalized fact decoded from a single frame: a device (MAC address) was seen, possibly with
 * an IPv4 address, a host name, a DHCP fingerprint or announced services. Only these fields ever
 * leave the agent; raw packets never do.
 *
 * @param observedAt capture timestamp
 * @param source protocol the fact comes from
 * @param mac device MAC address, lower case and colon separated
 * @param ip IPv4 address of the device, or {@code null} when unknown
 * @param hostname host name announced by the device, or {@code null}
 * @param dhcpFingerprint DHCP option 55 as comma separated option codes, or {@code null}
 * @param vendorClass DHCP option 60, or {@code null}
 * @param services DNS-SD services announced over mDNS, never {@code null}
 */
public record Observation(
    Instant observedAt,
    ObservationSource source,
    String mac,
    String ip,
    String hostname,
    String dhcpFingerprint,
    String vendorClass,
    List<ServiceAnnouncement> services) {

  public Observation {
    Objects.requireNonNull(observedAt, "observedAt");
    Objects.requireNonNull(source, "source");
    if (!MacAddresses.isCanonical(mac)) {
      throw new IllegalArgumentException("Invalid MAC address: " + mac);
    }
    services = services == null ? List.of() : List.copyOf(services);
  }

  public static Observation presence(
      Instant observedAt, ObservationSource source, String mac, String ip) {
    return new Observation(observedAt, source, mac, ip, null, null, null, List.of());
  }
}
