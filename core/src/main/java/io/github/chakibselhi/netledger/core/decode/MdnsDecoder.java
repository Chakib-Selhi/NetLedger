package io.github.chakibselhi.netledger.core.decode;

import io.github.chakibselhi.netledger.core.decode.DnsMessage.ResourceRecord;
import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Turns an mDNS packet into an observation of its sender (Ethernet source MAC).
 *
 * <p>Any mDNS packet proves the sender is present. Only responses describe the sender, because a
 * query's known-answer section repeats records owned by other devices. From a response:
 *
 * <ul>
 *   <li>A / AAAA {@code host.local} gives the host name;
 *   <li>PTR {@code _type._tcp.local -> Instance._type._tcp.local} lists a service instance (DNS-SD,
 *       RFC 6763);
 *   <li>SRV {@code Instance._type._tcp.local} gives its port and target host;
 *   <li>PTR {@code _services._dns-sd._udp.local -> _type._tcp.local} answers a service type
 *       enumeration: the device offers that type, instance unknown;
 *   <li>PTR {@code x.x.x.x.in-addr.arpa -> host.local} is a reverse mapping, another host name.
 * </ul>
 *
 * <p>Limitation: a Bonjour Sleep Proxy answers for sleeping devices with its own MAC address, so
 * those records would be attributed to the proxy.
 */
final class MdnsDecoder {

  static final int PORT = 5353;
  private static final String SERVICE_ENUMERATION = "_services._dns-sd._udp";

  private MdnsDecoder() {}

  static Optional<Observation> decode(
      Instant timestamp, String sourceMac, String ipv4Source, byte[] data, int offset, int length) {
    DnsMessage message = DnsMessage.parse(data, offset, length);
    if (!message.response()) {
      return Optional.of(
          Observation.presence(timestamp, ObservationSource.MDNS, sourceMac, ipv4Source));
    }
    String hostFromAddress = null;
    String hostFromSrv = null;
    String hostFromReverse = null;
    Map<String, ServiceAnnouncement> services = new LinkedHashMap<>();
    for (ResourceRecord record : message.records()) {
      DnsName name = record.name();
      switch (record.type()) {
        case DnsMessage.TYPE_A, DnsMessage.TYPE_AAAA -> {
          if (hostFromAddress == null && isHostName(name)) {
            hostFromAddress = name.label(0);
          }
        }
        case DnsMessage.TYPE_PTR -> {
          if (name.endsWith("in-addr", "arpa") || name.endsWith("ip6", "arpa")) {
            if (hostFromReverse == null && isHostName(record.target())) {
              hostFromReverse = record.target().label(0);
            }
          } else if (name.endsWith("_services", "_dns-sd", "_udp", "local")) {
            serviceType(record.target()).ifPresent(s -> services.putIfAbsent(key(s), s));
          } else {
            instance(record.target()).ifPresent(s -> services.putIfAbsent(key(s), s));
          }
        }
        case DnsMessage.TYPE_SRV -> {
          Optional<ServiceAnnouncement> withPort =
              instance(name)
                  .map(s -> new ServiceAnnouncement(s.type(), s.instanceName(), record.port()));
          withPort.ifPresent(s -> services.put(key(s), s));
          if (withPort.isPresent() && hostFromSrv == null && isHostName(record.target())) {
            hostFromSrv = record.target().label(0);
          }
        }
        default -> {
          // TXT and other records are not used yet.
        }
      }
    }
    var instanceTypes =
        services.values().stream()
            .filter(s -> s.instanceName() != null)
            .map(ServiceAnnouncement::type)
            .toList();
    services.values().removeIf(s -> s.instanceName() == null && instanceTypes.contains(s.type()));
    String hostname = firstNonNull(hostFromAddress, hostFromSrv, hostFromReverse);
    return Optional.of(
        new Observation(
            timestamp,
            ObservationSource.MDNS,
            sourceMac,
            ipv4Source,
            hostname == null ? null : TextSanitizer.clean(hostname),
            null,
            null,
            new ArrayList<>(services.values())));
  }

  /** {@code Instance._service._tcp.local}: exactly four labels, protocol _tcp or _udp. */
  static Optional<ServiceAnnouncement> instance(DnsName name) {
    if (name.size() != 4 || !name.endsWith("local")) {
      return Optional.empty();
    }
    String protocol = name.label(2).toLowerCase(Locale.ROOT);
    if (!name.label(1).startsWith("_") || !(protocol.equals("_tcp") || protocol.equals("_udp"))) {
      return Optional.empty();
    }
    String type = name.join(1, 3);
    String instanceName = TextSanitizer.clean(name.label(0));
    if (SERVICE_ENUMERATION.equals(type) || instanceName == null) {
      return Optional.empty();
    }
    return Optional.of(new ServiceAnnouncement(type, instanceName, null));
  }

  /**
   * {@code _service._tcp.local}: the answer to a service type enumeration ({@code
   * _services._dns-sd._udp.local}), which says the device offers this type of service.
   */
  static Optional<ServiceAnnouncement> serviceType(DnsName name) {
    if (name == null || name.size() != 3 || !name.endsWith("local")) {
      return Optional.empty();
    }
    String protocol = name.label(1).toLowerCase(Locale.ROOT);
    if (!name.label(0).startsWith("_") || !(protocol.equals("_tcp") || protocol.equals("_udp"))) {
      return Optional.empty();
    }
    return Optional.of(new ServiceAnnouncement(name.join(0, 2), null, null));
  }

  private static boolean isHostName(DnsName name) {
    return name != null
        && name.size() == 2
        && name.endsWith("local")
        && !name.label(0).startsWith("_");
  }

  private static String key(ServiceAnnouncement service) {
    return service.type() + "/" + service.instanceName();
  }

  private static String firstNonNull(String... values) {
    for (String value : values) {
      if (value != null) {
        return value;
      }
    }
    return null;
  }
}
