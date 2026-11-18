package io.github.chakibselhi.netledger.server.alerting;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.server.network.Network;
import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.persistence.Timestamps;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * Alert rules of the PRD. Called by the correlation engine inside its transaction, so an alert is
 * stored together with the observation that caused it.
 *
 * <ul>
 *   <li><b>Learning</b> (EF-11): no device alert during the first 24 hours of cumulated connection
 *       on a monitored network. When the agent comes back after an absence, the end of the period
 *       moves forward by the length of the absence.
 *   <li><b>Anti-repetition</b>: an alert of a kind is not repeated for the same device within an
 *       hour.
 *   <li><b>IP conflict</b>: an IP is "reserved" when it belongs to the gateway or to an approved
 *       device that used it in the last 24 hours. Another MAC announcing it over ARP is the classic
 *       sign of ARP spoofing (man in the middle).
 * </ul>
 */
@Component
public class AlertRules {

  public static final Duration LEARNING = Duration.ofHours(24);
  static final Duration REPEAT = Duration.ofHours(1);
  static final Duration ABSENCE = Duration.ofMinutes(5);
  static final Duration RESERVATION = Duration.ofHours(24);

  /** What the correlation engine knows about a device after applying an observation. */
  public record DeviceState(
      long id,
      String mac,
      boolean randomized,
      String vendor,
      String hostname,
      String dhcpFingerprint,
      String status,
      boolean created) {}

  private final EventRepository events;
  private final NetworkRepository networks;
  private final JdbcClient jdbc;
  private final ApplicationEventPublisher publisher;
  private final Clock clock;

  AlertRules(
      EventRepository events,
      NetworkRepository networks,
      JdbcClient jdbc,
      ApplicationEventPublisher publisher,
      Clock clock) {
    this.events = events;
    this.networks = networks;
    this.jdbc = jdbc;
    this.publisher = publisher;
    this.clock = clock;
  }

  /** A network seen for the first time: the user has to choose its status. */
  public void onNewNetwork(Network network) {
    raise(
        network.id(),
        null,
        EventKind.NEW_NETWORK,
        "Réseau " + network.subnet() + " : choisissez son statut dans le tableau de bord",
        clock.instant());
  }

  /** The agent declared a known network again; an absence extends the learning period. */
  public void onNetworkSeenAgain(Network before) {
    if (before.learningUntil() == null) {
      return;
    }
    Instant now = clock.instant();
    Instant until = Timestamps.parse(before.learningUntil());
    Duration absence = Duration.between(Timestamps.parse(before.lastSeen()), now);
    if (now.isBefore(until) && absence.compareTo(ABSENCE) > 0) {
      networks.setLearningUntil(before.id(), until.plus(absence));
    }
  }

  /** Starts the learning period of a monitored network the first time it is needed. */
  public Network ensureLearningStarted(Network network) {
    if (network.learningUntil() != null) {
      return network;
    }
    Instant until = clock.instant().plus(LEARNING);
    networks.setLearningUntil(network.id(), until);
    return new Network(
        network.id(),
        network.gatewayMac(),
        network.subnet(),
        network.label(),
        network.trust(),
        Timestamps.format(until),
        network.lastSeen());
  }

  public void onObservation(Network network, DeviceState device, Observation o) {
    Instant at = o.observedAt();
    if (device.created() && !learning(network, at)) {
      newDevice(network, device, o);
    } else if (!device.created() && "suspect".equals(device.status())) {
      raise(network.id(), device.id(), EventKind.SUSPECT_SEEN, describe(device, o.ip()), at);
    }
    if (o.source() == ObservationSource.ARP && o.ip() != null) {
      checkIpConflict(network, device, o.ip(), at);
    }
  }

  private void newDevice(Network network, DeviceState device, Observation o) {
    Optional<String> lookAlike =
        device.randomized() && device.hostname() != null && device.dhcpFingerprint() != null
            ? approvedLookAlike(network.id(), device)
            : Optional.empty();
    if (lookAlike.isPresent()) {
      raise(
          network.id(),
          device.id(),
          EventKind.KNOWN_DEVICE_NEW_MAC,
          "Probablement "
              + lookAlike.get()
              + " avec une nouvelle adresse privée · "
              + ipText(o.ip()),
          o.observedAt());
    } else {
      raise(
          network.id(),
          device.id(),
          EventKind.NEW_DEVICE,
          describe(device, o.ip()),
          o.observedAt());
    }
  }

  private Optional<String> approvedLookAlike(long networkId, DeviceState device) {
    return jdbc.sql(
            """
            SELECT COALESCE(display_name, hostname) FROM device
            WHERE network_id = :network AND status = 'approved' AND id <> :id
              AND hostname = :hostname AND dhcp_fingerprint = :fingerprint
            LIMIT 1
            """)
        .param("network", networkId)
        .param("id", device.id())
        .param("hostname", device.hostname())
        .param("fingerprint", device.dhcpFingerprint())
        .query(String.class)
        .optional();
  }

  private void checkIpConflict(Network network, DeviceState device, String ip, Instant at) {
    Optional<Map<String, Object>> owner =
        jdbc
            .sql(
                """
                SELECT d.mac AS mac, COALESCE(d.display_name, d.hostname, d.mac) AS label FROM device d
                WHERE d.network_id = :network AND d.mac <> :mac
                  AND ((d.mac = :gateway AND d.last_ip = :ip)
                    OR (d.status = 'approved' AND EXISTS (
                          SELECT 1 FROM ip_history h
                          WHERE h.device_id = d.id AND h.ip = :ip AND h.last_seen >= :since)))
                LIMIT 1
                """)
            .param("network", network.id())
            .param("mac", device.mac())
            .param("gateway", network.gatewayMac())
            .param("ip", ip)
            .param("since", Timestamps.format(at.minus(RESERVATION)))
            .query()
            .listOfRows()
            .stream()
            .findFirst();
    owner.ifPresent(
        o ->
            raise(
                network.id(),
                device.id(),
                EventKind.IP_CONFLICT,
                ip
                    + " annoncée par "
                    + device.mac()
                    + " alors qu'elle appartient à "
                    + o.get("label")
                    + " ("
                    + o.get("mac")
                    + ")",
                at));
  }

  private boolean learning(Network network, Instant at) {
    return network.learningUntil() == null
        || at.isBefore(Timestamps.parse(network.learningUntil()));
  }

  private void raise(long networkId, Long deviceId, EventKind kind, String message, Instant at) {
    if (deviceId != null) {
      Optional<Instant> last = events.lastOccurrence(deviceId, kind);
      if (last.isPresent() && at.isBefore(last.get().plus(REPEAT))) {
        return;
      }
    }
    publisher.publishEvent(new AlertRaised(events.insert(networkId, deviceId, kind, message, at)));
  }

  private static String describe(DeviceState device, String ip) {
    String vendor =
        device.vendor() != null
            ? device.vendor()
            : device.randomized() ? "Adresse privée" : "Fabricant inconnu";
    String name = device.hostname() == null ? "" : " · " + device.hostname();
    return vendor + " · " + ipText(ip) + name;
  }

  private static String ipText(String ip) {
    return ip == null ? "IP inconnue" : ip;
  }
}
