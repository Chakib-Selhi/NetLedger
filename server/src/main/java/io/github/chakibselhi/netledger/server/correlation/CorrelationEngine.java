package io.github.chakibselhi.netledger.server.correlation;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import io.github.chakibselhi.netledger.server.alerting.AlertRules;
import io.github.chakibselhi.netledger.server.alerting.AlertRules.DeviceState;
import io.github.chakibselhi.netledger.server.config.NetLedgerProperties;
import io.github.chakibselhi.netledger.server.correlation.DeviceRepository.DeviceRow;
import io.github.chakibselhi.netledger.server.identification.DeviceFacts;
import io.github.chakibselhi.netledger.server.identification.DeviceTypeRules;
import io.github.chakibselhi.netledger.server.identification.OuiRegistryProvider;
import io.github.chakibselhi.netledger.server.network.Network;
import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.persistence.Timestamps;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Turns observations into devices (EF-07). It is the only component that writes devices,
 * observations, IP history and services: SQLite allows one writer at a time, so batches are applied
 * one after the other, each in a single transaction.
 *
 * <p>Batches may arrive late and out of order (the agent buffers while the server is down), so an
 * older observation never overwrites a newer value: it only fills fields still empty.
 */
@Service
public class CorrelationEngine {

  private final DeviceRepository devices;
  private final NetworkRepository networks;
  private final OuiRegistryProvider oui;
  private final DeviceTypeRules typeRules;
  private final AlertRules alerts;
  private final ObservationValidator validator;
  private final TransactionTemplate transaction;
  private final ObjectMapper json;
  private final Clock clock;
  private final ReentrantLock writer = new ReentrantLock();

  CorrelationEngine(
      DeviceRepository devices,
      NetworkRepository networks,
      OuiRegistryProvider oui,
      DeviceTypeRules typeRules,
      AlertRules alerts,
      NetLedgerProperties properties,
      TransactionTemplate transaction,
      ObjectMapper json,
      Clock clock) {
    this.devices = devices;
    this.networks = networks;
    this.oui = oui;
    this.typeRules = typeRules;
    this.alerts = alerts;
    this.validator = new ObservationValidator(properties.maxClockSkew());
    this.transaction = transaction;
    this.json = json;
    this.clock = clock;
  }

  public IngestResult ingest(long networkId, List<Observation> observations) {
    writer.lock();
    try {
      return transaction.execute(status -> apply(networkId, observations));
    } finally {
      writer.unlock();
    }
  }

  private IngestResult apply(long networkId, List<Observation> observations) {
    Network network =
        alerts.ensureLearningStarted(
            networks
                .findById(networkId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown network " + networkId)));
    Instant now = clock.instant();
    int accepted = 0;
    Instant latest = null;
    for (Observation raw : observations) {
      Optional<Observation> valid = validator.validate(raw, now);
      if (valid.isEmpty()) {
        continue;
      }
      Observation o = valid.get();
      apply(network, o);
      accepted++;
      latest = latest == null || o.observedAt().isAfter(latest) ? o.observedAt() : latest;
    }
    if (latest != null) {
      networks.touch(networkId, latest);
    }
    return new IngestResult(accepted, observations.size() - accepted);
  }

  private void apply(Network network, Observation o) {
    long networkId = network.id();
    String at = Timestamps.format(o.observedAt());
    boolean randomized = isRandomized(o.mac());
    Optional<DeviceRow> existing = devices.find(networkId, o.mac());
    long deviceId;
    String fingerprint;
    String vendor;
    String hostname;
    String status;
    if (existing.isEmpty()) {
      hostname = o.hostname();
      status = "new";
      vendor = randomized ? null : oui.registry().vendorOf(o.mac()).orElse(null);
      fingerprint = o.dhcpFingerprint();
      deviceId =
          devices.insert(
              networkId, o.mac(), randomized, vendor, o.hostname(), fingerprint, o.ip(), at);
    } else {
      DeviceRow row = existing.get();
      boolean newest = at.compareTo(row.lastSeen()) >= 0;
      vendor =
          row.vendor() != null || randomized
              ? row.vendor()
              : oui.registry().vendorOf(o.mac()).orElse(null);
      fingerprint = merge(row.dhcpFingerprint(), o.dhcpFingerprint(), newest);
      hostname = merge(row.hostname(), o.hostname(), newest);
      status = row.status();
      deviceId = row.id();
      devices.update(
          deviceId,
          newest ? at : row.lastSeen(),
          merge(row.lastIp(), o.ip(), newest),
          hostname,
          fingerprint,
          vendor);
    }
    devices.insertObservation(deviceId, o.source().name().toLowerCase(), o.ip(), detail(o), at);
    if (o.ip() != null) {
      devices.recordIp(deviceId, o.ip(), at);
    }
    for (ServiceAnnouncement s : o.services()) {
      devices.recordService(deviceId, s.type(), s.instanceName(), s.port(), at);
    }
    var facts =
        new DeviceFacts(
            devices.serviceTypes(deviceId, false),
            devices.serviceTypes(deviceId, true),
            fingerprint,
            randomized,
            vendor);
    devices.setGuessedType(deviceId, typeRules.guess(facts).value());
    alerts.onObservation(
        network,
        new DeviceState(
            deviceId,
            o.mac(),
            randomized,
            vendor,
            hostname,
            fingerprint,
            status,
            existing.isEmpty()),
        o);
  }

  /** A newer non-null value replaces the stored one; an older one only fills a gap. */
  static String merge(String stored, String incoming, boolean incomingIsNewest) {
    if (incoming == null) {
      return stored;
    }
    return incomingIsNewest || stored == null ? incoming : stored;
  }

  private static boolean isRandomized(String mac) {
    return (HexFormat.fromHexDigits(mac, 0, 2) & 0x02) != 0;
  }

  private String detail(Observation o) {
    Map<String, Object> detail = new LinkedHashMap<>();
    if (o.hostname() != null) {
      detail.put("hostname", o.hostname());
    }
    if (o.dhcpFingerprint() != null) {
      detail.put("dhcpFingerprint", o.dhcpFingerprint());
    }
    if (o.vendorClass() != null) {
      detail.put("vendorClass", o.vendorClass());
    }
    if (!o.services().isEmpty()) {
      detail.put("services", o.services());
    }
    if (detail.isEmpty()) {
      return null;
    }
    try {
      return json.writeValueAsString(detail);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("Cannot serialize observation detail", e);
    }
  }
}
