package io.github.chakibselhi.netledger.server.correlation;

import io.github.chakibselhi.netledger.server.correlation.DeviceRepository.DeviceRow;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;

/**
 * Changes the user makes from the dashboard (EF-15). They go through the correlation engine's
 * writer lock, so a merge or a deletion never interleaves with a batch being applied.
 */
@Service
public class DeviceCommands {

  public static final Set<String> STATUSES =
      Set.of("new", "approved", "guest", "suspect", "ignored");
  public static final int MAX_NAME = 64;
  public static final int MAX_CATEGORY = 32;
  private static final Pattern CONTROL = Pattern.compile("\\p{Cntrl}");

  private final CorrelationEngine engine;
  private final DeviceRepository devices;

  DeviceCommands(CorrelationEngine engine, DeviceRepository devices) {
    this.engine = engine;
    this.devices = devices;
  }

  /**
   * {@code null} leaves a field unchanged; an empty name or category clears it.
   *
   * @throws IllegalArgumentException for an unknown status or an invalid text
   * @throws NoSuchElementException when the device does not exist
   */
  public void update(long deviceId, String displayName, String category, String status) {
    String name = text(displayName, MAX_NAME, "displayName");
    String cat = text(category, MAX_CATEGORY, "category");
    if (status != null && !STATUSES.contains(status)) {
      throw new IllegalArgumentException("status must be one of " + STATUSES);
    }
    engine.exclusive(
        () -> {
          require(deviceId);
          devices.updateUserFields(deviceId, name, cat, status);
          return null;
        });
  }

  /**
   * Merges two records of the same device, typically a phone that got a new private address. The
   * target keeps its name, category and status; it takes the MAC address seen most recently, and
   * everything observed for the source.
   *
   * @return the target id
   */
  public long merge(long sourceId, long targetId) {
    if (sourceId == targetId) {
      throw new IllegalArgumentException("A device cannot be merged with itself");
    }
    return engine.exclusive(
        () -> {
          DeviceRow source = require(sourceId);
          DeviceRow target = require(targetId);
          if (source.networkId() != target.networkId()) {
            throw new IllegalArgumentException("Both devices must belong to the same network");
          }
          devices.merge(sourceId, targetId, merged(source, target));
          engine.reclassify(targetId);
          return targetId;
        });
  }

  /** Forgets a network and everything seen on it; the agent declares it again as new. */
  public void deleteNetwork(long networkId) {
    boolean deleted = engine.exclusive(() -> devices.deleteNetwork(networkId));
    if (!deleted) {
      throw new NoSuchElementException("Unknown network");
    }
  }

  /** Identity of {@code target} after absorbing {@code source}: the most recent values win. */
  static DeviceRow merged(DeviceRow source, DeviceRow target) {
    DeviceRow newer = source.lastSeen().compareTo(target.lastSeen()) > 0 ? source : target;
    DeviceRow older = newer == source ? target : source;
    return new DeviceRow(
        target.id(),
        target.networkId(),
        newer.mac(),
        source.firstSeen().compareTo(target.firstSeen()) < 0
            ? source.firstSeen()
            : target.firstSeen(),
        newer.lastSeen(),
        CorrelationEngine.merge(older.lastIp(), newer.lastIp(), true),
        CorrelationEngine.merge(older.hostname(), newer.hostname(), true),
        CorrelationEngine.merge(older.dhcpFingerprint(), newer.dhcpFingerprint(), true),
        newer.vendor(),
        newer.randomized(),
        target.status());
  }

  private DeviceRow require(long deviceId) {
    return devices
        .findById(deviceId)
        .orElseThrow(() -> new NoSuchElementException("Unknown device"));
  }

  /** Text typed by the user: stripped, bounded, without control characters. */
  public static String text(String value, int max, String field) {
    if (value == null) {
      return null;
    }
    String stripped = value.strip();
    if (stripped.length() > max) {
      throw new IllegalArgumentException(field + " is limited to " + max + " characters");
    }
    if (CONTROL.matcher(stripped).find()) {
      throw new IllegalArgumentException(field + " contains control characters");
    }
    return stripped;
  }
}
