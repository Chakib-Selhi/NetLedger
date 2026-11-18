package io.github.chakibselhi.netledger.server.correlation;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Second line of defense: the agent is authenticated, but anything that ends up in the database and
 * on the dashboard is checked again. Invalid observations are dropped; overlong or dirty text is
 * cleaned.
 */
final class ObservationValidator {

  static final int MAX_TEXT_LENGTH = 255;
  static final int MAX_SERVICES = 64;
  private static final Pattern IPV4 =
      Pattern.compile(
          "((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");
  private static final Pattern FINGERPRINT = Pattern.compile("\\d{1,3}(,\\d{1,3}){0,254}");
  private static final Pattern SERVICE_TYPE = Pattern.compile("_[a-z0-9-]{1,63}\\._(tcp|udp)");

  private final Duration maxClockSkew;

  ObservationValidator(Duration maxClockSkew) {
    this.maxClockSkew = maxClockSkew;
  }

  /** The cleaned observation, or empty when it must be rejected. */
  Optional<Observation> validate(Observation o, Instant now) {
    if (o.observedAt().isAfter(now.plus(maxClockSkew))) {
      return Optional.empty();
    }
    if (o.ip() != null && !IPV4.matcher(o.ip()).matches()) {
      return Optional.empty();
    }
    String fingerprint =
        o.dhcpFingerprint() != null && FINGERPRINT.matcher(o.dhcpFingerprint()).matches()
            ? o.dhcpFingerprint()
            : null;
    var services = new ArrayList<ServiceAnnouncement>();
    for (ServiceAnnouncement s : o.services()) {
      if (services.size() < MAX_SERVICES && SERVICE_TYPE.matcher(s.type()).matches()) {
        services.add(new ServiceAnnouncement(s.type(), clean(s.instanceName()), s.port()));
      }
    }
    return Optional.of(
        new Observation(
            o.observedAt(),
            o.source(),
            o.mac(),
            o.ip(),
            clean(o.hostname()),
            fingerprint,
            clean(o.vendorClass()),
            services));
  }

  static String clean(String text) {
    if (text == null) {
      return null;
    }
    var out = new StringBuilder();
    text.codePoints()
        .filter(cp -> !Character.isISOControl(cp))
        .limit(MAX_TEXT_LENGTH)
        .forEach(out::appendCodePoint);
    String cleaned = out.toString().strip();
    return cleaned.isEmpty() ? null : cleaned;
  }
}
