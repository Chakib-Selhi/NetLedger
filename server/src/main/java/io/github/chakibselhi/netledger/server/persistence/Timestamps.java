package io.github.chakibselhi.netledger.server.persistence;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * Database timestamps: ISO 8601 UTC with exactly three fractional digits. {@link
 * Instant#toString()} omits zero fractions ("...:00Z" vs "...:00.250Z"), which breaks ordering of
 * the TEXT columns; a fixed width makes string order equal time order, so SQL can use MIN, MAX and
 * ranges directly.
 */
public final class Timestamps {

  private static final DateTimeFormatter FORMAT =
      DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

  private Timestamps() {}

  public static String format(Instant instant) {
    return FORMAT.format(instant.truncatedTo(ChronoUnit.MILLIS));
  }

  public static Instant parse(String value) {
    return Instant.parse(value);
  }
}
