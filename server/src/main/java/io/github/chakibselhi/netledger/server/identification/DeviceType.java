package io.github.chakibselhi.netledger.server.identification;

import java.util.Locale;

/** Probable device type, stored in {@code device.guessed_type}. */
public enum DeviceType {
  PHONE,
  COMPUTER,
  PRINTER,
  TV,
  IOT,
  UNKNOWN;

  public String value() {
    return name().toLowerCase(Locale.ROOT);
  }
}
