package io.github.chakibselhi.netledger.server.network;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import java.util.Locale;

/** What the user declared about a network. Only OWNED and AUTHORIZED networks are monitored. */
public enum Trust {
  UNSET,
  OWNED,
  AUTHORIZED,
  IGNORED;

  @JsonValue
  public String value() {
    return name().toLowerCase(Locale.ROOT);
  }

  public boolean allowsCapture() {
    return this == OWNED || this == AUTHORIZED;
  }

  public static Trust fromValue(String value) {
    return Arrays.stream(values())
        .filter(t -> t.value().equals(value))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unknown trust: " + value));
  }
}
