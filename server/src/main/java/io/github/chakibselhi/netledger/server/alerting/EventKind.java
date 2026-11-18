package io.github.chakibselhi.netledger.server.alerting;

import java.util.Arrays;
import java.util.Locale;

/** Alert kinds of the PRD, stored lower case in {@code event.kind}. */
public enum EventKind {
  NEW_NETWORK("Nouveau réseau", false),
  NEW_DEVICE("Nouvel appareil", true),
  KNOWN_DEVICE_NEW_MAC("Appareil connu probable, nouvelle adresse", false),
  SUSPECT_SEEN("Appareil suspect revenu", true),
  IP_CONFLICT("Conflit d'adresse IP", true);

  private final String title;
  private final boolean sound;

  EventKind(String title, boolean sound) {
    this.title = title;
    this.sound = sound;
  }

  public String title() {
    return title;
  }

  /** Whether the macOS notification plays a sound (PRD alert table). */
  public boolean sound() {
    return sound;
  }

  public String value() {
    return name().toLowerCase(Locale.ROOT);
  }

  public static EventKind fromValue(String value) {
    return Arrays.stream(values())
        .filter(k -> k.value().equals(value))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException("Unknown event kind: " + value));
  }
}
