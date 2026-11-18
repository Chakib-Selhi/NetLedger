package io.github.chakibselhi.netledger.agent.alerts;

import java.util.Optional;

/**
 * Incremental Server-Sent Events parser (WHATWG HTML, "server-sent events"). Lines are fed one by
 * one; an empty line ends an event. {@code event:} names it, {@code data:} lines are joined with
 * newlines, and lines starting with {@code :} are comments (heartbeats).
 */
public final class SseParser {

  /** A complete event. */
  public record Event(String name, String data) {}

  private String name = "message";
  private final StringBuilder data = new StringBuilder();
  private boolean hasData;

  public Optional<Event> feed(String line) {
    if (line.isEmpty()) {
      if (!hasData) {
        name = "message";
        return Optional.empty();
      }
      var event = new Event(name, data.toString());
      name = "message";
      data.setLength(0);
      hasData = false;
      return Optional.of(event);
    }
    if (line.startsWith(":")) {
      return Optional.empty();
    }
    int colon = line.indexOf(':');
    String field = colon < 0 ? line : line.substring(0, colon);
    String value = colon < 0 ? "" : line.substring(colon + 1);
    if (value.startsWith(" ")) {
      value = value.substring(1);
    }
    switch (field) {
      case "event" -> name = value;
      case "data" -> {
        if (hasData) {
          data.append('\n');
        }
        data.append(value);
        hasData = true;
      }
      default -> {
        // id and retry are not needed: the server tracks delivery itself.
      }
    }
    return Optional.empty();
  }
}
