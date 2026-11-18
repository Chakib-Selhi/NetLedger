package io.github.chakibselhi.netledger.server.alerting;

/**
 * What the agent receives on the SSE stream and turns into a macOS notification.
 *
 * @param id event id, or 0 for a summary of several pending alerts
 * @param kind event kind, or {@code summary}
 * @param sound whether the notification plays a sound
 * @param path dashboard page to open, relative to the server
 */
public record AlertMessage(
    long id,
    String kind,
    String title,
    String message,
    boolean sound,
    String occurredAt,
    String path) {

  static AlertMessage of(AlertEvent event) {
    String path = event.deviceId() != null ? "/devices/" + event.deviceId() : "/networks";
    return new AlertMessage(
        event.id(),
        event.kind().value(),
        event.kind().title(),
        event.message(),
        event.kind().sound(),
        event.occurredAt(),
        path);
  }
}
