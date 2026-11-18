package io.github.chakibselhi.netledger.server.alerting;

/** A row of the {@code event} table. */
public record AlertEvent(
    long id,
    long networkId,
    Long deviceId,
    EventKind kind,
    String message,
    String occurredAt,
    boolean delivered) {}
