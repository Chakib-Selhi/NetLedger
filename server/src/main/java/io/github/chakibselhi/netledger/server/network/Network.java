package io.github.chakibselhi.netledger.server.network;

/**
 * A row of the {@code network} table.
 *
 * @param learningUntil end of the learning period (ISO 8601 UTC), or {@code null} before the
 *     network is first monitored
 */
public record Network(
    long id,
    String gatewayMac,
    String subnet,
    String label,
    Trust trust,
    String learningUntil,
    String lastSeen) {}
