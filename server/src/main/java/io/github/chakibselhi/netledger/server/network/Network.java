package io.github.chakibselhi.netledger.server.network;

/** A row of the {@code network} table. */
public record Network(long id, String gatewayMac, String subnet, String label, Trust trust) {}
