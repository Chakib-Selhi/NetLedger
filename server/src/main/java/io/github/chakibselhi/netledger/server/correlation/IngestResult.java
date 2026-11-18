package io.github.chakibselhi.netledger.server.correlation;

/**
 * Outcome of one batch.
 *
 * @param accepted observations stored
 * @param rejected observations dropped by validation (future timestamp, invalid address...)
 */
public record IngestResult(int accepted, int rejected) {}
