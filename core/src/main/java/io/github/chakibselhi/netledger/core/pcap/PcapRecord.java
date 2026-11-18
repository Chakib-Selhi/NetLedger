package io.github.chakibselhi.netledger.core.pcap;

import java.time.Instant;

/**
 * One captured frame.
 *
 * @param originalLength length on the wire; larger than {@code data.length} when truncated by the
 *     snapshot length
 */
public record PcapRecord(Instant timestamp, byte[] data, int originalLength) {}
