package io.github.chakibselhi.netledger.core.pcap;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;

/** Writes classic little-endian, microsecond libpcap files (the format tcpdump writes on a Mac). */
public final class PcapWriter {

  private PcapWriter() {}

  public static void write(Path path, PcapFile file) throws IOException {
    Files.write(path, toBytes(file));
  }

  public static byte[] toBytes(PcapFile file) {
    int size = 24 + file.records().stream().mapToInt(r -> 16 + r.data().length).sum();
    var buffer = ByteBuffer.allocate(size).order(ByteOrder.LITTLE_ENDIAN);
    buffer.putInt(PcapReader.MAGIC_MICROS);
    buffer.putShort((short) 2);
    buffer.putShort((short) 4);
    buffer.putInt(0);
    buffer.putInt(0);
    buffer.putInt(file.snapLength());
    buffer.putInt(file.linkType());
    for (PcapRecord record : file.records()) {
      buffer.putInt((int) record.timestamp().getEpochSecond());
      buffer.putInt(record.timestamp().getNano() / 1_000);
      buffer.putInt(record.data().length);
      buffer.putInt(record.originalLength());
      buffer.put(record.data());
    }
    return buffer.array();
  }
}
