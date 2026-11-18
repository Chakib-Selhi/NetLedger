package io.github.chakibselhi.netledger.core.pcap;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;

/**
 * Reads classic libpcap files without native code, so decoding tests run anywhere.
 *
 * <pre>
 * global header (24 bytes): magic (4), version major (2), minor (2), thiszone (4),
 *                           sigfigs (4), snaplen (4), link type (4)
 * record header (16 bytes): seconds (4), micro- or nanoseconds (4), captured length (4),
 *                           original length (4), then the captured bytes
 * </pre>
 *
 * <p>The magic number tells both the byte order of the writer and the timestamp precision. pcapng
 * files (Wireshark's default) use another format and are rejected.
 */
public final class PcapReader {

  static final int MAGIC_MICROS = 0xA1B2C3D4;
  static final int MAGIC_NANOS = 0xA1B23C4D;
  private static final int MAGIC_PCAPNG = 0x0A0D0D0A;
  private static final int GLOBAL_HEADER_LENGTH = 24;
  private static final int RECORD_HEADER_LENGTH = 16;
  private static final int MAX_RECORD_LENGTH = 262_144;

  private PcapReader() {}

  public static PcapFile read(Path path) throws IOException {
    return read(Files.readAllBytes(path));
  }

  public static PcapFile read(byte[] content) throws IOException {
    if (content.length < GLOBAL_HEADER_LENGTH) {
      throw new IOException("Not a pcap file: too short");
    }
    var buffer = ByteBuffer.wrap(content).order(ByteOrder.BIG_ENDIAN);
    int magic = buffer.getInt(0);
    if (magic == MAGIC_PCAPNG) {
      throw new IOException("pcapng is not supported: save the capture as \"pcap\"");
    }
    boolean nanos;
    if (magic == MAGIC_MICROS || magic == MAGIC_NANOS) {
      nanos = magic == MAGIC_NANOS;
    } else if (Integer.reverseBytes(magic) == MAGIC_MICROS
        || Integer.reverseBytes(magic) == MAGIC_NANOS) {
      buffer.order(ByteOrder.LITTLE_ENDIAN);
      nanos = Integer.reverseBytes(magic) == MAGIC_NANOS;
    } else {
      throw new IOException("Not a pcap file: bad magic number");
    }
    int snapLength = buffer.getInt(16);
    int linkType = buffer.getInt(20);
    buffer.position(GLOBAL_HEADER_LENGTH);

    var records = new ArrayList<PcapRecord>();
    while (buffer.remaining() > 0) {
      if (buffer.remaining() < RECORD_HEADER_LENGTH) {
        throw new IOException("Truncated record header");
      }
      long seconds = Integer.toUnsignedLong(buffer.getInt());
      long fraction = Integer.toUnsignedLong(buffer.getInt());
      int capturedLength = buffer.getInt();
      int originalLength = buffer.getInt();
      if (capturedLength < 0 || capturedLength > MAX_RECORD_LENGTH) {
        throw new IOException("Invalid record length: " + capturedLength);
      }
      if (capturedLength > buffer.remaining()) {
        throw new IOException("Truncated record data");
      }
      var data = new byte[capturedLength];
      buffer.get(data);
      Instant timestamp = Instant.ofEpochSecond(seconds, nanos ? fraction : fraction * 1_000);
      records.add(new PcapRecord(timestamp, data, originalLength));
    }
    return new PcapFile(linkType, snapLength, records);
  }
}
