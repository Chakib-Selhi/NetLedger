package io.github.chakibselhi.netledger.core.decode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * DNS message (RFC 1035) as used by multicast DNS (RFC 6762).
 *
 * <pre>
 * header (12 bytes): id, flags (bit 15 = QR, 1 for responses), then four counts:
 *                    questions, answers, authority records, additional records
 * question:          name, type (2), class (2; top bit = "unicast response wanted" in mDNS)
 * resource record:   name, type (2), class (2; top bit = "cache flush" in mDNS), TTL (4),
 *                    rdlength (2), rdata
 * name:              labels, each a length byte (1-63) then its bytes, ended by a zero byte;
 *                    or a 2-byte pointer (top bits 11) to an earlier name in the message
 * </pre>
 *
 * <p>Compression pointers are the classic trap of DNS parsers: a pointer to itself or a cycle of
 * pointers loops forever. Here a pointer must point strictly backwards, at most {@value
 * #MAX_POINTER_JUMPS} pointers are followed per name, and a name is limited to {@value
 * #MAX_NAME_LENGTH} bytes.
 *
 * @param messageOffset absolute offset of the header, the origin of compression pointers
 */
public record DnsMessage(
    int messageOffset, boolean response, List<Question> questions, List<ResourceRecord> records) {

  public static final int TYPE_A = 1;
  public static final int TYPE_PTR = 12;
  public static final int TYPE_TXT = 16;
  public static final int TYPE_AAAA = 28;
  public static final int TYPE_SRV = 33;

  static final int MAX_POINTER_JUMPS = 16;
  static final int MAX_NAME_LENGTH = 255;
  private static final int HEADER_LENGTH = 12;
  private static final int MIN_QUESTION_LENGTH = 5;
  private static final int MIN_RECORD_LENGTH = 11;

  public record Question(DnsName name, int type, boolean unicastResponse) {}

  /**
   * One resource record from the answer, authority or additional section.
   *
   * @param target PTR target or SRV target host, otherwise {@code null}
   * @param port SRV port, otherwise -1
   * @param address A or AAAA address, otherwise {@code null}
   * @param text TXT character strings, otherwise empty
   * @param rdataOffset absolute offset of rdata
   */
  public record ResourceRecord(
      DnsName name,
      int type,
      int recordClass,
      boolean cacheFlush,
      long ttl,
      int rdataOffset,
      int rdataLength,
      DnsName target,
      int port,
      String address,
      List<String> text) {}

  /**
   * @throws MalformedPacketException when the message is truncated or a name is invalid
   */
  public static DnsMessage parse(byte[] data, int offset, int length) {
    var cursor = new ByteCursor(data, offset, length);
    cursor.skip(2);
    boolean response = (cursor.u16() & 0x8000) != 0;
    int questionCount = cursor.u16();
    int recordCount = cursor.u16() + cursor.u16() + cursor.u16();
    // Counts are attacker-controlled: reject those that cannot fit before allocating anything.
    long minimum =
        (long) questionCount * MIN_QUESTION_LENGTH + (long) recordCount * MIN_RECORD_LENGTH;
    if (minimum > length - HEADER_LENGTH) {
      throw new MalformedPacketException("Record counts exceed message size");
    }
    var questions = new ArrayList<Question>(questionCount);
    for (int i = 0; i < questionCount; i++) {
      DnsName name = readName(cursor, offset);
      int type = cursor.u16();
      int questionClass = cursor.u16();
      questions.add(new Question(name, type, (questionClass & 0x8000) != 0));
    }
    var records = new ArrayList<ResourceRecord>(recordCount);
    for (int i = 0; i < recordCount; i++) {
      records.add(readRecord(cursor, offset));
    }
    return new DnsMessage(offset, response, List.copyOf(questions), List.copyOf(records));
  }

  private static ResourceRecord readRecord(ByteCursor cursor, int messageOffset) {
    DnsName name = readName(cursor, messageOffset);
    int type = cursor.u16();
    int recordClass = cursor.u16();
    long ttl = cursor.u32();
    int rdataLength = cursor.u16();
    int rdataOffset = cursor.take(rdataLength);
    // rdata names may point anywhere earlier in the message, so read them from a full view.
    var rdata = new ByteCursor(cursor.data(), messageOffset, cursor.limit() - messageOffset);
    rdata.seek(rdataOffset);
    int rdataEnd = rdataOffset + rdataLength;

    DnsName target = null;
    int port = -1;
    String address = null;
    List<String> text = List.of();
    switch (type) {
      case TYPE_A -> address = readAddress(cursor.data(), rdataOffset, rdataLength, 4);
      case TYPE_AAAA -> address = readAddress(cursor.data(), rdataOffset, rdataLength, 16);
      case TYPE_PTR -> target = readName(rdata, messageOffset);
      case TYPE_SRV -> {
        rdata.skip(4);
        port = rdata.u16();
        target = readName(rdata, messageOffset);
      }
      case TYPE_TXT -> text = readText(cursor.data(), rdataOffset, rdataEnd);
      default -> {
        // Other record types carry nothing NetLedger uses.
      }
    }
    if ((type == TYPE_PTR || type == TYPE_SRV) && rdata.position() > rdataEnd) {
      throw new MalformedPacketException("Name overruns rdata");
    }
    return new ResourceRecord(
        name,
        type,
        recordClass & 0x7FFF,
        (recordClass & 0x8000) != 0,
        ttl,
        rdataOffset,
        rdataLength,
        target,
        port,
        address,
        text);
  }

  /** Reads a possibly compressed name and leaves the cursor just after its in-place part. */
  static DnsName readName(ByteCursor cursor, int messageOffset) {
    byte[] data = cursor.data();
    var labels = new ArrayList<String>();
    int position = cursor.position();
    int resumeAt = -1;
    int jumps = 0;
    int nameLength = 0;
    while (true) {
      cursor.seek(position);
      int length = cursor.u8();
      if ((length & 0xC0) == 0xC0) {
        int pointer = messageOffset + (((length & 0x3F) << 8) | cursor.u8());
        if (resumeAt < 0) {
          resumeAt = cursor.position();
        }
        if (pointer >= position || ++jumps > MAX_POINTER_JUMPS) {
          throw new MalformedPacketException("Invalid compression pointer");
        }
        position = pointer;
        continue;
      }
      if ((length & 0xC0) != 0) {
        throw new MalformedPacketException("Unsupported label type");
      }
      if (length == 0) {
        cursor.seek(resumeAt >= 0 ? resumeAt : cursor.position());
        return new DnsName(labels);
      }
      nameLength += length + 1;
      if (nameLength > MAX_NAME_LENGTH) {
        throw new MalformedPacketException("Name too long");
      }
      int labelOffset = cursor.take(length);
      labels.add(new String(data, labelOffset, length, StandardCharsets.UTF_8));
      position = cursor.position();
    }
  }

  private static String readAddress(byte[] data, int offset, int length, int expected) {
    if (length != expected) {
      throw new MalformedPacketException("Bad address record length");
    }
    return PacketLayout.address(data, offset, length);
  }

  private static List<String> readText(byte[] data, int offset, int end) {
    var strings = new ArrayList<String>();
    int position = offset;
    while (position < end) {
      int length = data[position] & 0xFF;
      if (position + 1 + length > end) {
        throw new MalformedPacketException("TXT string overruns rdata");
      }
      strings.add(new String(data, position + 1, length, StandardCharsets.UTF_8));
      position += 1 + length;
    }
    return List.copyOf(strings);
  }
}
