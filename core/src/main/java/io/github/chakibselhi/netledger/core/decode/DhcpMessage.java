package io.github.chakibselhi.netledger.core.decode;

import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A DHCPv4 client message (RFC 2131): the fixed BOOTP header, then the magic cookie and the options
 * as type-length-value triplets (RFC 2132).
 *
 * <pre>
 *   0 op (1 = BOOTREQUEST)  1 htype (1)  2 hlen (6)  3 hops   4 xid (4)
 *   8 secs (2)  10 flags (2)  12 ciaddr  16 yiaddr  20 siaddr  24 giaddr
 *  28 chaddr (16, first 6 used)  44 sname (64)  108 file (128)
 * 236 magic cookie 99.130.83.99   240 options: code, length, value ... 255 = end, 0 = pad
 * </pre>
 *
 * @param clientMacOffset absolute offset of chaddr
 * @param clientIpOffset absolute offset of ciaddr
 * @param options first occurrence of each option, by code
 */
public record DhcpMessage(int clientMacOffset, int clientIpOffset, Map<Integer, Option> options) {

  public static final int OPTION_HOST_NAME = 12;
  public static final int OPTION_REQUESTED_IP = 50;
  public static final int OPTION_MESSAGE_TYPE = 53;
  public static final int OPTION_PARAMETER_REQUEST_LIST = 55;
  public static final int OPTION_VENDOR_CLASS = 60;
  public static final int OPTION_CLIENT_ID = 61;

  public static final int TYPE_DISCOVER = 1;
  public static final int TYPE_REQUEST = 3;

  static final long MAGIC_COOKIE = 0x63825363L;
  private static final int BOOTREQUEST = 1;
  private static final int OPTION_PAD = 0;
  private static final int OPTION_END = 255;

  /** One option: absolute offset and length of its value. */
  public record Option(int code, int valueOffset, int length) {}

  /**
   * Parses a BOOTREQUEST sent by an Ethernet client. Server replies, other hardware types and plain
   * BOOTP (no magic cookie) yield an empty result.
   *
   * @throws MalformedPacketException when the message is truncated
   */
  public static Optional<DhcpMessage> parse(byte[] data, int offset, int length) {
    var cursor = new ByteCursor(data, offset, length);
    int op = cursor.u8();
    int hardwareType = cursor.u8();
    int hardwareLength = cursor.u8();
    if (op != BOOTREQUEST || hardwareType != 1 || hardwareLength != MacAddresses.LENGTH) {
      return Optional.empty();
    }
    cursor.skip(1 + 4 + 2 + 2);
    int clientIp = cursor.take(4);
    cursor.skip(4 + 4 + 4);
    int clientMac = cursor.take(16);
    cursor.skip(64 + 128);
    if (cursor.u32() != MAGIC_COOKIE) {
      return Optional.empty();
    }
    var options = new LinkedHashMap<Integer, Option>();
    while (cursor.remaining() > 0) {
      int code = cursor.u8();
      if (code == OPTION_PAD) {
        continue;
      }
      if (code == OPTION_END) {
        break;
      }
      int optionLength = cursor.u8();
      int valueOffset = cursor.take(optionLength);
      options.putIfAbsent(code, new Option(code, valueOffset, optionLength));
    }
    return Optional.of(new DhcpMessage(clientMac, clientIp, Collections.unmodifiableMap(options)));
  }

  public Optional<Option> option(int code) {
    return Optional.ofNullable(options.get(code));
  }

  /** Value of option 53, or -1 when absent or malformed. */
  public int messageType(byte[] data) {
    return option(OPTION_MESSAGE_TYPE)
        .filter(o -> o.length() == 1)
        .map(o -> data[o.valueOffset()] & 0xFF)
        .orElse(-1);
  }
}
