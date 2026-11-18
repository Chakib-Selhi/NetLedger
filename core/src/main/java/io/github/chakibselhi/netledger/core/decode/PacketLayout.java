package io.github.chakibselhi.netledger.core.decode;

import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * Locates the layers of an Ethernet frame: Ethernet II header (with an optional 802.1Q tag), then
 * for IPv4 and IPv6 the UDP header and payload. Offsets are absolute indexes in the frame.
 *
 * @param etherType EtherType after any VLAN tag (0x0806 ARP, 0x0800 IPv4, 0x86DD IPv6)
 * @param payloadOffset first byte after the Ethernet header
 * @param udp UDP location, or {@code null} when the frame is not an unfragmented UDP datagram
 */
public record PacketLayout(int etherType, int payloadOffset, Udp udp) {

  public static final int ETHERTYPE_IPV4 = 0x0800;
  public static final int ETHERTYPE_ARP = 0x0806;
  public static final int ETHERTYPE_IPV6 = 0x86DD;
  static final int ETHERTYPE_VLAN = 0x8100;
  static final int SOURCE_MAC_OFFSET = 6;
  private static final int PROTOCOL_UDP = 17;

  /**
   * @param ipVersion 4 or 6
   * @param ipOffset first byte of the IP header
   * @param udpOffset first byte of the UDP header
   * @param payloadOffset first byte of the UDP payload
   * @param payloadLength UDP payload length, from the UDP length field
   * @param ipv4Source IPv4 source address, or {@code null} for IPv6
   */
  public record Udp(
      int ipVersion,
      int ipOffset,
      int udpOffset,
      int sourcePort,
      int destinationPort,
      int payloadOffset,
      int payloadLength,
      String ipv4Source) {}

  /**
   * @throws MalformedPacketException when a header is truncated or inconsistent
   */
  public static PacketLayout parse(byte[] frame) {
    var cursor = ByteCursor.of(frame);
    cursor.skip(12);
    int etherType = cursor.u16();
    if (etherType == ETHERTYPE_VLAN) {
      cursor.skip(2);
      etherType = cursor.u16();
    }
    int payloadOffset = cursor.position();
    Udp udp =
        switch (etherType) {
          case ETHERTYPE_IPV4 -> ipv4(cursor);
          case ETHERTYPE_IPV6 -> ipv6(cursor);
          default -> null;
        };
    return new PacketLayout(etherType, payloadOffset, udp);
  }

  public String sourceMac(byte[] frame) {
    return MacAddresses.format(frame, SOURCE_MAC_OFFSET);
  }

  private static Udp ipv4(ByteCursor cursor) {
    int ipOffset = cursor.position();
    int versionAndLength = cursor.u8();
    int headerLength = (versionAndLength & 0x0F) * 4;
    if (versionAndLength >> 4 != 4 || headerLength < 20) {
      throw new MalformedPacketException("Bad IPv4 header");
    }
    cursor.skip(5);
    int flagsAndFragment = cursor.u16();
    boolean moreFragments = (flagsAndFragment & 0x2000) != 0;
    // Only the first fragment carries the UDP header; reassembly is not worth it for broadcasts.
    if (moreFragments || (flagsAndFragment & 0x1FFF) != 0) {
      return null;
    }
    cursor.skip(1);
    int protocol = cursor.u8();
    cursor.skip(2);
    int sourceAt = cursor.take(4);
    cursor.seek(ipOffset);
    cursor.skip(headerLength);
    if (protocol != PROTOCOL_UDP) {
      return null;
    }
    return udp(cursor, 4, ipOffset, address(cursor.data(), sourceAt, 4));
  }

  private static Udp ipv6(ByteCursor cursor) {
    int ipOffset = cursor.position();
    if (cursor.u8() >> 4 != 6) {
      throw new MalformedPacketException("Bad IPv6 header");
    }
    cursor.skip(5);
    int nextHeader = cursor.u8();
    cursor.skip(1 + 16 + 16);
    // Extension headers are not followed: link-local mDNS traffic does not use them.
    return nextHeader == PROTOCOL_UDP ? udp(cursor, 6, ipOffset, null) : null;
  }

  private static Udp udp(ByteCursor cursor, int ipVersion, int ipOffset, String ipv4Source) {
    int udpOffset = cursor.position();
    int sourcePort = cursor.u16();
    int destinationPort = cursor.u16();
    int length = cursor.u16();
    cursor.skip(2);
    if (length < 8 || length - 8 > cursor.remaining()) {
      throw new MalformedPacketException("Bad UDP length");
    }
    return new Udp(
        ipVersion,
        ipOffset,
        udpOffset,
        sourcePort,
        destinationPort,
        cursor.position(),
        length - 8,
        ipv4Source);
  }

  static String address(byte[] data, int offset, int length) {
    try {
      return InetAddress.getByAddress(Arrays.copyOfRange(data, offset, offset + length))
          .getHostAddress();
    } catch (UnknownHostException e) {
      throw new MalformedPacketException("Bad address length");
    }
  }
}
