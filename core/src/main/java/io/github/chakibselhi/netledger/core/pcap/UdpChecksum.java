package io.github.chakibselhi.netledger.core.pcap;

import io.github.chakibselhi.netledger.core.decode.PacketLayout;

/**
 * Internet checksum (RFC 1071) of a UDP datagram, over a pseudo-header made of the IP source and
 * destination, the protocol number and the UDP length (RFC 768 for IPv4, RFC 8200 for IPv6).
 */
final class UdpChecksum {

  private static final int PROTOCOL_UDP = 17;

  private UdpChecksum() {}

  /** Recomputes the checksum in place. An IPv4 checksum of zero means "not used" and is kept. */
  static void update(byte[] frame, PacketLayout.Udp udp) {
    int checksumAt = udp.udpOffset() + 6;
    if (udp.ipVersion() == 4 && frame[checksumAt] == 0 && frame[checksumAt + 1] == 0) {
      return;
    }
    int udpLength = udp.payloadLength() + 8;
    frame[checksumAt] = 0;
    frame[checksumAt + 1] = 0;
    long sum;
    if (udp.ipVersion() == 4) {
      sum = add(0, frame, udp.ipOffset() + 12, 8);
    } else {
      sum = add(0, frame, udp.ipOffset() + 8, 32);
    }
    sum += PROTOCOL_UDP + udpLength;
    sum = add(sum, frame, udp.udpOffset(), udpLength);
    while ((sum >> 16) != 0) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    int checksum = (int) (~sum & 0xFFFF);
    if (checksum == 0) {
      checksum = 0xFFFF;
    }
    frame[checksumAt] = (byte) (checksum >> 8);
    frame[checksumAt + 1] = (byte) checksum;
  }

  static boolean isValid(byte[] frame, PacketLayout.Udp udp) {
    byte[] copy = frame.clone();
    update(copy, udp);
    int at = udp.udpOffset() + 6;
    return copy[at] == frame[at] && copy[at + 1] == frame[at + 1];
  }

  private static long add(long sum, byte[] data, int offset, int length) {
    for (int i = 0; i < length; i += 2) {
      int high = data[offset + i] & 0xFF;
      int low = i + 1 < length ? data[offset + i + 1] & 0xFF : 0;
      sum += (high << 8) | low;
    }
    return sum;
  }
}
