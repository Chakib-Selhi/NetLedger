package io.github.chakibselhi.netledger.core.decode;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.time.Instant;
import java.util.Optional;

/**
 * ARP over Ethernet (RFC 826), 28 bytes after the Ethernet header:
 *
 * <pre>
 *  0  hardware type (1 = Ethernet)      2  protocol type (0x0800 = IPv4)
 *  4  hardware length (6)               5  protocol length (4)
 *  6  operation (1 = request, 2 = reply)
 *  8  sender MAC   14  sender IPv4   18  target MAC   24  target IPv4
 * </pre>
 *
 * <p>The sender pair is what the device says about itself, so it becomes the observation. A sender
 * IPv4 of 0.0.0.0 is an ARP probe (RFC 5227: "is this address free?"), so only presence is
 * recorded. Gratuitous ARP (sender IP equal to target IP) is an announcement and is kept.
 */
final class ArpDecoder {

  static final int OPERATION_REQUEST = 1;
  static final int OPERATION_REPLY = 2;

  private ArpDecoder() {}

  static Optional<Observation> decode(Instant timestamp, byte[] frame, int offset) {
    var cursor = new ByteCursor(frame, offset, frame.length - offset);
    int hardwareType = cursor.u16();
    int protocolType = cursor.u16();
    int hardwareLength = cursor.u8();
    int protocolLength = cursor.u8();
    if (hardwareType != 1
        || protocolType != PacketLayout.ETHERTYPE_IPV4
        || hardwareLength != MacAddresses.LENGTH
        || protocolLength != 4) {
      return Optional.empty();
    }
    int operation = cursor.u16();
    if (operation != OPERATION_REQUEST && operation != OPERATION_REPLY) {
      return Optional.empty();
    }
    int senderMac = cursor.take(MacAddresses.LENGTH);
    int senderIp = cursor.take(4);
    cursor.skip(MacAddresses.LENGTH + 4);
    // Anything after the 28 bytes is Ethernet padding and is ignored.
    if (!MacAddresses.isUnicast(frame, senderMac)) {
      return Optional.empty();
    }
    String ip = isZero(frame, senderIp) ? null : PacketLayout.address(frame, senderIp, 4);
    return Optional.of(
        Observation.presence(
            timestamp, ObservationSource.ARP, MacAddresses.format(frame, senderMac), ip));
  }

  private static boolean isZero(byte[] data, int offset) {
    return data[offset] == 0
        && data[offset + 1] == 0
        && data[offset + 2] == 0
        && data[offset + 3] == 0;
  }
}
