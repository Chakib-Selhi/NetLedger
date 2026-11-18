package io.github.chakibselhi.netledger.core.decode;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.time.Instant;
import java.util.Optional;

/**
 * Entry point of the decoding layer: one Ethernet frame in, at most one observation out.
 *
 * <p>Frames come from the network, so they are untrusted input. This method never throws for a
 * malformed frame: anything truncated or inconsistent simply yields no observation.
 */
public final class FrameDecoder {

  static final int DHCP_SERVER_PORT = 67;

  public Optional<Observation> decode(Instant timestamp, byte[] frame) {
    try {
      return decodeOrThrow(timestamp, frame);
    } catch (MalformedPacketException e) {
      return Optional.empty();
    }
  }

  private Optional<Observation> decodeOrThrow(Instant timestamp, byte[] frame) {
    PacketLayout layout = PacketLayout.parse(frame);
    if (layout.etherType() == PacketLayout.ETHERTYPE_ARP) {
      return ArpDecoder.decode(timestamp, frame, layout.payloadOffset());
    }
    PacketLayout.Udp udp = layout.udp();
    if (udp == null) {
      return Optional.empty();
    }
    if (udp.destinationPort() == DHCP_SERVER_PORT && udp.ipVersion() == 4) {
      return DhcpDecoder.decode(timestamp, frame, udp.payloadOffset(), udp.payloadLength());
    }
    if (udp.sourcePort() == MdnsDecoder.PORT || udp.destinationPort() == MdnsDecoder.PORT) {
      if (!MacAddresses.isUnicast(frame, PacketLayout.SOURCE_MAC_OFFSET)) {
        return Optional.empty();
      }
      return MdnsDecoder.decode(
          timestamp,
          layout.sourceMac(frame),
          udp.ipv4Source(),
          frame,
          udp.payloadOffset(),
          udp.payloadLength());
    }
    return Optional.empty();
  }
}
