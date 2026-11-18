package io.github.chakibselhi.netledger.agent.mdns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Sends one standard DNS-SD service type enumeration ({@code _services._dns-sd._udp.local PTR?}) to
 * the mDNS group, like {@code dns-sd -B} does. Devices answer, and the passive capture records the
 * answers. Sent from an ephemeral port, so responders reply directly to the Mac (RFC 6762 section
 * 6.7) instead of to the whole group.
 *
 * <p>JmDNS was the PRD's choice, but creating a JmDNS instance announces a host name of its own on
 * the network; a single query is all the agent needs.
 */
public final class MdnsQuerier {

  static final InetSocketAddress MDNS_GROUP = new InetSocketAddress("224.0.0.251", 5353);
  private static final int TYPE_PTR = 12;
  private static final int CLASS_IN = 1;

  public void queryServiceTypes(String localIp) throws IOException {
    send(localIp, serviceTypeQuery());
  }

  private static void send(String localIp, byte[] query) throws IOException {
    try (var socket =
        new DatagramSocket(new InetSocketAddress(InetAddress.getByName(localIp), 0))) {
      socket.send(new DatagramPacket(query, query.length, MDNS_GROUP));
    }
  }

  /**
   * Service types whose instances identify a device type: a bare enumeration answer from a proxy
   * (Apple TV, HomePod) does not count, an instance of its own does.
   */
  static final List<String> IDENTIFYING_TYPES =
      List.of("_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp", "_printer._tcp");

  /** Asks every device for its instances of {@link #IDENTIFYING_TYPES}, in one packet. */
  public void queryIdentifyingInstances(String localIp) throws IOException {
    send(localIp, query(IDENTIFYING_TYPES));
  }

  static byte[] serviceTypeQuery() {
    return query(List.of("_services._dns-sd._udp"));
  }

  /** Header (id 0, standard query, one question per type) and the PTR questions. */
  static byte[] query(List<String> types) {
    var out = new ByteArrayOutputStream();
    out.writeBytes(new byte[] {0, 0, 0, 0, 0, (byte) types.size(), 0, 0, 0, 0, 0, 0});
    for (String type : types) {
      for (String label : (type + ".local").split("\\.")) {
        byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
        out.write(bytes.length);
        out.writeBytes(bytes);
      }
      out.write(0);
      out.writeBytes(new byte[] {0, TYPE_PTR, 0, CLASS_IN});
    }
    return out.toByteArray();
  }
}
