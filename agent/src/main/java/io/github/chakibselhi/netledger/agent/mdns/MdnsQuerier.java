package io.github.chakibselhi.netledger.agent.mdns;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

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
    byte[] query = serviceTypeQuery();
    try (var socket =
        new DatagramSocket(new InetSocketAddress(InetAddress.getByName(localIp), 0))) {
      socket.send(new DatagramPacket(query, query.length, MDNS_GROUP));
    }
  }

  /** Header (id 0, standard query, one question) and the PTR question. */
  static byte[] serviceTypeQuery() {
    var out = new ByteArrayOutputStream();
    out.writeBytes(new byte[] {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0});
    for (String label : new String[] {"_services", "_dns-sd", "_udp", "local"}) {
      byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
      out.write(bytes.length);
      out.writeBytes(bytes);
    }
    out.write(0);
    out.writeBytes(new byte[] {0, TYPE_PTR, 0, CLASS_IN});
    return out.toByteArray();
  }
}
