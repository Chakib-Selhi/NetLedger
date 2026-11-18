package io.github.chakibselhi.netledger.agent.scan;

import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/**
 * Optional active ARP sweep (EF-17): one "who-has" request per address of the Mac's own subnet, to
 * find silent devices. Replies arrive through the passive capture like any other ARP frame.
 *
 * <p>Safeguards: the agent only calls it on networks the user marked as theirs, it never leaves the
 * subnet the Mac is on, it refuses subnets larger than {@value #MAX_TARGETS} addresses, and it
 * paces requests ({@value #REQUESTS_PER_SECOND} per second).
 */
public final class ArpScanner {

  /** Sends one raw Ethernet frame on an interface. */
  @FunctionalInterface
  public interface FrameSender {
    void send(String interfaceName, List<byte[]> frames, Duration spacing) throws IOException;
  }

  static final int MAX_TARGETS = 1024;
  static final int REQUESTS_PER_SECOND = 50;
  private static final byte[] BROADCAST = {-1, -1, -1, -1, -1, -1};

  private final FrameSender sender;

  public ArpScanner(FrameSender sender) {
    this.sender = sender;
  }

  /**
   * @param localMac the Mac's own address on the interface, used as sender
   * @return number of requests sent
   * @throws IllegalArgumentException when the subnet is too large to sweep
   */
  public int scan(NetworkIdentity network, byte[] localMac) throws IOException {
    List<String> targets = targets(network.subnet(), network.localIp());
    var frames = new ArrayList<byte[]>(targets.size());
    for (String target : targets) {
      frames.add(request(localMac, network.localIp(), target));
    }
    sender.send(network.interfaceName(), frames, Duration.ofMillis(1000 / REQUESTS_PER_SECOND));
    return frames.size();
  }

  /** Every host address of the subnet except the Mac itself (no network or broadcast address). */
  static List<String> targets(String cidr, String localIp) {
    String[] parts = cidr.split("/");
    int prefix = Integer.parseInt(parts[1]);
    long size = 1L << (32 - prefix);
    if (prefix < 22 || size - 2 > MAX_TARGETS) {
      throw new IllegalArgumentException(
          "Refusing to sweep " + cidr + ": more than " + MAX_TARGETS + " addresses");
    }
    int base = toInt(parts[0]);
    int self = toInt(localIp);
    var targets = new ArrayList<String>();
    for (long i = 1; i < size - 1; i++) {
      int address = base + (int) i;
      if (address != self) {
        targets.add(toText(address));
      }
    }
    return targets;
  }

  /**
   * Ethernet broadcast frame carrying an ARP request (RFC 826): "who has {@code targetIp}? tell
   * {@code localIp}". 42 bytes; the network card pads it to the 60-byte Ethernet minimum.
   */
  static byte[] request(byte[] localMac, String localIp, String targetIp) {
    ByteBuffer frame = ByteBuffer.allocate(42);
    frame.put(BROADCAST).put(localMac).putShort((short) 0x0806);
    frame
        .putShort((short) 1)
        .putShort((short) 0x0800)
        .put((byte) 6)
        .put((byte) 4)
        .putShort((short) 1);
    frame.put(localMac).put(address(localIp)).put(new byte[6]).put(address(targetIp));
    return frame.array();
  }

  private static byte[] address(String ip) {
    try {
      return InetAddress.getByName(ip).getAddress();
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Not an IPv4 literal: " + ip, e);
    }
  }

  private static int toInt(String ip) {
    byte[] b = address(ip);
    return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
  }

  private static String toText(int ip) {
    return (ip >>> 24) + "." + ((ip >>> 16) & 0xFF) + "." + ((ip >>> 8) & 0xFF) + "." + (ip & 0xFF);
  }
}
