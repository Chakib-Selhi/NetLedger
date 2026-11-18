package io.github.chakibselhi.netledger.server.network;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * An IPv4 subnet in CIDR notation, normalized so that host bits are zero (10.0.0.7/24 ->
 * 10.0.0.0/24).
 */
public record Subnet(String network, int prefixLength) {

  private static final Pattern CIDR = Pattern.compile("(\\d{1,3}(?:\\.\\d{1,3}){3})/(\\d{1,2})");

  public static Subnet parse(String cidr) {
    var matcher = CIDR.matcher(cidr == null ? "" : cidr.strip());
    if (!matcher.matches()) {
      throw new IllegalArgumentException("Subnet must be IPv4 CIDR, such as 192.168.1.0/24");
    }
    int prefix = Integer.parseInt(matcher.group(2));
    if (prefix < 8 || prefix > 30) {
      throw new IllegalArgumentException("Subnet prefix must be between /8 and /30");
    }
    byte[] address;
    try {
      // The pattern guarantees a numeric literal, so no DNS lookup happens here.
      InetAddress parsed = InetAddress.getByName(matcher.group(1));
      if (!(parsed instanceof Inet4Address)) {
        throw new IllegalArgumentException("Subnet must be IPv4");
      }
      address = parsed.getAddress();
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Invalid subnet address");
    }
    for (String octet : matcher.group(1).split("\\.")) {
      if (Integer.parseInt(octet) > 255) {
        throw new IllegalArgumentException("Invalid subnet address");
      }
    }
    int value =
        ((address[0] & 0xFF) << 24)
            | ((address[1] & 0xFF) << 16)
            | ((address[2] & 0xFF) << 8)
            | (address[3] & 0xFF);
    int masked = value & (int) (0xFFFFFFFFL << (32 - prefix));
    String network =
        (masked >>> 24)
            + "."
            + ((masked >>> 16) & 0xFF)
            + "."
            + ((masked >>> 8) & 0xFF)
            + "."
            + (masked & 0xFF);
    return new Subnet(network, prefix);
  }

  @Override
  public String toString() {
    return network + "/" + prefixLength;
  }
}
