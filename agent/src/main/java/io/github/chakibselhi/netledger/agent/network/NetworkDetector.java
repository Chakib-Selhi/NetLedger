package io.github.chakibselhi.netledger.agent.network;

import io.github.chakibselhi.netledger.agent.system.CommandRunner;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the network the Mac is on, using the routing table and the ARP cache:
 *
 * <ol>
 *   <li>{@code route -n get default}: default gateway and the interface used to reach it;
 *   <li>the interface's IPv4 address and prefix length, which give the subnet;
 *   <li>{@code arp -n <gateway>}: the gateway's MAC address, already in the ARP cache because all
 *       traffic leaving the subnet goes through it. Nothing is sent to find it.
 * </ol>
 */
public final class NetworkDetector {

  private static final Pattern GATEWAY = Pattern.compile("(?m)^\\s*gateway:\\s*(\\S+)\\s*$");
  private static final Pattern INTERFACE = Pattern.compile("(?m)^\\s*interface:\\s*(\\S+)\\s*$");
  private static final Pattern IPV4 =
      Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
  // macOS prints MAC octets without leading zeros: "c4:4f:d5:b9:a7:4".
  private static final Pattern ARP_MAC =
      Pattern.compile("\\sat\\s+((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})\\s");
  private static final Pattern INTERFACE_NAME = Pattern.compile("[a-z]{1,8}\\d{1,3}");

  /** IPv4 address and prefix length of an interface. */
  public record InterfaceAddressInfo(String ip, int prefixLength) {}

  /** Looks up the IPv4 address of an interface; replaceable in tests. */
  @FunctionalInterface
  public interface InterfaceLookup {
    Optional<InterfaceAddressInfo> ipv4(String interfaceName) throws IOException;
  }

  private final CommandRunner commands;
  private final InterfaceLookup interfaces;
  private final String interfaceOverride;

  public NetworkDetector(
      CommandRunner commands, InterfaceLookup interfaces, String interfaceOverride) {
    this.commands = commands;
    this.interfaces = interfaces;
    this.interfaceOverride = interfaceOverride;
  }

  /** The current network, or empty when offline or when the gateway is not resolved yet. */
  public Optional<NetworkIdentity> detect() throws IOException {
    String route = commands.run(List.of("route", "-n", "get", "default"));
    Optional<String> gateway = field(GATEWAY, route).filter(NetworkDetector::isIpv4);
    Optional<String> routeInterface = field(INTERFACE, route);
    String interfaceName =
        interfaceOverride != null ? interfaceOverride : routeInterface.orElse(null);
    if (gateway.isEmpty()
        || interfaceName == null
        || !INTERFACE_NAME.matcher(interfaceName).matches()) {
      return Optional.empty();
    }
    Optional<InterfaceAddressInfo> address = interfaces.ipv4(interfaceName);
    if (address.isEmpty()) {
      return Optional.empty();
    }
    Optional<String> gatewayMac = parseArpMac(commands.run(List.of("arp", "-n", gateway.get())));
    if (gatewayMac.isEmpty()) {
      return Optional.empty();
    }
    return Optional.of(
        new NetworkIdentity(
            interfaceName,
            address.get().ip(),
            subnet(address.get().ip(), address.get().prefixLength()),
            gateway.get(),
            gatewayMac.get()));
  }

  static Optional<String> field(Pattern pattern, String text) {
    Matcher matcher = pattern.matcher(text);
    return matcher.find() ? Optional.of(matcher.group(1)) : Optional.empty();
  }

  /** Extracts and normalizes the MAC from {@code arp -n} output (padding octets to 2 digits). */
  static Optional<String> parseArpMac(String arpOutput) {
    Matcher matcher = ARP_MAC.matcher(arpOutput);
    if (!matcher.find()) {
      return Optional.empty();
    }
    var normalized = new StringBuilder();
    for (String octet : matcher.group(1).split(":")) {
      if (!normalized.isEmpty()) {
        normalized.append(':');
      }
      normalized.append(octet.length() == 1 ? "0" + octet : octet);
    }
    String mac = normalized.toString().toLowerCase(Locale.ROOT);
    return "00:00:00:00:00:00".equals(mac) || "ff:ff:ff:ff:ff:ff".equals(mac)
        ? Optional.empty()
        : Optional.of(mac);
  }

  static boolean isIpv4(String text) {
    Matcher matcher = IPV4.matcher(text);
    if (!matcher.matches()) {
      return false;
    }
    for (int i = 1; i <= 4; i++) {
      if (Integer.parseInt(matcher.group(i)) > 255) {
        return false;
      }
    }
    return true;
  }

  /** Network address of {@code ip/prefix}: host bits cleared. */
  static String subnet(String ip, int prefixLength) {
    String[] parts = ip.split("\\.");
    int value = 0;
    for (String part : parts) {
      value = (value << 8) | Integer.parseInt(part);
    }
    int mask = prefixLength == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - prefixLength));
    int network = value & mask;
    return (network >>> 24)
        + "."
        + ((network >>> 16) & 0xFF)
        + "."
        + ((network >>> 8) & 0xFF)
        + "."
        + (network & 0xFF)
        + "/"
        + prefixLength;
  }

  /** Reads the address from the JDK, which needs no command. */
  public static Optional<InterfaceAddressInfo> javaInterfaceLookup(String name)
      throws SocketException {
    NetworkInterface nif = NetworkInterface.getByName(name);
    if (nif == null || !nif.isUp()) {
      return Optional.empty();
    }
    for (InterfaceAddress address : nif.getInterfaceAddresses()) {
      if (address.getAddress() instanceof Inet4Address ipv4) {
        return Optional.of(
            new InterfaceAddressInfo(ipv4.getHostAddress(), address.getNetworkPrefixLength()));
      }
    }
    return Optional.empty();
  }
}
