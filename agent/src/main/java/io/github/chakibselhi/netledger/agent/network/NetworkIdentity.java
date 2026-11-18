package io.github.chakibselhi.netledger.agent.network;

/**
 * The network the Mac is on, as the server identifies it (EF-03): the gateway's MAC address and the
 * IPv4 subnet. The interface and local address are what the capture needs.
 *
 * @param interfaceName capture interface, such as {@code en0}
 * @param localIp IPv4 address of the Mac on that interface
 * @param subnet CIDR, such as {@code 192.168.1.0/24}
 * @param gatewayIp default gateway
 * @param gatewayMac gateway MAC address, lower case and colon separated
 */
public record NetworkIdentity(
    String interfaceName, String localIp, String subnet, String gatewayIp, String gatewayMac) {

  /** Same network for the server: same gateway and subnet, whatever the local address. */
  public boolean sameNetworkAs(NetworkIdentity other) {
    return other != null && gatewayMac.equals(other.gatewayMac) && subnet.equals(other.subnet);
  }
}
