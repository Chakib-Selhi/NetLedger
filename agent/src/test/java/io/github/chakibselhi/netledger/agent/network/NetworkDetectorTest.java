package io.github.chakibselhi.netledger.agent.network;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.network.NetworkDetector.InterfaceAddressInfo;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class NetworkDetectorTest {

  // Same layout as `route -n get default` on macOS 27, with documentation addresses.
  static final String ROUTE =
      """
         route to: default
      destination: default
             mask: default
          gateway: 192.0.2.1
        interface: en0
            flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
       recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
             0         0         0         0         0         0      1500         0
      """;
  static final String ARP = "? (192.0.2.1) at c4:4f:d5:b9:a7:4 on en0 ifscope [ethernet]\n";

  private final List<List<String>> commands = new ArrayList<>();

  private NetworkDetector detector(Map<String, String> outputs, String override) {
    return new NetworkDetector(
        command -> {
          commands.add(command);
          return outputs.getOrDefault(command.get(0), "");
        },
        name ->
            name.equals("en0") || name.equals("en7")
                ? Optional.of(new InterfaceAddressInfo("192.0.2.57", 24))
                : Optional.empty(),
        override);
  }

  @Test
  void findsGatewayInterfaceSubnetAndPaddedGatewayMac() throws Exception {
    Optional<NetworkIdentity> network = detector(Map.of("route", ROUTE, "arp", ARP), null).detect();

    assertThat(network)
        .contains(
            new NetworkIdentity(
                "en0", "192.0.2.57", "192.0.2.0/24", "192.0.2.1", "c4:4f:d5:b9:a7:04"));
    assertThat(commands)
        .containsExactly(
            List.of("route", "-n", "get", "default"), List.of("arp", "-n", "192.0.2.1"));
  }

  @Test
  void interfaceOverrideWins() throws Exception {
    assertThat(detector(Map.of("route", ROUTE, "arp", ARP), "en7").detect())
        .hasValueSatisfying(n -> assertThat(n.interfaceName()).isEqualTo("en7"));
  }

  @Test
  void emptyWhenOfflineOrUnresolved() throws Exception {
    assertThat(
            detector(Map.of("route", "route: writing to routing socket: not in table\n"), null)
                .detect())
        .isEmpty();
    assertThat(
            detector(Map.of("route", ROUTE, "arp", "192.0.2.1 (192.0.2.1) -- no entry\n"), null)
                .detect())
        .isEmpty();
    assertThat(
            detector(
                    Map.of(
                        "route",
                        ROUTE,
                        "arp",
                        "? (192.0.2.1) at (incomplete) on en0 ifscope [ethernet]\n"),
                    null)
                .detect())
        .isEmpty();
    assertThat(detector(Map.of("route", ROUTE.replace("en0", "en9"), "arp", ARP), null).detect())
        .isEmpty();
  }

  @Test
  void neverPassesUnexpectedValuesToCommands() throws Exception {
    String hostileGateway = ROUTE.replace("192.0.2.1", "192.0.2.1;rm");
    String hostileInterface = ROUTE.replace("en0", "../en0");

    assertThat(detector(Map.of("route", hostileGateway, "arp", ARP), null).detect()).isEmpty();
    assertThat(detector(Map.of("route", hostileInterface, "arp", ARP), null).detect()).isEmpty();
    assertThat(commands).allSatisfy(c -> assertThat(c.get(0)).isEqualTo("route"));
  }

  @Test
  void parsesHelpers() {
    assertThat(NetworkDetector.parseArpMac("? (10.0.0.1) at 0:1:2:a:b:c on en0"))
        .contains("00:01:02:0a:0b:0c");
    assertThat(NetworkDetector.parseArpMac("? (10.0.0.1) at ff:ff:ff:ff:ff:ff on en0")).isEmpty();
    assertThat(NetworkDetector.isIpv4("256.0.0.1")).isFalse();
    assertThat(NetworkDetector.isIpv4("10.0.0.1")).isTrue();
    assertThat(NetworkDetector.subnet("10.225.228.188", 20)).isEqualTo("10.225.224.0/20");
    assertThat(NetworkDetector.subnet("10.0.0.1", 0)).isEqualTo("0.0.0.0/0");
  }

  @Test
  void sameNetworkIgnoresTheLocalAddress() {
    var a = new NetworkIdentity("en0", "10.0.0.2", "10.0.0.0/24", "10.0.0.1", "02:00:00:00:00:01");
    var b = new NetworkIdentity("en1", "10.0.0.99", "10.0.0.0/24", "10.0.0.1", "02:00:00:00:00:01");
    var c = new NetworkIdentity("en0", "10.0.0.2", "10.0.0.0/24", "10.0.0.1", "02:00:00:00:00:02");

    assertThat(a.sameNetworkAs(b)).isTrue();
    assertThat(a.sameNetworkAs(c)).isFalse();
    assertThat(a.sameNetworkAs(null)).isFalse();
  }

  @Test
  void javaLookupFindsLoopbackOrNothing() throws Exception {
    assertThat(NetworkDetector.javaInterfaceLookup("does-not-exist0")).isEmpty();
    assertThat(NetworkDetector.javaInterfaceLookup("lo0"))
        .hasValueSatisfying(a -> assertThat(a.ip()).isEqualTo("127.0.0.1"));
  }
}
