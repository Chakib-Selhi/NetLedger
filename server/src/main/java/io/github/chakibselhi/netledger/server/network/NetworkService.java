package io.github.chakibselhi.netledger.server.network;

import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.time.Clock;
import java.util.Locale;
import org.springframework.stereotype.Service;

/** Recognizes the network the agent is on (EF-03) and tells it whether to capture (EF-04). */
@Service
public class NetworkService {

  private final NetworkRepository networks;
  private final Clock clock;

  NetworkService(NetworkRepository networks, Clock clock) {
    this.networks = networks;
    this.clock = clock;
  }

  /**
   * @throws IllegalArgumentException when the gateway MAC or the subnet is invalid
   */
  public Network declareCurrent(String gatewayMac, String subnet) {
    String mac = gatewayMac == null ? null : gatewayMac.strip().toLowerCase(Locale.ROOT);
    if (!MacAddresses.isCanonical(mac)) {
      throw new IllegalArgumentException("gatewayMac must look like aa:bb:cc:dd:ee:ff");
    }
    return networks.upsert(mac, Subnet.parse(subnet), clock.instant());
  }
}
