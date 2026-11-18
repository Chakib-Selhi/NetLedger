package io.github.chakibselhi.netledger.server.network;

import io.github.chakibselhi.netledger.core.net.MacAddresses;
import io.github.chakibselhi.netledger.server.alerting.AlertRules;
import java.time.Clock;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Recognizes the network the agent is on (EF-03) and tells it whether to capture (EF-04). */
@Service
public class NetworkService {

  private final NetworkRepository networks;
  private final AlertRules alerts;
  private final Clock clock;

  NetworkService(NetworkRepository networks, AlertRules alerts, Clock clock) {
    this.networks = networks;
    this.alerts = alerts;
    this.clock = clock;
  }

  /**
   * @throws IllegalArgumentException when the gateway MAC or the subnet is invalid
   */
  @Transactional
  public Network declareCurrent(String gatewayMac, String subnet) {
    String mac = gatewayMac == null ? null : gatewayMac.strip().toLowerCase(Locale.ROOT);
    if (!MacAddresses.isCanonical(mac)) {
      throw new IllegalArgumentException("gatewayMac must look like aa:bb:cc:dd:ee:ff");
    }
    Subnet parsed = Subnet.parse(subnet);
    Optional<Network> before = networks.find(mac, parsed);
    Network network = networks.upsert(mac, parsed, clock.instant());
    if (before.isEmpty()) {
      alerts.onNewNetwork(network);
    } else {
      alerts.onNetworkSeenAgain(before.get());
    }
    return network;
  }

  /** Sets what the user declared; monitoring starts the learning period. */
  @Transactional
  public void changeTrust(long networkId, Trust trust) {
    if (!networks.setTrust(networkId, trust)) {
      throw new NoSuchElementException("Unknown network");
    }
    if (trust.allowsCapture()) {
      networks.findById(networkId).ifPresent(alerts::ensureLearningStarted);
    }
  }

  /** An empty label clears it. */
  public void rename(long networkId, String label) {
    if (!networks.setLabel(networkId, label == null || label.isEmpty() ? null : label)) {
      throw new NoSuchElementException("Unknown network");
    }
  }
}
