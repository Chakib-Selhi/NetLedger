package io.github.chakibselhi.netledger.server.api;

import io.github.chakibselhi.netledger.core.model.ObservationBatch;
import io.github.chakibselhi.netledger.server.config.NetLedgerProperties;
import io.github.chakibselhi.netledger.server.correlation.CorrelationEngine;
import io.github.chakibselhi.netledger.server.correlation.IngestResult;
import io.github.chakibselhi.netledger.server.network.Network;
import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.network.NetworkService;
import io.github.chakibselhi.netledger.server.network.Trust;
import java.time.Clock;
import java.time.Instant;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Routes used by the native agent. All require the shared token (see SecurityConfig). */
@RestController
@RequestMapping("/api/v1")
class AgentApiController {

  record Health(String status, Instant time) {}

  record CurrentNetworkRequest(String gatewayMac, String subnet) {}

  /**
   * @param capture whether the agent may capture on this network: only when the user declared it as
   *     theirs or as authorized by its administrator
   */
  record CurrentNetworkResponse(long networkId, String label, Trust trust, boolean capture) {}

  private final NetworkService networkService;
  private final NetworkRepository networks;
  private final CorrelationEngine correlation;
  private final int maxBatchSize;
  private final Clock clock;

  AgentApiController(
      NetworkService networkService,
      NetworkRepository networks,
      CorrelationEngine correlation,
      NetLedgerProperties properties,
      Clock clock) {
    this.networkService = networkService;
    this.networks = networks;
    this.correlation = correlation;
    this.maxBatchSize = properties.maxBatchSize();
    this.clock = clock;
  }

  @GetMapping("/health")
  Health health() {
    return new Health("UP", clock.instant());
  }

  @PostMapping("/networks/current")
  CurrentNetworkResponse currentNetwork(@RequestBody CurrentNetworkRequest request) {
    Network network = networkService.declareCurrent(request.gatewayMac(), request.subnet());
    return new CurrentNetworkResponse(
        network.id(), network.label(), network.trust(), network.trust().allowsCapture());
  }

  @PostMapping("/observations")
  IngestResult observations(@RequestBody ObservationBatch batch) {
    if (batch.observations().size() > maxBatchSize) {
      throw new ApiException(
          HttpStatus.PAYLOAD_TOO_LARGE, "A batch holds at most " + maxBatchSize + " observations");
    }
    Network network =
        networks
            .findById(batch.networkId())
            .orElseThrow(() -> new ApiException(HttpStatus.NOT_FOUND, "Unknown network"));
    if (!network.trust().allowsCapture()) {
      // Defense in depth for EF-04: even a misbehaving agent cannot store data from a network
      // the user has not declared as theirs or authorized.
      throw new ApiException(HttpStatus.FORBIDDEN, "This network is not monitored");
    }
    return correlation.ingest(network.id(), batch.observations());
  }
}
