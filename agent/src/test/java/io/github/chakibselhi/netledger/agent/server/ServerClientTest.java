package io.github.chakibselhi.netledger.agent.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import io.github.chakibselhi.netledger.agent.server.ServerException.Reason;
import io.github.chakibselhi.netledger.core.json.ObservationJson;
import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ServerClientTest {

  private static final NetworkIdentity HOME =
      new NetworkIdentity("en0", "10.0.0.2", "10.0.0.0/24", "10.0.0.1", "02:00:00:00:00:01");
  private final FakeServer server;
  private final ServerClient client;

  ServerClientTest() throws Exception {
    server = new FakeServer();
    client = new ServerClient(server.url(), "secret-token", Duration.ofSeconds(2));
  }

  @AfterEach
  void stop() {
    server.close();
  }

  @Test
  void declaresTheNetworkWithTheToken() throws Exception {
    NetworkDecision decision = client.declare(HOME);

    assertThat(decision).isEqualTo(new NetworkDecision(7, "owned", true));
    assertThat(decision.owned()).isTrue();
    FakeServer.Request request = server.requests("/api/v1/networks/current").get(0);
    assertThat(request.authorization()).isEqualTo("Bearer secret-token");
    assertThat(request.body())
        .contains("\"gatewayMac\":\"02:00:00:00:00:01\"")
        .contains("\"subnet\":\"10.0.0.0/24\"");
  }

  @Test
  void sendsBatchesInTheSharedFormat() throws Exception {
    var observation =
        Observation.presence(
            Instant.parse("2026-11-18T12:00:00Z"),
            ObservationSource.ARP,
            "a4:83:e7:00:00:01",
            "10.0.0.9");

    client.sendObservations(7, List.of(observation));

    String body = server.requests("/api/v1/observations").get(0).body();
    assertThat(ObservationJson.read(body).networkId()).isEqualTo(7);
    assertThat(ObservationJson.read(body).observations()).containsExactly(observation);
  }

  @Test
  void mapsStatusCodesToReasons() {
    for (int[] c : new int[][] {{401, 0}, {403, 1}, {404, 2}, {500, 3}, {400, 4}}) {
      server.observationsStatus = c[0];
      Reason expected =
          List.of(
                  Reason.UNAUTHORIZED,
                  Reason.NOT_MONITORED,
                  Reason.UNKNOWN_NETWORK,
                  Reason.UNAVAILABLE,
                  Reason.REJECTED)
              .get(c[1]);
      assertThatThrownBy(() -> client.sendObservations(7, List.of()))
          .isInstanceOfSatisfying(
              ServerException.class, e -> assertThat(e.reason()).isEqualTo(expected));
    }
  }

  @Test
  void healthAndUnreachableServer() throws Exception {
    assertThat(client.healthy()).isTrue();
    var down = new ServerClient(URI.create("http://127.0.0.1:1/"), "t", Duration.ofMillis(500));

    assertThat(down.healthy()).isFalse();
    assertThatThrownBy(() -> down.declare(HOME))
        .isInstanceOfSatisfying(
            ServerException.class, e -> assertThat(e.reason()).isEqualTo(Reason.UNAVAILABLE));
  }

  @Test
  void rejectsUnreadableAnswers() {
    server.declareStatus = 200;
    server.trust = "\"broken";

    assertThatThrownBy(() -> client.declare(HOME))
        .isInstanceOfSatisfying(
            ServerException.class, e -> assertThat(e.reason()).isEqualTo(Reason.REJECTED));
  }
}
