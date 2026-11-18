package io.github.chakibselhi.netledger.agent.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import io.github.chakibselhi.netledger.agent.server.ServerException.Reason;
import io.github.chakibselhi.netledger.core.json.ObservationJson;
import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationBatch;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** HTTP client of the server's agent API, authenticated by the shared token. */
public final class ServerClient {

  private final URI baseUrl;
  private final String authorization;
  private final HttpClient http;
  private final Duration timeout;
  private final ObjectMapper json = ObservationJson.mapper();

  public ServerClient(URI baseUrl, String token, Duration timeout) {
    this.baseUrl = baseUrl.toString().endsWith("/") ? baseUrl : URI.create(baseUrl + "/");
    this.authorization = "Bearer " + token;
    this.timeout = timeout;
    this.http = HttpClient.newBuilder().connectTimeout(timeout).build();
  }

  public boolean healthy() {
    try {
      return send(HttpRequest.newBuilder(baseUrl.resolve("api/v1/health")).GET()).statusCode()
          == 200;
    } catch (ServerException e) {
      return false;
    }
  }

  /** Declares the current network; the answer says whether capture is allowed. */
  public NetworkDecision declare(NetworkIdentity network) throws ServerException {
    String body = write(Map.of("gatewayMac", network.gatewayMac(), "subnet", network.subnet()));
    HttpResponse<String> response = check(send(post("api/v1/networks/current", body)));
    try {
      return json.readValue(response.body(), NetworkDecision.class);
    } catch (JsonProcessingException e) {
      throw new ServerException(Reason.REJECTED, "Unexpected server answer", e);
    }
  }

  public void sendObservations(long networkId, List<Observation> observations)
      throws ServerException {
    check(
        send(
            post(
                "api/v1/observations",
                ObservationJson.write(new ObservationBatch(networkId, observations)))));
  }

  private HttpRequest.Builder post(String path, String body) {
    return HttpRequest.newBuilder(baseUrl.resolve(path))
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body));
  }

  private HttpResponse<String> send(HttpRequest.Builder request) throws ServerException {
    try {
      return http.send(
          request.header("Authorization", authorization).timeout(timeout).build(),
          HttpResponse.BodyHandlers.ofString());
    } catch (IOException e) {
      throw new ServerException(Reason.UNAVAILABLE, "Server unreachable: " + e.getMessage(), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new ServerException(Reason.UNAVAILABLE, "Interrupted", e);
    }
  }

  static HttpResponse<String> check(HttpResponse<String> response) throws ServerException {
    int status = response.statusCode();
    if (status >= 200 && status < 300) {
      return response;
    }
    Reason reason =
        switch (status) {
          case 401 -> Reason.UNAUTHORIZED;
          case 403 -> Reason.NOT_MONITORED;
          case 404 -> Reason.UNKNOWN_NETWORK;
          default -> status >= 500 ? Reason.UNAVAILABLE : Reason.REJECTED;
        };
    throw new ServerException(reason, "Server answered HTTP " + status, null);
  }

  private String write(Object value) {
    try {
      return json.writeValueAsString(value);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }
}
