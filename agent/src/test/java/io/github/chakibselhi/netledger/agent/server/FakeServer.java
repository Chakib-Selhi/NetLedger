package io.github.chakibselhi.netledger.agent.server;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** Minimal stand-in for the NetLedger server, with scriptable answers. */
public final class FakeServer implements AutoCloseable {

  public record Request(String method, String path, String authorization, String body) {}

  public final List<Request> requests = new CopyOnWriteArrayList<>();
  public volatile int declareStatus = 200;
  public volatile String trust = "owned";
  public volatile long networkId = 7;
  public volatile int observationsStatus = 200;
  private final HttpServer server;

  public FakeServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          String body =
              new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
          String path = exchange.getRequestURI().getPath();
          requests.add(
              new Request(
                  exchange.getRequestMethod(),
                  path,
                  exchange.getRequestHeaders().getFirst("Authorization"),
                  body));
          int status;
          String answer = "";
          switch (path) {
            case "/api/v1/health" -> {
              status = 200;
              answer = "{\"status\":\"UP\"}";
            }
            case "/api/v1/networks/current" -> {
              status = declareStatus;
              boolean capture = trust.equals("owned") || trust.equals("authorized");
              answer =
                  "{\"networkId\":%d,\"label\":null,\"trust\":\"%s\",\"capture\":%s,\"extra\":1}"
                      .formatted(networkId, trust, capture);
            }
            case "/api/v1/observations" -> {
              status = observationsStatus;
              answer = "{\"accepted\":1,\"rejected\":0}";
            }
            default -> status = 404;
          }
          byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
          if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
          }
          exchange.close();
        });
    server.start();
  }

  public URI url() {
    return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
  }

  public List<Request> requests(String path) {
    return requests.stream().filter(r -> r.path().equals(path)).toList();
  }

  @Override
  public void close() {
    server.stop(0);
  }
}
