package io.github.chakibselhi.netledger.agent.alerts;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AlertStreamClientTest {

  private final HttpServer server;
  private final AtomicInteger connections = new AtomicInteger();
  private final List<String> authorizations = new CopyOnWriteArrayList<>();

  AlertStreamClientTest() throws Exception {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/api/v1/alerts/stream",
        exchange -> {
          authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));
          if (connections.incrementAndGet() == 1) {
            exchange.sendResponseHeaders(503, -1);
            exchange.close();
            return;
          }
          exchange.getResponseHeaders().add("Content-Type", "text/event-stream");
          exchange.sendResponseHeaders(200, 0);
          try (OutputStream out = exchange.getResponseBody()) {
            String body =
                ":ping\n\n"
                    + "event:alert\ndata:{\"id\":5,\"kind\":\"new_device\",\"title\":\"Nouvel appareil\","
                    + "\"message\":\"Réseau à l'étage\",\"sound\":true,\"occurredAt\":\"2026-11-18T12:00:00.000Z\","
                    + "\"path\":\"/devices/5\",\"future\":1}\n\n"
                    + "event:alert\ndata:{not json\n\n";
            out.write(body.getBytes(StandardCharsets.UTF_8));
          }
        });
    server.start();
  }

  @AfterEach
  void stop() {
    server.stop(0);
  }

  @Test
  void reconnectsAndDeliversAlertsDecodedAsUtf8() throws Exception {
    var received = new CopyOnWriteArrayList<Alert>();
    var got = new CountDownLatch(1);
    var client =
        new AlertStreamClient(
                URI.create("http://127.0.0.1:" + server.getAddress().getPort()),
                "secret",
                alert -> {
                  received.add(alert);
                  got.countDown();
                })
            .start();

    assertThat(got.await(10, TimeUnit.SECONDS)).isTrue();
    client.stop();

    assertThat(received)
        .first()
        .isEqualTo(
            new Alert(
                5,
                "new_device",
                "Nouvel appareil",
                "Réseau à l'étage",
                true,
                "2026-11-18T12:00:00.000Z",
                "/devices/5"));
    assertThat(connections.get()).isGreaterThanOrEqualTo(2);
    assertThat(authorizations).allMatch("Bearer secret"::equals);
  }

  @Test
  void recentAlertsKeepsTheNewestFirst() {
    var recent = new RecentAlerts(2);
    for (int i = 1; i <= 3; i++) {
      recent.add(new Alert(i, "k", "t", "m" + i, false, "2026-11-18T12:00:00Z", "/"));
    }

    assertThat(recent.list()).extracting(Alert::id).containsExactly(3L, 2L);
  }
}
