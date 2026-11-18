package io.github.chakibselhi.netledger.agent.alerts;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chakibselhi.netledger.core.json.ObservationJson;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Listens to the server's alert stream ({@code GET /api/v1/alerts/stream}) on its own thread and
 * hands each alert to a consumer. Reconnects with a growing delay, up to one minute, whenever the
 * stream ends or the server is unreachable.
 */
public final class AlertStreamClient {

  private static final Logger log = LoggerFactory.getLogger(AlertStreamClient.class);
  static final Duration MAX_RETRY_DELAY = Duration.ofMinutes(1);

  private final URI streamUrl;
  private final String authorization;
  private final Consumer<Alert> consumer;
  private final HttpClient http;
  private final ObjectMapper json = ObservationJson.mapper();
  private final Thread thread;
  private volatile boolean running = true;
  private volatile boolean connected;

  public AlertStreamClient(URI serverUrl, String token, Consumer<Alert> consumer) {
    String base = serverUrl.toString().endsWith("/") ? serverUrl.toString() : serverUrl + "/";
    this.streamUrl = URI.create(base + "api/v1/alerts/stream");
    this.authorization = "Bearer " + token;
    this.consumer = consumer;
    this.http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    this.thread = Thread.ofPlatform().daemon().name("alerts").unstarted(this::run);
  }

  public AlertStreamClient start() {
    thread.start();
    return this;
  }

  public boolean connected() {
    return connected;
  }

  public void stop() {
    running = false;
    thread.interrupt();
  }

  private void run() {
    Duration delay = Duration.ofSeconds(1);
    while (running) {
      try {
        listenOnce();
        delay = Duration.ofSeconds(1);
      } catch (IOException e) {
        log.debug("Alert stream unavailable: {}", e.getMessage());
      } catch (InterruptedException e) {
        return;
      } finally {
        connected = false;
      }
      try {
        Thread.sleep(delay);
      } catch (InterruptedException e) {
        return;
      }
      delay =
          delay.multipliedBy(2).compareTo(MAX_RETRY_DELAY) > 0
              ? MAX_RETRY_DELAY
              : delay.multipliedBy(2);
    }
  }

  /** Reads one connection until it ends. */
  void listenOnce() throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(streamUrl)
            .header("Authorization", authorization)
            .header("Accept", "text/event-stream")
            .GET()
            .build();
    HttpResponse<Stream<String>> response = http.send(request, HttpResponse.BodyHandlers.ofLines());
    if (response.statusCode() != 200) {
      response.body().close();
      throw new IOException("Alert stream answered HTTP " + response.statusCode());
    }
    connected = true;
    var parser = new SseParser();
    try (Stream<String> lines = response.body()) {
      lines.forEach(
          line ->
              parser.feed(line).filter(e -> e.name().equals("alert")).ifPresent(this::dispatch));
    }
  }

  private void dispatch(SseParser.Event event) {
    try {
      consumer.accept(json.readValue(event.data(), Alert.class));
    } catch (JsonProcessingException e) {
      log.warn("Ignoring a malformed alert: {}", e.getOriginalMessage());
    } catch (RuntimeException e) {
      log.warn("Alert handling failed: {}", e.getMessage());
    }
  }
}
