package io.github.chakibselhi.netledger.server.identification;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import io.github.chakibselhi.netledger.server.config.NetLedgerProperties;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OuiRegistryProviderTest {

  private static final String HEADER =
      "Registry,Assignment,Organization Name,Organization Address\n";
  private static final String TOKEN = "x".repeat(32);
  private static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");

  @TempDir Path dataDir;
  private HttpServer server;
  private final Map<String, String> served = new HashMap<>();
  private final Map<String, Integer> status = new HashMap<>();

  @BeforeEach
  void startServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        exchange -> {
          String path = exchange.getRequestURI().getPath().substring(1);
          byte[] body = served.getOrDefault(path, "").getBytes(StandardCharsets.UTF_8);
          exchange.sendResponseHeaders(status.getOrDefault(path, 200), body.length);
          exchange.getResponseBody().write(body);
          exchange.close();
        });
    server.start();
    served.put("oui/oui.csv", bigRegistry());
    served.put("oui28/mam.csv", HEADER);
    served.put("oui36/oui36.csv", HEADER);
  }

  @AfterEach
  void stopServer() {
    server.stop(0);
  }

  private static String bigRegistry() {
    var csv = new StringBuilder(HEADER);
    for (int i = 0; i < 1_200; i++) {
      csv.append("MA-L,%06X,Vendor %d,addr\n".formatted(0xF00000 + i, i));
    }
    return csv.toString();
  }

  private OuiRegistryProvider provider(boolean updates, Path bundled) {
    URI base = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
    var properties =
        new NetLedgerProperties(
            dataDir,
            TOKEN,
            1000,
            Duration.ofMinutes(5),
            Duration.ofDays(30),
            new NetLedgerProperties.Oui(bundled, updates, Duration.ofDays(30), base));
    return new OuiRegistryProvider(properties, Clock.fixed(NOW, ZoneOffset.UTC));
  }

  @Test
  void downloadsWhenMissingThenServesFromTheCache() {
    OuiRegistryProvider provider = provider(true, null);
    assertThat(provider.registry().size()).isZero();

    provider.refreshIfStale();

    assertThat(provider.registry().vendorOf("f0:00:05:00:00:01")).contains("Vendor 5");
    assertThat(dataDir.resolve("oui/oui.csv")).exists();
    assertThat(provider(false, null).registry().size()).isEqualTo(1_200);
  }

  @Test
  void prefersTheBundledCopyUntilADownloadExists() {
    OuiRegistryProvider provider = provider(false, Path.of("src/test/resources/oui"));

    assertThat(provider.registry().vendorOf("ec:b5:fa:00:00:01")).contains("Philips Lighting BV");
  }

  @Test
  void keepsTheCurrentRegistryWhenADownloadIsInvalid() throws Exception {
    OuiRegistryProvider provider = provider(true, Path.of("src/test/resources/oui"));
    int before = provider.registry().size();

    served.put("oui/oui.csv", HEADER + "MA-L,F00000,Only one,\n");
    assertThatThrownBy(provider::download).hasMessageContaining("only 1 entries");
    served.put("oui/oui.csv", "<html>Forbidden</html>");
    assertThatThrownBy(provider::download).hasMessageContaining("Not an IEEE registry");
    status.put("oui28/mam.csv", 503);
    served.put("oui/oui.csv", bigRegistry());
    assertThatThrownBy(provider::download).hasMessageContaining("HTTP 503");
    provider.refreshIfStale();

    assertThat(provider.registry().size()).isEqualTo(before);
    assertThat(dataDir.resolve("oui/oui.csv")).doesNotExist();
    try (var leftovers = Files.list(dataDir.resolve("oui"))) {
      assertThat(leftovers).as("temporary files are cleaned up").isEmpty();
    }
  }

  @Test
  void staleOnlyAfterTheUpdateInterval() throws Exception {
    OuiRegistryProvider provider = provider(true, null);
    assertThat(provider.isStale()).isTrue();

    provider.download();
    Path marker = dataDir.resolve("oui/oui.csv");
    Files.setLastModifiedTime(marker, FileTime.from(NOW.minus(Duration.ofDays(29))));
    assertThat(provider.isStale()).isFalse();
    Files.setLastModifiedTime(marker, FileTime.from(NOW.minus(Duration.ofDays(31))));
    assertThat(provider.isStale()).isTrue();
  }

  @Test
  void doesNothingWhenUpdatesAreDisabled() {
    OuiRegistryProvider provider = provider(false, null);

    provider.refreshIfStale();

    assertThat(dataDir.resolve("oui")).doesNotExist();
  }
}
