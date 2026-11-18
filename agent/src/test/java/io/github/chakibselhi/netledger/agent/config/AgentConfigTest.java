package io.github.chakibselhi.netledger.agent.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AgentConfigTest {

  @Test
  void defaultsMatchThePrd(@TempDir Path dir) throws IOException {
    AgentConfig config = AgentConfig.load(dir.resolve("missing.properties"));

    assertThat(config.serverUrl()).hasToString("http://127.0.0.1:8080");
    assertThat(config.interfaceOverride()).isNull();
    assertThat(config.bufferCapacity()).isEqualTo(10_000);
    assertThat(config.mdnsQueryInterval()).isEqualTo(Duration.ofMinutes(15));
    assertThat(config.arpScanEnabled()).isFalse();
    assertThat(config.arpScanInterval()).isEqualTo(Duration.ofMinutes(15));
    assertThat(AgentConfig.defaultFile().toString())
        .endsWith("/Library/Application Support/NetLedger/agent.properties");
  }

  @Test
  void readsOverridesFromTheFile(@TempDir Path dir) throws IOException {
    Path file = dir.resolve("agent.properties");
    Files.writeString(
        file,
        "server.url=https://127.0.0.1:8443\ninterface=en7\narp.scan.enabled=true\nflush.interval=PT2S\n");

    AgentConfig config = AgentConfig.load(file);

    assertThat(config.serverUrl()).hasToString("https://127.0.0.1:8443");
    assertThat(config.interfaceOverride()).isEqualTo("en7");
    assertThat(config.arpScanEnabled()).isTrue();
    assertThat(config.flushInterval()).isEqualTo(Duration.ofSeconds(2));
  }

  @Test
  void rejectsNonHttpServers() {
    var p = new Properties();
    p.setProperty("server.url", "file:///etc/passwd");

    assertThatThrownBy(() -> AgentConfig.from(p)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void readsTheTokenFromTheKeychain() {
    var store =
        new KeychainTokenStore(
            command -> {
              assertThat(command)
                  .isEqualTo(
                      List.of(
                          "security",
                          "find-generic-password",
                          "-s",
                          "NetLedger",
                          "-a",
                          "agent",
                          "-w"));
              return "abc123\n";
            });

    assertThat(store.read()).contains("abc123");
    assertThat(new KeychainTokenStore(c -> "  \n").read()).isEmpty();
    assertThat(
            new KeychainTokenStore(
                    c -> {
                      throw new IOException("item not found");
                    })
                .read())
        .isEmpty();
  }
}
