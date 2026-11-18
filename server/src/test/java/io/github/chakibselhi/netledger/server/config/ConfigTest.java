package io.github.chakibselhi.netledger.server.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class ConfigTest {

  private static NetLedgerProperties properties(String token) {
    return new NetLedgerProperties(
        Path.of("data"),
        token,
        1000,
        Duration.ofMinutes(5),
        Duration.ofDays(30),
        null,
        List.of("127.0.0.1"));
  }

  @Test
  void refusesToStartWithoutAStrongToken() {
    assertThatThrownBy(() -> properties(null)).hasMessageContaining("NETLEDGER_AGENT_TOKEN");
    assertThatThrownBy(() -> properties("short")).hasMessageContaining("at least 32");
    assertThatThrownBy(() -> properties(" ".repeat(40))).isInstanceOf(IllegalStateException.class);
    assertThat(properties(" " + "k".repeat(32) + "\n").agentToken()).isEqualTo("k".repeat(32));
    assertThat(properties("k".repeat(32)).ouiCacheDir()).isEqualTo(Path.of("data", "oui"));
  }

  @Test
  void bodiesOfUnknownLengthAreRefused() throws Exception {
    var request = new MockHttpServletRequest("POST", "/api/v1/observations");
    var response = new MockHttpServletResponse();
    var chain = new MockFilterChain();

    new RequestSizeFilter().doFilter(request, response, chain);

    assertThat(response.getStatus()).isEqualTo(411);
    assertThat(chain.getRequest()).isNull();
  }

  @Test
  void requestsWithoutBodyPass() throws Exception {
    var chain = new MockFilterChain();

    new RequestSizeFilter()
        .doFilter(
            new MockHttpServletRequest("GET", "/api/v1/health"),
            new MockHttpServletResponse(),
            chain);

    assertThat(chain.getRequest()).isNotNull();
  }
}
