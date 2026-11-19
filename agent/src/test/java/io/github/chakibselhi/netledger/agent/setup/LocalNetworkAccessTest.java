package io.github.chakibselhi.netledger.agent.setup;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.setup.LocalNetworkAccess.State;
import java.io.IOException;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class LocalNetworkAccessTest {

  private static LocalNetworkAccess access(Optional<String> gateway, String arp, boolean fails) {
    return new LocalNetworkAccess(
        new LocalNetworkAccess.Probe() {
          @Override
          public Optional<String> gateway() throws IOException {
            if (fails) {
              throw new IOException("route exited with 1");
            }
            return gateway;
          }

          @Override
          public String arpEntry(String ip) {
            return arp;
          }
        },
        () -> {});
  }

  @Test
  void hiddenGatewayEntryMeansBlocked() {
    assertThat(
            access(
                    Optional.of("10.0.0.1"),
                    "arp exited with 1: 10.0.0.1 (10.0.0.1) -- no entry",
                    false)
                .state())
        .isEqualTo(State.BLOCKED);
  }

  @Test
  void visibleGatewayEntryMeansOk() {
    assertThat(
            access(
                    Optional.of("10.0.0.1"),
                    "? (10.0.0.1) at 02:00:5e:10:00:01 on en0 ifscope [ethernet]",
                    false)
                .state())
        .isEqualTo(State.OK);
  }

  @Test
  void noDefaultRouteMeansOffline() {
    assertThat(access(Optional.empty(), "", false).state()).isEqualTo(State.OFFLINE);
    assertThat(access(Optional.empty(), "", true).state()).isEqualTo(State.OFFLINE);
  }

  @Test
  void requestSendsThePrompt() throws IOException {
    var sent = new AtomicInteger();
    new LocalNetworkAccess(
            new LocalNetworkAccess.Probe() {
              @Override
              public Optional<String> gateway() {
                return Optional.empty();
              }

              @Override
              public String arpEntry(String ip) {
                return "";
              }
            },
            sent::incrementAndGet)
        .request();

    assertThat(sent).hasValue(1);
  }
}
