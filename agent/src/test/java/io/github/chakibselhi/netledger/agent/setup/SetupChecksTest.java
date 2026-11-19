package io.github.chakibselhi.netledger.agent.setup;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.server.ServerClient.Health;
import io.github.chakibselhi.netledger.agent.setup.SetupChecks.Check;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SetupChecksTest {

  private static List<Check> run(boolean bpf, String token, Health health) {
    var asked = new AtomicReference<String>();
    List<Check> checks =
        new SetupChecks(
                () -> bpf,
                () -> Optional.ofNullable(token),
                t -> {
                  asked.set(t);
                  return health;
                })
            .run();
    if (token != null) {
      assertThat(asked.get()).isEqualTo(token);
    }
    return checks;
  }

  @Test
  void readyWhenEverythingPasses() {
    List<Check> checks = run(true, "secret", Health.UP);

    assertThat(checks).hasSize(3).allMatch(Check::ok);
    assertThat(checks).allMatch(c -> c.fix() == null);
    assertThat(SetupChecks.ready(checks)).isTrue();
  }

  @Test
  void bpfAndTokenAreRequired() {
    List<Check> noBpf = run(false, "secret", Health.UP);
    assertThat(SetupChecks.ready(noBpf)).isFalse();
    assertThat(noBpf.get(0).fix()).contains("wireshark-chmodbpf");

    List<Check> noToken = run(true, null, Health.UP);
    assertThat(SetupChecks.ready(noToken)).isFalse();
    assertThat(noToken.get(1).fix()).contains("install-agent-token.sh");
    assertThat(noToken.get(2).ok()).isFalse();
    assertThat(noToken.get(2).fix()).isNull();
  }

  @Test
  void aServerProblemDoesNotPreventStarting() {
    List<Check> down = run(true, "secret", Health.UNREACHABLE);
    assertThat(SetupChecks.ready(down)).isTrue();
    assertThat(down.get(2).fix()).contains("docker compose up -d");

    List<Check> refused = run(true, "secret", Health.TOKEN_REFUSED);
    assertThat(SetupChecks.ready(refused)).isTrue();
    assertThat(refused.get(2).detail()).contains("refuse le jeton");
  }
}
