package io.github.chakibselhi.netledger.agent.setup;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.server.ServerClient.Health;
import io.github.chakibselhi.netledger.agent.setup.LocalNetworkAccess.State;
import io.github.chakibselhi.netledger.agent.setup.SetupChecks.Check;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SetupChecksTest {

  private final AtomicBoolean requested = new AtomicBoolean();

  private List<Check> run(boolean bpf, State network, String token, Health health) {
    var asked = new AtomicReference<String>();
    List<Check> checks =
        new SetupChecks(
                () -> bpf,
                () -> network,
                () -> requested.set(true),
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

  private static Check named(List<Check> checks, String title) {
    return checks.stream().filter(c -> c.title().equals(title)).findFirst().orElseThrow();
  }

  @Test
  void readyWhenEverythingPasses() {
    List<Check> checks = run(true, State.OK, "secret", Health.UP);

    assertThat(checks).hasSize(4).allMatch(Check::ok);
    assertThat(checks).allMatch(c -> c.fix() == null && c.action() == null);
    assertThat(SetupChecks.ready(checks)).isTrue();
  }

  @Test
  void bpfAndTokenAreRequired() {
    List<Check> noBpf = run(false, State.OK, "secret", Health.UP);
    assertThat(SetupChecks.ready(noBpf)).isFalse();
    assertThat(named(noBpf, "Accès à la capture (BPF)").fix()).contains("wireshark-chmodbpf");

    List<Check> noToken = run(true, State.OK, null, Health.UP);
    assertThat(SetupChecks.ready(noToken)).isFalse();
    assertThat(named(noToken, "Jeton du serveur dans le trousseau").fix())
        .contains("install-agent-token.sh");
    assertThat(named(noToken, "Serveur NetLedger (Docker)").ok()).isFalse();
  }

  @Test
  void hiddenLocalNetworkBlocksStartingAndOffersToAsk() {
    List<Check> checks = run(true, State.BLOCKED, "secret", Health.UP);
    Check network = named(checks, "Accès au réseau local");

    assertThat(SetupChecks.ready(checks)).isFalse();
    assertThat(network.actionLabel()).isEqualTo("Demander l'accès");
    assertThat(network.fix()).contains("Réseau local");
    network.action().run();
    assertThat(requested).isTrue();
  }

  @Test
  void beingOfflineDoesNotPreventStarting() {
    List<Check> checks = run(true, State.OFFLINE, "secret", Health.UP);

    assertThat(SetupChecks.ready(checks)).isTrue();
    assertThat(named(checks, "Accès au réseau local").action()).isNull();
  }

  @Test
  void aServerProblemDoesNotPreventStarting() {
    List<Check> down = run(true, State.OK, "secret", Health.UNREACHABLE);
    assertThat(SetupChecks.ready(down)).isTrue();
    assertThat(named(down, "Serveur NetLedger (Docker)").fix()).contains("docker compose up -d");

    List<Check> refused = run(true, State.OK, "secret", Health.TOKEN_REFUSED);
    assertThat(SetupChecks.ready(refused)).isTrue();
    assertThat(named(refused, "Serveur NetLedger (Docker)").detail()).contains("refuse le jeton");
  }
}
