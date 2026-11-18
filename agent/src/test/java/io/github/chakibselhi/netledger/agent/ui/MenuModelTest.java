package io.github.chakibselhi.netledger.agent.ui;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.Agent;
import io.github.chakibselhi.netledger.agent.alerts.Alert;
import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import io.github.chakibselhi.netledger.agent.server.NetworkDecision;
import java.util.List;
import org.junit.jupiter.api.Test;

class MenuModelTest {

  private static final NetworkIdentity HOME =
      new NetworkIdentity("en0", "10.0.0.2", "10.0.0.0/24", "10.0.0.1", "02:00:00:00:00:01");

  private static Agent.Status status(
      String trust, boolean capturing, boolean paused, boolean serverUp) {
    NetworkDecision decision = trust == null ? null : new NetworkDecision(2, trust, capturing);
    return new Agent.Status(HOME, decision, capturing, paused, 0, 0, 0, serverUp);
  }

  @Test
  void capturingOnAnOwnedNetworkIsGreen() {
    MenuModel model = MenuModel.of(status("owned", true, false, true), true, List.of());

    assertThat(model.state()).isEqualTo(MenuModel.State.ACTIVE);
    assertThat(model.server()).isEqualTo("Serveur : connecté");
    assertThat(model.network()).isEqualTo("Réseau : 10.0.0.0/24 (Mon réseau)");
    assertThat(model.capture()).isEqualTo("Surveillance : active");
    assertThat(model.pauseLabel()).isEqualTo("Pause");
  }

  @Test
  void pausedOrUnmonitoredIsGreyAndUnreachableServerIsRed() {
    assertThat(MenuModel.of(status("owned", false, true, true), false, List.of()))
        .satisfies(
            m -> {
              assertThat(m.state()).isEqualTo(MenuModel.State.IDLE);
              assertThat(m.capture()).isEqualTo("Surveillance : en pause");
              assertThat(m.pauseLabel()).isEqualTo("Reprendre");
            });
    assertThat(MenuModel.of(status("unset", false, false, true), false, List.of()).network())
        .endsWith("(statut à choisir)");
    assertThat(MenuModel.of(status("authorized", false, false, true), false, List.of()).network())
        .endsWith("(Réseau autorisé)");
    assertThat(MenuModel.of(status("ignored", false, false, true), false, List.of()).network())
        .endsWith("(Ne pas surveiller)");
    assertThat(MenuModel.of(status(null, false, false, false), false, List.of()).state())
        .isEqualTo(MenuModel.State.SERVER_DOWN);
    assertThat(
            MenuModel.of(
                    new Agent.Status(null, null, false, false, 0, 0, 0, true), false, List.of())
                .network())
        .isEqualTo("Réseau : aucun");
  }

  @Test
  void alertEntriesAreShortAndOnlyOpenDashboardPaths() {
    var alerts =
        List.of(
            new Alert(
                1,
                "new_device",
                "Nouvel appareil",
                "x".repeat(200),
                true,
                "2026-11-18T12:00:00Z",
                "/devices/1"),
            new Alert(
                2,
                "ip_conflict",
                "Conflit",
                "m",
                true,
                "2026-11-18T12:00:00Z",
                "https://evil.example/"),
            new Alert(
                3, "summary", "3 alertes", "m", false, "2026-11-18T12:00:00Z", "//evil.example"),
            new Alert(4, "summary", "3 alertes", "m", false, "2026-11-18T12:00:00Z", null));

    MenuModel model = MenuModel.of(status("owned", true, false, true), true, alerts);

    assertThat(model.alerts().get(0).label()).hasSize(70).endsWith("…");
    assertThat(model.alerts())
        .extracting(MenuModel.AlertEntry::path)
        .containsExactly("/devices/1", "/events", "/events", "/events");
  }
}
