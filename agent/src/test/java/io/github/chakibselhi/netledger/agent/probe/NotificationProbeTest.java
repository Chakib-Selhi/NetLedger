package io.github.chakibselhi.netledger.agent.probe;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class NotificationProbeTest {

  @Test
  void passesUserTextAsArgumentsNotAsScript() {
    String hostile = "\" & (do shell script \"touch /tmp/pwned\") & \"";

    var command = NotificationProbe.osascriptCommand("NetLedger", hostile, "Glass");

    assertThat(command).first().isEqualTo("osascript");
    assertThat(command).endsWith("NetLedger", hostile, "Glass");
    assertThat(command.subList(0, command.size() - 3)).noneMatch(part -> part.contains(hostile));
  }
}
