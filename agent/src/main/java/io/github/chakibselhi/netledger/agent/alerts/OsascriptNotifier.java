package io.github.chakibselhi.netledger.agent.alerts;

import io.github.chakibselhi.netledger.agent.system.CommandRunner;
import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Shows alerts as macOS notifications (EF-13) through AppleScript's {@code display notification},
 * which works for an unbundled Java process (phase 0 test). Device names come from the network, so
 * they are untrusted: the text is passed as {@code argv} items of the script, never spliced into
 * the script source, so a host name cannot inject AppleScript.
 */
public final class OsascriptNotifier implements Consumer<Alert> {

  private static final Logger log = LoggerFactory.getLogger(OsascriptNotifier.class);
  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm");
  static final String SOUND = "Glass";

  private final CommandRunner commands;
  private final ZoneId zone;

  public OsascriptNotifier(CommandRunner commands, ZoneId zone) {
    this.commands = commands;
    this.zone = zone;
  }

  @Override
  public void accept(Alert alert) {
    try {
      commands.run(command(alert));
    } catch (IOException e) {
      log.warn("Cannot show notification: {}", e.getMessage());
    }
  }

  List<String> command(Alert alert) {
    String time = TIME.format(Instant.parse(alert.occurredAt()).atZone(zone));
    var command = new ArrayList<>(List.of("osascript", "-e", "on run argv"));
    if (alert.sound()) {
      command.addAll(
          List.of(
              "-e",
              "display notification (item 2 of argv) with title (item 1 of argv)"
                  + " subtitle (item 3 of argv) sound name (item 4 of argv)"));
    } else {
      command.addAll(
          List.of(
              "-e",
              "display notification (item 2 of argv) with title (item 1 of argv)"
                  + " subtitle (item 3 of argv)"));
    }
    command.addAll(
        List.of("-e", "end run", "NetLedger", alert.message(), alert.title() + " · " + time));
    if (alert.sound()) {
      command.add(SOUND);
    }
    return command;
  }
}
