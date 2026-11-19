package io.github.chakibselhi.netledger.agent.launch;

import io.github.chakibselhi.netledger.agent.system.ProcessCommandRunner;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;

/**
 * Main class of NetLedger.app: hands the agent over to launchd (see {@link LaunchAgentInstaller})
 * and exits. The agent itself runs {@code AgentMain} with the Java runtime bundled in the app.
 */
public final class AppLauncher {

  private AppLauncher() {}

  public static void main(String[] args) throws URISyntaxException {
    var commands = new ProcessCommandRunner(Duration.ofSeconds(10));
    Path java = Path.of(System.getProperty("java.home"), "bin", "java");
    Path jar =
        Path.of(AppLauncher.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    try {
      new LaunchAgentInstaller(commands, Path.of(System.getProperty("user.home")))
          .installAndStart(java, jar);
    } catch (IOException e) {
      try {
        // The text goes in as an argument, never into the AppleScript source.
        commands.run(
            List.of(
                "osascript",
                "-e",
                "on run argv",
                "-e",
                "display alert \"NetLedger ne peut pas démarrer\" message (item 1 of argv)",
                "-e",
                "end run",
                String.valueOf(e.getMessage())));
      } catch (IOException ignored) {
        // No way left to tell the user; the exit code says it failed.
      }
      System.exit(1);
    }
  }
}
