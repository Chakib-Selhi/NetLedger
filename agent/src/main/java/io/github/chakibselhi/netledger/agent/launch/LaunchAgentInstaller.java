package io.github.chakibselhi.netledger.agent.launch;

import io.github.chakibselhi.netledger.agent.system.CommandRunner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Starts the agent as a per-user launchd job instead of inside the app.
 *
 * <p>macOS hides the local network from a process it identifies as an app until the user allows it,
 * and for an app signed only locally that permission did not lift it: {@code arp} run by the app
 * answered "no entry" for the gateway. The same Java runtime started by launchd, outside the app's
 * identity, sees the network. So NetLedger.app only writes the job and asks launchd to run it.
 *
 * <p>The job does not start at login ({@code RunAtLoad} false): the agent runs when the user opens
 * NetLedger, and "Quitter" stops it until the next time.
 */
public final class LaunchAgentInstaller {

  public static final String LABEL = "io.github.chakibselhi.netledger.agent";

  static final int UNLOAD_CHECKS = 20;

  private final CommandRunner commands;
  private final Runnable wait;
  private final Path launchAgents;
  private final Path log;

  public LaunchAgentInstaller(CommandRunner commands, Path home) {
    this(commands, home, LaunchAgentInstaller::pause);
  }

  LaunchAgentInstaller(CommandRunner commands, Path home, Runnable wait) {
    this.wait = wait;
    this.commands = commands;
    this.launchAgents = home.resolve("Library/LaunchAgents");
    this.log = home.resolve("Library/Logs/NetLedger/agent.log");
  }

  public Path plistFile() {
    return launchAgents.resolve(LABEL + ".plist");
  }

  /**
   * Writes the job, reloads it when it changed (the app was moved or updated), then starts it
   * unless it already runs.
   */
  public void installAndStart(Path java, Path jar) throws IOException {
    String uid = commands.run(List.of("id", "-u")).strip();
    String domain = "gui/" + uid;
    String service = domain + "/" + LABEL;
    String wanted = plist(java, jar, log);
    Path file = plistFile();
    boolean loaded = isLoaded(service);
    boolean changed = !Files.exists(file) || !Files.readString(file).equals(wanted);
    if (changed) {
      if (loaded) {
        commands.run(List.of("launchctl", "bootout", service));
        // bootout returns before the agent has exited; bootstrapping meanwhile fails with
        // "Bootstrap failed: 5: Input/output error".
        for (int i = 0; i < UNLOAD_CHECKS && isLoaded(service); i++) {
          wait.run();
        }
        loaded = false;
      }
      Files.createDirectories(launchAgents);
      Files.writeString(file, wanted);
    }
    if (!loaded) {
      Files.createDirectories(log.getParent());
      commands.run(List.of("launchctl", "bootstrap", domain, file.toString()));
    }
    // Without -k, kickstart leaves a running agent alone: opening the app twice starts one agent.
    commands.run(List.of("launchctl", "kickstart", service));
  }

  private static void pause() {
    try {
      Thread.sleep(250);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private boolean isLoaded(String service) {
    try {
      commands.run(List.of("launchctl", "print", service));
      return true;
    } catch (IOException e) {
      return false;
    }
  }

  static String plist(Path java, Path jar, Path log) {
    return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" \
        "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key>
          <string>%s</string>
          <key>ProgramArguments</key>
          <array>
            <string>%s</string>
            <string>-Dapple.awt.UIElement=true</string>
            <string>-jar</string>
            <string>%s</string>
          </array>
          <key>RunAtLoad</key>
          <false/>
          <key>KeepAlive</key>
          <false/>
          <key>LimitLoadToSessionType</key>
          <string>Aqua</string>
          <key>ProcessType</key>
          <string>Interactive</string>
          <key>StandardOutPath</key>
          <string>%s</string>
          <key>StandardErrorPath</key>
          <string>%s</string>
        </dict>
        </plist>
        """
        .formatted(LABEL, xml(java), xml(jar), xml(log), xml(log));
  }

  private static String xml(Path path) {
    return path.toString().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
