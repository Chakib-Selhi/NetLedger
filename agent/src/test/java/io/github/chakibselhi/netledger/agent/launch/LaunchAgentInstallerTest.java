package io.github.chakibselhi.netledger.agent.launch;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LaunchAgentInstallerTest {

  private static final String SERVICE = "gui/501/" + LaunchAgentInstaller.LABEL;

  @TempDir Path home;

  private final List<String> calls = new ArrayList<>();
  private boolean loaded;

  private final Path java = Path.of("/Applications/NetLedger.app/Contents/runtime/bin/java");
  private final Path jar = Path.of("/Applications/NetLedger.app/Contents/app/netledger-agent.jar");

  private LaunchAgentInstaller installer() {
    return new LaunchAgentInstaller(
        command -> {
          String line = String.join(" ", command);
          calls.add(line);
          if (line.equals("id -u")) {
            return "501\n";
          }
          if (line.startsWith("launchctl print") && !loaded) {
            throw new IOException("launchctl exited with 113");
          }
          return "";
        },
        home);
  }

  @Test
  void firstLaunchWritesTheJobLoadsItAndStartsIt() throws IOException {
    var installer = installer();

    installer.installAndStart(java, jar);

    String plist = Files.readString(installer.plistFile());
    assertThat(plist)
        .contains("<string>" + java + "</string>", "<string>" + jar + "</string>")
        .contains("<key>RunAtLoad</key>\n  <false/>")
        .contains("Library/Logs/NetLedger/agent.log");
    assertThat(Files.isDirectory(home.resolve("Library/Logs/NetLedger"))).isTrue();
    assertThat(calls)
        .containsExactly(
            "id -u",
            "launchctl print " + SERVICE,
            "launchctl bootstrap gui/501 " + installer.plistFile(),
            "launchctl kickstart " + SERVICE);
  }

  @Test
  void openingTheAppAgainOnlyAsksLaunchdToStartIt() throws IOException {
    installer().installAndStart(java, jar);
    loaded = true;
    calls.clear();

    installer().installAndStart(java, jar);

    assertThat(calls)
        .containsExactly("id -u", "launchctl print " + SERVICE, "launchctl kickstart " + SERVICE);
  }

  @Test
  void aMovedAppReloadsTheJob() throws IOException {
    installer().installAndStart(java, jar);
    loaded = true;
    calls.clear();
    Path moved = Path.of("/Users/me/Apps/NetLedger.app/Contents/app/netledger-agent.jar");

    var installer = installer();
    installer.installAndStart(java, moved);

    assertThat(calls)
        .containsExactly(
            "id -u",
            "launchctl print " + SERVICE,
            "launchctl bootout " + SERVICE,
            "launchctl bootstrap gui/501 " + installer.plistFile(),
            "launchctl kickstart " + SERVICE);
    assertThat(Files.readString(installer.plistFile())).contains(moved.toString());
  }

  @Test
  void pathsAreEscapedForXml() {
    String plist =
        LaunchAgentInstaller.plist(Path.of("/A&B/<java>"), Path.of("/x.jar"), Path.of("/log"));

    assertThat(plist).contains("/A&amp;B/&lt;java&gt;").doesNotContain("A&B");
  }
}
