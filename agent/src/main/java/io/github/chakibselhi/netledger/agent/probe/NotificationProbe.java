package io.github.chakibselhi.netledger.agent.probe;

import java.awt.AWTException;
import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.SystemTray;
import java.awt.TrayIcon;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Phase 0 diagnostic: shows a test macOS notification with one of two methods, to compare them.
 *
 * <ul>
 *   <li>{@code osascript}: AppleScript {@code display notification}, run as a child process.
 *   <li>{@code tray}: {@link TrayIcon#displayMessage} from AWT, which also reports clicks.
 * </ul>
 */
public final class NotificationProbe {

  private static final String TITLE = "NetLedger";
  private static final int TRAY_WAIT_SECONDS = 20;

  private NotificationProbe() {}

  public static void main(String[] args) throws Exception {
    String method = args.length > 0 ? args[0] : "osascript";
    String message =
        "Test notification at "
            + LocalTime.now().truncatedTo(ChronoUnit.SECONDS)
            + " ("
            + method
            + ")";
    switch (method) {
      case "osascript" -> viaOsascript(TITLE, message);
      case "tray" -> viaTray(TITLE, message);
      default -> throw new IllegalArgumentException("Unknown method: " + method);
    }
  }

  // Text travels as argv items, never spliced into the script, so it cannot inject AppleScript.
  static List<String> osascriptCommand(String title, String message, String sound) {
    return List.of(
        "osascript",
        "-e",
        "on run argv",
        "-e",
        "display notification (item 2 of argv) with title (item 1 of argv)"
            + " sound name (item 3 of argv)",
        "-e",
        "end run",
        title,
        message,
        sound);
  }

  private static void viaOsascript(String title, String message)
      throws IOException, InterruptedException {
    Process process =
        new ProcessBuilder(osascriptCommand(title, message, "Glass"))
            .redirectErrorStream(true)
            .start();
    if (!process.waitFor(10, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      throw new IllegalStateException("osascript did not finish within 10 s");
    }
    String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    System.out.printf("osascript exit=%d %s%n", process.exitValue(), output.strip());
  }

  private static void viaTray(String title, String message)
      throws AWTException, InterruptedException {
    // Keeps the probe out of the Dock; a menu bar agent should not have a Dock icon.
    System.setProperty("apple.awt.UIElement", "true");
    if (!SystemTray.isSupported()) {
      System.out.println("SystemTray is not supported on this system.");
      return;
    }
    SystemTray tray = SystemTray.getSystemTray();
    TrayIcon icon = new TrayIcon(dotImage(), title);
    icon.setImageAutoSize(true);
    icon.addActionListener(e -> System.out.println("Notification or tray icon clicked."));
    tray.add(icon);
    icon.displayMessage(title, message, TrayIcon.MessageType.INFO);
    System.out.printf(
        "Notification sent. Click it within %d s to test click handling.%n", TRAY_WAIT_SECONDS);
    Thread.sleep(TimeUnit.SECONDS.toMillis(TRAY_WAIT_SECONDS));
    tray.remove(icon);
    System.exit(0);
  }

  private static BufferedImage dotImage() {
    var image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_ARGB);
    Graphics2D g = image.createGraphics();
    g.setColor(Color.BLACK);
    g.fillOval(3, 3, 10, 10);
    g.dispose();
    return image;
  }
}
