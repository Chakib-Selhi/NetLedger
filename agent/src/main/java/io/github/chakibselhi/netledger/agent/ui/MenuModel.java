package io.github.chakibselhi.netledger.agent.ui;

import io.github.chakibselhi.netledger.agent.Agent;
import io.github.chakibselhi.netledger.agent.alerts.Alert;
import java.util.List;
import java.util.regex.Pattern;

/**
 * What the menu bar shows (EF-14), computed from the agent status without any AWT code, so it can
 * be tested headless.
 *
 * @param state icon color: green when capturing, grey when idle or paused, red when the server is
 *     unreachable
 */
public record MenuModel(
    State state,
    String server,
    String network,
    String capture,
    String pauseLabel,
    List<AlertEntry> alerts) {

  public enum State {
    ACTIVE,
    IDLE,
    SERVER_DOWN
  }

  /** A "Dernières alertes" entry; {@code path} is a dashboard page. */
  public record AlertEntry(String label, String path) {}

  private static final Pattern SAFE_PATH = Pattern.compile("/[A-Za-z0-9/_-]{0,100}");

  public static MenuModel of(Agent.Status status, boolean alertsConnected, List<Alert> recent) {
    boolean serverUp = status.serverReachable() || alertsConnected;
    State state = !serverUp ? State.SERVER_DOWN : status.capturing() ? State.ACTIVE : State.IDLE;
    String server = serverUp ? "Serveur : connecté" : "Serveur : injoignable";
    String network =
        status.network() == null
            ? "Réseau : aucun"
            : "Réseau : " + status.network().subnet() + trust(status);
    String capture =
        status.paused()
            ? "Surveillance : en pause"
            : status.capturing() ? "Surveillance : active" : "Surveillance : inactive";
    List<AlertEntry> alerts =
        recent.stream()
            .map(
                a ->
                    new AlertEntry(
                        truncate(a.title() + " — " + a.message(), 70), safePath(a.path())))
            .toList();
    return new MenuModel(
        state, server, network, capture, status.paused() ? "Reprendre" : "Pause", alerts);
  }

  private static String trust(Agent.Status status) {
    if (status.decision() == null) {
      return "";
    }
    return switch (status.decision().trust()) {
      case "owned" -> " (Mon réseau)";
      case "authorized" -> " (Réseau autorisé)";
      case "ignored" -> " (Ne pas surveiller)";
      default -> " (statut à choisir)";
    };
  }

  /** Only plain dashboard paths are opened; anything else falls back to the alert timeline. */
  static String safePath(String path) {
    return path != null && SAFE_PATH.matcher(path).matches() && !path.contains("//")
        ? path
        : "/events";
  }

  static String truncate(String text, int max) {
    return text.length() <= max ? text : text.substring(0, max - 1) + "…";
  }
}
