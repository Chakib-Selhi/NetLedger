package io.github.chakibselhi.netledger.agent.setup;

import io.github.chakibselhi.netledger.agent.server.ServerClient.Health;
import io.github.chakibselhi.netledger.agent.setup.LocalNetworkAccess.State;
import java.util.List;
import java.util.Optional;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * What the agent needs before it can run, checked at every launch and shown by the setup assistant.
 * Pure logic, without AWT, so it is tested headless.
 */
public final class SetupChecks {

  /**
   * @param required whether the agent cannot start without it
   * @param fix what to do when it fails, or {@code null} when there is nothing to do
   * @param actionLabel label of a button that fixes it, or {@code null}
   * @param action what that button does
   */
  public record Check(
      String title,
      boolean ok,
      boolean required,
      String detail,
      String fix,
      String actionLabel,
      Runnable action) {

    Check(String title, boolean ok, boolean required, String detail, String fix) {
      this(title, ok, required, detail, fix, null, null);
    }
  }

  private final BooleanSupplier bpfReadable;
  private final Supplier<State> localNetwork;
  private final Runnable requestLocalNetwork;
  private final Supplier<Optional<String>> token;
  private final Function<String, Health> serverHealth;

  public SetupChecks(
      BooleanSupplier bpfReadable,
      Supplier<State> localNetwork,
      Runnable requestLocalNetwork,
      Supplier<Optional<String>> token,
      Function<String, Health> serverHealth) {
    this.bpfReadable = bpfReadable;
    this.localNetwork = localNetwork;
    this.requestLocalNetwork = requestLocalNetwork;
    this.token = token;
    this.serverHealth = serverHealth;
  }

  public List<Check> run() {
    Optional<String> stored = token.get();
    return List.of(bpf(), localNetwork(), token(stored.isPresent()), server(stored));
  }

  /** The agent can start when every required check passes. */
  public static boolean ready(List<Check> checks) {
    return checks.stream().allMatch(c -> c.ok() || !c.required());
  }

  private Check bpf() {
    String title = "Accès à la capture (BPF)";
    if (bpfReadable.getAsBoolean()) {
      return new Check(title, true, true, "Les périphériques /dev/bpf sont lisibles.", null);
    }
    return new Check(
        title,
        false,
        true,
        "macOS réserve la capture à l'administrateur. NetLedger utilise plutôt le groupe"
            + " access_bpf, comme Wireshark.",
        "brew install --cask wireshark-chmodbpf, puis fermez et rouvrez votre session.");
  }

  private Check localNetwork() {
    String title = "Accès au réseau local";
    return switch (localNetwork.get()) {
      case OK -> new Check(title, true, true, "macOS laisse NetLedger voir le réseau local.", null);
      case OFFLINE ->
          new Check(
              title, false, false, "Aucun réseau pour l'instant : vérifié à la connexion.", null);
      case BLOCKED ->
          new Check(
              title,
              false,
              true,
              "macOS cache le réseau local à NetLedger tant que vous ne l'avez pas autorisé. Le"
                  + " bouton envoie une seule question mDNS, comme tout Mac le fait sans cesse, pour"
                  + " que macOS affiche sa demande : choisissez Autoriser.",
              "Sans fenêtre de macOS : Réglages Système › Confidentialité et sécurité › Réseau"
                  + " local › NetLedger.",
              "Demander l'accès",
              requestLocalNetwork);
    };
  }

  private Check token(boolean present) {
    String title = "Jeton du serveur dans le trousseau";
    if (present) {
      return new Check(title, true, true, "Le jeton est rangé dans le trousseau macOS.", null);
    }
    return new Check(
        title,
        false,
        true,
        "L'agent s'identifie auprès du serveur avec le jeton du fichier .env.",
        "Dans le dossier du projet : ./scripts/install-agent-token.sh");
  }

  private Check server(Optional<String> stored) {
    String title = "Serveur NetLedger (Docker)";
    if (stored.isEmpty()) {
      return new Check(title, false, false, "Vérifié une fois le jeton installé.", null);
    }
    return switch (serverHealth.apply(stored.get())) {
      case UP -> new Check(title, true, false, "Le serveur répond sur 127.0.0.1:8080.", null);
      case TOKEN_REFUSED ->
          new Check(
              title,
              false,
              false,
              "Le serveur refuse le jeton du trousseau.",
              "Relancez ./scripts/install-agent-token.sh avec le jeton du fichier .env.");
      case UNREACHABLE ->
          new Check(
              title,
              false,
              false,
              "Le serveur ne répond pas. L'agent garde les observations en attendant.",
              "Lancez Docker Desktop, puis docker compose up -d dans le dossier du projet.");
    };
  }
}
