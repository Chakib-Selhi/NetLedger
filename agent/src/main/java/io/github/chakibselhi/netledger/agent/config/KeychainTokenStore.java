package io.github.chakibselhi.netledger.agent.config;

import io.github.chakibselhi.netledger.agent.system.CommandRunner;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Reads the shared token from the macOS keychain with the {@code security} tool. The keychain
 * encrypts it at rest and only releases it to the user's session; scripts/install-agent-token.sh
 * stores it.
 */
public final class KeychainTokenStore {

  public static final String SERVICE = "NetLedger";
  public static final String ACCOUNT = "agent";

  private final CommandRunner commands;

  public KeychainTokenStore(CommandRunner commands) {
    this.commands = commands;
  }

  public Optional<String> read() {
    try {
      String token =
          commands
              .run(List.of("security", "find-generic-password", "-s", SERVICE, "-a", ACCOUNT, "-w"))
              .strip();
      return token.isEmpty() ? Optional.empty() : Optional.of(token);
    } catch (IOException e) {
      return Optional.empty();
    }
  }
}
