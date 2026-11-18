package io.github.chakibselhi.netledger.server.config;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings under {@code netledger.*}.
 *
 * @param dataDir directory of the SQLite database and of the downloaded OUI registry
 * @param agentToken shared secret the agent sends as {@code Authorization: Bearer}
 * @param maxBatchSize largest accepted observation batch
 * @param maxClockSkew how far in the future an observation timestamp may be
 * @param observationRetention how long raw observations are kept
 * @param oui IEEE registry settings
 */
@ConfigurationProperties("netledger")
public record NetLedgerProperties(
    Path dataDir,
    String agentToken,
    @DefaultValue("1000") int maxBatchSize,
    @DefaultValue("PT5M") Duration maxClockSkew,
    @DefaultValue("P30D") Duration observationRetention,
    @DefaultValue Oui oui) {

  public static final int MIN_TOKEN_LENGTH = 32;

  public NetLedgerProperties {
    if (agentToken == null || agentToken.strip().length() < MIN_TOKEN_LENGTH) {
      throw new IllegalStateException(
          "netledger.agent-token (NETLEDGER_AGENT_TOKEN) must be set to at least "
              + MIN_TOKEN_LENGTH
              + " characters; generate one with scripts/generate-token.sh");
    }
    agentToken = agentToken.strip();
  }

  /**
   * @param bundledDir registry copy shipped with the application, used until a download succeeds
   * @param updateEnabled download the registry at startup when missing, then every {@code
   *     updateInterval}
   * @param baseUrl IEEE server serving oui/oui.csv, oui28/mam.csv and oui36/oui36.csv
   */
  public record Oui(
      Path bundledDir,
      @DefaultValue("false") boolean updateEnabled,
      @DefaultValue("P30D") Duration updateInterval,
      @DefaultValue("https://standards-oui.ieee.org/") URI baseUrl) {}

  public Path ouiCacheDir() {
    return dataDir.resolve("oui");
  }
}
