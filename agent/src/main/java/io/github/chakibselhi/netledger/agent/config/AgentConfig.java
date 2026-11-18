package io.github.chakibselhi.netledger.agent.config;

import java.io.IOException;
import java.io.Reader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

/**
 * Agent settings, read from {@code ~/Library/Application Support/NetLedger/agent.properties} when
 * present; every key has a default. The token is not here: it lives in the macOS keychain.
 */
public record AgentConfig(
    URI serverUrl,
    String interfaceOverride,
    Duration tickInterval,
    Duration networkPollInterval,
    Duration flushInterval,
    int batchSize,
    int bufferCapacity,
    Duration dedupWindow,
    Duration sleepThreshold,
    Duration mdnsQueryInterval,
    boolean arpScanEnabled,
    Duration arpScanInterval) {

  public static Path defaultFile() {
    return Path.of(
        System.getProperty("user.home"),
        "Library",
        "Application Support",
        "NetLedger",
        "agent.properties");
  }

  public static AgentConfig load(Path file) throws IOException {
    var properties = new Properties();
    if (Files.isRegularFile(file)) {
      try (Reader reader = Files.newBufferedReader(file)) {
        properties.load(reader);
      }
    }
    return from(properties);
  }

  public static AgentConfig from(Properties p) {
    URI server = URI.create(p.getProperty("server.url", "http://127.0.0.1:8080"));
    if (!"http".equals(server.getScheme()) && !"https".equals(server.getScheme())) {
      throw new IllegalArgumentException("server.url must be http or https");
    }
    String iface = p.getProperty("interface", "").strip();
    return new AgentConfig(
        server,
        iface.isEmpty() ? null : iface,
        duration(p, "tick.interval", "PT5S"),
        duration(p, "network.poll.interval", "PT10S"),
        duration(p, "flush.interval", "PT5S"),
        Integer.parseInt(p.getProperty("batch.size", "500")),
        Integer.parseInt(p.getProperty("buffer.capacity", "10000")),
        duration(p, "dedup.window", "PT60S"),
        duration(p, "sleep.threshold", "PT60S"),
        duration(p, "mdns.query.interval", "PT15M"),
        Boolean.parseBoolean(p.getProperty("arp.scan.enabled", "false")),
        duration(p, "arp.scan.interval", "PT15M"));
  }

  private static Duration duration(Properties p, String key, String fallback) {
    return Duration.parse(p.getProperty(key, fallback));
  }
}
