package io.github.chakibselhi.netledger.agent;

import io.github.chakibselhi.netledger.agent.buffer.ObservationBuffer;
import io.github.chakibselhi.netledger.agent.buffer.ObservationBuffer.Batch;
import io.github.chakibselhi.netledger.agent.capture.CaptureSession;
import io.github.chakibselhi.netledger.agent.config.AgentConfig;
import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import io.github.chakibselhi.netledger.agent.server.NetworkDecision;
import io.github.chakibselhi.netledger.agent.server.ServerClient;
import io.github.chakibselhi.netledger.agent.server.ServerException;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The agent's control loop. {@link #tick()} runs every few seconds on a single thread and decides
 * everything; the capture thread only fills the buffer.
 *
 * <ul>
 *   <li><b>Sleep</b> (EF-06): Java has no sleep event, but the wall clock keeps running while the
 *       Mac sleeps and the scheduler does not. A gap much longer than the tick interval means the
 *       Mac slept: capture stops and the network is detected again from scratch.
 *   <li><b>Network</b> (EF-03, EF-04): on every change the network is declared to the server and
 *       capture starts only if the answer allows it. Without an answer, nothing is captured. While
 *       capturing, the decision is refreshed every 5 minutes, otherwise every 30 seconds.
 *   <li><b>Upload</b> (EF-05): buffered observations are sent in batches; when the server is
 *       unavailable they stay in the bounded buffer and sending is retried with a growing delay.
 * </ul>
 */
public final class Agent {

  /** Detects the current network. */
  @FunctionalInterface
  public interface NetworkSource {
    Optional<NetworkIdentity> detect() throws IOException;
  }

  /** Starts a capture on a network. */
  @FunctionalInterface
  public interface CaptureStarter {
    CaptureSession start(NetworkIdentity network, long networkId, ObservationBuffer buffer);
  }

  /** Active step run periodically while capturing (mDNS query, ARP scan). */
  @FunctionalInterface
  public interface PeriodicProbe {
    void run(NetworkIdentity network, NetworkDecision decision) throws IOException;
  }

  private static final Logger log = LoggerFactory.getLogger(Agent.class);
  static final Duration DECLARE_WHILE_IDLE = Duration.ofSeconds(30);
  static final Duration DECLARE_WHILE_CAPTURING = Duration.ofMinutes(5);
  static final Duration MAX_BACKOFF = Duration.ofMinutes(5);

  private final AgentConfig config;
  private final NetworkSource networks;
  private final ServerClient server;
  private final ObservationBuffer buffer;
  private final CaptureStarter captures;
  private final PeriodicProbe mdnsQuery;
  private final PeriodicProbe arpScan;
  private final Clock clock;

  private Instant lastTick;
  private Instant lastDetect;
  private Instant lastDeclare;
  private Instant lastFlush;
  private Instant lastMdnsQuery;
  private Instant lastArpScan;
  private Instant nextSendAllowed = Instant.MIN;
  private Duration backoff = Duration.ZERO;
  private NetworkIdentity network;
  private NetworkDecision decision;
  private CaptureSession capture;
  private long sent;
  private boolean serverReachable;

  public Agent(
      AgentConfig config,
      NetworkSource networks,
      ServerClient server,
      ObservationBuffer buffer,
      CaptureStarter captures,
      PeriodicProbe mdnsQuery,
      PeriodicProbe arpScan,
      Clock clock) {
    this.config = config;
    this.networks = networks;
    this.server = server;
    this.buffer = buffer;
    this.captures = captures;
    this.mdnsQuery = mdnsQuery;
    this.arpScan = arpScan;
    this.clock = clock;
  }

  public synchronized void tick() {
    Instant now = clock.instant();
    if (lastTick != null
        && Duration.between(lastTick, now).compareTo(config.sleepThreshold()) > 0) {
      log.info(
          "Wake-up detected after {} s: restarting detection",
          Duration.between(lastTick, now).toSeconds());
      stopCapture();
      network = null;
      decision = null;
      lastDetect = null;
    }
    lastTick = now;

    if (due(lastDetect, config.networkPollInterval(), now)) {
      lastDetect = now;
      detectNetwork();
    }
    Duration declareEvery = capturing() ? DECLARE_WHILE_CAPTURING : DECLARE_WHILE_IDLE;
    if (network != null && due(lastDeclare, declareEvery, now)) {
      lastDeclare = now;
      declare();
    }
    if (capturing()) {
      runProbe("mDNS query", mdnsQuery, lastMdnsQuery, config.mdnsQueryInterval(), now);
      lastMdnsQuery = due(lastMdnsQuery, config.mdnsQueryInterval(), now) ? now : lastMdnsQuery;
      if (config.arpScanEnabled() && decision.owned()) {
        runProbe("ARP scan", arpScan, lastArpScan, config.arpScanInterval(), now);
        lastArpScan = due(lastArpScan, config.arpScanInterval(), now) ? now : lastArpScan;
      }
    }
    flush(now, false);
  }

  /** Stops capturing and tries once to send what is left. */
  public synchronized void shutdown() {
    stopCapture();
    flush(clock.instant(), true);
  }

  public synchronized Status status() {
    return new Status(
        network, decision, capturing(), buffer.size(), sent, buffer.dropped(), serverReachable);
  }

  /** Snapshot for logs and, later, the menu bar. */
  public record Status(
      NetworkIdentity network,
      NetworkDecision decision,
      boolean capturing,
      int buffered,
      long sent,
      long dropped,
      boolean serverReachable) {}

  private void detectNetwork() {
    Optional<NetworkIdentity> detected;
    try {
      detected = networks.detect();
    } catch (IOException e) {
      log.debug("Network detection failed: {}", e.getMessage());
      detected = Optional.empty();
    }
    NetworkIdentity current = detected.orElse(null);
    if (current == null ? network == null : current.sameNetworkAs(network)) {
      network = current;
      return;
    }
    log.info(
        "Network changed: {}",
        current == null ? "offline" : current.subnet() + " via " + current.gatewayIp());
    stopCapture();
    network = current;
    decision = null;
    lastDeclare = null;
  }

  private void declare() {
    try {
      NetworkDecision answer = server.declare(network);
      serverReachable = true;
      boolean changed =
          decision == null
              || decision.networkId() != answer.networkId()
              || decision.capture() != answer.capture();
      decision = answer;
      if (answer.capture() && !capturing()) {
        log.info(
            "Network {} is {}: capture starts on {}",
            answer.networkId(),
            answer.trust(),
            network.interfaceName());
        capture = captures.start(network, answer.networkId(), buffer);
        lastMdnsQuery = null;
        lastArpScan = null;
      } else if (!answer.capture() && (capturing() || changed)) {
        log.info("Network {} is {}: not captured", answer.networkId(), answer.trust());
        stopCapture();
      }
    } catch (ServerException e) {
      serverReachable = e.reason() != ServerException.Reason.UNAVAILABLE;
      // Keep the current decision: an authorized network stays captured while the server is
      // down, and an unknown one stays uncaptured.
      log.warn("Cannot declare the network: {}", e.getMessage());
    }
  }

  private void flush(Instant now, boolean force) {
    boolean timeToFlush =
        lastFlush == null || !now.isBefore(lastFlush.plus(config.flushInterval()));
    boolean ready = timeToFlush || buffer.size() >= config.batchSize();
    if (buffer.size() == 0 || (!force && (now.isBefore(nextSendAllowed) || !ready))) {
      return;
    }
    lastFlush = now;
    Optional<Batch> next;
    while ((next = buffer.take(config.batchSize())).isPresent()) {
      Batch batch = next.get();
      try {
        server.sendObservations(batch.networkId(), batch.observations());
        sent += batch.observations().size();
        backoff = Duration.ZERO;
        serverReachable = true;
      } catch (ServerException e) {
        handleSendFailure(batch, e, now);
        return;
      }
    }
  }

  private void handleSendFailure(Batch batch, ServerException e, Instant now) {
    switch (e.reason()) {
      case UNAVAILABLE, UNAUTHORIZED -> {
        buffer.putBack(batch);
        serverReachable = e.reason() == ServerException.Reason.UNAUTHORIZED;
        backoff =
            backoff.isZero() ? config.flushInterval() : min(backoff.multipliedBy(2), MAX_BACKOFF);
        nextSendAllowed = now.plus(backoff);
        log.warn(
            "{}; {} observation(s) kept, retry in {} s",
            e.getMessage(),
            buffer.size(),
            backoff.toSeconds());
      }
      case NOT_MONITORED, UNKNOWN_NETWORK -> {
        buffer.discardNetwork(batch.networkId());
        if (decision != null && decision.networkId() == batch.networkId()) {
          log.info("Network {} is no longer monitored: capture stops", batch.networkId());
          stopCapture();
          decision = null;
          lastDeclare = null;
        }
      }
      case REJECTED ->
          log.warn(
              "Server rejected a batch of {}: {}", batch.observations().size(), e.getMessage());
    }
  }

  private void runProbe(
      String name, PeriodicProbe probe, Instant last, Duration every, Instant now) {
    if (!due(last, every, now)) {
      return;
    }
    try {
      probe.run(network, decision);
    } catch (IOException | RuntimeException e) {
      log.warn("{} failed: {}", name, e.getMessage());
    }
  }

  private boolean capturing() {
    return capture != null;
  }

  private void stopCapture() {
    if (capture != null) {
      capture.stop();
      capture = null;
    }
  }

  private static boolean due(Instant last, Duration every, Instant now) {
    return last == null || !now.isBefore(last.plus(every));
  }

  private static Duration min(Duration a, Duration b) {
    return a.compareTo(b) <= 0 ? a : b;
  }
}
