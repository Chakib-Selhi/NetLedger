package io.github.chakibselhi.netledger.agent;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.buffer.ObservationBuffer;
import io.github.chakibselhi.netledger.agent.capture.CaptureSession;
import io.github.chakibselhi.netledger.agent.capture.FrameHandler;
import io.github.chakibselhi.netledger.agent.capture.PacketSource;
import io.github.chakibselhi.netledger.agent.config.AgentConfig;
import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import io.github.chakibselhi.netledger.agent.server.FakeServer;
import io.github.chakibselhi.netledger.agent.server.ServerClient;
import io.github.chakibselhi.netledger.core.json.ObservationJson;
import io.github.chakibselhi.netledger.core.pcap.Fixtures;
import io.github.chakibselhi.netledger.core.pcap.PcapRecord;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class AgentTest {

  static final NetworkIdentity HOME =
      new NetworkIdentity("en0", "10.0.0.2", "10.0.0.0/24", "10.0.0.1", "02:00:00:00:00:01");
  static final NetworkIdentity CAFE =
      new NetworkIdentity("en0", "172.16.0.9", "172.16.0.0/16", "172.16.0.1", "02:00:00:00:00:99");

  /** Clock moved by hand. */
  static final class TestClock extends Clock {
    Instant now = Instant.parse("2026-11-18T12:00:00Z");

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  /** Replays the anonymized captures once, then idles until stopped. */
  static final class ReplaySource implements PacketSource {
    final CountDownLatch replayed = new CountDownLatch(1);
    private volatile boolean running = true;

    @Override
    public void run(FrameHandler handler) {
      Stream.of("arp", "dhcp", "mdns")
          .flatMap(name -> Fixtures.load(name).records().stream())
          .forEach((PcapRecord r) -> handler.onFrame(r.timestamp(), r.data()));
      replayed.countDown();
      while (running) {
        try {
          Thread.sleep(10);
        } catch (InterruptedException e) {
          return;
        }
      }
    }

    @Override
    public void stop() {
      running = false;
    }
  }

  private final FakeServer server;
  private final TestClock clock = new TestClock();
  private final List<ReplaySource> sources = new ArrayList<>();
  private final List<CaptureSession> sessions = new ArrayList<>();
  private final AtomicInteger mdnsQueries = new AtomicInteger();
  private final AtomicInteger arpScans = new AtomicInteger();
  private volatile Optional<NetworkIdentity> current = Optional.of(HOME);
  private final ObservationBuffer buffer = new ObservationBuffer(10_000, Duration.ofSeconds(60));
  private Agent agent;

  AgentTest() throws Exception {
    server = new FakeServer();
  }

  private Agent agent(boolean arpScan) {
    var properties = new Properties();
    properties.setProperty("server.url", server.url().toString());
    properties.setProperty("arp.scan.enabled", Boolean.toString(arpScan));
    agent =
        new Agent(
            AgentConfig.from(properties),
            () -> current,
            new ServerClient(server.url(), "token", Duration.ofSeconds(2)),
            buffer,
            (network, networkId, target) -> {
              var source = new ReplaySource();
              sources.add(source);
              CaptureSession session =
                  new CaptureSession(source, networkId, target, "test").start();
              sessions.add(session);
              return session;
            },
            (network, decision) -> mdnsQueries.incrementAndGet(),
            (network, decision) -> arpScans.incrementAndGet(),
            clock);
    return agent;
  }

  @AfterEach
  void cleanUp() {
    if (agent != null) {
      agent.shutdown();
    }
    server.close();
  }

  private void awaitReplay() throws InterruptedException {
    assertThat(sources.get(sources.size() - 1).replayed.await(5, TimeUnit.SECONDS)).isTrue();
  }

  @Test
  void unmonitoredNetworkIsNeverCaptured() {
    server.trust = "unset";
    Agent agent = agent(false);

    agent.tick();
    clock.advance(Duration.ofMinutes(1));
    agent.tick();

    assertThat(sessions).isEmpty();
    assertThat(agent.status().capturing()).isFalse();
    assertThat(server.requests("/api/v1/networks/current")).hasSize(2);
    assertThat(mdnsQueries).hasValue(0);
  }

  @Test
  void monitoredNetworkIsCapturedAndUploaded() throws Exception {
    Agent agent = agent(false);

    agent.tick();
    awaitReplay();
    clock.advance(Duration.ofSeconds(5));
    agent.tick();

    assertThat(agent.status().capturing()).isTrue();
    assertThat(mdnsQueries).hasValue(1);
    List<FakeServer.Request> uploads = server.requests("/api/v1/observations");
    assertThat(uploads).isNotEmpty();
    int total =
        uploads.stream().mapToInt(r -> ObservationJson.read(r.body()).observations().size()).sum();
    // Fewer than the 261 decoded frames: identical observations within 60 s are sent once.
    assertThat(total).isBetween(50, 261).isEqualTo(agent.status().sent());
    assertThat(buffer.deduplicated()).isPositive();
    assertThat(uploads)
        .allSatisfy(r -> assertThat(ObservationJson.read(r.body()).networkId()).isEqualTo(7));
    assertThat(agent.status().buffered()).isZero();
  }

  @Test
  void serverDownAtFirstContactMeansNoCapture() {
    server.declareStatus = 503;
    Agent agent = agent(false);

    agent.tick();

    assertThat(sessions).isEmpty();
    assertThat(agent.status().serverReachable()).isFalse();
  }

  @Test
  void keepsCapturingAndBufferingWhileTheServerIsDown() throws Exception {
    // Down from the start: otherwise a fast replay is fully uploaded by the first tick and
    // nothing is left to buffer.
    server.observationsStatus = 503;
    Agent agent = agent(false);
    agent.tick();
    awaitReplay();

    clock.advance(Duration.ofSeconds(5));
    agent.tick();
    int buffered = agent.status().buffered();
    assertThat(buffered).isPositive();
    assertThat(agent.status().capturing()).isTrue();

    int attempts = server.requests("/api/v1/observations").size();
    clock.advance(Duration.ofSeconds(1));
    agent.tick();
    assertThat(server.requests("/api/v1/observations")).as("backoff").hasSize(attempts);

    server.observationsStatus = 200;
    clock.advance(Duration.ofSeconds(30));
    agent.tick();
    assertThat(agent.status().buffered()).isZero();
    assertThat(agent.status().sent()).isEqualTo(buffered);
  }

  @Test
  void revokedNetworkStopsCaptureAndDiscardsItsData() throws Exception {
    Agent agent = agent(false);
    agent.tick();
    awaitReplay();
    server.observationsStatus = 403;

    clock.advance(Duration.ofSeconds(5));
    agent.tick();

    assertThat(agent.status().capturing()).isFalse();
    assertThat(agent.status().buffered()).isZero();
  }

  @Test
  void changingNetworkStopsCaptureAndAsksAgain() throws Exception {
    Agent agent = agent(false);
    agent.tick();
    awaitReplay();

    current = Optional.of(CAFE);
    server.trust = "unset";
    server.networkId = 8;
    clock.advance(Duration.ofSeconds(10));
    agent.tick();

    assertThat(agent.status().capturing()).isFalse();
    assertThat(agent.status().network()).isEqualTo(CAFE);
    assertThat(agent.status().decision().networkId()).isEqualTo(8);
  }

  @Test
  void wakeUpRestartsFromScratch() throws Exception {
    Agent agent = agent(false);
    agent.tick();
    awaitReplay();

    clock.advance(Duration.ofHours(8));
    agent.tick();

    assertThat(sessions).hasSize(2);
    assertThat(server.requests("/api/v1/networks/current")).hasSize(2);
  }

  @Test
  void goingOfflineStopsCapture() throws Exception {
    Agent agent = agent(false);
    agent.tick();
    awaitReplay();

    current = Optional.empty();
    clock.advance(Duration.ofSeconds(10));
    agent.tick();

    assertThat(agent.status().capturing()).isFalse();
    assertThat(agent.status().network()).isNull();
  }

  @Test
  void arpScanOnlyWhenEnabledAndOwned() throws Exception {
    Agent enabled = agent(true);
    enabled.tick();
    assertThat(arpScans).hasValue(1);
    enabled.shutdown();

    arpScans.set(0);
    server.trust = "authorized";
    clock.advance(Duration.ofHours(1));
    Agent authorizedOnly = agent(true);
    authorizedOnly.tick();
    assertThat(arpScans).hasValue(0);
    authorizedOnly.shutdown();

    server.trust = "owned";
    clock.advance(Duration.ofHours(1));
    Agent disabled = agent(false);
    disabled.tick();
    assertThat(arpScans).hasValue(0);
  }

  @Test
  void pauseStopsCaptureUntilResumed() throws Exception {
    Agent agent = agent(false);
    agent.tick();
    awaitReplay();

    agent.setPaused(true);
    clock.advance(Duration.ofMinutes(10));
    agent.tick();
    assertThat(agent.status().capturing()).isFalse();
    assertThat(agent.status().paused()).isTrue();

    agent.setPaused(false);
    agent.tick();
    assertThat(agent.status().capturing()).isTrue();
    assertThat(sessions).hasSize(2);
  }

  @Test
  void describesItsStatus() {
    Agent agent = agent(false);
    agent.tick();

    assertThat(AgentMain.describe(agent.status()))
        .contains("network=10.0.0.0/24", "trust=owned", "capturing=true", "server=up");
  }
}
