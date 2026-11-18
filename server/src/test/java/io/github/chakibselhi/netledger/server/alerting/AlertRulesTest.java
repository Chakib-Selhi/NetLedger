package io.github.chakibselhi.netledger.server.alerting;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.server.correlation.CorrelationEngine;
import io.github.chakibselhi.netledger.server.network.Network;
import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.network.NetworkService;
import io.github.chakibselhi.netledger.server.network.Trust;
import io.github.chakibselhi.netledger.server.persistence.Timestamps;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

@SpringBootTest
class AlertRulesTest {

  private static final String HUE = "ec:b5:fa:00:00:01";
  private static final String PHONE = "3a:1f:22:aa:bb:01";

  @Autowired NetworkService networkService;
  @Autowired NetworkRepository networks;
  @Autowired CorrelationEngine engine;
  @Autowired EventRepository events;
  @Autowired JdbcClient jdbc;

  // Scenarios happen two hours ago: the server rejects observations dated in the future.
  private final Instant now =
      Instant.now().truncatedTo(ChronoUnit.MILLIS).minus(Duration.ofHours(2));
  private Network network;
  private String gateway;

  @BeforeEach
  void monitoredNetworkPastItsLearningPeriod() {
    var random = ThreadLocalRandom.current();
    gateway =
        "02:00:00:%02x:%02x:%02x"
            .formatted(random.nextInt(256), random.nextInt(256), random.nextInt(256));
    network = networkService.declareCurrent(gateway, "10.7.0.0/24");
    networkService.changeTrust(network.id(), Trust.OWNED);
    networks.setLearningUntil(network.id(), now.minus(Duration.ofDays(3)));
  }

  private List<AlertEvent> events() {
    return events.recent(network.id(), null, 50);
  }

  private AlertEvent latest(EventKind kind) {
    return events().stream().filter(e -> e.kind() == kind).findFirst().orElseThrow();
  }

  private List<EventKind> kinds() {
    return events().stream().map(AlertEvent::kind).toList();
  }

  private static Observation arp(Instant at, String mac, String ip) {
    return Observation.presence(at, ObservationSource.ARP, mac, ip);
  }

  private static Observation dhcp(Instant at, String mac, String host, String fingerprint) {
    return new Observation(
        at, ObservationSource.DHCP, mac, null, host, fingerprint, null, List.of());
  }

  private void setStatus(String mac, String status) {
    jdbc.sql("UPDATE device SET status = :s WHERE network_id = :n AND mac = :m")
        .param("s", status)
        .param("n", network.id())
        .param("m", mac)
        .update();
  }

  @Test
  void newNetworkAsksTheUserForItsStatus() {
    assertThat(events())
        .singleElement()
        .satisfies(
            e -> {
              assertThat(e.kind()).isEqualTo(EventKind.NEW_NETWORK);
              assertThat(e.deviceId()).isNull();
              assertThat(e.message()).contains("10.7.0.0/24");
            });
  }

  @Test
  void newDeviceAfterLearning() {
    engine.ingest(network.id(), List.of(arp(now, HUE, "10.7.0.20")));

    assertThat(latest(EventKind.NEW_DEVICE))
        .satisfies(
            e -> {
              assertThat(e.message()).isEqualTo("Philips Lighting BV · 10.7.0.20");
              assertThat(e.deviceId()).isNotNull();
            });
  }

  @Test
  void noDeviceAlertWhileLearning() {
    networks.setLearningUntil(network.id(), now.plus(Duration.ofHours(1)));

    engine.ingest(network.id(), List.of(arp(now, HUE, "10.7.0.20")));

    assertThat(kinds()).containsExactly(EventKind.NEW_NETWORK);
  }

  @Test
  void privateAddressOfAnApprovedDeviceIsAKnownDeviceProbably() {
    engine.ingest(network.id(), List.of(dhcp(now, PHONE, "Pixel-8", "1,3,6,15")));
    setStatus(PHONE, "approved");

    engine.ingest(
        network.id(),
        List.of(dhcp(now.plusSeconds(1), "3a:1f:22:aa:bb:02", "Pixel-8", "1,3,6,15")));

    assertThat(latest(EventKind.KNOWN_DEVICE_NEW_MAC))
        .satisfies(
            e -> {
              assertThat(e.message()).startsWith("Probablement Pixel-8");
              assertThat(e.kind().sound()).isFalse();
            });
  }

  @Test
  void suspectComingBackIsReportedOncePerHour() {
    engine.ingest(network.id(), List.of(arp(now, HUE, "10.7.0.20")));
    setStatus(HUE, "suspect");

    engine.ingest(network.id(), List.of(arp(now.plusSeconds(60), HUE, "10.7.0.20")));
    engine.ingest(network.id(), List.of(arp(now.plusSeconds(120), HUE, "10.7.0.20")));
    engine.ingest(network.id(), List.of(arp(now.plus(Duration.ofMinutes(61)), HUE, "10.7.0.20")));

    assertThat(kinds()).filteredOn(k -> k == EventKind.SUSPECT_SEEN).hasSize(2);
  }

  @Test
  void anotherMacClaimingTheGatewayIpIsAConflict() {
    engine.ingest(network.id(), List.of(arp(now, gateway, "10.7.0.1")));

    engine.ingest(network.id(), List.of(arp(now.plusSeconds(5), "de:ad:be:ef:00:01", "10.7.0.1")));

    assertThat(latest(EventKind.IP_CONFLICT))
        .satisfies(
            e -> {
              assertThat(e.message()).contains("10.7.0.1", "de:ad:be:ef:00:01", gateway);
            });
  }

  @Test
  void anotherMacClaimingARecentIpOfAnApprovedDeviceIsAConflict() {
    engine.ingest(network.id(), List.of(arp(now, HUE, "10.7.0.20")));
    setStatus(HUE, "approved");
    jdbc.sql("UPDATE device SET display_name = 'Lampe salon' WHERE mac = :m")
        .param("m", HUE)
        .update();

    engine.ingest(network.id(), List.of(arp(now.plusSeconds(5), "de:ad:be:ef:00:02", "10.7.0.20")));

    assertThat(latest(EventKind.IP_CONFLICT).message()).contains("Lampe salon");
    assertThat(kinds()).contains(EventKind.IP_CONFLICT);
  }

  @Test
  void ipOfANewDeviceOrAnOldLeaseIsNoConflict() {
    engine.ingest(network.id(), List.of(arp(now.minus(Duration.ofDays(2)), HUE, "10.7.0.20")));
    setStatus(HUE, "approved");
    engine.ingest(network.id(), List.of(arp(now, "de:ad:be:ef:00:03", "10.7.0.20")));
    engine.ingest(network.id(), List.of(arp(now, "de:ad:be:ef:00:04", "10.7.0.30")));
    engine.ingest(network.id(), List.of(arp(now.plusSeconds(1), "de:ad:be:ef:00:05", "10.7.0.30")));

    assertThat(kinds()).doesNotContain(EventKind.IP_CONFLICT);
  }

  @Test
  void trustStartsLearningAndAbsenceExtendsIt() {
    Network fresh = networkService.declareCurrent("02:00:00:ab:cd:ef", "10.6.0.0/24");
    networkService.changeTrust(fresh.id(), Trust.AUTHORIZED);
    Instant until = Timestamps.parse(networks.findById(fresh.id()).orElseThrow().learningUntil());
    assertThat(Duration.between(Instant.now(), until))
        .isBetween(Duration.ofHours(23), Duration.ofHours(25));

    jdbc.sql("UPDATE network SET last_seen = :t WHERE id = :id")
        .param("t", Timestamps.format(Instant.now().minus(Duration.ofHours(3))))
        .param("id", fresh.id())
        .update();
    networkService.declareCurrent("02:00:00:ab:cd:ef", "10.6.0.0/24");

    Instant extended =
        Timestamps.parse(networks.findById(fresh.id()).orElseThrow().learningUntil());
    assertThat(Duration.between(until, extended))
        .isBetween(Duration.ofMinutes(179), Duration.ofMinutes(181));
  }

  @Test
  void eventKindValues() {
    assertThat(EventKind.fromValue("ip_conflict")).isEqualTo(EventKind.IP_CONFLICT);
    assertThat(EventKind.NEW_DEVICE.sound()).isTrue();
    assertThat(EventKind.NEW_NETWORK.sound()).isFalse();
    org.assertj.core.api.Assertions.assertThatThrownBy(() -> EventKind.fromValue("x"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
