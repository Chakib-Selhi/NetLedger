package io.github.chakibselhi.netledger.server.correlation;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.network.Subnet;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

@SpringBootTest
class CorrelationEngineTest {

  private static final Instant T0 = Instant.parse("2026-11-17T12:00:00Z");
  private static final String HUE = "ec:b5:fa:00:00:01";
  private static final String PRIVATE = "3a:1f:22:aa:bb:cc";

  @Autowired CorrelationEngine engine;
  @Autowired NetworkRepository networks;
  @Autowired JdbcClient jdbc;

  private long network;

  @BeforeEach
  void newNetwork() {
    var random = java.util.concurrent.ThreadLocalRandom.current();
    String gateway =
        "02:00:00:%02x:%02x:%02x"
            .formatted(random.nextInt(256), random.nextInt(256), random.nextInt(256));
    network = networks.upsert(gateway, Subnet.parse("10.9.0.0/16"), T0).id();
  }

  private Map<String, Object> device(String mac) {
    return jdbc.sql("SELECT * FROM device WHERE network_id = :n AND mac = :m")
        .param("n", network)
        .param("m", mac)
        .query()
        .singleRow();
  }

  private static Observation arp(Instant at, String mac, String ip) {
    return Observation.presence(at, ObservationSource.ARP, mac, ip);
  }

  @Test
  void createsDeviceWithVendorTypeAndHistory() {
    IngestResult result = engine.ingest(network, List.of(arp(T0, HUE, "10.9.0.20")));

    assertThat(result).isEqualTo(new IngestResult(1, 0));
    Map<String, Object> row = device(HUE);
    assertThat(row)
        .containsEntry("vendor", "Philips Lighting BV")
        .containsEntry("mac_randomized", 0)
        .containsEntry("guessed_type", "iot")
        .containsEntry("status", "new")
        .containsEntry("first_seen", "2026-11-17T12:00:00.000Z")
        .containsEntry("last_seen", "2026-11-17T12:00:00.000Z")
        .containsEntry("last_ip", "10.9.0.20");
    assertThat(
            jdbc.sql("SELECT COUNT(*) FROM observation WHERE device_id = :d")
                .param("d", row.get("id"))
                .query(Integer.class)
                .single())
        .isEqualTo(1);
  }

  @Test
  void privateAddressHasNoVendor() {
    engine.ingest(network, List.of(arp(T0, PRIVATE, "10.9.0.21")));

    assertThat(device(PRIVATE)).containsEntry("mac_randomized", 1).containsEntry("vendor", null);
  }

  @Test
  void olderObservationsNeverOverwriteNewerValues() {
    engine.ingest(network, List.of(arp(T0.plusSeconds(60), HUE, "10.9.0.30")));
    engine.ingest(
        network,
        List.of(
            new Observation(
                T0,
                ObservationSource.DHCP,
                HUE,
                "10.9.0.29",
                "old-name",
                "1,3,6",
                null,
                List.of())));

    Map<String, Object> row = device(HUE);
    assertThat(row)
        .containsEntry("last_ip", "10.9.0.30")
        .containsEntry("last_seen", "2026-11-17T12:01:00.000Z")
        .containsEntry("hostname", "old-name")
        .containsEntry("dhcp_fingerprint", "1,3,6");

    var history =
        jdbc.sql(
                "SELECT ip, first_seen, last_seen FROM ip_history WHERE device_id = :d ORDER BY ip")
            .param("d", row.get("id"))
            .query()
            .listOfRows();
    assertThat(history).hasSize(2);
    assertThat(history.get(0)).containsEntry("ip", "10.9.0.29");
  }

  @Test
  void ipHistoryKeepsFirstAndLastSighting() {
    engine.ingest(network, List.of(arp(T0.plusSeconds(10), HUE, "10.9.0.40")));
    engine.ingest(
        network, List.of(arp(T0, HUE, "10.9.0.40"), arp(T0.plusSeconds(99), HUE, "10.9.0.40")));

    Map<String, Object> history =
        jdbc.sql("SELECT first_seen, last_seen FROM ip_history WHERE device_id = :d")
            .param("d", device(HUE).get("id"))
            .query()
            .singleRow();
    assertThat(history)
        .containsEntry("first_seen", "2026-11-17T12:00:00.000Z")
        .containsEntry("last_seen", "2026-11-17T12:01:39.000Z");
  }

  @Test
  void servicesMergeAndDriveTheType() {
    String mac = "f0:b3:ec:00:00:02";
    engine.ingest(
        network,
        List.of(
            new Observation(
                T0,
                ObservationSource.MDNS,
                mac,
                null,
                "Salon",
                null,
                null,
                List.of(new ServiceAnnouncement("_airplay._tcp", null, null)))));
    assertThat(device(mac))
        .containsEntry("guessed_type", "tv")
        .containsEntry("vendor", "Apple, Inc.");

    engine.ingest(
        network,
        List.of(
            new Observation(
                T0.plusSeconds(5),
                ObservationSource.MDNS,
                mac,
                null,
                null,
                null,
                null,
                List.of(
                    new ServiceAnnouncement("_airplay._tcp", "Salon", 7000),
                    new ServiceAnnouncement("_companion-link._tcp", null, null)))));

    Map<String, Object> airplay =
        jdbc.sql("SELECT name, port FROM service WHERE device_id = :d AND type = '_airplay._tcp'")
            .param("d", device(mac).get("id"))
            .query()
            .singleRow();
    assertThat(airplay).containsEntry("name", "Salon").containsEntry("port", 7000);
    assertThat(device(mac))
        .containsEntry("guessed_type", "unknown")
        .containsEntry("hostname", "Salon");
  }

  @Test
  void rejectsFutureObservationsAndTouchesTheNetwork() {
    IngestResult result =
        engine.ingest(
            network,
            List.of(
                arp(Instant.now().plusSeconds(3600), HUE, "10.9.0.50"),
                arp(T0.plusSeconds(7), HUE, null)));

    assertThat(result).isEqualTo(new IngestResult(1, 1));
    assertThat(
            jdbc.sql("SELECT last_seen FROM network WHERE id = :n")
                .param("n", network)
                .query(String.class)
                .single())
        .isEqualTo("2026-11-17T12:00:07.000Z");
  }

  @Test
  void storesObservationDetailAsJson() {
    engine.ingest(
        network,
        List.of(
            new Observation(
                T0,
                ObservationSource.DHCP,
                PRIVATE,
                null,
                "Pixel",
                "1,3,6",
                "android-dhcp-14",
                List.of())));

    String detail =
        jdbc.sql(
                "SELECT detail FROM observation o JOIN device d ON d.id = o.device_id WHERE d.network_id = :n")
            .param("n", network)
            .query(String.class)
            .single();
    assertThat(detail)
        .isEqualTo(
            "{\"hostname\":\"Pixel\",\"dhcpFingerprint\":\"1,3,6\",\"vendorClass\":\"android-dhcp-14\"}");
  }

  @Test
  void mergeKeepsNewestNonNullValue() {
    assertThat(CorrelationEngine.merge("a", null, true)).isEqualTo("a");
    assertThat(CorrelationEngine.merge("a", "b", true)).isEqualTo("b");
    assertThat(CorrelationEngine.merge("a", "b", false)).isEqualTo("a");
    assertThat(CorrelationEngine.merge(null, "b", false)).isEqualTo("b");
  }
}
