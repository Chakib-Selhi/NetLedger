package io.github.chakibselhi.netledger.server.persistence;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest
class SchemaMigrationTest {

  private static final String NOW = "2026-11-12T18:00:00Z";

  @TempDir static Path dataDir;

  @DynamicPropertySource
  static void dataDir(DynamicPropertyRegistry registry) {
    registry.add("netledger.data-dir", () -> dataDir.resolve("nested").toString());
  }

  @Autowired JdbcTemplate jdbc;

  @Test
  void createsAllTablesFromThePrd() {
    var tables =
        jdbc.queryForList(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'flyway%'"
                + " AND name NOT LIKE 'sqlite%'",
            String.class);

    assertThat(tables)
        .containsExactlyInAnyOrder(
            "network", "device", "observation", "ip_history", "service", "event");
  }

  @Test
  void createsTimeIndexes() {
    var indexes =
        jdbc.queryForList(
            "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%'",
            String.class);

    assertThat(indexes).contains("idx_observation_time", "idx_event_time");
  }

  @Test
  void enablesForeignKeysAndWal() {
    assertThat(jdbc.queryForObject("PRAGMA foreign_keys", Integer.class)).isEqualTo(1);
    assertThat(jdbc.queryForObject("PRAGMA journal_mode", String.class))
        .isEqualToIgnoringCase("wal");
  }

  @Test
  void rejectsObservationForUnknownDevice() {
    assertThatThrownBy(
            () ->
                jdbc.update(
                    "INSERT INTO observation (device_id, source, observed_at) VALUES (?, ?, ?)",
                    999_999,
                    "arp",
                    "2026-11-12T18:00:00Z"))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("SQLITE_CONSTRAINT_FOREIGNKEY");
  }

  @Test
  void newNetworkIsNotTrustedByDefault() {
    long network = insertNetwork("02:00:00:00:00:a1", "10.0.0.0/24");

    assertThat(jdbc.queryForObject("SELECT trust FROM network WHERE id = ?", String.class, network))
        .isEqualTo("unset");
  }

  @Test
  void appliesDeviceDefaults() {
    long network = insertNetwork("02:00:00:00:00:a2", "10.0.1.0/24");
    insertDevice(network, "02:00:00:00:00:01");

    var row =
        jdbc.queryForMap(
            "SELECT status, mac_randomized FROM device WHERE network_id = ? AND mac = ?",
            network,
            "02:00:00:00:00:01");

    assertThat(row).containsEntry("status", "new").containsEntry("mac_randomized", 0);
  }

  @Test
  void sameMacOnTwoNetworksGivesTwoDevices() {
    long home = insertNetwork("02:00:00:00:00:a3", "192.168.1.0/24");
    long school = insertNetwork("02:00:00:00:00:a4", "172.16.0.0/16");

    insertDevice(home, "02:00:00:00:00:02");
    insertDevice(school, "02:00:00:00:00:02");

    assertThat(
            jdbc.queryForObject(
                "SELECT COUNT(*) FROM device WHERE mac = ?", Integer.class, "02:00:00:00:00:02"))
        .isEqualTo(2);
    assertThatThrownBy(() -> insertDevice(home, "02:00:00:00:00:02"))
        .isInstanceOf(DataAccessException.class)
        .hasMessageContaining("SQLITE_CONSTRAINT_UNIQUE");
  }

  private long insertNetwork(String gatewayMac, String subnet) {
    jdbc.update(
        "INSERT INTO network (gateway_mac, subnet, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        gatewayMac,
        subnet,
        NOW,
        NOW);
    return jdbc.queryForObject(
        "SELECT id FROM network WHERE gateway_mac = ? AND subnet = ?",
        Long.class,
        gatewayMac,
        subnet);
  }

  private void insertDevice(long networkId, String mac) {
    jdbc.update(
        "INSERT INTO device (network_id, mac, first_seen, last_seen) VALUES (?, ?, ?, ?)",
        networkId,
        mac,
        NOW,
        NOW);
  }
}
