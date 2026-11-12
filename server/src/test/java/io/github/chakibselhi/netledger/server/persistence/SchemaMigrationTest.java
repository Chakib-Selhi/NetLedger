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

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
class SchemaMigrationTest {

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
        .containsExactlyInAnyOrder("device", "observation", "ip_history", "service", "event");
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
  void appliesDeviceDefaults() {
    jdbc.update(
        "INSERT INTO device (mac, first_seen, last_seen) VALUES (?, ?, ?)",
        "02:00:00:00:00:01",
        "2026-11-12T18:00:00Z",
        "2026-11-12T18:00:00Z");

    var row =
        jdbc.queryForMap(
            "SELECT status, mac_randomized FROM device WHERE mac = ?", "02:00:00:00:00:01");

    assertThat(row).containsEntry("status", "new").containsEntry("mac_randomized", 0);
  }
}
