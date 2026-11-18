package io.github.chakibselhi.netledger.server.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NetworkAdminTest {

  private Connection db;
  private final ByteArrayOutputStream output = new ByteArrayOutputStream();
  private final PrintStream out = new PrintStream(output, true, StandardCharsets.UTF_8);

  @BeforeEach
  void database() throws Exception {
    db = DriverManager.getConnection("jdbc:sqlite::memory:");
    db.createStatement()
        .execute(
            "CREATE TABLE network (id INTEGER PRIMARY KEY, gateway_mac TEXT, subnet TEXT, trust TEXT, last_seen TEXT)");
    db.createStatement()
        .execute(
            "INSERT INTO network VALUES (1, '02:00:00:00:00:01', '10.0.0.0/24', 'unset', '2026-11-18T12:00:00.000Z')");
    db.createStatement()
        .execute(
            "CREATE TABLE device (network_id INTEGER, mac TEXT, vendor TEXT, mac_randomized INTEGER,"
                + " guessed_type TEXT, last_ip TEXT, hostname TEXT, last_seen TEXT)");
    db.createStatement()
        .execute(
            "INSERT INTO device VALUES (1, '3a:1f:22:aa:bb:cc', NULL, 1, 'phone', '10.0.0.9', 'Pixel',"
                + " '2026-11-18T12:00:00.000Z')");
  }

  @AfterEach
  void close() throws Exception {
    db.close();
  }

  @Test
  void listsAndTrustsNetworks() throws Exception {
    assertThat(NetworkAdmin.run(db, new String[] {"trust", "1", "owned"}, out)).isZero();
    assertThat(NetworkAdmin.run(db, new String[] {"list"}, out)).isZero();

    assertThat(output.toString(StandardCharsets.UTF_8))
        .contains("Network 1 is now owned")
        .contains("02:00:00:00:00:01")
        .contains("10.0.0.0/24")
        .contains("owned");
  }

  @Test
  void listsDevicesOfANetwork() throws Exception {
    assertThat(NetworkAdmin.run(db, new String[] {"devices", "1"}, out)).isZero();

    assertThat(output.toString(StandardCharsets.UTF_8))
        .contains("3a:1f:22:aa:bb:cc", "Adresse privee", "phone", "10.0.0.9", "Pixel");
  }

  @Test
  void reportsMistakes() throws Exception {
    assertThat(NetworkAdmin.run(db, new String[] {"trust", "9", "owned"}, out)).isEqualTo(1);
    assertThat(NetworkAdmin.run(db, new String[] {"delete", "1"}, out)).isEqualTo(64);
    assertThatThrownBy(() -> NetworkAdmin.run(db, new String[] {"trust", "1", "trusted"}, out))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
