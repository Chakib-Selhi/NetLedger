package io.github.chakibselhi.netledger.server.correlation;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * SQL for devices and what hangs off them. Used only by the correlation engine, the single writer.
 */
@Repository
class DeviceRepository {

  record DeviceRow(
      long id,
      long networkId,
      String mac,
      String firstSeen,
      String lastSeen,
      String lastIp,
      String hostname,
      String dhcpFingerprint,
      String vendor,
      boolean randomized,
      String status) {}

  private static final String COLUMNS =
      "id, network_id, mac, first_seen, last_seen, last_ip, hostname, dhcp_fingerprint, vendor,"
          + " mac_randomized, status";

  private final JdbcClient jdbc;

  DeviceRepository(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  Optional<DeviceRow> find(long networkId, String mac) {
    return jdbc.sql("SELECT " + COLUMNS + " FROM device WHERE network_id = :network AND mac = :mac")
        .param("network", networkId)
        .param("mac", mac)
        .query(DeviceRepository::map)
        .optional();
  }

  Optional<DeviceRow> findById(long id) {
    return jdbc.sql("SELECT " + COLUMNS + " FROM device WHERE id = :id")
        .param("id", id)
        .query(DeviceRepository::map)
        .optional();
  }

  /**
   * Changes what the user decides about a device. {@code null} leaves a column unchanged, an empty
   * string clears it.
   */
  void updateUserFields(long id, String displayName, String category, String status) {
    jdbc.sql(
            """
            UPDATE device SET
              display_name = CASE WHEN :setName = 1 THEN :name ELSE display_name END,
              category = CASE WHEN :setCategory = 1 THEN :category ELSE category END,
              status = COALESCE(:status, status)
            WHERE id = :id
            """)
        .param("setName", displayName != null ? 1 : 0)
        .param("name", displayName == null || displayName.isEmpty() ? null : displayName)
        .param("setCategory", category != null ? 1 : 0)
        .param("category", category == null || category.isEmpty() ? null : category)
        .param("status", status)
        .param("id", id)
        .update();
  }

  /**
   * Moves everything recorded for {@code source} to {@code target}, deletes {@code source}, then
   * gives {@code target} the identity fields of {@code merged}.
   */
  void merge(long source, long target, DeviceRow merged) {
    jdbc.sql("UPDATE observation SET device_id = :target WHERE device_id = :source")
        .param("target", target)
        .param("source", source)
        .update();
    jdbc.sql(
            """
            INSERT INTO ip_history (device_id, ip, first_seen, last_seen)
            SELECT :target, ip, first_seen, last_seen FROM ip_history WHERE device_id = :source
            ON CONFLICT (device_id, ip) DO UPDATE SET
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen)
            """)
        .param("target", target)
        .param("source", source)
        .update();
    jdbc.sql(
            """
            INSERT INTO service (device_id, type, name, port, last_seen)
            SELECT :target, type, name, port, last_seen FROM service WHERE device_id = :source
            ON CONFLICT (device_id, type) DO UPDATE SET
              name = COALESCE(excluded.name, name),
              port = COALESCE(excluded.port, port),
              last_seen = MAX(last_seen, excluded.last_seen)
            """)
        .param("target", target)
        .param("source", source)
        .update();
    for (String table : new String[] {"ip_history", "service"}) {
      jdbc.sql("DELETE FROM " + table + " WHERE device_id = :source")
          .param("source", source)
          .update();
    }
    jdbc.sql("UPDATE event SET device_id = :target WHERE device_id = :source")
        .param("target", target)
        .param("source", source)
        .update();
    jdbc.sql("DELETE FROM device WHERE id = :source").param("source", source).update();
    jdbc.sql(
            """
            UPDATE device SET mac = :mac, mac_randomized = :randomized, vendor = :vendor,
                              hostname = :hostname, dhcp_fingerprint = :fingerprint,
                              first_seen = :first, last_seen = :last, last_ip = :ip
            WHERE id = :target
            """)
        .param("mac", merged.mac())
        .param("randomized", merged.randomized() ? 1 : 0)
        .param("vendor", merged.vendor())
        .param("hostname", merged.hostname())
        .param("fingerprint", merged.dhcpFingerprint())
        .param("first", merged.firstSeen())
        .param("last", merged.lastSeen())
        .param("ip", merged.lastIp())
        .param("target", target)
        .update();
  }

  /** Deletes a network and everything observed on it; returns whether it existed. */
  boolean deleteNetwork(long networkId) {
    String devicesOf = "(SELECT id FROM device WHERE network_id = :network)";
    for (String table : new String[] {"observation", "ip_history", "service"}) {
      jdbc.sql("DELETE FROM " + table + " WHERE device_id IN " + devicesOf)
          .param("network", networkId)
          .update();
    }
    jdbc.sql("DELETE FROM event WHERE network_id = :network").param("network", networkId).update();
    jdbc.sql("DELETE FROM device WHERE network_id = :network").param("network", networkId).update();
    return jdbc.sql("DELETE FROM network WHERE id = :network").param("network", networkId).update()
        == 1;
  }

  long insert(
      long networkId,
      String mac,
      boolean randomized,
      String vendor,
      String hostname,
      String dhcpFingerprint,
      String lastIp,
      String seenAt) {
    return jdbc.sql(
            """
            INSERT INTO device (network_id, mac, mac_randomized, vendor, hostname, dhcp_fingerprint,
                                first_seen, last_seen, last_ip)
            VALUES (:network, :mac, :randomized, :vendor, :hostname, :fingerprint, :seen, :seen, :ip)
            RETURNING id
            """)
        .param("network", networkId)
        .param("mac", mac)
        .param("randomized", randomized ? 1 : 0)
        .param("vendor", vendor)
        .param("hostname", hostname)
        .param("fingerprint", dhcpFingerprint)
        .param("seen", seenAt)
        .param("ip", lastIp)
        .query(Long.class)
        .single();
  }

  void update(
      long id,
      String lastSeen,
      String lastIp,
      String hostname,
      String dhcpFingerprint,
      String vendor) {
    jdbc.sql(
            """
            UPDATE device SET last_seen = :seen, last_ip = :ip, hostname = :hostname,
                              dhcp_fingerprint = :fingerprint, vendor = :vendor
            WHERE id = :id
            """)
        .param("seen", lastSeen)
        .param("ip", lastIp)
        .param("hostname", hostname)
        .param("fingerprint", dhcpFingerprint)
        .param("vendor", vendor)
        .param("id", id)
        .update();
  }

  void setGuessedType(long id, String type) {
    jdbc.sql("UPDATE device SET guessed_type = :type WHERE id = :id")
        .param("type", type)
        .param("id", id)
        .update();
  }

  void insertObservation(
      long deviceId, String source, String ip, String detail, String observedAt) {
    jdbc.sql(
            """
            INSERT INTO observation (device_id, source, ip, detail, observed_at)
            VALUES (:device, :source, :ip, :detail, :at)
            """)
        .param("device", deviceId)
        .param("source", source)
        .param("ip", ip)
        .param("detail", detail)
        .param("at", observedAt)
        .update();
  }

  void recordIp(long deviceId, String ip, String seenAt) {
    jdbc.sql(
            """
            INSERT INTO ip_history (device_id, ip, first_seen, last_seen) VALUES (:device, :ip, :at, :at)
            ON CONFLICT (device_id, ip) DO UPDATE SET
              first_seen = MIN(first_seen, excluded.first_seen),
              last_seen = MAX(last_seen, excluded.last_seen)
            """)
        .param("device", deviceId)
        .param("ip", ip)
        .param("at", seenAt)
        .update();
  }

  void recordService(long deviceId, String type, String name, Integer port, String seenAt) {
    jdbc.sql(
            """
            INSERT INTO service (device_id, type, name, port, last_seen)
            VALUES (:device, :type, :name, :port, :at)
            ON CONFLICT (device_id, type) DO UPDATE SET
              name = COALESCE(excluded.name, name),
              port = COALESCE(excluded.port, port),
              last_seen = MAX(last_seen, excluded.last_seen)
            """)
        .param("device", deviceId)
        .param("type", type)
        .param("name", name)
        .param("port", port)
        .param("at", seenAt)
        .update();
  }

  Set<String> serviceTypes(long deviceId, boolean withInstanceOnly) {
    String sql =
        withInstanceOnly
            ? "SELECT type FROM service WHERE device_id = :device AND name IS NOT NULL"
            : "SELECT type FROM service WHERE device_id = :device";
    return new HashSet<>(jdbc.sql(sql).param("device", deviceId).query(String.class).list());
  }

  private static DeviceRow map(ResultSet rs, int row) throws SQLException {
    return new DeviceRow(
        rs.getLong("id"),
        rs.getLong("network_id"),
        rs.getString("mac"),
        rs.getString("first_seen"),
        rs.getString("last_seen"),
        rs.getString("last_ip"),
        rs.getString("hostname"),
        rs.getString("dhcp_fingerprint"),
        rs.getString("vendor"),
        rs.getInt("mac_randomized") == 1,
        rs.getString("status"));
  }
}
