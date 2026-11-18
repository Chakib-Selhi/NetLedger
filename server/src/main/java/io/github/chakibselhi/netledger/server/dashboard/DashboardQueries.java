package io.github.chakibselhi.netledger.server.dashboard;

import io.github.chakibselhi.netledger.server.alerting.EventKind;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Read-only queries behind the dashboard pages; every write goes through the services. */
@Repository
class DashboardQueries {

  record NetworkView(
      long id,
      String gatewayMac,
      String subnet,
      String label,
      String trust,
      String learningUntil,
      String firstSeen,
      String lastSeen,
      int devices,
      int newDevices) {}

  record DeviceView(
      long id,
      long networkId,
      String mac,
      boolean randomized,
      String vendor,
      String hostname,
      String dhcpFingerprint,
      String type,
      String displayName,
      String category,
      String status,
      String firstSeen,
      String lastSeen,
      String lastIp) {}

  record IpView(String ip, String firstSeen, String lastSeen) {}

  record ServiceView(String type, String name, Integer port, String lastSeen) {}

  /**
   * @param detail JSON written by the correlation engine (host name, DHCP options, services)
   */
  record ObservationView(String source, String ip, String detail, String observedAt) {}

  record EventView(
      long id,
      long networkId,
      Long deviceId,
      String deviceLabel,
      String kind,
      String title,
      String message,
      String occurredAt) {}

  private static final String NETWORK =
      """
      SELECT n.id, n.gateway_mac, n.subnet, n.label, n.trust, n.learning_until, n.first_seen,
             n.last_seen,
             (SELECT COUNT(*) FROM device d WHERE d.network_id = n.id) AS devices,
             (SELECT COUNT(*) FROM device d WHERE d.network_id = n.id AND d.status = 'new')
               AS new_devices
      FROM network n
      """;

  private static final String DEVICE =
      """
      SELECT id, network_id, mac, mac_randomized, vendor, hostname, dhcp_fingerprint, guessed_type,
             display_name, category, status, first_seen, last_seen, last_ip
      FROM device
      """;

  private final JdbcClient jdbc;

  DashboardQueries(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  List<NetworkView> networks() {
    return jdbc.sql(NETWORK + " ORDER BY n.last_seen DESC, n.id DESC")
        .query(DashboardQueries::network)
        .list();
  }

  Optional<NetworkView> network(long id) {
    return jdbc.sql(NETWORK + " WHERE n.id = :id")
        .param("id", id)
        .query(DashboardQueries::network)
        .optional();
  }

  List<DeviceView> devices(long networkId) {
    return jdbc.sql(DEVICE + " WHERE network_id = :network ORDER BY last_seen DESC, id DESC")
        .param("network", networkId)
        .query(DashboardQueries::device)
        .list();
  }

  Optional<DeviceView> device(long id) {
    return jdbc.sql(DEVICE + " WHERE id = :id")
        .param("id", id)
        .query(DashboardQueries::device)
        .optional();
  }

  List<IpView> ips(long deviceId) {
    return jdbc.sql(
            "SELECT ip, first_seen, last_seen FROM ip_history WHERE device_id = :device"
                + " ORDER BY last_seen DESC")
        .param("device", deviceId)
        .query((rs, row) -> new IpView(rs.getString(1), rs.getString(2), rs.getString(3)))
        .list();
  }

  List<ServiceView> services(long deviceId) {
    return jdbc.sql(
            "SELECT type, name, port, last_seen FROM service WHERE device_id = :device"
                + " ORDER BY type")
        .param("device", deviceId)
        .query(
            (rs, row) -> {
              int port = rs.getInt(3);
              Integer p = rs.wasNull() ? null : port;
              return new ServiceView(rs.getString(1), rs.getString(2), p, rs.getString(4));
            })
        .list();
  }

  List<ObservationView> observations(long deviceId, int limit) {
    return jdbc.sql(
            "SELECT source, ip, detail, observed_at FROM observation WHERE device_id = :device"
                + " ORDER BY observed_at DESC, id DESC LIMIT :limit")
        .param("device", deviceId)
        .param("limit", limit)
        .query(
            (rs, row) ->
                new ObservationView(
                    rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4)))
        .list();
  }

  List<EventView> events(Long networkId, Long deviceId, int limit) {
    return jdbc.sql(
            """
            SELECT e.id, e.network_id, e.device_id,
                   COALESCE(d.display_name, d.hostname, d.mac) AS device_label,
                   e.kind, e.message, e.occurred_at
            FROM event e LEFT JOIN device d ON d.id = e.device_id
            WHERE (:network IS NULL OR e.network_id = :network)
              AND (:device IS NULL OR e.device_id = :device)
            ORDER BY e.occurred_at DESC, e.id DESC LIMIT :limit
            """)
        .param("network", networkId)
        .param("device", deviceId)
        .param("limit", limit)
        .query(DashboardQueries::event)
        .list();
  }

  private static NetworkView network(ResultSet rs, int row) throws SQLException {
    return new NetworkView(
        rs.getLong("id"),
        rs.getString("gateway_mac"),
        rs.getString("subnet"),
        rs.getString("label"),
        rs.getString("trust"),
        rs.getString("learning_until"),
        rs.getString("first_seen"),
        rs.getString("last_seen"),
        rs.getInt("devices"),
        rs.getInt("new_devices"));
  }

  private static DeviceView device(ResultSet rs, int row) throws SQLException {
    return new DeviceView(
        rs.getLong("id"),
        rs.getLong("network_id"),
        rs.getString("mac"),
        rs.getInt("mac_randomized") == 1,
        rs.getString("vendor"),
        rs.getString("hostname"),
        rs.getString("dhcp_fingerprint"),
        rs.getString("guessed_type"),
        rs.getString("display_name"),
        rs.getString("category"),
        rs.getString("status"),
        rs.getString("first_seen"),
        rs.getString("last_seen"),
        rs.getString("last_ip"));
  }

  private static EventView event(ResultSet rs, int row) throws SQLException {
    long device = rs.getLong("device_id");
    // wasNull() refers to the last column read, so it must follow getLong("device_id") directly.
    Long deviceId = rs.wasNull() ? null : device;
    String kind = rs.getString("kind");
    return new EventView(
        rs.getLong("id"),
        rs.getLong("network_id"),
        deviceId,
        rs.getString("device_label"),
        kind,
        EventKind.fromValue(kind).title(),
        rs.getString("message"),
        rs.getString("occurred_at"));
  }
}
