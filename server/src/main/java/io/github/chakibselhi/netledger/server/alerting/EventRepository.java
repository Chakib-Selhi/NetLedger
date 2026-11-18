package io.github.chakibselhi.netledger.server.alerting;

import io.github.chakibselhi.netledger.server.persistence.Timestamps;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class EventRepository {

  private static final String COLUMNS =
      "id, network_id, device_id, kind, message, occurred_at, delivered";

  private final JdbcClient jdbc;

  EventRepository(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  AlertEvent insert(
      long networkId, Long deviceId, EventKind kind, String message, Instant occurredAt) {
    return jdbc.sql(
            "INSERT INTO event (network_id, device_id, kind, message, occurred_at)"
                + " VALUES (:network, :device, :kind, :message, :at) RETURNING "
                + COLUMNS)
        .param("network", networkId)
        .param("device", deviceId)
        .param("kind", kind.value())
        .param("message", message)
        .param("at", Timestamps.format(occurredAt))
        .query(EventRepository::map)
        .single();
  }

  Optional<Instant> lastOccurrence(long deviceId, EventKind kind) {
    return jdbc.sql("SELECT MAX(occurred_at) FROM event WHERE device_id = :device AND kind = :kind")
        .param("device", deviceId)
        .param("kind", kind.value())
        .query(String.class)
        .optional()
        .map(Timestamps::parse);
  }

  List<AlertEvent> undelivered() {
    return jdbc.sql(
            "SELECT " + COLUMNS + " FROM event WHERE delivered = 0 ORDER BY occurred_at, id")
        .query(EventRepository::map)
        .list();
  }

  void markDelivered(Collection<Long> ids) {
    for (Long id : ids) {
      jdbc.sql("UPDATE event SET delivered = 1 WHERE id = :id").param("id", id).update();
    }
  }

  /** Most recent events, optionally of one network or one device, newest first. */
  public List<AlertEvent> recent(Long networkId, Long deviceId, int limit) {
    return jdbc.sql(
            "SELECT "
                + COLUMNS
                + " FROM event"
                + " WHERE (:network IS NULL OR network_id = :network)"
                + " AND (:device IS NULL OR device_id = :device)"
                + " ORDER BY occurred_at DESC, id DESC LIMIT :limit")
        .param("network", networkId)
        .param("device", deviceId)
        .param("limit", limit)
        .query(EventRepository::map)
        .list();
  }

  private static AlertEvent map(ResultSet rs, int row) throws SQLException {
    long device = rs.getLong("device_id");
    // wasNull() refers to the last column read, so it must follow getLong("device_id") directly.
    Long deviceId = rs.wasNull() ? null : device;
    return new AlertEvent(
        rs.getLong("id"),
        rs.getLong("network_id"),
        deviceId,
        EventKind.fromValue(rs.getString("kind")),
        rs.getString("message"),
        rs.getString("occurred_at"),
        rs.getInt("delivered") == 1);
  }
}
