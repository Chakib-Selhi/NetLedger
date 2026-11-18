package io.github.chakibselhi.netledger.server.network;

import io.github.chakibselhi.netledger.server.persistence.Timestamps;
import java.time.Instant;
import java.util.Optional;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class NetworkRepository {

  private final JdbcClient jdbc;

  NetworkRepository(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  /** Inserts the network if new, otherwise refreshes {@code last_seen}; returns the stored row. */
  public Network upsert(String gatewayMac, Subnet subnet, Instant seenAt) {
    String now = Timestamps.format(seenAt);
    return jdbc.sql(
            """
            INSERT INTO network (gateway_mac, subnet, first_seen, last_seen)
            VALUES (:mac, :subnet, :now, :now)
            ON CONFLICT (gateway_mac, subnet) DO UPDATE SET last_seen = MAX(last_seen, excluded.last_seen)
            RETURNING id, gateway_mac, subnet, label, trust
            """)
        .param("mac", gatewayMac)
        .param("subnet", subnet.toString())
        .param("now", now)
        .query(NetworkRepository::map)
        .single();
  }

  public Optional<Network> findById(long id) {
    return jdbc.sql("SELECT id, gateway_mac, subnet, label, trust FROM network WHERE id = :id")
        .param("id", id)
        .query(NetworkRepository::map)
        .optional();
  }

  public void touch(long id, Instant seenAt) {
    jdbc.sql("UPDATE network SET last_seen = MAX(last_seen, :seen) WHERE id = :id")
        .param("seen", Timestamps.format(seenAt))
        .param("id", id)
        .update();
  }

  public void setTrust(long id, Trust trust) {
    jdbc.sql("UPDATE network SET trust = :trust WHERE id = :id")
        .param("trust", trust.value())
        .param("id", id)
        .update();
  }

  private static Network map(java.sql.ResultSet rs, int row) throws java.sql.SQLException {
    return new Network(
        rs.getLong("id"),
        rs.getString("gateway_mac"),
        rs.getString("subnet"),
        rs.getString("label"),
        Trust.fromValue(rs.getString("trust")));
  }
}
