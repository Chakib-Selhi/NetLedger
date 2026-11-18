package io.github.chakibselhi.netledger.server.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;

@SpringBootTest
class RetentionJobTest {

  @Autowired RetentionJob job;
  @Autowired JdbcClient jdbc;

  @Test
  void deletesOnlyObservationsOlderThanRetention() {
    String now = Timestamps.format(Instant.now());
    long network =
        jdbc.sql(
                "INSERT INTO network (gateway_mac, subnet, first_seen, last_seen) VALUES ('02:00:00:ee:ee:ee', '10.8.0.0/24', :t, :t) RETURNING id")
            .param("t", now)
            .query(Long.class)
            .single();
    long device =
        jdbc.sql(
                "INSERT INTO device (network_id, mac, first_seen, last_seen) VALUES (:n, '02:00:00:ee:ee:01', :t, :t) RETURNING id")
            .param("n", network)
            .param("t", now)
            .query(Long.class)
            .single();
    String old = Timestamps.format(Instant.now().minusSeconds(31L * 24 * 3600));
    for (String at : new String[] {old, now}) {
      jdbc.sql("INSERT INTO observation (device_id, source, observed_at) VALUES (:d, 'arp', :at)")
          .param("d", device)
          .param("at", at)
          .update();
    }

    assertThat(job.purge()).isGreaterThanOrEqualTo(1);
    assertThat(
            jdbc.sql("SELECT observed_at FROM observation WHERE device_id = :d")
                .param("d", device)
                .query(String.class)
                .list())
        .containsExactly(now);
    assertThat(
            jdbc.sql("SELECT COUNT(*) FROM device WHERE id = :d")
                .param("d", device)
                .query(Integer.class)
                .single())
        .isEqualTo(1);
  }

  @Test
  void timestampsHaveFixedWidthSoTextOrderIsTimeOrder() {
    String whole = Timestamps.format(Instant.parse("2026-11-17T12:00:00Z"));
    String fraction = Timestamps.format(Instant.parse("2026-11-17T12:00:00.250999Z"));

    assertThat(whole).isEqualTo("2026-11-17T12:00:00.000Z");
    assertThat(fraction).isEqualTo("2026-11-17T12:00:00.250Z");
    assertThat(whole).isLessThan(fraction);
    assertThat(Timestamps.parse(fraction)).isEqualTo(Instant.parse("2026-11-17T12:00:00.250Z"));
  }
}
