package io.github.chakibselhi.netledger.server.persistence;

import io.github.chakibselhi.netledger.server.config.NetLedgerProperties;
import java.time.Clock;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Deletes raw observations past the retention period; devices and events are kept forever. */
@Component
class RetentionJob {

  private static final Logger log = LoggerFactory.getLogger(RetentionJob.class);

  private final JdbcClient jdbc;
  private final Duration retention;
  private final Clock clock;

  RetentionJob(JdbcClient jdbc, NetLedgerProperties properties, Clock clock) {
    this.jdbc = jdbc;
    this.retention = properties.observationRetention();
    this.clock = clock;
  }

  @Scheduled(cron = "0 30 3 * * *", zone = "America/Toronto")
  int purge() {
    String cutoff = Timestamps.format(clock.instant().minus(retention));
    int deleted =
        jdbc.sql("DELETE FROM observation WHERE observed_at < :cutoff")
            .param("cutoff", cutoff)
            .update();
    if (deleted > 0) {
      log.info("Retention: deleted {} observation(s) older than {}", deleted, cutoff);
    }
    return deleted;
  }
}
