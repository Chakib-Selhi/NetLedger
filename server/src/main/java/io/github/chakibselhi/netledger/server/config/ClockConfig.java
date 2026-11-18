package io.github.chakibselhi.netledger.server.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class ClockConfig {

  /** Injected instead of calling Instant.now() so tests can control time. */
  @Bean
  Clock clock() {
    return Clock.systemUTC();
  }
}
