package io.github.chakibselhi.netledger.server.persistence;

import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.sql.DataSource;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class SqliteDataSourceConfig {

  private static final String SQLITE_PREFIX = "jdbc:sqlite:";

  @Bean
  DataSource dataSource(DataSourceProperties properties) throws IOException {
    createParentDirectory(properties.getUrl());
    return properties.initializeDataSourceBuilder().type(HikariDataSource.class).build();
  }

  // SQLite creates the database file on demand but fails if its directory does not exist.
  static void createParentDirectory(String jdbcUrl) throws IOException {
    if (jdbcUrl == null || !jdbcUrl.startsWith(SQLITE_PREFIX)) {
      return;
    }
    String file = jdbcUrl.substring(SQLITE_PREFIX.length());
    int query = file.indexOf('?');
    if (query >= 0) {
      file = file.substring(0, query);
    }
    if (file.isBlank() || file.equals(":memory:") || file.startsWith("file:")) {
      return;
    }
    Path parent = Path.of(file).toAbsolutePath().getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
  }
}
