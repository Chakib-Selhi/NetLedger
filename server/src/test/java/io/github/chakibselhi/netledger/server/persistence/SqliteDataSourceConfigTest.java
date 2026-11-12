package io.github.chakibselhi.netledger.server.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SqliteDataSourceConfigTest {

  @TempDir Path tmp;

  @Test
  void createsMissingParentDirectoryAndIgnoresQueryString() throws Exception {
    Path db = tmp.resolve("a/b/netledger.db");

    SqliteDataSourceConfig.createParentDirectory("jdbc:sqlite:" + db + "?foreign_keys=true");

    assertThat(db.getParent()).isDirectory();
    assertThat(tmp.resolve("a/b/netledger.db?foreign_keys=true")).doesNotExist();
  }

  @Test
  void ignoresInMemoryAndNonSqliteUrls() throws Exception {
    SqliteDataSourceConfig.createParentDirectory("jdbc:sqlite::memory:");
    SqliteDataSourceConfig.createParentDirectory("jdbc:h2:mem:test");
    SqliteDataSourceConfig.createParentDirectory(null);
  }
}
