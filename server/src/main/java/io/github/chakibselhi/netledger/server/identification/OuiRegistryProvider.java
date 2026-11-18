package io.github.chakibselhi.netledger.server.identification;

import io.github.chakibselhi.netledger.server.config.NetLedgerProperties;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Keeps the IEEE registry current. At startup it loads the most recent copy available: the one
 * downloaded into the data volume, else the one bundled with the image. When updates are enabled,
 * it downloads the registry if the copy is missing or older than the update interval. A download
 * replaces the files only after the new ones parsed successfully.
 */
@Component
public class OuiRegistryProvider {

  static final List<String> FILES = List.of("oui/oui.csv", "oui28/mam.csv", "oui36/oui36.csv");
  static final long MAX_FILE_BYTES = 32L * 1024 * 1024;
  static final int MIN_ENTRIES = 1_000;
  private static final Logger log = LoggerFactory.getLogger(OuiRegistryProvider.class);

  private final NetLedgerProperties.Oui settings;
  private final Path cacheDir;
  private final Clock clock;
  private final HttpClient http;
  private final AtomicReference<OuiRegistry> current = new AtomicReference<>(OuiRegistry.empty());

  OuiRegistryProvider(NetLedgerProperties properties, Clock clock) {
    this.settings = properties.oui();
    this.cacheDir = properties.ouiCacheDir();
    this.clock = clock;
    this.http =
        HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(20))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();
    loadBestLocalCopy();
  }

  public OuiRegistry registry() {
    return current.get();
  }

  /** Daily check; downloads only when the cached copy is older than the update interval. */
  @Scheduled(initialDelay = 30_000, fixedDelay = 86_400_000)
  public void refreshIfStale() {
    if (!settings.updateEnabled() || !isStale()) {
      return;
    }
    try {
      download();
    } catch (IOException e) {
      log.warn(
          "IEEE registry download failed, keeping {} entries: {}",
          registry().size(),
          e.getMessage());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  boolean isStale() {
    Path marker = cacheDir.resolve(fileName(FILES.get(0)));
    try {
      Instant modified = Files.getLastModifiedTime(marker).toInstant();
      return modified.plus(settings.updateInterval()).isBefore(clock.instant());
    } catch (IOException e) {
      return true;
    }
  }

  void download() throws IOException, InterruptedException {
    Files.createDirectories(cacheDir);
    var downloaded = new ArrayList<Path>();
    try {
      for (String file : FILES) {
        Path temp = Files.createTempFile(cacheDir, "download-", ".csv");
        downloaded.add(temp);
        fetch(settings.baseUrl().resolve(file), temp);
      }
      OuiRegistry registry = load(downloaded);
      if (registry.size() < MIN_ENTRIES) {
        throw new IOException("Downloaded registry has only " + registry.size() + " entries");
      }
      for (int i = 0; i < FILES.size(); i++) {
        Files.move(
            downloaded.get(i),
            cacheDir.resolve(fileName(FILES.get(i))),
            StandardCopyOption.REPLACE_EXISTING,
            StandardCopyOption.ATOMIC_MOVE);
      }
      current.set(registry);
      log.info("IEEE registry updated: {} entries", registry.size());
    } finally {
      for (Path temp : downloaded) {
        Files.deleteIfExists(temp);
      }
    }
  }

  private void fetch(URI uri, Path target) throws IOException, InterruptedException {
    HttpRequest request =
        HttpRequest.newBuilder(uri)
            .timeout(Duration.ofMinutes(2))
            .header("User-Agent", "NetLedger (self-hosted network inventory)")
            .build();
    HttpResponse<InputStream> response =
        http.send(request, HttpResponse.BodyHandlers.ofInputStream());
    try (InputStream body = response.body()) {
      if (response.statusCode() != 200) {
        throw new IOException(uri + " returned HTTP " + response.statusCode());
      }
      byte[] content = body.readNBytes((int) MAX_FILE_BYTES + 1);
      if (content.length > MAX_FILE_BYTES) {
        throw new IOException(uri + " is larger than " + MAX_FILE_BYTES + " bytes");
      }
      Files.write(target, content);
    }
  }

  private void loadBestLocalCopy() {
    for (Path dir : candidateDirs()) {
      List<Path> files = FILES.stream().map(f -> dir.resolve(fileName(f))).toList();
      if (!files.stream().allMatch(Files::isRegularFile)) {
        continue;
      }
      try {
        current.set(load(files));
        log.info("IEEE registry loaded from {}: {} entries", dir, registry().size());
        return;
      } catch (IOException e) {
        log.warn("Ignoring unreadable IEEE registry in {}: {}", dir, e.getMessage());
      }
    }
    log.warn("No IEEE registry available: vendors stay unknown until a download succeeds");
  }

  private List<Path> candidateDirs() {
    var dirs = new ArrayList<Path>();
    dirs.add(cacheDir);
    if (settings.bundledDir() != null && !settings.bundledDir().toString().isBlank()) {
      dirs.add(settings.bundledDir());
    }
    return dirs;
  }

  private static OuiRegistry load(List<Path> files) throws IOException {
    var readers = new ArrayList<Reader>();
    try {
      for (Path file : files) {
        readers.add(Files.newBufferedReader(file, StandardCharsets.UTF_8));
      }
      return OuiRegistry.fromCsv(readers);
    } finally {
      for (Reader reader : readers) {
        reader.close();
      }
    }
  }

  static String fileName(String remotePath) {
    return remotePath.substring(remotePath.lastIndexOf('/') + 1);
  }
}
