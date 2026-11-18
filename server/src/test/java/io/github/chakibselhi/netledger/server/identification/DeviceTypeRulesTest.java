package io.github.chakibselhi.netledger.server.identification;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class DeviceTypeRulesTest {

  private final DeviceTypeRules rules =
      new DeviceTypeRules(
          Map.of("1,2,3", "ios", "4,5,6", "android", "7,8,9", "macos", "9,9", "windows"),
          List.of("Espressif", "Philips Lighting"));

  private DeviceType guess(
      Set<String> services, String fingerprint, boolean randomized, String vendor) {
    return rules.guess(new DeviceFacts(services, services, fingerprint, randomized, vendor));
  }

  @Test
  void printerComesFirst() {
    assertThat(
            guess(
                Set.of("_ipp._tcp", "_airplay._tcp", "_ssh._tcp"),
                "7,8,9",
                false,
                "Espressif Inc."))
        .isEqualTo(DeviceType.PRINTER);
    assertThat(guess(Set.of("_printer._tcp"), null, false, null)).isEqualTo(DeviceType.PRINTER);
  }

  @Test
  void castTargetWithoutCompanionLinkIsATv() {
    assertThat(guess(Set.of("_googlecast._tcp"), null, false, null)).isEqualTo(DeviceType.TV);
    assertThat(guess(Set.of("_airplay._tcp"), null, false, null)).isEqualTo(DeviceType.TV);
    assertThat(guess(Set.of("_airplay._tcp", "_companion-link._tcp"), null, false, null))
        .isEqualTo(DeviceType.UNKNOWN);
  }

  @Test
  void mobileFingerprintNeedsAPrivateAddress() {
    assertThat(guess(Set.of(), "1,2,3", true, null)).isEqualTo(DeviceType.PHONE);
    assertThat(guess(Set.of(), "4,5,6", true, null)).isEqualTo(DeviceType.PHONE);
    assertThat(guess(Set.of(), "1,2,3", false, null)).isEqualTo(DeviceType.UNKNOWN);
  }

  @Test
  void computerFromServicesOrDesktopFingerprint() {
    assertThat(guess(Set.of("_ssh._tcp"), null, false, null)).isEqualTo(DeviceType.COMPUTER);
    assertThat(guess(Set.of("_smb._tcp"), null, false, null)).isEqualTo(DeviceType.COMPUTER);
    assertThat(guess(Set.of(), "7,8,9", true, null)).isEqualTo(DeviceType.COMPUTER);
    assertThat(guess(Set.of(), "9,9", false, null)).isEqualTo(DeviceType.COMPUTER);
  }

  @Test
  void iotVendorMatchesCaseInsensitivelyAsLastRule() {
    assertThat(guess(Set.of(), null, false, "PHILIPS LIGHTING BV")).isEqualTo(DeviceType.IOT);
    assertThat(guess(Set.of("_ssh._tcp"), null, false, "Espressif Inc."))
        .isEqualTo(DeviceType.COMPUTER);
    assertThat(guess(Set.of(), null, false, "Apple, Inc.")).isEqualTo(DeviceType.UNKNOWN);
    assertThat(guess(Set.of(), "unknown", false, null)).isEqualTo(DeviceType.UNKNOWN);
  }

  @Test
  void proxiesCountOnlyServicesBackedByAnInstance() {
    Set<String> enumerated =
        Set.of("_dnssd-server._udp", "_printer._tcp", "_ssh._tcp", "_spotify-connect._tcp");

    assertThat(
            rules.guess(
                new DeviceFacts(enumerated, Set.of("_spotify-connect._tcp"), null, false, null)))
        .isEqualTo(DeviceType.UNKNOWN);
    assertThat(
            rules.guess(
                new DeviceFacts(
                    Set.of("_sleep-proxy._udp", "_airplay._tcp"),
                    Set.of("_airplay._tcp"),
                    null,
                    false,
                    null)))
        .isEqualTo(DeviceType.TV);
    assertThat(
            rules.guess(
                new DeviceFacts(Set.of("_printer._tcp", "_ssh._tcp"), Set.of(), null, false, null)))
        .as("non-proxies keep enumerated types")
        .isEqualTo(DeviceType.PRINTER);
  }

  @Test
  void loadsBundledDataFiles() {
    var bundled = new DeviceTypeRules();

    assertThat(bundled.operatingSystem("1,121,3,6,15,108,114,119,162,252,95,44,46"))
        .contains("macos");
    assertThat(bundled.operatingSystem(null)).isEmpty();
    assertThat(bundled.guess(new DeviceFacts(Set.of(), Set.of(), null, false, "ecobee inc")))
        .isEqualTo(DeviceType.IOT);
  }

  @Test
  void dataFilesIgnoreCommentsAndBlankLines() {
    var in =
        new ByteArrayInputStream(
            "# comment\n\n 1,2;IOS;src \nbad\n".getBytes(StandardCharsets.UTF_8));

    assertThat(DeviceTypeRules.loadFingerprints(in)).containsExactly(Map.entry("1,2", "ios"));
  }
}
