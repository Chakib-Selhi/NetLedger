package io.github.chakibselhi.netledger.server.correlation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.chakibselhi.netledger.server.correlation.DeviceRepository.DeviceRow;
import org.junit.jupiter.api.Test;

class DeviceCommandsTest {

  private static DeviceRow row(
      long id, String mac, String first, String last, String ip, String host, String status) {
    return new DeviceRow(id, 1, mac, first, last, ip, host, null, null, true, status);
  }

  @Test
  void mergedDeviceKeepsTheTargetDecisionAndTheMostRecentIdentity() {
    DeviceRow known =
        row(
            1,
            "3a:00:00:00:00:01",
            "2026-11-01T00:00:00.000Z",
            "2026-11-10T00:00:00.000Z",
            "10.0.0.5",
            "iPhone",
            "approved");
    DeviceRow fresh =
        row(
            2,
            "3a:00:00:00:00:02",
            "2026-11-17T00:00:00.000Z",
            "2026-11-18T00:00:00.000Z",
            null,
            null,
            "new");

    DeviceRow merged = DeviceCommands.merged(fresh, known);

    assertThat(merged.id()).isEqualTo(1);
    assertThat(merged.mac()).isEqualTo("3a:00:00:00:00:02");
    assertThat(merged.firstSeen()).isEqualTo("2026-11-01T00:00:00.000Z");
    assertThat(merged.lastSeen()).isEqualTo("2026-11-18T00:00:00.000Z");
    assertThat(merged.lastIp()).isEqualTo("10.0.0.5");
    assertThat(merged.hostname()).isEqualTo("iPhone");
    assertThat(merged.status()).isEqualTo("approved");
  }

  @Test
  void mergingAnOlderRecordKeepsTheTargetAddress() {
    DeviceRow target =
        row(
            1,
            "3a:00:00:00:00:01",
            "2026-11-10T00:00:00.000Z",
            "2026-11-18T00:00:00.000Z",
            "10.0.0.9",
            "new-name",
            "new");
    DeviceRow stale =
        row(
            2,
            "3a:00:00:00:00:02",
            "2026-11-01T00:00:00.000Z",
            "2026-11-05T00:00:00.000Z",
            "10.0.0.5",
            "old-name",
            "approved");

    DeviceRow merged = DeviceCommands.merged(stale, target);

    assertThat(merged.mac()).isEqualTo("3a:00:00:00:00:01");
    assertThat(merged.hostname()).isEqualTo("new-name");
    assertThat(merged.firstSeen()).isEqualTo("2026-11-01T00:00:00.000Z");
    assertThat(merged.status()).isEqualTo("new");
  }

  @Test
  void userTextIsStrippedAndBounded() {
    assertThat(DeviceCommands.text(null, 5, "f")).isNull();
    assertThat(DeviceCommands.text("  ok  ", 5, "f")).isEqualTo("ok");
    assertThatThrownBy(() -> DeviceCommands.text("toolong", 5, "f"))
        .hasMessageContaining("limited to 5");
    assertThatThrownBy(() -> DeviceCommands.text("a\u0007b", 5, "f"))
        .hasMessageContaining("control characters");
  }
}
