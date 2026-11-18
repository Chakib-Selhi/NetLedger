package io.github.chakibselhi.netledger.server.correlation;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;

class ObservationValidatorTest {

  private static final Instant NOW = Instant.parse("2026-11-18T12:00:00Z");
  private static final String MAC = "a4:83:e7:12:34:56";
  private final ObservationValidator validator = new ObservationValidator(Duration.ofMinutes(5));

  private static Observation observation(
      String ip, String host, String fingerprint, List<ServiceAnnouncement> services) {
    return new Observation(
        NOW, ObservationSource.MDNS, MAC, ip, host, fingerprint, " class\u0007 ", services);
  }

  @Test
  void toleratesSmallClockSkewOnly() {
    assertThat(
            validator.validate(
                Observation.presence(NOW.plusSeconds(299), ObservationSource.ARP, MAC, null), NOW))
        .isPresent();
    assertThat(
            validator.validate(
                Observation.presence(NOW.plusSeconds(301), ObservationSource.ARP, MAC, null), NOW))
        .isEmpty();
  }

  @Test
  void rejectsInvalidIpv4() {
    for (String ip : List.of("256.0.0.1", "10.0.0", "fe80::1", "10.0.0.1 ", "010.0.0.1x")) {
      assertThat(validator.validate(observation(ip, null, null, List.of()), NOW)).as(ip).isEmpty();
    }
    assertThat(validator.validate(observation("10.0.0.255", null, null, List.of()), NOW))
        .isPresent();
  }

  @Test
  void cleansTextAndDropsMalformedFields() {
    Observation clean =
        validator
            .validate(
                observation(
                    null,
                    "x".repeat(300) + "\n",
                    "1,3,abc",
                    List.of(
                        new ServiceAnnouncement("_ssh._tcp", "\tnas\u0000", 22),
                        new ServiceAnnouncement("_BAD TYPE", null, null))),
                NOW)
            .orElseThrow();

    assertThat(clean.hostname()).hasSize(255);
    assertThat(clean.dhcpFingerprint()).isNull();
    assertThat(clean.vendorClass()).isEqualTo("class");
    assertThat(clean.services()).containsExactly(new ServiceAnnouncement("_ssh._tcp", "nas", 22));
  }

  @Test
  void capsTheNumberOfServices() {
    var many = Collections.nCopies(100, new ServiceAnnouncement("_ssh._tcp", null, null));

    assertThat(
            validator.validate(observation(null, null, null, many), NOW).orElseThrow().services())
        .hasSize(ObservationValidator.MAX_SERVICES);
  }

  @Test
  void blankTextBecomesNull() {
    assertThat(ObservationValidator.clean(" \u0001 ")).isNull();
    assertThat(ObservationValidator.clean(null)).isNull();
  }
}
