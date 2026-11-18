package io.github.chakibselhi.netledger.core.model;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ObservationTest {

  private static final Instant T = Instant.EPOCH;

  @Test
  void requiresCanonicalMacTimestampAndSource() {
    assertThatThrownBy(
            () -> Observation.presence(T, ObservationSource.ARP, "A4:83:E7:12:34:56", null))
        .hasMessageContaining("Invalid MAC");
    assertThatThrownBy(
            () -> Observation.presence(null, ObservationSource.ARP, "a4:83:e7:12:34:56", null))
        .isInstanceOf(NullPointerException.class);
    assertThatThrownBy(() -> Observation.presence(T, null, "a4:83:e7:12:34:56", null))
        .isInstanceOf(NullPointerException.class);
  }

  @Test
  void servicesAreDefensivelyCopiedAndNeverNull() {
    var services = new ArrayList<ServiceAnnouncement>();
    services.add(new ServiceAnnouncement("_ssh._tcp", "nas", 22));
    var observation =
        new Observation(
            T, ObservationSource.MDNS, "a4:83:e7:12:34:56", null, null, null, null, services);
    services.clear();

    assertThat(observation.services()).hasSize(1);
    assertThatThrownBy(() -> observation.services().clear())
        .isInstanceOf(UnsupportedOperationException.class);
    assertThat(
            new Observation(
                    T, ObservationSource.MDNS, "a4:83:e7:12:34:56", null, null, null, null, null)
                .services())
        .isEmpty();
    assertThat(new ObservationBatch(1, null).observations()).isEmpty();
  }

  @Test
  void serviceAnnouncementValidatesTypeAndPort() {
    assertThatThrownBy(() -> new ServiceAnnouncement("airplay", null, null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ServiceAnnouncement("_ssh._tcp", null, 70_000))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new ServiceAnnouncement(null, null, null))
        .isInstanceOf(NullPointerException.class);
    assertThat(new ServiceAnnouncement("_ssh._tcp", null, List.of(22).get(0)).port()).isEqualTo(22);
  }
}
