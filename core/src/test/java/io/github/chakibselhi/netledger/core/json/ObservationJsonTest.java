package io.github.chakibselhi.netledger.core.json;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationBatch;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class ObservationJsonTest {

  private static final Instant T = Instant.parse("2026-11-17T12:00:00.250Z");

  private final ObservationBatch batch =
      new ObservationBatch(
          List.of(
              Observation.presence(T, ObservationSource.ARP_SCAN, "a4:83:e7:12:34:56", "10.0.0.2"),
              new Observation(
                  T,
                  ObservationSource.MDNS,
                  "3c:22:fb:01:02:03",
                  null,
                  "Apple-TV",
                  null,
                  null,
                  List.of(
                      new ServiceAnnouncement("_airplay._tcp", "Salon", 7000),
                      new ServiceAnnouncement("_hap._tcp", null, null)))));

  @Test
  void roundTripsWithoutLoss() {
    assertThat(ObservationJson.read(ObservationJson.write(batch))).isEqualTo(batch);
  }

  @Test
  void usesIsoTimestampsDatabaseSourceNamesAndOmitsNulls() {
    String json = ObservationJson.write(batch);

    assertThat(json)
        .contains("\"observedAt\":\"2026-11-17T12:00:00.250Z\"")
        .contains("\"source\":\"arp_scan\"")
        .contains("\"source\":\"mdns\"")
        .doesNotContain("null")
        .doesNotContain("vendorClass");
  }

  @Test
  void ignoresUnknownFieldsFromNewerAgents() {
    String json =
        "{\"observations\":[{\"observedAt\":\"2026-11-17T12:00:00Z\",\"source\":\"arp\","
            + "\"mac\":\"a4:83:e7:12:34:56\",\"futureField\":42}],\"agentVersion\":\"2.0\"}";

    assertThat(ObservationJson.read(json).observations())
        .singleElement()
        .satisfies(o -> assertThat(o.services()).isEmpty());
  }

  @Test
  void rejectsInvalidInput() {
    assertThatThrownBy(() -> ObservationJson.read("{not json"))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(
            () ->
                ObservationJson.read(
                    "{\"observations\":[{\"observedAt\":\"2026-11-17T12:00:00Z\","
                        + "\"source\":\"arp\",\"mac\":\"<script>\"}]}"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Invalid MAC");
    assertThatThrownBy(
            () ->
                ObservationJson.read(
                    "{\"observations\":[{\"observedAt\":\"2026-11-17T12:00:00Z\","
                        + "\"source\":\"telnet\",\"mac\":\"a4:83:e7:12:34:56\"}]}"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void mapperIsADefensiveCopy() {
    assertThat(ObservationJson.mapper()).isNotSameAs(ObservationJson.mapper());
  }
}
