package io.github.chakibselhi.netledger.core.decode;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import io.github.chakibselhi.netledger.core.pcap.Fixtures;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Decodes the anonymized captures from a real home network. */
class RealCaptureTest {

  private final FrameDecoder decoder = new FrameDecoder();

  private List<Observation> decode(String fixture) {
    return Fixtures.load(fixture).records().stream()
        .map(r -> decoder.decode(r.timestamp(), r.data()))
        .flatMap(Optional::stream)
        .toList();
  }

  @Test
  void arpCaptureYieldsOneObservationPerFrame() {
    List<Observation> observations = decode("arp");

    assertThat(observations).hasSize(17).allSatisfy(o -> assertThat(o.ip()).startsWith("10.0.0."));
    assertThat(observations.stream().map(Observation::mac).distinct()).hasSize(9);
  }

  @Test
  void dhcpCaptureYieldsTheClientMessagesOfAMac() {
    List<Observation> observations = decode("dhcp");

    // Release, 2 Discover, 2 Offer, Request, Ack: only Discover and Request describe the client.
    assertThat(observations).hasSize(3);
    assertThat(observations.stream().map(Observation::mac).distinct()).hasSize(1);
    assertThat(observations)
        .allSatisfy(
            o -> {
              assertThat(o.hostname()).isNotBlank();
              assertThat(o.vendorClass()).as("Apple sends no option 60").isNull();
              assertThat(o.dhcpFingerprint())
                  .isEqualTo("1,121,3,6,15,108,114,119,162,252,95,44,46");
            });
    assertThat(observations.get(2).ip()).isEqualTo("10.0.0.197");
    String mac = observations.get(0).mac();
    assertThat(Integer.parseInt(mac.substring(0, 2), 16) & 0x02)
        .as("macOS uses a private Wi-Fi address")
        .isEqualTo(0x02);
  }

  @Test
  void mdnsCaptureRevealsServicesAndHostNames() {
    List<Observation> observations = decode("mdns");

    assertThat(observations).hasSize(244);
    assertThat(observations.stream().map(Observation::mac).distinct()).hasSize(21);
    assertThat(observations.stream().filter(o -> o.ip() != null)).hasSize(144);
    assertThat(
            observations.stream()
                .filter(o -> o.hostname() != null)
                .map(Observation::mac)
                .distinct())
        .hasSize(8);
    assertThat(
            observations.stream()
                .flatMap(o -> o.services().stream())
                .map(ServiceAnnouncement::type))
        .contains(
            "_airplay._tcp", "_ipp._tcp", "_printer._tcp", "_hap._tcp", "_ssh._tcp", "_smb._tcp");
    assertThat(observations.stream().flatMap(o -> o.services().stream()))
        .anySatisfy(s -> assertThat(s.port()).isNotNull());
  }
}
