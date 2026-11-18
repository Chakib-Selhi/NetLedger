package io.github.chakibselhi.netledger.core.decode;

import static io.github.chakibselhi.netledger.core.decode.TestFrames.arp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.arpFrame;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ethernet;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.ObservationSource;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class ArpDecoderTest {

  private static final Instant T = Instant.parse("2026-11-17T12:00:00Z");
  private static final String DEVICE = "a4:83:e7:12:34:56";
  private final FrameDecoder decoder = new FrameDecoder();

  @Test
  void requestRevealsSenderMacAndIp() {
    var observation = decoder.decode(T, arpFrame(1, DEVICE, "192.168.1.20", "192.168.1.1"));

    assertThat(observation)
        .hasValueSatisfying(
            o -> {
              assertThat(o.source()).isEqualTo(ObservationSource.ARP);
              assertThat(o.mac()).isEqualTo(DEVICE);
              assertThat(o.ip()).isEqualTo("192.168.1.20");
              assertThat(o.observedAt()).isEqualTo(T);
            });
  }

  @Test
  void replyAndGratuitousAnnouncementAreObservations() {
    assertThat(decoder.decode(T, arpFrame(2, DEVICE, "192.168.1.20", "192.168.1.30")))
        .hasValueSatisfying(o -> assertThat(o.ip()).isEqualTo("192.168.1.20"));
    assertThat(decoder.decode(T, arpFrame(1, DEVICE, "192.168.1.20", "192.168.1.20")))
        .hasValueSatisfying(o -> assertThat(o.ip()).isEqualTo("192.168.1.20"));
  }

  @Test
  void probeProvesPresenceWithoutAddress() {
    assertThat(decoder.decode(T, arpFrame(1, DEVICE, "0.0.0.0", "192.168.1.20")))
        .hasValueSatisfying(o -> assertThat(o.ip()).isNull());
  }

  @Test
  void ignoresEthernetPadding() {
    byte[] frame = Arrays.copyOf(arpFrame(1, DEVICE, "192.168.1.20", "192.168.1.1"), 60);

    assertThat(decoder.decode(T, frame)).isPresent();
  }

  @Test
  void rejectsGroupOrZeroSenderAddresses() {
    assertThat(decoder.decode(T, arpFrame(1, "01:00:5e:00:00:01", "192.168.1.20", "192.168.1.1")))
        .isEmpty();
    assertThat(decoder.decode(T, arpFrame(1, "00:00:00:00:00:00", "192.168.1.20", "192.168.1.1")))
        .isEmpty();
  }

  @Test
  void ignoresUnknownOperationsAndNonEthernetArp() {
    assertThat(decoder.decode(T, arpFrame(3, DEVICE, "192.168.1.20", "192.168.1.1"))).isEmpty();

    byte[] payload = arp(1, DEVICE, "192.168.1.20", "00:00:00:00:00:00", "192.168.1.1");
    payload[1] = 6; // hardware type IEEE 802 instead of Ethernet
    assertThat(decoder.decode(T, ethernet(TestFrames.BROADCAST, DEVICE, 0x0806, payload)))
        .isEmpty();
  }

  @Test
  void truncatedArpYieldsNothing() {
    byte[] frame = arpFrame(1, DEVICE, "192.168.1.20", "192.168.1.1");

    assertThat(decoder.decode(T, Arrays.copyOf(frame, frame.length - 1))).isEmpty();
  }
}
