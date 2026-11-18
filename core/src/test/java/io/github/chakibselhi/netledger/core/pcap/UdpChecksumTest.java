package io.github.chakibselhi.netledger.core.pcap;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.decode.PacketLayout;
import java.util.List;
import org.junit.jupiter.api.Test;

class UdpChecksumTest {

  @Test
  void fixtureChecksumsAreValidAndDetectCorruption() {
    int checked = 0;
    for (String name : List.of("dhcp", "mdns")) {
      for (PcapRecord record : Fixtures.load(name).records()) {
        byte[] frame = record.data();
        PacketLayout.Udp udp = PacketLayout.parse(frame).udp();
        int at = udp.udpOffset() + 6;
        if (udp.ipVersion() == 4 && frame[at] == 0 && frame[at + 1] == 0) {
          continue;
        }
        assertThat(UdpChecksum.isValid(frame, udp)).isTrue();
        byte[] corrupted = frame.clone();
        corrupted[udp.payloadOffset()] ^= 0x01;
        assertThat(UdpChecksum.isValid(corrupted, udp)).isFalse();
        checked++;
      }
    }
    assertThat(checked).isGreaterThan(200);
  }
}
