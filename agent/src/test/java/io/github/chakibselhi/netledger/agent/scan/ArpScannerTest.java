package io.github.chakibselhi.netledger.agent.scan;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.chakibselhi.netledger.agent.network.NetworkIdentity;
import io.github.chakibselhi.netledger.core.decode.FrameDecoder;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class ArpScannerTest {

  private static final byte[] MAC = {(byte) 0xa4, (byte) 0x83, (byte) 0xe7, 0x12, 0x34, 0x56};

  @Test
  void targetsEveryHostOfTheSubnetExceptItself() {
    List<String> targets = ArpScanner.targets("192.168.1.0/24", "192.168.1.57");

    assertThat(targets).hasSize(253).contains("192.168.1.1", "192.168.1.254");
    assertThat(targets).doesNotContain("192.168.1.0", "192.168.1.255", "192.168.1.57");
    assertThat(ArpScanner.targets("10.0.0.0/22", "10.0.0.2")).hasSize(1021);
  }

  @Test
  void refusesLargeSubnets() {
    assertThatThrownBy(() -> ArpScanner.targets("10.225.224.0/20", "10.225.228.188"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("Refusing");
    assertThatThrownBy(() -> ArpScanner.targets("10.0.0.0/8", "10.0.0.2"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void buildsAStandardArpRequestTheDecoderUnderstands() {
    byte[] frame = ArpScanner.request(MAC, "192.168.1.57", "192.168.1.20");

    assertThat(frame).hasSize(42);
    assertThat(new FrameDecoder().decode(Instant.EPOCH, frame))
        .hasValueSatisfying(
            o -> {
              assertThat(o.source()).isEqualTo(ObservationSource.ARP);
              assertThat(o.mac()).isEqualTo("a4:83:e7:12:34:56");
              assertThat(o.ip()).isEqualTo("192.168.1.57");
            });
    assertThat(frame[21]).as("operation = request").isEqualTo((byte) 1);
    assertThat(frame[41]).as("last octet of the target").isEqualTo((byte) 20);
  }

  @Test
  void sendsOnTheNetworkInterfaceWithPacing() throws Exception {
    var sent = new ArrayList<byte[]>();
    var spacing = new Duration[1];
    var interfaceName = new String[1];
    var scanner =
        new ArpScanner(
            (name, frames, delay) -> {
              interfaceName[0] = name;
              spacing[0] = delay;
              sent.addAll(frames);
            });
    var network =
        new NetworkIdentity(
            "en0", "192.168.1.57", "192.168.1.0/24", "192.168.1.1", "02:00:00:00:00:01");

    assertThat(scanner.scan(network, MAC)).isEqualTo(253);
    assertThat(sent).hasSize(253);
    assertThat(interfaceName[0]).isEqualTo("en0");
    assertThat(spacing[0]).isEqualTo(Duration.ofMillis(20));
  }
}
