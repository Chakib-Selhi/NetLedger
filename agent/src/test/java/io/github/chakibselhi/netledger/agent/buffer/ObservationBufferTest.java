package io.github.chakibselhi.netledger.agent.buffer;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class ObservationBufferTest {

  private static final Instant T = Instant.parse("2026-11-18T12:00:00Z");

  private static Observation arp(int second, String ip) {
    return Observation.presence(
        T.plusSeconds(second), ObservationSource.ARP, "a4:83:e7:00:00:01", ip);
  }

  @Test
  void dropsRepeatsWithinTheWindowOnly() {
    var buffer = new ObservationBuffer(100, Duration.ofSeconds(60));

    assertThat(buffer.add(1, arp(0, "10.0.0.2"))).isTrue();
    assertThat(buffer.add(1, arp(30, "10.0.0.2"))).isFalse();
    assertThat(buffer.add(1, arp(30, "10.0.0.3"))).as("different content").isTrue();
    assertThat(buffer.add(2, arp(30, "10.0.0.2"))).as("different network").isTrue();
    assertThat(buffer.add(1, arp(61, "10.0.0.2"))).as("window elapsed").isTrue();
    assertThat(buffer.size()).isEqualTo(4);
    assertThat(buffer.deduplicated()).isEqualTo(1);
  }

  @Test
  void dropsOldestWhenFull() {
    var buffer = new ObservationBuffer(3, Duration.ZERO);
    for (int i = 0; i < 5; i++) {
      buffer.add(1, arp(i, "10.0.0." + i));
    }

    assertThat(buffer.size()).isEqualTo(3);
    assertThat(buffer.dropped()).isEqualTo(2);
    assertThat(buffer.take(10).orElseThrow().observations().get(0).ip()).isEqualTo("10.0.0.2");
  }

  @Test
  void batchesNeverMixNetworksAndPutBackKeepsOrder() {
    var buffer = new ObservationBuffer(100, Duration.ZERO);
    buffer.add(1, arp(0, "10.0.0.1"));
    buffer.add(1, arp(1, "10.0.0.2"));
    buffer.add(2, arp(2, "10.0.0.3"));
    buffer.add(1, arp(3, "10.0.0.4"));

    ObservationBuffer.Batch first = buffer.take(10).orElseThrow();
    assertThat(first.networkId()).isEqualTo(1);
    assertThat(first.observations()).hasSize(2);

    buffer.putBack(first);
    assertThat(buffer.take(1).orElseThrow().observations().get(0).ip()).isEqualTo("10.0.0.1");
    assertThat(buffer.take(10).orElseThrow().observations()).hasSize(1);
    assertThat(buffer.take(10).orElseThrow().networkId()).isEqualTo(2);
  }

  @Test
  void discardsANetwork() {
    var buffer = new ObservationBuffer(100, Duration.ZERO);
    buffer.add(1, arp(0, "10.0.0.1"));
    buffer.add(2, arp(1, "10.0.0.2"));

    buffer.discardNetwork(1);

    assertThat(buffer.size()).isEqualTo(1);
    assertThat(buffer.take(10).orElseThrow().networkId()).isEqualTo(2);
    assertThat(buffer.take(10)).isEmpty();
  }

  @Test
  void dedupMemoryIsPruned() {
    var buffer = new ObservationBuffer(2, Duration.ofSeconds(1));
    for (int i = 0; i < 50; i++) {
      buffer.add(1, arp(i * 10, "10.0.1." + i));
    }

    assertThat(buffer.add(1, arp(0, "10.0.1.0"))).as("old key forgotten after pruning").isTrue();
  }
}
