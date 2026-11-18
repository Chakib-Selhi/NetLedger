package io.github.chakibselhi.netledger.core.decode;

import static org.assertj.core.api.Assertions.assertThatCode;

import io.github.chakibselhi.netledger.core.pcap.Fixtures;
import io.github.chakibselhi.netledger.core.pcap.PcapRecord;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * Frames come from the network, so an attacker controls every byte. Whatever arrives, decoding must
 * return normally: no exception, no hang.
 */
class RobustnessTest {

  private static final Instant T = Instant.EPOCH;
  private final FrameDecoder decoder = new FrameDecoder();

  private static List<byte[]> realFrames() {
    return Stream.of("arp", "dhcp", "mdns")
        .flatMap(name -> Fixtures.load(name).records().stream())
        .map(PcapRecord::data)
        .toList();
  }

  @Test
  void everyTruncationOfEveryRealFrameIsHandled() {
    for (byte[] frame : realFrames()) {
      for (int length = 0; length <= frame.length; length++) {
        byte[] truncated = Arrays.copyOf(frame, length);
        assertThatCode(() -> decoder.decode(T, truncated)).doesNotThrowAnyException();
      }
    }
  }

  @Test
  void randomCorruptionOfRealFramesIsHandled() {
    var random = new Random(20261117);
    List<byte[]> frames = realFrames();
    for (int i = 0; i < 20_000; i++) {
      byte[] frame = frames.get(random.nextInt(frames.size())).clone();
      int flips = 1 + random.nextInt(4);
      for (int f = 0; f < flips; f++) {
        // Keep Ethernet/IP/UDP headers intact half of the time so corruption reaches the decoders.
        int from = random.nextBoolean() ? Math.min(42, frame.length - 1) : 0;
        frame[from + random.nextInt(frame.length - from)] = (byte) random.nextInt(256);
      }
      assertThatCode(() -> decoder.decode(T, frame)).doesNotThrowAnyException();
    }
  }

  @Test
  void randomBytesAsDnsMessagesNeverEscapeAsUnexpectedExceptions() {
    var random = new Random(42);
    for (int i = 0; i < 20_000; i++) {
      byte[] message = new byte[random.nextInt(120)];
      random.nextBytes(message);
      try {
        DnsMessage.parse(message, 0, message.length);
      } catch (MalformedPacketException expected) {
        // The only acceptable failure.
      }
    }
  }
}
