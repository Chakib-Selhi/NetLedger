package io.github.chakibselhi.netledger.core.pcap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PcapReaderTest {

  private static byte[] pcap(ByteOrder order, int magic, int fraction, byte[]... frames) {
    int size = 24 + java.util.Arrays.stream(frames).mapToInt(f -> 16 + f.length).sum();
    var buffer = ByteBuffer.allocate(size).order(order);
    buffer.putInt(magic).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0);
    buffer.putInt(65_535).putInt(1);
    for (byte[] frame : frames) {
      buffer.putInt(1_763_380_800).putInt(fraction).putInt(frame.length).putInt(frame.length + 10);
      buffer.put(frame);
    }
    return buffer.array();
  }

  @Test
  void readsBothByteOrdersAndPrecisions() throws IOException {
    byte[] frame = {1, 2, 3};
    Instant second = Instant.ofEpochSecond(1_763_380_800);

    PcapFile littleMicros = PcapReader.read(pcap(ByteOrder.LITTLE_ENDIAN, 0xA1B2C3D4, 250, frame));
    PcapFile bigNanos = PcapReader.read(pcap(ByteOrder.BIG_ENDIAN, 0xA1B23C4D, 250, frame));

    assertThat(littleMicros.linkType()).isEqualTo(PcapFile.LINKTYPE_ETHERNET);
    assertThat(littleMicros.snapLength()).isEqualTo(65_535);
    assertThat(littleMicros.records())
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.data()).containsExactly(1, 2, 3);
              assertThat(r.originalLength()).isEqualTo(13);
              assertThat(r.timestamp()).isEqualTo(second.plusNanos(250_000));
            });
    assertThat(bigNanos.records().get(0).timestamp()).isEqualTo(second.plusNanos(250));
  }

  @Test
  void rejectsOtherFormatsAndCorruptFiles() {
    byte[] valid = pcap(ByteOrder.LITTLE_ENDIAN, 0xA1B2C3D4, 0, new byte[] {1, 2, 3});
    byte[] pcapng = valid.clone();
    ByteBuffer.wrap(pcapng).putInt(0, 0x0A0D0D0A);
    byte[] unknown = valid.clone();
    ByteBuffer.wrap(unknown).putInt(0, 0x12345678);
    byte[] hugeRecord = valid.clone();
    ByteBuffer.wrap(hugeRecord).order(ByteOrder.LITTLE_ENDIAN).putInt(24 + 8, 1_000_000);

    assertThatThrownBy(() -> PcapReader.read(new byte[10])).hasMessageContaining("too short");
    assertThatThrownBy(() -> PcapReader.read(pcapng)).hasMessageContaining("pcapng");
    assertThatThrownBy(() -> PcapReader.read(unknown)).hasMessageContaining("magic");
    assertThatThrownBy(() -> PcapReader.read(hugeRecord))
        .hasMessageContaining("Invalid record length");
    assertThatThrownBy(() -> PcapReader.read(java.util.Arrays.copyOf(valid, valid.length - 1)))
        .hasMessageContaining("Truncated record data");
    assertThatThrownBy(() -> PcapReader.read(java.util.Arrays.copyOf(valid, 30)))
        .hasMessageContaining("Truncated record header");
  }

  @Test
  void writerRoundTrips(@TempDir Path dir) throws IOException {
    var original =
        new PcapFile(
            1,
            262_144,
            List.of(
                new PcapRecord(Instant.parse("2026-11-17T12:00:00.123456Z"), new byte[] {9, 8}, 2),
                new PcapRecord(Instant.parse("2026-11-17T12:00:01Z"), new byte[] {7}, 60)));
    Path file = dir.resolve("out.pcap");

    PcapWriter.write(file, original);
    PcapFile read = PcapReader.read(file);

    assertThat(read.linkType()).isEqualTo(1);
    assertThat(read.snapLength()).isEqualTo(262_144);
    assertThat(read.records()).hasSize(2);
    assertThat(read.records().get(0).timestamp()).isEqualTo(original.records().get(0).timestamp());
    assertThat(read.records().get(0).data()).containsExactly(9, 8);
    assertThat(read.records().get(1).originalLength()).isEqualTo(60);
  }
}
