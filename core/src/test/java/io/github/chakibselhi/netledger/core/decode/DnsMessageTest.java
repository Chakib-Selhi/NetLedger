package io.github.chakibselhi.netledger.core.decode;

import static io.github.chakibselhi.netledger.core.decode.TestFrames.dns;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.name;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.question;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.record;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.srv;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.txt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.github.chakibselhi.netledger.core.decode.TestFrames.Bytes;
import org.junit.jupiter.api.Test;

class DnsMessageTest {

  private static DnsMessage parse(byte[] message) {
    return DnsMessage.parse(message, 0, message.length);
  }

  @Test
  void parsesQuestionsAndTheUnicastResponseBit() {
    byte[] q = new Bytes().put(name("_airplay", "_tcp", "local")).u16(12).u16(0x8001).toByteArray();

    DnsMessage message = parse(dns(false, 1, 0, q));

    assertThat(message.response()).isFalse();
    assertThat(message.questions())
        .singleElement()
        .satisfies(
            question -> {
              assertThat(question.name()).isEqualTo(DnsName.of("_airplay", "_tcp", "local"));
              assertThat(question.type()).isEqualTo(DnsMessage.TYPE_PTR);
              assertThat(question.unicastResponse()).isTrue();
            });
  }

  @Test
  void parsesAddressServiceAndTextRecordsWithCacheFlush() {
    byte[] a = record(name("tv", "local"), 1, 0x8001, TestFrames.ip("10.0.0.5"));
    byte[] aaaa = record(name("tv", "local"), 28, 1, TestFrames.ip("fe80::1"));
    byte[] srv =
        record(name("Salon", "_airplay", "_tcp", "local"), 33, 1, srv(7000, name("tv", "local")));
    byte[] text =
        record(name("Salon", "_airplay", "_tcp", "local"), 16, 1, txt("model=AppleTV6,2", "x"));

    DnsMessage message = parse(dns(true, 0, 4, a, aaaa, srv, text));

    assertThat(message.response()).isTrue();
    assertThat(message.records()).hasSize(4);
    assertThat(message.records().get(0).address()).isEqualTo("10.0.0.5");
    assertThat(message.records().get(0).cacheFlush()).isTrue();
    assertThat(message.records().get(0).recordClass()).isEqualTo(1);
    assertThat(message.records().get(1).address()).isEqualTo("fe80:0:0:0:0:0:0:1");
    assertThat(message.records().get(2).port()).isEqualTo(7000);
    assertThat(message.records().get(2).target()).isEqualTo(DnsName.of("tv", "local"));
    assertThat(message.records().get(3).text()).containsExactly("model=AppleTV6,2", "x");
  }

  @Test
  void followsCompressionPointers() {
    // Answer name "tv.local" at offset 12; the PTR target points back to it (0xC00C).
    byte[] answer = record(name("tv", "local"), 1, 1, TestFrames.ip("10.0.0.5"));
    byte[] ptr =
        new Bytes()
            .put(name("5", "0", "0", "10", "in-addr", "arpa"))
            .u16(12)
            .u16(1)
            .u32(120)
            .u16(2)
            .u16(0xC00C)
            .toByteArray();

    DnsMessage message = parse(dns(true, 0, 2, answer, ptr));

    assertThat(message.records().get(1).target()).isEqualTo(DnsName.of("tv", "local"));
  }

  @Test
  void compressedNameMayEndWithAPointerAfterLabels() {
    byte[] first =
        record(name("_hap", "_tcp", "local"), 12, 1, name("Lamp", "_hap", "_tcp", "local"));
    // "Desk" + pointer to "_hap._tcp.local" (offset 12).
    byte[] second =
        record(new Bytes().u8(4).put("Desk".getBytes()).u16(0xC00C).toByteArray(), 16, 1, txt("a"));

    DnsMessage message = parse(dns(true, 0, 2, first, second));

    assertThat(message.records().get(1).name())
        .isEqualTo(DnsName.of("Desk", "_hap", "_tcp", "local"));
    assertThat(message.records().get(1).text()).containsExactly("a");
  }

  @Test
  void rejectsPointerToItselfOrForward() {
    byte[] selfPointer = new Bytes().u16(0xC00C).u16(1).u16(1).u32(0).u16(0).toByteArray();
    byte[] forward =
        new Bytes().u16(0xC020).u16(1).u16(1).u32(0).u16(0).put(new byte[20]).toByteArray();

    assertThatThrownBy(() -> parse(dns(true, 0, 1, selfPointer)))
        .isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> parse(dns(true, 0, 1, forward)))
        .isInstanceOf(MalformedPacketException.class);
  }

  @Test
  void rejectsTooManyPointerJumps() {
    // A chain of 20 names, each "a" followed by a pointer to the previous one.
    var chain = new Bytes().u8(1).u8('a').u8(0);
    int previous = 12;
    for (int i = 0; i < 20; i++) {
      int here = 12 + 3 + i * 4;
      chain.u8(1).u8('a').u16(0xC000 | previous);
      previous = here;
    }
    byte[] body = chain.toByteArray();
    byte[] message = new Bytes().put(dns(false, 0, 0)).put(body).toByteArray();
    var cursor = new ByteCursor(message, 0, message.length);
    cursor.seek(previous);

    assertThatThrownBy(() -> DnsMessage.readName(cursor, 0))
        .isInstanceOf(MalformedPacketException.class)
        .hasMessageContaining("pointer");
  }

  @Test
  void rejectsOverlongNamesAndReservedLabelTypes() {
    var labels = new String[5];
    java.util.Arrays.fill(labels, "x".repeat(60));
    byte[] tooLong = question(name(labels), 1);
    byte[] reserved = new Bytes().u8(0x40).u8(0).u16(1).u16(1).toByteArray();

    assertThatThrownBy(() -> parse(dns(false, 1, 0, tooLong)))
        .isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> parse(dns(false, 1, 0, reserved)))
        .isInstanceOf(MalformedPacketException.class);
  }

  @Test
  void rejectsCountsThatCannotFit() {
    byte[] header = new Bytes().u16(0).u16(0).u16(0xFFFF).u16(0xFFFF).u16(0).u16(0).toByteArray();

    assertThatThrownBy(() -> parse(header))
        .isInstanceOf(MalformedPacketException.class)
        .hasMessageContaining("counts");
  }

  @Test
  void rejectsInconsistentRdata() {
    byte[] badA = record(name("tv", "local"), 1, 1, new byte[] {10, 0, 0});
    byte[] badTxt = record(name("tv", "local"), 16, 1, new byte[] {5, 'a'});
    byte[] ptrOverrun =
        new Bytes()
            .put(name("x", "local"))
            .u16(12)
            .u16(1)
            .u32(0)
            .u16(1)
            .put(name("y", "local"))
            .toByteArray();

    assertThatThrownBy(() -> parse(dns(true, 0, 1, badA)))
        .isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> parse(dns(true, 0, 1, badTxt)))
        .isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> parse(dns(true, 0, 1, ptrOverrun)))
        .isInstanceOf(MalformedPacketException.class);
  }

  @Test
  void dnsNameHelpers() {
    DnsName name = DnsName.of("Salon", "_AirPlay", "_TCP", "Local");

    assertThat(name.endsWith("_tcp", "local")).isTrue();
    assertThat(name.endsWith("_udp", "local")).isFalse();
    assertThat(name.endsWith("a", "b", "c", "d", "e")).isFalse();
    assertThat(name.join(1, 3)).isEqualTo("_airplay._tcp");
    assertThat(name).hasToString("Salon._AirPlay._TCP.Local");
  }
}
