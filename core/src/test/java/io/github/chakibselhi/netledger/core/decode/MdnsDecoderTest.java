package io.github.chakibselhi.netledger.core.decode;

import static io.github.chakibselhi.netledger.core.decode.TestFrames.dns;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ethernet;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ipv6Udp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.name;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.question;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.record;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.srv;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.udpFrame;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class MdnsDecoderTest {

  private static final Instant T = Instant.parse("2026-11-17T12:00:00Z");
  private static final String TV = "3c:22:fb:01:02:03";
  private final FrameDecoder decoder = new FrameDecoder();

  private Optional<Observation> decode(byte[] dns) {
    return decoder.decode(T, udpFrame(TV, "10.0.0.5", 5353, dns));
  }

  @Test
  void queryOnlyProvesPresence() {
    byte[] query = dns(false, 1, 0, question(name("_airplay", "_tcp", "local"), 12));

    assertThat(decode(query))
        .hasValueSatisfying(
            o -> {
              assertThat(o.source()).isEqualTo(ObservationSource.MDNS);
              assertThat(o.mac()).isEqualTo(TV);
              assertThat(o.ip()).isEqualTo("10.0.0.5");
              assertThat(o.hostname()).isNull();
              assertThat(o.services()).isEmpty();
            });
  }

  @Test
  void responseGivesHostNameAndServiceWithPort() {
    byte[] instance = name("Salon", "_airplay", "_tcp", "local");
    byte[] response =
        dns(
            true,
            0,
            3,
            record(name("_airplay", "_tcp", "local"), 12, 1, instance),
            record(instance, 33, 0x8001, srv(7000, name("Apple-TV", "local"))),
            record(name("Apple-TV", "local"), 1, 0x8001, TestFrames.ip("10.0.0.5")));

    assertThat(decode(response))
        .hasValueSatisfying(
            o -> {
              assertThat(o.hostname()).isEqualTo("Apple-TV");
              assertThat(o.services())
                  .containsExactly(new ServiceAnnouncement("_airplay._tcp", "Salon", 7000));
            });
  }

  @Test
  void ptrWithoutSrvGivesServiceWithoutPort() {
    byte[] response =
        dns(
            true,
            0,
            1,
            record(name("_ipp", "_tcp", "local"), 12, 1, name("Office", "_ipp", "_tcp", "local")));

    assertThat(decode(response))
        .hasValueSatisfying(
            o ->
                assertThat(o.services())
                    .containsExactly(new ServiceAnnouncement("_ipp._tcp", "Office", null)));
  }

  @Test
  void serviceTypeEnumerationAnswerGivesTypeOnly() {
    byte[] enumeration = name("_services", "_dns-sd", "_udp", "local");
    byte[] response =
        dns(
            true,
            0,
            2,
            record(enumeration, 12, 1, name("_googlecast", "_tcp", "local")),
            record(enumeration, 12, 1, name("_hap", "_udp", "local")));

    assertThat(decode(response))
        .hasValueSatisfying(
            o ->
                assertThat(o.services())
                    .containsExactly(
                        new ServiceAnnouncement("_googlecast._tcp", null, null),
                        new ServiceAnnouncement("_hap._udp", null, null)));
  }

  @Test
  void typeOnlyEntryDisappearsWhenTheInstanceIsKnown() {
    byte[] response =
        dns(
            true,
            0,
            2,
            record(
                name("_services", "_dns-sd", "_udp", "local"),
                12,
                1,
                name("_hap", "_tcp", "local")),
            record(name("_hap", "_tcp", "local"), 12, 1, name("Lamp", "_hap", "_tcp", "local")));

    assertThat(decode(response))
        .hasValueSatisfying(
            o ->
                assertThat(o.services())
                    .containsExactly(new ServiceAnnouncement("_hap._tcp", "Lamp", null)));
  }

  @Test
  void hostNameFallsBackToSrvTargetThenReverseMapping() {
    byte[] srvOnly =
        dns(
            true,
            0,
            1,
            record(
                name("Salon", "_raop", "_tcp", "local"),
                33,
                1,
                srv(7000, name("speaker", "local"))));
    byte[] reverseOnly =
        dns(
            true,
            0,
            1,
            record(name("5", "0", "0", "10", "in-addr", "arpa"), 12, 1, name("printer", "local")));

    assertThat(decode(srvOnly))
        .hasValueSatisfying(o -> assertThat(o.hostname()).isEqualTo("speaker"));
    assertThat(decode(reverseOnly))
        .hasValueSatisfying(o -> assertThat(o.hostname()).isEqualTo("printer"));
  }

  @Test
  void ignoresNamesThatAreNotInstancesOrHosts() {
    byte[] response =
        dns(
            true,
            0,
            3,
            record(
                name("_http", "_tcp", "local"),
                12,
                1,
                name("_printer", "_sub", "_http", "_tcp", "local")),
            record(name("_x", "local"), 1, 1, TestFrames.ip("10.0.0.5")),
            record(name("_http", "_tcp", "local"), 12, 1, name("A", "_http", "_sctp", "local")));

    assertThat(decode(response))
        .hasValueSatisfying(
            o -> {
              assertThat(o.hostname()).isNull();
              assertThat(o.services()).isEmpty();
            });
  }

  @Test
  void ipv6PacketGivesNamesButNoIpv4() {
    byte[] response =
        dns(true, 0, 1, record(name("laptop", "local"), 28, 1, TestFrames.ip("fe80::1")));
    byte[] frame =
        ethernet(
            "33:33:00:00:00:fb", TV, 0x86DD, ipv6Udp("fe80::1", "ff02::fb", 5353, 5353, response));

    assertThat(decoder.decode(T, frame))
        .hasValueSatisfying(
            o -> {
              assertThat(o.ip()).isNull();
              assertThat(o.hostname()).isEqualTo("laptop");
            });
  }

  @Test
  void ignoresPacketsFromGroupSourceAddresses() {
    byte[] query = dns(false, 0, 0);

    assertThat(decoder.decode(T, udpFrame("01:00:5e:00:00:fb", "10.0.0.5", 5353, query))).isEmpty();
  }
}
