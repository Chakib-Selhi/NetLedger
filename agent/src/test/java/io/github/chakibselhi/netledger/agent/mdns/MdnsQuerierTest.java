package io.github.chakibselhi.netledger.agent.mdns;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.decode.DnsMessage;
import io.github.chakibselhi.netledger.core.decode.DnsName;
import org.junit.jupiter.api.Test;

class MdnsQuerierTest {

  @Test
  void buildsAStandardServiceTypeEnumerationQuery() {
    byte[] query = MdnsQuerier.serviceTypeQuery();
    DnsMessage message = DnsMessage.parse(query, 0, query.length);

    assertThat(message.response()).isFalse();
    assertThat(message.records()).isEmpty();
    assertThat(message.questions())
        .singleElement()
        .satisfies(
            q -> {
              assertThat(q.name()).isEqualTo(DnsName.of("_services", "_dns-sd", "_udp", "local"));
              assertThat(q.type()).isEqualTo(DnsMessage.TYPE_PTR);
              assertThat(q.unicastResponse()).isFalse();
            });
  }

  @Test
  void asksForInstancesOfIdentifyingTypesInOnePacket() {
    byte[] query = MdnsQuerier.query(MdnsQuerier.IDENTIFYING_TYPES);
    DnsMessage message = DnsMessage.parse(query, 0, query.length);

    assertThat(message.questions())
        .extracting(q -> q.name().toString())
        .containsExactly(
            "_airplay._tcp.local",
            "_raop._tcp.local",
            "_googlecast._tcp.local",
            "_ipp._tcp.local",
            "_printer._tcp.local");
    assertThat(message.questions()).allMatch(q -> q.type() == DnsMessage.TYPE_PTR);
  }
}
