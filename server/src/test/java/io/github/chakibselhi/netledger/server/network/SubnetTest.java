package io.github.chakibselhi.netledger.server.network;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class SubnetTest {

  @Test
  void normalizesHostBits() {
    assertThat(Subnet.parse("192.168.1.42/24")).hasToString("192.168.1.0/24");
    assertThat(Subnet.parse(" 10.225.228.188/20 ")).hasToString("10.225.224.0/20");
    assertThat(Subnet.parse("172.16.5.4/12")).hasToString("172.16.0.0/12");
  }

  @Test
  void rejectsAnythingElse() {
    for (String bad :
        List.of(
            "",
            "10.0.0.0",
            "10.0.0.0/7",
            "10.0.0.0/31",
            "300.0.0.0/24",
            "fe80::/64",
            "example.com/24")) {
      assertThatThrownBy(() -> Subnet.parse(bad))
          .as(bad)
          .isInstanceOf(IllegalArgumentException.class);
    }
    assertThatThrownBy(() -> Subnet.parse(null)).isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void trustValues() {
    assertThat(Trust.fromValue("owned")).isEqualTo(Trust.OWNED);
    assertThat(Trust.OWNED.allowsCapture()).isTrue();
    assertThat(Trust.AUTHORIZED.allowsCapture()).isTrue();
    assertThat(Trust.UNSET.allowsCapture()).isFalse();
    assertThat(Trust.IGNORED.allowsCapture()).isFalse();
    assertThatThrownBy(() -> Trust.fromValue("trusted"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
