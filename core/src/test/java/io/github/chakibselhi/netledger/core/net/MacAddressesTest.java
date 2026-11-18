package io.github.chakibselhi.netledger.core.net;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class MacAddressesTest {

  private static byte[] mac(String value) {
    return HexFormat.ofDelimiter(":").parseHex(value);
  }

  @Test
  void formatsLowerCaseColonSeparated() {
    byte[] data = {0, (byte) 0xA4, (byte) 0x83, (byte) 0xE7, 0x12, 0x34, 0x56};

    assertThat(MacAddresses.format(data, 1)).isEqualTo("a4:83:e7:12:34:56");
  }

  @Test
  void recognisesCanonicalForm() {
    assertThat(MacAddresses.isCanonical("a4:83:e7:12:34:56")).isTrue();
    assertThat(MacAddresses.isCanonical("A4:83:E7:12:34:56")).isFalse();
    assertThat(MacAddresses.isCanonical("a4-83-e7-12-34-56")).isFalse();
    assertThat(MacAddresses.isCanonical(null)).isFalse();
  }

  @Test
  void classifiesAddressBits() {
    assertThat(MacAddresses.isUnicast(mac("a4:83:e7:12:34:56"), 0)).isTrue();
    assertThat(MacAddresses.isUnicast(mac("ff:ff:ff:ff:ff:ff"), 0)).isFalse();
    assertThat(MacAddresses.isUnicast(mac("01:00:5e:00:00:fb"), 0)).isFalse();
    assertThat(MacAddresses.isUnicast(mac("00:00:00:00:00:00"), 0)).isFalse();
    assertThat(MacAddresses.isLocallyAdministered(mac("3a:1f:22:aa:bb:cc"), 0)).isTrue();
    assertThat(MacAddresses.isLocallyAdministered(mac("a4:83:e7:12:34:56"), 0)).isFalse();
  }
}
