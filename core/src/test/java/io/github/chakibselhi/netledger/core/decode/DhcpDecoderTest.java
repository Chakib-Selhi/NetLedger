package io.github.chakibselhi.netledger.core.decode;

import static io.github.chakibselhi.netledger.core.decode.TestFrames.dhcp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.dhcpFrame;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.option;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.model.ObservationSource;
import java.time.Instant;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class DhcpDecoderTest {

  private static final Instant T = Instant.parse("2026-11-17T12:00:00Z");
  private static final String PHONE = "3a:1f:22:aa:bb:cc";
  private static final byte[] DISCOVER = {1};
  private static final byte[] REQUEST = {3};
  private final FrameDecoder decoder = new FrameDecoder();

  @Test
  void discoverCarriesHostNameFingerprintAndVendorClass() {
    byte[] message =
        dhcp(
            1,
            PHONE,
            "0.0.0.0",
            option(53, DISCOVER),
            option(
                61,
                (byte) 1,
                (byte) 0x3a,
                (byte) 0x1f,
                (byte) 0x22,
                (byte) 0xaa,
                (byte) 0xbb,
                (byte) 0xcc),
            option(12, "Pixel-8"),
            option(60, "android-dhcp-14"),
            option(
                55, (byte) 1, (byte) 3, (byte) 6, (byte) 15, (byte) 26, (byte) 28, (byte) 51,
                (byte) 58, (byte) 59, (byte) 43));

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message)))
        .hasValueSatisfying(
            o -> {
              assertThat(o.source()).isEqualTo(ObservationSource.DHCP);
              assertThat(o.mac()).isEqualTo(PHONE);
              assertThat(o.ip()).isNull();
              assertThat(o.hostname()).isEqualTo("Pixel-8");
              assertThat(o.vendorClass()).isEqualTo("android-dhcp-14");
              assertThat(o.dhcpFingerprint()).isEqualTo("1,3,6,15,26,28,51,58,59,43");
            });
  }

  @Test
  void requestedAddressBecomesTheIp() {
    byte[] message =
        dhcp(1, PHONE, "0.0.0.0", option(53, REQUEST), option(50, TestFrames.ip("10.0.0.42")));

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message)))
        .hasValueSatisfying(o -> assertThat(o.ip()).isEqualTo("10.0.0.42"));
  }

  @Test
  void renewalUsesClientAddressField() {
    byte[] message = dhcp(1, PHONE, "10.0.0.42", option(53, REQUEST));

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message)))
        .hasValueSatisfying(o -> assertThat(o.ip()).isEqualTo("10.0.0.42"));
  }

  @Test
  void chaddrIsTheDeviceEvenBehindARelay() {
    byte[] message = dhcp(1, PHONE, "0.0.0.0", option(53, DISCOVER));

    assertThat(decoder.decode(T, dhcpFrame("00:11:22:33:44:55", message)))
        .hasValueSatisfying(o -> assertThat(o.mac()).isEqualTo(PHONE));
  }

  @Test
  void onlyDiscoverAndRequestAreObservations() {
    for (int type : new int[] {2, 4, 5, 6, 7, 8}) {
      byte[] message = dhcp(1, PHONE, "0.0.0.0", option(53, (byte) type));
      assertThat(decoder.decode(T, dhcpFrame(PHONE, message))).as("type %d", type).isEmpty();
    }
    assertThat(decoder.decode(T, dhcpFrame(PHONE, dhcp(1, PHONE, "0.0.0.0")))).isEmpty();
  }

  @Test
  void serverRepliesAreIgnored() {
    byte[] offer = dhcp(2, PHONE, "0.0.0.0", option(53, (byte) 2));

    assertThat(decoder.decode(T, dhcpFrame(PHONE, offer))).isEmpty();
  }

  @Test
  void plainBootpWithoutMagicCookieIsIgnored() {
    byte[] message = dhcp(1, PHONE, "0.0.0.0", option(53, DISCOVER));
    message[236] = 0;

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message))).isEmpty();
  }

  @Test
  void padOptionsAreSkippedAndMissingEndIsTolerated() {
    byte[] message = dhcp(1, PHONE, "0.0.0.0", new byte[] {0, 0}, option(53, DISCOVER));
    byte[] withoutEnd = Arrays.copyOf(message, message.length - 1);

    assertThat(decoder.decode(T, dhcpFrame(PHONE, withoutEnd))).isPresent();
  }

  @Test
  void optionOverrunningTheMessageYieldsNothing() {
    byte[] message = dhcp(1, PHONE, "0.0.0.0", option(53, DISCOVER), option(12, "abc"));
    message[message.length - 5] = 50; // host name claims 50 bytes, only 3 follow

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message))).isEmpty();
  }

  @Test
  void hostNameIsSanitized() {
    byte[] message =
        dhcp(
            1, PHONE, "0.0.0.0", option(53, DISCOVER), option(12, "  evil\u001b[31m\nname\u0000 "));

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message)))
        .hasValueSatisfying(o -> assertThat(o.hostname()).isEqualTo("evil[31mname"));
  }

  @Test
  void emptyValuesBecomeNull() {
    byte[] message = dhcp(1, PHONE, "0.0.0.0", option(53, DISCOVER), option(12, " "), option(55));

    assertThat(decoder.decode(T, dhcpFrame(PHONE, message)))
        .hasValueSatisfying(
            o -> {
              assertThat(o.hostname()).isNull();
              assertThat(o.dhcpFingerprint()).isNull();
            });
  }
}
