package io.github.chakibselhi.netledger.core.decode;

import static io.github.chakibselhi.netledger.core.decode.TestFrames.arp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ethernet;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ipv4Udp;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.decode.TestFrames.Bytes;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class FrameDecoderTest {

  private static final Instant T = Instant.parse("2026-11-17T12:00:00Z");
  private static final String DEVICE = "a4:83:e7:12:34:56";
  private final FrameDecoder decoder = new FrameDecoder();

  @Test
  void handlesVlanTaggedFrames() {
    byte[] payload = arp(1, DEVICE, "10.0.0.2", "00:00:00:00:00:00", "10.0.0.1");
    byte[] tagged =
        new Bytes()
            .put(TestFrames.mac(TestFrames.BROADCAST))
            .put(TestFrames.mac(DEVICE))
            .u16(0x8100)
            .u16(10)
            .u16(0x0806)
            .put(payload)
            .toByteArray();

    assertThat(decoder.decode(T, tagged)).isPresent();
  }

  @Test
  void ignoresOtherTrafficAndDhcpServerReplies() {
    byte[] unknownEtherType = ethernet(TestFrames.BROADCAST, DEVICE, 0x88CC, new byte[40]);
    byte[] serverReply =
        ethernet(
            TestFrames.BROADCAST,
            DEVICE,
            0x0800,
            ipv4Udp("10.0.0.1", "255.255.255.255", 67, 68, new byte[300]));
    byte[] otherUdp =
        ethernet(
            TestFrames.BROADCAST,
            DEVICE,
            0x0800,
            ipv4Udp("10.0.0.2", "10.0.0.255", 137, 137, new byte[50]));

    assertThat(decoder.decode(T, unknownEtherType)).isEmpty();
    assertThat(decoder.decode(T, serverReply)).isEmpty();
    assertThat(decoder.decode(T, otherUdp)).isEmpty();
  }

  @Test
  void ignoresNonUdpAndFragments() {
    byte[] ip = ipv4Udp("10.0.0.2", "224.0.0.251", 5353, 5353, TestFrames.dns(false, 0, 0));
    byte[] tcp = ip.clone();
    tcp[9] = 6;
    byte[] moreFragments = ip.clone();
    moreFragments[6] = 0x20;
    byte[] laterFragment = ip.clone();
    laterFragment[7] = 0x10;

    assertThat(decoder.decode(T, ethernet(TestFrames.MDNS_V4_MAC, DEVICE, 0x0800, ip))).isPresent();
    for (byte[] packet : new byte[][] {tcp, moreFragments, laterFragment}) {
      assertThat(decoder.decode(T, ethernet(TestFrames.MDNS_V4_MAC, DEVICE, 0x0800, packet)))
          .isEmpty();
    }
  }

  @Test
  void malformedHeadersYieldNothing() {
    byte[] ip = ipv4Udp("10.0.0.2", "224.0.0.251", 5353, 5353, TestFrames.dns(false, 0, 0));
    byte[] badVersion = ip.clone();
    badVersion[0] = 0x65;
    byte[] badUdpLength = ip.clone();
    badUdpLength[24] = (byte) 0xFF;
    byte[] badIpv6 = new byte[40];

    assertThat(decoder.decode(T, new byte[0])).isEmpty();
    assertThat(decoder.decode(T, new byte[13])).isEmpty();
    assertThat(decoder.decode(T, ethernet(TestFrames.MDNS_V4_MAC, DEVICE, 0x0800, badVersion)))
        .isEmpty();
    assertThat(decoder.decode(T, ethernet(TestFrames.MDNS_V4_MAC, DEVICE, 0x0800, badUdpLength)))
        .isEmpty();
    assertThat(decoder.decode(T, ethernet(TestFrames.MDNS_V4_MAC, DEVICE, 0x86DD, badIpv6)))
        .isEmpty();
  }
}
