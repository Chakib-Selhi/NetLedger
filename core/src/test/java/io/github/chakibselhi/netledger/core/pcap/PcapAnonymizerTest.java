package io.github.chakibselhi.netledger.core.pcap;

import static io.github.chakibselhi.netledger.core.decode.TestFrames.dhcp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.dhcpFrame;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.dns;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ethernet;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ipv4Udp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.ipv6Udp;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.name;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.option;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.record;
import static io.github.chakibselhi.netledger.core.decode.TestFrames.txt;
import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.core.decode.FrameDecoder;
import io.github.chakibselhi.netledger.core.decode.PacketLayout;
import io.github.chakibselhi.netledger.core.decode.TestFrames;
import io.github.chakibselhi.netledger.core.model.Observation;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class PcapAnonymizerTest {

  private static final Instant T = Instant.parse("2026-11-17T12:00:00Z");
  private static final String VENDOR_MAC = "a4:83:e7:12:34:56";
  private static final String PRIVATE_MAC = "3a:1f:22:aa:bb:cc";
  private static final String HOST = "Chakibs-iPhone";

  private final byte[] arp = TestFrames.arpFrame(1, VENDOR_MAC, "10.0.0.2", "10.0.0.1");
  private final byte[] dhcp =
      dhcpFrame(
          PRIVATE_MAC, dhcp(1, PRIVATE_MAC, "0.0.0.0", option(53, (byte) 1), option(12, HOST)));
  private final byte[] mdns = withChecksum(mdnsFrame());
  private final byte[] mdnsV6 =
      withChecksum(
          ethernet(
              "33:33:00:00:00:fb",
              VENDOR_MAC,
              0x86DD,
              ipv6Udp(
                  "2a02:1234:5678:9abc::42",
                  "ff02::fb",
                  5353,
                  5353,
                  dns(
                      true,
                      0,
                      1,
                      record(name(HOST, "local"), 28, 1, TestFrames.ip("fe80::abcd"))))));

  private static byte[] mdnsFrame() {
    byte[] response =
        dns(
            true,
            0,
            2,
            record(name(HOST, "local"), 1, 1, TestFrames.ip("10.0.0.2")),
            record(
                name("Living Room", "_airplay", "_tcp", "local"),
                16,
                1,
                txt("deviceid=A4:83:E7:12:34:56", "flag")));
    byte[] frame =
        ethernet(
            TestFrames.MDNS_V4_MAC,
            VENDOR_MAC,
            0x0800,
            ipv4Udp("10.0.0.2", "224.0.0.251", 5353, 5353, response));
    return frame;
  }

  private static byte[] withChecksum(byte[] frame) {
    frame[PacketLayout.parse(frame).udp().udpOffset() + 7] = 1;
    UdpChecksum.update(frame, PacketLayout.parse(frame).udp());
    return frame;
  }

  private List<byte[]> anonymize(byte[]... frames) {
    var records = java.util.Arrays.stream(frames).map(f -> new PcapRecord(T, f, f.length)).toList();
    var anonymizer = new PcapAnonymizer(new byte[] {1, 2, 3});
    PcapFile out = anonymizer.anonymize(List.of(new PcapFile(1, 65_535, records))).get(0);
    assertThat(anonymizer.findLeaks(List.of(out))).isEmpty();
    assertThat(anonymizer.findLeaks(List.of(new PcapFile(1, 65_535, records)))).isNotEmpty();
    return out.records().stream().map(PcapRecord::data).toList();
  }

  private static Observation decode(byte[] frame) {
    return new FrameDecoder().decode(T, frame).orElseThrow();
  }

  @Test
  void keepsVendorPrefixAndReplacesDeviceSpecificBytes() {
    Observation after = decode(anonymize(arp).get(0));

    assertThat(after.mac()).startsWith("a4:83:e7:").isNotEqualTo(VENDOR_MAC);
    assertThat(after.ip()).isEqualTo("10.0.0.2");
  }

  @Test
  void fullyReplacesPrivateAddressesButKeepsThemPrivate() {
    String after = decode(anonymize(dhcp).get(0)).mac();
    byte first = (byte) Integer.parseInt(after.substring(0, 2), 16);

    assertThat(after.substring(3)).isNotEqualTo(PRIVATE_MAC.substring(3));
    assertThat(first & 0x02).as("locally administered bit").isEqualTo(0x02);
    assertThat(first & 0x01).as("group bit").isZero();
  }

  @Test
  void sameDeviceAndNameStayConsistentAcrossFramesAndProtocols() {
    List<byte[]> out = anonymize(arp, dhcp, mdns, mdnsV6);
    Observation arpAfter = decode(out.get(0));
    Observation dhcpAfter = decode(out.get(1));
    Observation mdnsAfter = decode(out.get(2));

    assertThat(mdnsAfter.mac()).isEqualTo(arpAfter.mac());
    assertThat(mdnsAfter.hostname())
        .isEqualTo(dhcpAfter.hostname())
        .isNotEqualTo(HOST)
        .hasSameSizeAs(HOST);
  }

  @Test
  void masksTxtValuesButKeepsKeys() {
    String text = new String(anonymize(mdns).get(0), StandardCharsets.ISO_8859_1);

    assertThat(text).contains("deviceid=xxxxxxxxxxxxxxxxx").contains("flag");
    assertThat(text).doesNotContain("Living Room");
  }

  @Test
  void movesIpv6UnicastToDocumentationPrefixAndKeepsLinkLocalPrefix() {
    byte[] out = anonymize(mdnsV6).get(0);
    PacketLayout.Udp udp = PacketLayout.parse(out).udp();

    assertThat(out[udp.ipOffset() + 8]).isEqualTo((byte) 0x20);
    assertThat(out[udp.ipOffset() + 9]).isEqualTo((byte) 0x01);
    assertThat(out[udp.ipOffset() + 10]).isEqualTo((byte) 0x0D);
    assertThat(out[udp.ipOffset() + 11]).isEqualTo((byte) 0xB8);
    assertThat(UdpChecksum.isValid(out, udp)).isTrue();
  }

  @Test
  void keepsUdpChecksumsValid() {
    for (byte[] frame : anonymize(mdns, mdnsV6)) {
      assertThat(UdpChecksum.isValid(frame, PacketLayout.parse(frame).udp())).isTrue();
    }
  }

  @Test
  void structuralLabelsAreNotPersonal() {
    assertThat(PcapAnonymizer.isPersonal("local")).isFalse();
    assertThat(PcapAnonymizer.isPersonal("in-addr")).isFalse();
    assertThat(PcapAnonymizer.isPersonal("_airplay")).isFalse();
    assertThat(PcapAnonymizer.isPersonal("192")).isFalse();
    assertThat(PcapAnonymizer.isPersonal("f")).isFalse();
    assertThat(PcapAnonymizer.isPersonal("")).isFalse();
    assertThat(PcapAnonymizer.isPersonal("Chakibs-iPhone")).isTrue();
  }

  @Test
  void writesAnonymizedFilesFromADirectory(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
      throws Exception {
    java.nio.file.Path in = java.nio.file.Files.createDirectory(dir.resolve("in"));
    java.nio.file.Path out = dir.resolve("out");
    PcapWriter.write(
        in.resolve("mixed.pcap"),
        new PcapFile(1, 65_535, List.of(new PcapRecord(T, dhcp, dhcp.length))));

    PcapAnonymizer.main(new String[] {in.toString(), out.toString()});

    byte[] written = PcapReader.read(out.resolve("mixed.pcap")).records().get(0).data();
    assertThat(PcapAnonymizer.indexOf(written, HOST.getBytes(StandardCharsets.UTF_8), 0))
        .isEqualTo(-1);
  }
}
