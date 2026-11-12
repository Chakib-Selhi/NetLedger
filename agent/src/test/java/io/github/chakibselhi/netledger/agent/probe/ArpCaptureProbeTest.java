package io.github.chakibselhi.netledger.agent.probe;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.namednumber.ArpHardwareType;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.util.MacAddress;

class ArpCaptureProbeTest {

  private static final Instant T = Instant.parse("2026-11-12T18:00:00Z");
  private static final MacAddress SENDER = MacAddress.getByName("02:00:00:aa:bb:cc");
  private static final MacAddress UNKNOWN = MacAddress.getByName("00:00:00:00:00:00");

  @Test
  void formatsRequest() throws Exception {
    var line = ArpCaptureProbe.format(T, arp(ArpOperation.REQUEST, "192.168.1.10", "192.168.1.1"));

    assertThat(line)
        .contains("REQUEST", "who-has 192.168.1.1", "tell 192.168.1.10", "02:00:00:aa:bb:cc");
  }

  @Test
  void formatsReply() throws Exception {
    var line = ArpCaptureProbe.format(T, arp(ArpOperation.REPLY, "192.168.1.1", "192.168.1.10"));

    assertThat(line).contains("REPLY", "192.168.1.1", "is-at 02:00:00:aa:bb:cc");
  }

  @Test
  void recognisesGratuitousArp() throws Exception {
    var line = ArpCaptureProbe.format(T, arp(ArpOperation.REQUEST, "192.168.1.42", "192.168.1.42"));

    assertThat(line).contains("GRATUIT", "192.168.1.42");
  }

  @Test
  void recognisesAddressConflictProbe() throws Exception {
    var line = ArpCaptureProbe.format(T, arp(ArpOperation.REQUEST, "0.0.0.0", "192.168.1.42"));

    assertThat(line).contains("PROBE", "who-has 192.168.1.42");
  }

  private static ArpPacket.ArpHeader arp(ArpOperation op, String senderIp, String targetIp)
      throws Exception {
    return new ArpPacket.Builder()
        .hardwareType(ArpHardwareType.ETHERNET)
        .protocolType(EtherType.IPV4)
        .hardwareAddrLength((byte) MacAddress.SIZE_IN_BYTES)
        .protocolAddrLength((byte) 4)
        .operation(op)
        .srcHardwareAddr(SENDER)
        .srcProtocolAddr(InetAddress.getByName(senderIp))
        .dstHardwareAddr(UNKNOWN)
        .dstProtocolAddr(InetAddress.getByName(targetIp))
        .build()
        .getHeader();
  }
}
