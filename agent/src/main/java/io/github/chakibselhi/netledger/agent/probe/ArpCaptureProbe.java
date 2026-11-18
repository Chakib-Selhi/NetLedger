package io.github.chakibselhi.netledger.agent.probe;

import java.io.PrintStream;
import java.net.InetAddress;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.stream.Collectors;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.ArpOperation;

/**
 * Phase 0 diagnostic: lists capture interfaces, or prints ARP frames seen on one interface for a
 * limited time. Read-only and non-promiscuous; nothing is sent or stored.
 *
 * <p>Usage: {@code ArpCaptureProbe} (list) or {@code ArpCaptureProbe <interface> [seconds]}.
 */
public final class ArpCaptureProbe {

  private static final int DEFAULT_SECONDS = 30;
  // An Ethernet ARP frame is 42 bytes (60 with padding); there is no reason to copy more.
  private static final int SNAPLEN = 128;
  private static final int READ_TIMEOUT_MILLIS = 500;
  private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("HH:mm:ss.SSS");

  private final PrintStream out;

  ArpCaptureProbe(PrintStream out) {
    this.out = out;
  }

  public static void main(String[] args) throws Exception {
    var probe = new ArpCaptureProbe(System.out);
    System.out.println("libpcap: " + Pcaps.libVersion());
    if (args.length == 0) {
      probe.listInterfaces(Pcaps.findAllDevs());
      return;
    }
    int seconds = args.length > 1 ? Integer.parseInt(args[1]) : DEFAULT_SECONDS;
    probe.capture(args[0], Duration.ofSeconds(seconds));
  }

  void listInterfaces(List<PcapNetworkInterface> interfaces) {
    if (interfaces.isEmpty()) {
      out.println("No interface visible: check capture permissions.");
      return;
    }
    for (PcapNetworkInterface nif : interfaces) {
      String flags = (nif.isUp() ? "UP" : "DOWN") + (nif.isLoopBack() ? " LOOPBACK" : "");
      String addresses =
          nif.getAddresses().stream()
              .map(PcapAddress::getAddress)
              .map(InetAddress::getHostAddress)
              .collect(Collectors.joining(", "));
      out.printf(
          "%-12s %-14s %s%s%n",
          nif.getName(),
          flags,
          addresses.isEmpty() ? "-" : addresses,
          nif.getDescription() == null ? "" : "  (" + nif.getDescription() + ")");
    }
  }

  void capture(String interfaceName, Duration duration)
      throws PcapNativeException, NotOpenException {
    PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
    if (nif == null) {
      throw new IllegalArgumentException("Unknown interface: " + interfaceName);
    }
    out.printf("Listening for ARP on %s for %ds...%n", interfaceName, duration.toSeconds());

    int count = 0;
    try (PcapHandle handle =
        nif.openLive(SNAPLEN, PromiscuousMode.NONPROMISCUOUS, READ_TIMEOUT_MILLIS)) {
      // The kernel filters with BPF, so only ARP frames are ever copied to user space.
      handle.setFilter("arp", BpfCompileMode.OPTIMIZE);
      Instant deadline = Instant.now().plus(duration);
      while (Instant.now().isBefore(deadline)) {
        Packet packet;
        try {
          // getNextPacketEx (pcap_next_ex): pcap_next overflows pcap4j's header buffer on macOS.
          packet = handle.getNextPacketEx();
        } catch (java.util.concurrent.TimeoutException e) {
          continue;
        } catch (java.io.EOFException e) {
          break;
        }
        ArpPacket arp = packet.get(ArpPacket.class);
        if (arp != null) {
          out.println(format(handle.getTimestamp().toInstant(), arp.getHeader()));
          count++;
        }
      }
    }
    out.printf("%d ARP frame(s) captured.%n", count);
  }

  static String format(Instant timestamp, ArpPacket.ArpHeader arp) {
    String time = LocalTime.ofInstant(timestamp, ZoneId.systemDefault()).format(TIME);
    String senderIp = arp.getSrcProtocolAddr().getHostAddress();
    String targetIp = arp.getDstProtocolAddr().getHostAddress();
    String senderMac = arp.getSrcHardwareAddr().toString();

    if (ArpOperation.REQUEST.equals(arp.getOperation())) {
      if ("0.0.0.0".equals(senderIp)) {
        return "%s PROBE    who-has %-15s from %s".formatted(time, targetIp, senderMac);
      }
      if (senderIp.equals(targetIp)) {
        return "%s GRATUIT  %-15s is-at %s".formatted(time, senderIp, senderMac);
      }
      return "%s REQUEST  who-has %-15s tell %-15s (%s)"
          .formatted(time, targetIp, senderIp, senderMac);
    }
    if (ArpOperation.REPLY.equals(arp.getOperation())) {
      return "%s REPLY    %-15s is-at %s".formatted(time, senderIp, senderMac);
    }
    return "%s %s %s -> %s".formatted(time, arp.getOperation(), senderIp, targetIp);
  }
}
