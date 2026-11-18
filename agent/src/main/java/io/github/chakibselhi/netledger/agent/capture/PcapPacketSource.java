package io.github.chakibselhi.netledger.agent.capture;

import java.io.EOFException;
import java.io.IOException;
import java.util.concurrent.TimeoutException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;

/**
 * Live capture through libpcap (BPF on macOS). Non-promiscuous: on Wi-Fi and switched networks the
 * Mac only receives broadcast, multicast and its own traffic anyway, which is all ARP, DHCP and
 * mDNS need. The BPF filter runs in the kernel, so no other packet is ever copied to the agent.
 */
public final class PcapPacketSource implements PacketSource {

  /** ARP, DHCP (67/68) and mDNS (5353) only. */
  public static final String FILTER = "arp or (udp and (port 67 or port 68 or port 5353))";

  // Enough for any DHCP or mDNS packet on a 1500-byte MTU network, plus headroom.
  static final int SNAPLEN = 4096;
  private static final int READ_TIMEOUT_MILLIS = 500;

  private final String interfaceName;
  private volatile boolean running;

  public PcapPacketSource(String interfaceName) {
    this.interfaceName = interfaceName;
  }

  @Override
  public void run(FrameHandler handler) throws IOException {
    running = true;
    try {
      PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
      if (nif == null) {
        throw new IOException("Interface " + interfaceName + " not found");
      }
      try (PcapHandle handle =
          nif.openLive(SNAPLEN, PromiscuousMode.NONPROMISCUOUS, READ_TIMEOUT_MILLIS)) {
        handle.setFilter(FILTER, BpfCompileMode.OPTIMIZE);
        while (running) {
          byte[] frame;
          try {
            // pcap_next_ex, not pcap_next: on macOS, Apple's libpcap appends a 256-byte comment
            // field to struct pcap_pkthdr. pcap_next copies that larger header into the 24-byte
            // buffer pcap4j allocates, overflowing the heap on every packet. pcap_next_ex only
            // hands back a pointer to libpcap's own header.
            frame = handle.getNextRawPacketEx();
          } catch (TimeoutException e) {
            continue;
          } catch (EOFException e) {
            return;
          }
          handler.onFrame(handle.getTimestamp().toInstant(), frame);
        }
      }
    } catch (PcapNativeException | NotOpenException e) {
      throw new IOException("Capture on " + interfaceName + " failed: " + e.getMessage(), e);
    }
  }

  @Override
  public void stop() {
    running = false;
  }
}
