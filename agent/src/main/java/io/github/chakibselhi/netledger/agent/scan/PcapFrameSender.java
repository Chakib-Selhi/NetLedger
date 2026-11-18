package io.github.chakibselhi.netledger.agent.scan;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;

/** Injects frames through libpcap; needs write access to /dev/bpf* (group access_bpf). */
public final class PcapFrameSender implements ArpScanner.FrameSender {

  @Override
  public void send(String interfaceName, List<byte[]> frames, Duration spacing) throws IOException {
    try {
      PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
      if (nif == null) {
        throw new IOException("Interface " + interfaceName + " not found");
      }
      try (PcapHandle handle = nif.openLive(64, PromiscuousMode.NONPROMISCUOUS, 100)) {
        for (byte[] frame : frames) {
          handle.sendPacket(frame);
          Thread.sleep(spacing);
        }
      }
    } catch (PcapNativeException | NotOpenException e) {
      throw new IOException("Cannot send on " + interfaceName + ": " + e.getMessage(), e);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException("ARP sweep interrupted", e);
    }
  }
}
