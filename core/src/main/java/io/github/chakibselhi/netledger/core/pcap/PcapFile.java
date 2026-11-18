package io.github.chakibselhi.netledger.core.pcap;

import java.util.List;

/**
 * Content of a classic libpcap capture file.
 *
 * @param linkType link-layer header type; 1 is Ethernet
 */
public record PcapFile(int linkType, int snapLength, List<PcapRecord> records) {

  public static final int LINKTYPE_ETHERNET = 1;

  public PcapFile {
    records = List.copyOf(records);
  }
}
