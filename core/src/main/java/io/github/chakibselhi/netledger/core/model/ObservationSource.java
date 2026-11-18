package io.github.chakibselhi.netledger.core.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Protocol an observation was decoded from. JSON names match the {@code observation.source} column.
 */
public enum ObservationSource {
  @JsonProperty("arp")
  ARP,
  @JsonProperty("dhcp")
  DHCP,
  @JsonProperty("mdns")
  MDNS,
  @JsonProperty("arp_scan")
  ARP_SCAN
}
