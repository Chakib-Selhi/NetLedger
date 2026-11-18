package io.github.chakibselhi.netledger.server.identification;

import java.util.Set;

/**
 * What is known about a device when guessing its type.
 *
 * @param serviceTypes all announced mDNS service types, such as {@code _airplay._tcp}
 * @param instanceServiceTypes the subset backed by a service instance (name, port), as opposed to a
 *     bare answer to a service type enumeration
 * @param dhcpFingerprint DHCP option 55, or {@code null}
 * @param randomizedMac whether the MAC address is locally administered
 * @param vendor IEEE vendor, or {@code null}
 */
public record DeviceFacts(
    Set<String> serviceTypes,
    Set<String> instanceServiceTypes,
    String dhcpFingerprint,
    boolean randomizedMac,
    String vendor) {

  public DeviceFacts {
    serviceTypes = Set.copyOf(serviceTypes);
    instanceServiceTypes = Set.copyOf(instanceServiceTypes);
  }
}
