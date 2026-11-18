package io.github.chakibselhi.netledger.core.model;

import java.util.Objects;

/**
 * A DNS-SD service announced over mDNS.
 *
 * @param type service type such as {@code _airplay._tcp}, lower case
 * @param instanceName human readable instance name, such as {@code Living Room}, or {@code null}
 *     when only the service type was announced
 * @param port TCP or UDP port from the SRV record, or {@code null} when only a PTR was seen
 */
public record ServiceAnnouncement(String type, String instanceName, Integer port) {

  public ServiceAnnouncement {
    Objects.requireNonNull(type, "type");
    if (!type.startsWith("_")) {
      throw new IllegalArgumentException("Service type must start with '_': " + type);
    }
    if (port != null && (port < 0 || port > 65_535)) {
      throw new IllegalArgumentException("Invalid port: " + port);
    }
  }
}
