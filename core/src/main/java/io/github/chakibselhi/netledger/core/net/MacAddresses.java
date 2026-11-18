package io.github.chakibselhi.netledger.core.net;

import java.util.HexFormat;
import java.util.regex.Pattern;

/** Helpers for 48-bit IEEE 802 MAC addresses. */
public final class MacAddresses {

  public static final int LENGTH = 6;

  private static final Pattern CANONICAL = Pattern.compile("([0-9a-f]{2}:){5}[0-9a-f]{2}");
  private static final HexFormat HEX = HexFormat.ofDelimiter(":");

  private MacAddresses() {}

  /** Formats 6 bytes as {@code aa:bb:cc:dd:ee:ff}. */
  public static String format(byte[] data, int offset) {
    return HEX.formatHex(data, offset, offset + LENGTH);
  }

  public static boolean isCanonical(String mac) {
    return mac != null && CANONICAL.matcher(mac).matches();
  }

  /**
   * Bit 0 of the first octet (I/G bit) marks group addresses: broadcast and multicast. A real
   * device never uses one as its own address.
   */
  public static boolean isGroup(byte[] data, int offset) {
    return (data[offset] & 0x01) != 0;
  }

  /** All six octets are zero: "unknown", used for example as ARP request target. */
  public static boolean isZero(byte[] data, int offset) {
    for (int i = 0; i < LENGTH; i++) {
      if (data[offset + i] != 0) {
        return false;
      }
    }
    return true;
  }

  /** A usable device address: neither zero nor a group address. */
  public static boolean isUnicast(byte[] data, int offset) {
    return !isZero(data, offset) && !isGroup(data, offset);
  }

  /**
   * Bit 1 of the first octet (U/L bit) marks locally administered addresses, which is how phones
   * and computers build their private, randomized Wi-Fi addresses.
   */
  public static boolean isLocallyAdministered(byte[] data, int offset) {
    return (data[offset] & 0x02) != 0;
  }
}
