package io.github.chakibselhi.netledger.server.identification;

import io.github.chakibselhi.netledger.core.net.MacAddresses;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * IEEE MAC address block registry. The IEEE assigns blocks of three sizes, identified by the first
 * 24, 28 or 36 bits of the address:
 *
 * <ul>
 *   <li>MA-L (6 hex digits, "OUI"): 16 million addresses, large vendors;
 *   <li>MA-M (7 hex digits): 1 million addresses;
 *   <li>MA-S (9 hex digits): 4096 addresses, small vendors.
 * </ul>
 *
 * <p>MA-M and MA-S blocks are carved out of MA-L blocks registered to "IEEE Registration
 * Authority", so the longest matching prefix wins.
 */
public final class OuiRegistry {

  private static final int[] PREFIX_LENGTHS = {9, 7, 6};
  private static final String PRIVATE = "Private";

  private final Map<String, String> vendorsByPrefix;

  private OuiRegistry(Map<String, String> vendorsByPrefix) {
    this.vendorsByPrefix = Map.copyOf(vendorsByPrefix);
  }

  public static OuiRegistry empty() {
    return new OuiRegistry(Map.of());
  }

  /** Builds a registry from IEEE CSV files (oui.csv, mam.csv, oui36.csv), in any order. */
  public static OuiRegistry fromCsv(List<Reader> csvFiles) throws IOException {
    var entries = new HashMap<String, String>();
    for (Reader reader : csvFiles) {
      parse(reader).forEach(entries::putIfAbsent);
    }
    return new OuiRegistry(entries);
  }

  public int size() {
    return vendorsByPrefix.size();
  }

  /**
   * Vendor owning the address block, or empty for unknown blocks, blocks registered as "Private"
   * and locally administered (randomized) addresses, which belong to no vendor.
   */
  public Optional<String> vendorOf(String mac) {
    byte[] bytes = HexFormat.ofDelimiter(":").parseHex(mac);
    if (MacAddresses.isLocallyAdministered(bytes, 0)) {
      return Optional.empty();
    }
    String hex = HexFormat.of().withUpperCase().formatHex(bytes);
    for (int length : PREFIX_LENGTHS) {
      String vendor = vendorsByPrefix.get(hex.substring(0, length));
      if (vendor != null) {
        return PRIVATE.equalsIgnoreCase(vendor) ? Optional.empty() : Optional.of(vendor);
      }
    }
    return Optional.empty();
  }

  /**
   * Parses one IEEE registry CSV: {@code Registry,Assignment,Organization Name,Organization
   * Address}, with RFC 4180 quoting.
   */
  static Map<String, String> parse(Reader reader) throws IOException {
    var entries = new HashMap<String, String>();
    try (var lines = new BufferedReader(reader)) {
      String header = lines.readLine();
      if (header == null || !header.startsWith("Registry,Assignment,Organization Name")) {
        throw new IOException("Not an IEEE registry CSV");
      }
      String line;
      while ((line = lines.readLine()) != null) {
        List<String> fields = fields(line);
        if (fields.size() < 3) {
          continue;
        }
        String assignment = fields.get(1).strip().toUpperCase(Locale.ROOT);
        String vendor = fields.get(2).strip();
        if (assignment.matches("[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}") && !vendor.isEmpty()) {
          entries.put(assignment, vendor);
        }
      }
    }
    return entries;
  }

  static List<String> fields(String line) {
    var fields = new ArrayList<String>();
    var field = new StringBuilder();
    boolean quoted = false;
    for (int i = 0; i < line.length(); i++) {
      char c = line.charAt(i);
      if (quoted) {
        if (c == '"' && i + 1 < line.length() && line.charAt(i + 1) == '"') {
          field.append('"');
          i++;
        } else if (c == '"') {
          quoted = false;
        } else {
          field.append(c);
        }
      } else if (c == '"') {
        quoted = true;
      } else if (c == ',') {
        fields.add(field.toString());
        field.setLength(0);
      } else {
        field.append(c);
      }
    }
    fields.add(field.toString());
    return fields;
  }
}
