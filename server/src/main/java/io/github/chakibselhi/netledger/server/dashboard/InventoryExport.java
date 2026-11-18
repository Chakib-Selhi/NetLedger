package io.github.chakibselhi.netledger.server.dashboard;

import io.github.chakibselhi.netledger.server.dashboard.DashboardQueries.DeviceView;
import java.util.List;

/** Inventory of a network as CSV (EF-16), safe to open in a spreadsheet. */
final class InventoryExport {

  static final String HEADER =
      "mac,private_address,vendor,type,hostname,name,category,status,last_ip,first_seen,last_seen";

  private InventoryExport() {}

  static String csv(List<DeviceView> devices) {
    var out = new StringBuilder(HEADER).append("\r\n");
    for (DeviceView d : devices) {
      String[] fields = {
        d.mac(),
        d.randomized() ? "yes" : "no",
        d.vendor(),
        d.type(),
        d.hostname(),
        d.displayName(),
        d.category(),
        d.status(),
        d.lastIp(),
        d.firstSeen(),
        d.lastSeen()
      };
      for (int i = 0; i < fields.length; i++) {
        if (i > 0) {
          out.append(',');
        }
        out.append(cell(fields[i]));
      }
      out.append("\r\n");
    }
    return out.toString();
  }

  /**
   * Quotes every cell (RFC 4180). Host names come from the network, so anyone can pick one like
   * {@code =HYPERLINK(...)}: a spreadsheet would run it as a formula. A leading apostrophe makes
   * the spreadsheet show it as plain text (CSV injection).
   */
  static String cell(String value) {
    if (value == null) {
      return "";
    }
    String text = value;
    if (!text.isEmpty() && "=+-@\t\r".indexOf(text.charAt(0)) >= 0) {
      text = "'" + text;
    }
    return '"' + text.replace("\"", "\"\"") + '"';
  }
}
