package io.github.chakibselhi.netledger.server.admin;

import io.github.chakibselhi.netledger.server.network.Trust;
import java.io.PrintStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

/**
 * Temporary command line to list networks and set their trust until the dashboard exists (phase 4).
 * It runs inside the server container, with direct database access, on purpose: the agent API must
 * never let an agent authorize the network it wants to capture on.
 *
 * <pre>
 * NetworkAdmin list
 * NetworkAdmin trust &lt;network id&gt; owned|authorized|ignored|unset
 * NetworkAdmin devices &lt;network id&gt;
 * </pre>
 */
public final class NetworkAdmin {

  private NetworkAdmin() {}

  public static void main(String[] args) throws SQLException {
    String dataDir = System.getenv().getOrDefault("NETLEDGER_DATA_DIR", "./data");
    try (Connection db =
        DriverManager.getConnection("jdbc:sqlite:" + dataDir + "/netledger.db?busy_timeout=5000")) {
      System.exit(run(db, args, System.out));
    }
  }

  static int run(Connection db, String[] args, PrintStream out) throws SQLException {
    if (args.length == 1 && args[0].equals("list")) {
      try (var rows =
          db.createStatement()
              .executeQuery(
                  "SELECT id, gateway_mac, subnet, trust, last_seen FROM network ORDER BY id")) {
        out.printf("%-4s %-17s %-18s %-10s %s%n", "id", "gateway", "subnet", "trust", "last seen");
        while (rows.next()) {
          out.printf(
              "%-4d %-17s %-18s %-10s %s%n",
              rows.getLong(1),
              rows.getString(2),
              rows.getString(3),
              rows.getString(4),
              rows.getString(5));
        }
      }
      return 0;
    }
    if (args.length == 3 && args[0].equals("trust")) {
      Trust trust = Trust.fromValue(args[2]);
      try (var update = db.prepareStatement("UPDATE network SET trust = ? WHERE id = ?")) {
        update.setString(1, trust.value());
        update.setLong(2, Long.parseLong(args[1]));
        if (update.executeUpdate() == 0) {
          out.println("No network " + args[1]);
          return 1;
        }
      }
      out.println("Network " + args[1] + " is now " + trust.value());
      return 0;
    }
    if (args.length == 2 && args[0].equals("devices")) {
      try (var query =
          db.prepareStatement(
              "SELECT mac, COALESCE(vendor, CASE WHEN mac_randomized = 1 THEN 'Adresse privee' END),"
                  + " guessed_type, last_ip, hostname, last_seen FROM device WHERE network_id = ?"
                  + " ORDER BY last_seen DESC")) {
        query.setLong(1, Long.parseLong(args[1]));
        try (var rows = query.executeQuery()) {
          out.printf(
              "%-17s %-28s %-8s %-15s %-24s %s%n",
              "mac", "vendor", "type", "ip", "hostname", "last seen");
          while (rows.next()) {
            out.printf(
                "%-17s %-28.28s %-8s %-15s %-24.24s %s%n",
                rows.getString(1),
                rows.getString(2),
                rows.getString(3),
                rows.getString(4),
                rows.getString(5),
                rows.getString(6));
          }
        }
      }
      return 0;
    }
    out.println("Usage: list | trust <id> owned|authorized|ignored|unset | devices <id>");
    return 64;
  }
}
