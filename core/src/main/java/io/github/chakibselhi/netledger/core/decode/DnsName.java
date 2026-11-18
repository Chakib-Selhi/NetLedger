package io.github.chakibselhi.netledger.core.decode;

import java.util.List;
import java.util.Locale;

/**
 * A domain name as its list of labels. Kept as labels because DNS-SD instance names may contain
 * dots ("Mr. Robot's TV"), so joining and splitting on '.' would corrupt them.
 */
public record DnsName(List<String> labels) {

  public DnsName {
    labels = List.copyOf(labels);
  }

  public static DnsName of(String... labels) {
    return new DnsName(List.of(labels));
  }

  public int size() {
    return labels.size();
  }

  public String label(int index) {
    return labels.get(index);
  }

  /** True when the last labels equal {@code suffix}, ignoring ASCII case as DNS does. */
  public boolean endsWith(String... suffix) {
    if (suffix.length > labels.size()) {
      return false;
    }
    int start = labels.size() - suffix.length;
    for (int i = 0; i < suffix.length; i++) {
      if (!labels.get(start + i).equalsIgnoreCase(suffix[i])) {
        return false;
      }
    }
    return true;
  }

  /** Labels {@code [from, to)} joined with dots, lower case: used for service types. */
  public String join(int from, int to) {
    return String.join(".", labels.subList(from, to)).toLowerCase(Locale.ROOT);
  }

  @Override
  public String toString() {
    return String.join(".", labels);
  }
}
