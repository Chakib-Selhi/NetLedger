package io.github.chakibselhi.netledger.core.pcap;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;

/** Anonymized captures recorded on a home network, in src/test/resources/pcap. */
public final class Fixtures {

  private Fixtures() {}

  public static PcapFile load(String name) {
    try (InputStream in = Fixtures.class.getResourceAsStream("/pcap/" + name + ".pcap")) {
      if (in == null) {
        throw new IllegalStateException("Missing fixture " + name);
      }
      return PcapReader.read(in.readAllBytes());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }
}
