package io.github.chakibselhi.netledger.agent.setup;

import java.io.IOException;
import java.util.Optional;

/**
 * macOS "Local Network" privacy (macOS 15 and later). An app the user has not allowed does not see
 * the devices of the local network: {@code arp} run by the agent answers "no entry" for the
 * gateway, even though the entry exists. Reading the ARP table does not make macOS ask, sending a
 * packet to the local network does.
 */
public final class LocalNetworkAccess {

  public enum State {
    OK,
    BLOCKED,
    OFFLINE
  }

  /** The default route and the gateway's ARP entry, as the agent reads them. */
  public interface Probe {
    /** Gateway IP of the default route, or empty when the Mac is offline. */
    Optional<String> gateway() throws IOException;

    /** Output of {@code arp -n <gateway>}, even when it fails. */
    String arpEntry(String gateway) throws IOException;
  }

  /** Sends one packet to the local network so that macOS shows its permission prompt. */
  @FunctionalInterface
  public interface Prompt {
    void send() throws IOException;
  }

  private final Probe probe;
  private final Prompt prompt;

  public LocalNetworkAccess(Probe probe, Prompt prompt) {
    this.probe = probe;
    this.prompt = prompt;
  }

  /** Blocked when there is a gateway but its ARP entry is hidden from the agent. */
  public State state() {
    try {
      Optional<String> gateway = probe.gateway();
      if (gateway.isEmpty()) {
        return State.OFFLINE;
      }
      return probe.arpEntry(gateway.get()).contains("no entry") ? State.BLOCKED : State.OK;
    } catch (IOException e) {
      return State.OFFLINE;
    }
  }

  public void request() throws IOException {
    prompt.send();
  }
}
