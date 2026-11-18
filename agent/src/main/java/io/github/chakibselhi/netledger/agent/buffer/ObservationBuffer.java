package io.github.chakibselhi.netledger.agent.buffer;

import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Bounded in-memory buffer between capture and upload (EF-05). Nothing is written to disk.
 *
 * <ul>
 *   <li>Each observation keeps the network it was captured on, so a batch never mixes networks.
 *   <li>An observation identical to one accepted less than {@code dedupWindow} earlier is dropped:
 *       devices repeat the same ARP and mDNS packets, and sending each copy would only cost CPU.
 *   <li>When full, the oldest observations are dropped and counted.
 * </ul>
 */
public final class ObservationBuffer {

  /** Observations of one network, taken from the head of the buffer. */
  public record Batch(long networkId, List<Observation> observations) {}

  private record Entry(long networkId, Observation observation) {}

  private record DedupKey(
      long networkId,
      Object source,
      String mac,
      String ip,
      String hostname,
      String dhcpFingerprint,
      String vendorClass,
      List<ServiceAnnouncement> services) {

    static DedupKey of(long networkId, Observation o) {
      return new DedupKey(
          networkId,
          o.source(),
          o.mac(),
          o.ip(),
          o.hostname(),
          o.dhcpFingerprint(),
          o.vendorClass(),
          o.services());
    }
  }

  private final int capacity;
  private final Duration dedupWindow;
  private final Deque<Entry> entries = new ArrayDeque<>();
  private final Map<DedupKey, Instant> lastAccepted = new HashMap<>();
  private long dropped;
  private long deduplicated;

  public ObservationBuffer(int capacity, Duration dedupWindow) {
    this.capacity = capacity;
    this.dedupWindow = dedupWindow;
  }

  /** Adds an observation; returns false when it duplicates a recent one. */
  public synchronized boolean add(long networkId, Observation observation) {
    DedupKey key = DedupKey.of(networkId, observation);
    Instant previous = lastAccepted.get(key);
    if (previous != null && observation.observedAt().isBefore(previous.plus(dedupWindow))) {
      deduplicated++;
      return false;
    }
    lastAccepted.put(key, observation.observedAt());
    if (lastAccepted.size() > capacity * 2) {
      Instant cutoff = observation.observedAt().minus(dedupWindow);
      lastAccepted.values().removeIf(at -> at.isBefore(cutoff));
    }
    entries.addLast(new Entry(networkId, observation));
    trim();
    return true;
  }

  /** Removes up to {@code max} leading observations that belong to the same network. */
  public synchronized Optional<Batch> take(int max) {
    Entry head = entries.peekFirst();
    if (head == null) {
      return Optional.empty();
    }
    var taken = new ArrayList<Observation>();
    while (taken.size() < max
        && !entries.isEmpty()
        && entries.peekFirst().networkId() == head.networkId()) {
      taken.add(entries.pollFirst().observation());
    }
    return Optional.of(new Batch(head.networkId(), List.copyOf(taken)));
  }

  /** Puts back a batch that could not be sent, ahead of newer observations. */
  public synchronized void putBack(Batch batch) {
    List<Observation> observations = batch.observations();
    for (int i = observations.size() - 1; i >= 0; i--) {
      entries.addFirst(new Entry(batch.networkId(), observations.get(i)));
    }
    trim();
  }

  /** Forgets everything captured on a network that is no longer monitored. */
  public synchronized void discardNetwork(long networkId) {
    entries.removeIf(e -> e.networkId() == networkId);
  }

  public synchronized int size() {
    return entries.size();
  }

  public synchronized long dropped() {
    return dropped;
  }

  public synchronized long deduplicated() {
    return deduplicated;
  }

  private void trim() {
    while (entries.size() > capacity) {
      entries.pollFirst();
      dropped++;
    }
  }
}
