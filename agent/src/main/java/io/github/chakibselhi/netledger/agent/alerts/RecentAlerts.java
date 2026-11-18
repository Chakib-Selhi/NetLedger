package io.github.chakibselhi.netledger.agent.alerts;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/** The last alerts received, newest first, for the "Dernières alertes" menu. Memory only. */
public final class RecentAlerts {

  private final int capacity;
  private final Deque<Alert> alerts = new ArrayDeque<>();

  public RecentAlerts(int capacity) {
    this.capacity = capacity;
  }

  public synchronized void add(Alert alert) {
    alerts.addFirst(alert);
    while (alerts.size() > capacity) {
      alerts.removeLast();
    }
  }

  public synchronized List<Alert> list() {
    return List.copyOf(alerts);
  }
}
