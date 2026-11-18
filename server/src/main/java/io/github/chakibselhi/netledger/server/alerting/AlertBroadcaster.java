package io.github.chakibselhi.netledger.server.alerting;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionalEventListener;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

/**
 * Pushes alerts to connected agents over Server-Sent Events (EF-12). An alert is marked delivered
 * once written to at least one stream. Alerts raised while no agent listens are sent when one
 * connects, merged into a single summary when there are more than {@value #SUMMARY_THRESHOLD}.
 */
@Component
public class AlertBroadcaster {

  static final int SUMMARY_THRESHOLD = 3;
  static final Duration STREAM_TIMEOUT = Duration.ofHours(1);
  private static final Logger log = LoggerFactory.getLogger(AlertBroadcaster.class);

  private final EventRepository events;
  private final List<SseEmitter> emitters = new CopyOnWriteArrayList<>();

  AlertBroadcaster(EventRepository events) {
    this.events = events;
  }

  /** Opens a stream and first sends what was raised while no agent was connected. */
  public SseEmitter connect() {
    var emitter = new SseEmitter(STREAM_TIMEOUT.toMillis());
    emitter.onCompletion(() -> emitters.remove(emitter));
    emitter.onTimeout(() -> emitters.remove(emitter));
    emitter.onError(e -> emitters.remove(emitter));
    synchronized (this) {
      List<AlertEvent> pending = events.undelivered();
      boolean sent =
          pending.size() > SUMMARY_THRESHOLD
              ? send(emitter, summary(pending))
              : pending.stream().allMatch(e -> send(emitter, AlertMessage.of(e)));
      if (sent && !pending.isEmpty()) {
        events.markDelivered(pending.stream().map(AlertEvent::id).toList());
      }
      emitters.add(emitter);
    }
    return emitter;
  }

  @TransactionalEventListener(fallbackExecution = true)
  public synchronized void onAlert(AlertRaised raised) {
    AlertMessage message = AlertMessage.of(raised.event());
    boolean delivered = false;
    for (SseEmitter emitter : emitters) {
      delivered |= send(emitter, message);
    }
    if (delivered) {
      events.markDelivered(List.of(raised.event().id()));
    }
  }

  /** Comment lines keep idle connections open through proxies and reveal dead agents. */
  @Scheduled(fixedDelay = 25_000)
  public void heartbeat() {
    for (SseEmitter emitter : emitters) {
      try {
        emitter.send(SseEmitter.event().comment("ping"));
      } catch (IOException | IllegalStateException e) {
        emitters.remove(emitter);
      }
    }
  }

  int connected() {
    return emitters.size();
  }

  static AlertMessage summary(List<AlertEvent> pending) {
    boolean sound = pending.stream().anyMatch(e -> e.kind().sound());
    long devices = pending.stream().filter(e -> e.kind() == EventKind.NEW_DEVICE).count();
    String detail =
        devices > 0
            ? devices + " nouvel(s) appareil(s) parmi " + pending.size() + " alertes"
            : pending.size() + " alertes";
    return new AlertMessage(
        0,
        "summary",
        pending.size() + " alertes en attente",
        detail,
        sound,
        pending.get(pending.size() - 1).occurredAt(),
        "/events");
  }

  private boolean send(SseEmitter emitter, AlertMessage message) {
    try {
      emitter.send(
          SseEmitter.event()
              .id(Long.toString(message.id()))
              .name("alert")
              .data(message, MediaType.APPLICATION_JSON));
      return true;
    } catch (IOException | IllegalStateException e) {
      log.debug("Dropping a closed alert stream: {}", e.getMessage());
      emitters.remove(emitter);
      return false;
    }
  }
}
