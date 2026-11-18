package io.github.chakibselhi.netledger.agent.capture;

import io.github.chakibselhi.netledger.agent.buffer.ObservationBuffer;
import io.github.chakibselhi.netledger.core.decode.FrameDecoder;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Captures on one network until stopped: frames are decoded at once and only the resulting
 * observations are buffered. If the source breaks (interface down, sleep), it is reopened after a
 * growing delay, up to one minute.
 */
public final class CaptureSession {

  private static final Logger log = LoggerFactory.getLogger(CaptureSession.class);
  private static final Duration MAX_RETRY_DELAY = Duration.ofMinutes(1);

  private final PacketSource source;
  private final long networkId;
  private final ObservationBuffer buffer;
  private final FrameDecoder decoder = new FrameDecoder();
  private final AtomicLong frames = new AtomicLong();
  private final Thread thread;
  private volatile boolean active = true;

  public CaptureSession(
      PacketSource source, long networkId, ObservationBuffer buffer, String name) {
    this.source = source;
    this.networkId = networkId;
    this.buffer = buffer;
    this.thread = Thread.ofPlatform().daemon().name("capture-" + name).unstarted(this::runLoop);
  }

  public CaptureSession start() {
    thread.start();
    return this;
  }

  public long networkId() {
    return networkId;
  }

  public long frames() {
    return frames.get();
  }

  public void stop() {
    active = false;
    source.stop();
    thread.interrupt();
    try {
      thread.join(Duration.ofSeconds(3));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  private void runLoop() {
    Duration delay = Duration.ofSeconds(1);
    while (active) {
      try {
        source.run(
            (timestamp, frame) -> {
              frames.incrementAndGet();
              decoder.decode(timestamp, frame).ifPresent(o -> buffer.add(networkId, o));
            });
        delay = Duration.ofSeconds(1);
      } catch (IOException e) {
        if (!active) {
          return;
        }
        log.warn("{}; retrying in {} s", e.getMessage(), delay.toSeconds());
        if (!sleep(delay)) {
          return;
        }
        delay =
            delay.multipliedBy(2).compareTo(MAX_RETRY_DELAY) > 0
                ? MAX_RETRY_DELAY
                : delay.multipliedBy(2);
      }
      if (active && !sleep(Duration.ofMillis(100))) {
        return;
      }
    }
  }

  private static boolean sleep(Duration duration) {
    try {
      Thread.sleep(duration);
      return true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }
}
