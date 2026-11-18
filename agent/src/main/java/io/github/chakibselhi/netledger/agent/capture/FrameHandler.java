package io.github.chakibselhi.netledger.agent.capture;

import java.time.Instant;

/** Receives captured frames, still raw; they never leave memory. */
@FunctionalInterface
public interface FrameHandler {
  void onFrame(Instant timestamp, byte[] frame);
}
