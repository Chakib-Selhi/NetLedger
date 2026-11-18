package io.github.chakibselhi.netledger.agent.capture;

import java.io.IOException;

/** A source of frames: the live interface, or a capture file in tests. */
public interface PacketSource {

  /**
   * Delivers frames until {@link #stop()} is called or the source fails.
   *
   * @throws IOException when the source cannot be opened or breaks (interface gone...)
   */
  void run(FrameHandler handler) throws IOException;

  /** Makes {@link #run} return soon; callable from any thread. */
  void stop();
}
