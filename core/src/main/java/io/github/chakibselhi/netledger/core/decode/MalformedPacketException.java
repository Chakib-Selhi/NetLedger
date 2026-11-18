package io.github.chakibselhi.netledger.core.decode;

/** A frame is truncated or internally inconsistent. Caught by {@link FrameDecoder}. */
public final class MalformedPacketException extends RuntimeException {

  public MalformedPacketException(String message) {
    // Thrown for every bad packet an attacker sends: skip the costly stack trace.
    super(message, null, false, false);
  }
}
