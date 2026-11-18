package io.github.chakibselhi.netledger.core.decode;

import java.nio.charset.StandardCharsets;

/** Turns attacker-controlled name bytes into a safe, bounded display string. */
final class TextSanitizer {

  static final int MAX_LENGTH = 255;

  private TextSanitizer() {}

  /** Decodes UTF-8, drops control characters, trims; returns {@code null} when nothing is left. */
  static String clean(byte[] data, int offset, int length) {
    String raw = new String(data, offset, length, StandardCharsets.UTF_8);
    return clean(raw);
  }

  static String clean(String raw) {
    var out = new StringBuilder(Math.min(raw.length(), MAX_LENGTH));
    raw.codePoints()
        .filter(cp -> !Character.isISOControl(cp) && cp != '�')
        .limit(MAX_LENGTH)
        .forEach(out::appendCodePoint);
    String cleaned = out.toString().strip();
    return cleaned.isEmpty() ? null : cleaned;
  }
}
