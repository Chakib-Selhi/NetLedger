package io.github.chakibselhi.netledger.core.decode;

/**
 * Bounds-checked, big-endian (network order) reader over a slice of a byte array. Positions are
 * absolute indexes in the underlying array. Every read past the slice throws {@link
 * MalformedPacketException} instead of reading foreign bytes or throwing an index exception.
 */
public final class ByteCursor {

  private final byte[] data;
  private final int start;
  private final int limit;
  private int position;

  public ByteCursor(byte[] data, int offset, int length) {
    if (offset < 0 || length < 0 || offset > data.length - length) {
      throw new MalformedPacketException("Slice out of bounds");
    }
    this.data = data;
    this.start = offset;
    this.limit = offset + length;
    this.position = offset;
  }

  public static ByteCursor of(byte[] data) {
    return new ByteCursor(data, 0, data.length);
  }

  public byte[] data() {
    return data;
  }

  public int position() {
    return position;
  }

  public int limit() {
    return limit;
  }

  public int remaining() {
    return limit - position;
  }

  public void seek(int absolutePosition) {
    if (absolutePosition < start || absolutePosition > limit) {
      throw new MalformedPacketException("Seek out of bounds");
    }
    position = absolutePosition;
  }

  public void skip(int count) {
    require(count);
    position += count;
  }

  public int u8() {
    require(1);
    return data[position++] & 0xFF;
  }

  public int u16() {
    require(2);
    int value = ((data[position] & 0xFF) << 8) | (data[position + 1] & 0xFF);
    position += 2;
    return value;
  }

  public long u32() {
    require(4);
    long value =
        ((long) (data[position] & 0xFF) << 24)
            | ((data[position + 1] & 0xFF) << 16)
            | ((data[position + 2] & 0xFF) << 8)
            | (data[position + 3] & 0xFF);
    position += 4;
    return value;
  }

  /** Returns the current position and advances by {@code count} bytes. */
  public int take(int count) {
    require(count);
    int at = position;
    position += count;
    return at;
  }

  private void require(int count) {
    if (count < 0 || count > limit - position) {
      throw new MalformedPacketException("Truncated packet");
    }
  }
}
