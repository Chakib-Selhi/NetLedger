package io.github.chakibselhi.netledger.core.decode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ByteCursorTest {

  private final byte[] data = {0x12, 0x34, (byte) 0xAB, (byte) 0xCD, 0x01, 0x02, 0x03};

  @Test
  void readsBigEndianValues() {
    var cursor = ByteCursor.of(data);

    assertThat(cursor.u16()).isEqualTo(0x1234);
    assertThat(cursor.u32()).isEqualTo(0xABCD0102L);
    assertThat(cursor.u8()).isEqualTo(3);
    assertThat(cursor.remaining()).isZero();
  }

  @Test
  void neverReadsOutsideItsSlice() {
    var cursor = new ByteCursor(data, 2, 3);

    assertThat(cursor.u16()).isEqualTo(0xABCD);
    assertThatThrownBy(cursor::u16).isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> cursor.seek(1)).isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> cursor.seek(6)).isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> cursor.skip(-1)).isInstanceOf(MalformedPacketException.class);
  }

  @Test
  void rejectsSlicesOutsideTheArray() {
    assertThatThrownBy(() -> new ByteCursor(data, 5, 3))
        .isInstanceOf(MalformedPacketException.class);
    assertThatThrownBy(() -> new ByteCursor(data, -1, 2))
        .isInstanceOf(MalformedPacketException.class);
  }

  @Test
  void takeReturnsStartOfSkippedRegion() {
    var cursor = ByteCursor.of(data);
    cursor.skip(1);

    assertThat(cursor.take(2)).isEqualTo(1);
    assertThat(cursor.position()).isEqualTo(3);
  }
}
