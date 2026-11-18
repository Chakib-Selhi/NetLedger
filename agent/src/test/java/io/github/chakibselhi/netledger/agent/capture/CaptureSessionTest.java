package io.github.chakibselhi.netledger.agent.capture;

import static org.assertj.core.api.Assertions.assertThat;

import io.github.chakibselhi.netledger.agent.buffer.ObservationBuffer;
import io.github.chakibselhi.netledger.core.pcap.Fixtures;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class CaptureSessionTest {

  @Test
  void reopensABrokenSourceAndDecodesFrames() throws Exception {
    var attempts = new AtomicInteger();
    var delivered = new CountDownLatch(1);
    PacketSource flaky =
        new PacketSource() {
          private volatile boolean running = true;

          @Override
          public void run(FrameHandler handler) throws IOException {
            if (attempts.incrementAndGet() == 1) {
              throw new IOException("interface down");
            }
            Fixtures.load("arp").records().forEach(r -> handler.onFrame(r.timestamp(), r.data()));
            delivered.countDown();
            while (running) {
              Thread.onSpinWait();
            }
          }

          @Override
          public void stop() {
            running = false;
          }
        };
    var buffer = new ObservationBuffer(100, Duration.ZERO);

    CaptureSession session = new CaptureSession(flaky, 3, buffer, "test").start();
    assertThat(delivered.await(5, TimeUnit.SECONDS)).isTrue();
    session.stop();

    assertThat(attempts).hasValue(2);
    assertThat(session.frames()).isEqualTo(17);
    assertThat(session.networkId()).isEqualTo(3);
    assertThat(buffer.size()).isEqualTo(17);
    assertThat(buffer.take(100).orElseThrow().networkId()).isEqualTo(3);
  }

  @Test
  void stopsWhileWaitingToRetry() throws Exception {
    PacketSource broken =
        new PacketSource() {
          @Override
          public void run(FrameHandler handler) throws IOException {
            throw new IOException("no such interface");
          }

          @Override
          public void stop() {}
        };

    CaptureSession session =
        new CaptureSession(broken, 1, new ObservationBuffer(10, Duration.ZERO), "test").start();
    Thread.sleep(200);
    long before = System.nanoTime();
    session.stop();

    assertThat(Duration.ofNanos(System.nanoTime() - before)).isLessThan(Duration.ofSeconds(2));
  }

  @Test
  void filterOnlyLetsTheThreeProtocolsThrough() {
    assertThat(PcapPacketSource.FILTER)
        .isEqualTo("arp or (udp and (port 67 or port 68 or port 5353))");
  }
}
