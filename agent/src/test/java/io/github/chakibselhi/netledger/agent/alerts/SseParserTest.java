package io.github.chakibselhi.netledger.agent.alerts;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class SseParserTest {

  private static List<SseParser.Event> parse(String... lines) {
    var parser = new SseParser();
    var events = new ArrayList<SseParser.Event>();
    for (String line : lines) {
      parser.feed(line).ifPresent(events::add);
    }
    return events;
  }

  @Test
  void parsesNamedEventsAndIgnoresComments() {
    assertThat(parse(":ping", "", "id:3", "event:alert", "data:{\"a\":1}", "", "data: plain", ""))
        .containsExactly(
            new SseParser.Event("alert", "{\"a\":1}"), new SseParser.Event("message", "plain"));
  }

  @Test
  void joinsMultiLineDataAndResetsBetweenEvents() {
    assertThat(parse("event:alert", "data:a", "data:b", "", "retry:1000", "data", ""))
        .containsExactly(new SseParser.Event("alert", "a\nb"), new SseParser.Event("message", ""));
  }

  @Test
  void eventWithoutDataIsNotDispatched() {
    assertThat(parse("event:alert", "", "data:x", ""))
        .containsExactly(new SseParser.Event("message", "x"));
  }
}
