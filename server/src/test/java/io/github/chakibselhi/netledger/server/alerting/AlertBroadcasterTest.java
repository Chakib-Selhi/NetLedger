package io.github.chakibselhi.netledger.server.alerting;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.request;

import io.github.chakibselhi.netledger.server.network.NetworkService;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@SpringBootTest
@AutoConfigureMockMvc
class AlertBroadcasterTest {

  @Autowired MockMvc mvc;
  @Autowired AlertBroadcaster broadcaster;
  @Autowired EventRepository events;
  @Autowired NetworkService networks;
  @Autowired JdbcClient jdbc;

  private long network;

  private static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
      authorized(
          org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder request) {
    return request.header("Authorization", "Bearer test-token-0123456789abcdef0123456789abcdef");
  }

  @BeforeEach
  void clean() {
    jdbc.sql("UPDATE event SET delivered = 1").update();
    network = networks.declareCurrent("02:00:00:bb:bb:bb", "10.5.0.0/24").id();
    jdbc.sql("UPDATE event SET delivered = 1").update();
  }

  private void pending(int count) {
    for (int i = 0; i < count; i++) {
      events.insert(
          network,
          null,
          i % 2 == 0 ? EventKind.NEW_DEVICE : EventKind.NEW_NETWORK,
          "event " + i,
          Instant.now());
    }
  }

  private String stream() throws Exception {
    MvcResult result =
        mvc.perform(authorized(get("/api/v1/alerts/stream")))
            .andExpect(request().asyncStarted())
            .andReturn();
    return result.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
  }

  @Test
  void sendsPendingAlertsOnConnectAndMarksThemDelivered() throws Exception {
    pending(2);

    String body = stream();

    assertThat(body)
        .contains(
            "event:alert",
            "\"kind\":\"new_device\"",
            "event 0",
            "event 1",
            "\"path\":\"/networks\"");
    assertThat(events.undelivered()).isEmpty();
  }

  @Test
  void mergesMoreThanThreePendingAlertsIntoOneSummary() throws Exception {
    pending(5);

    String body = stream();

    assertThat(body)
        .contains(
            "\"kind\":\"summary\"",
            "5 alertes en attente",
            "3 nouvel(s) appareil(s)",
            "\"sound\":true");
    assertThat(body).doesNotContain("event 4");
    assertThat(events.undelivered()).isEmpty();
  }

  @Test
  void pushesNewAlertsToConnectedAgentsOnly() throws Exception {
    AlertEvent offline =
        events.insert(network, null, EventKind.NEW_NETWORK, "nobody listening", Instant.now());
    new AlertBroadcaster(events).onAlert(new AlertRaised(offline));
    assertThat(events.undelivered()).extracting(AlertEvent::id).contains(offline.id());

    stream();
    assertThat(broadcaster.connected()).isPositive();
    AlertEvent live = events.insert(network, null, EventKind.NEW_NETWORK, "pushed", Instant.now());
    broadcaster.onAlert(new AlertRaised(live));
    broadcaster.heartbeat();

    assertThat(events.undelivered()).isEmpty();
  }

  @Test
  void streamRequiresTheToken() throws Exception {
    mvc.perform(get("/api/v1/alerts/stream"))
        .andExpect(
            org.springframework.test.web.servlet.result.MockMvcResultMatchers.status()
                .isUnauthorized());
  }

  @Test
  void summaryWithoutNewDevices() {
    var e =
        new AlertEvent(
            1, network, null, EventKind.NEW_NETWORK, "m", "2026-11-18T12:00:00.000Z", false);

    AlertMessage summary = AlertBroadcaster.summary(List.of(e, e, e, e));

    assertThat(summary.message()).isEqualTo("4 alertes");
    assertThat(summary.sound()).isFalse();
    assertThat(summary.id()).isZero();
  }
}
