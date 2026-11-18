package io.github.chakibselhi.netledger.server.api;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.network.Trust;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class AgentApiTest {

  static final String TOKEN = "test-token-0123456789abcdef0123456789abcdef";

  @Autowired MockMvc mvc;
  @Autowired NetworkRepository networks;

  static MockHttpServletRequestBuilder authorized(MockHttpServletRequestBuilder request) {
    return request.header("Authorization", "Bearer " + TOKEN);
  }

  private ResultActions postJson(String path, String json) throws Exception {
    return mvc.perform(
        authorized(post(path)).contentType(MediaType.APPLICATION_JSON).content(json));
  }

  static String randomGateway() {
    var random = ThreadLocalRandom.current();
    return "02:00:00:%02x:%02x:%02x"
        .formatted(random.nextInt(256), random.nextInt(256), random.nextInt(256));
  }

  private long declare(String gateway) throws Exception {
    String body =
        postJson(
                "/api/v1/networks/current",
                "{\"gatewayMac\":\"" + gateway + "\",\"subnet\":\"10.1.2.3/24\"}")
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    return Long.parseLong(body.replaceAll(".*\"networkId\":(\\d+).*", "$1"));
  }

  private String batch(long networkId, String observations) {
    return "{\"networkId\":" + networkId + ",\"observations\":[" + observations + "]}";
  }

  private static String arp(String mac, String ip) {
    return "{\"observedAt\":\"2026-11-17T12:00:00Z\",\"source\":\"arp\",\"mac\":\""
        + mac
        + "\",\"ip\":\""
        + ip
        + "\"}";
  }

  @Test
  void healthAnswersWithAValidToken() throws Exception {
    mvc.perform(authorized(get("/api/v1/health")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("UP"));
  }

  @Test
  void newNetworkIsNotCapturedUntilTheUserTrustsIt() throws Exception {
    String gateway = randomGateway();

    postJson(
            "/api/v1/networks/current",
            "{\"gatewayMac\":\"" + gateway.toUpperCase() + "\",\"subnet\":\"10.1.2.3/24\"}")
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trust").value("unset"))
        .andExpect(jsonPath("$.capture").value(false));

    long id = declare(gateway);
    networks.setTrust(id, Trust.AUTHORIZED);

    postJson(
            "/api/v1/networks/current",
            "{\"gatewayMac\":\"" + gateway + "\",\"subnet\":\"10.1.2.0/24\"}")
        .andExpect(jsonPath("$.networkId").value(id))
        .andExpect(jsonPath("$.trust").value("authorized"))
        .andExpect(jsonPath("$.capture").value(true));
  }

  @Test
  void rejectsInvalidNetworkDeclarations() throws Exception {
    postJson("/api/v1/networks/current", "{\"gatewayMac\":\"nope\",\"subnet\":\"10.0.0.0/24\"}")
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.detail").value(containsString("gatewayMac")));
    postJson(
            "/api/v1/networks/current",
            "{\"gatewayMac\":\"" + randomGateway() + "\",\"subnet\":\"10.0.0.0/33\"}")
        .andExpect(status().isBadRequest());
    postJson("/api/v1/networks/current", "{not json").andExpect(status().isBadRequest());
  }

  @Test
  void storesObservationsOnlyForMonitoredNetworks() throws Exception {
    long id = declare(randomGateway());
    String body = batch(id, arp("a4:83:e7:00:00:01", "10.1.2.10"));

    postJson("/api/v1/observations", body)
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.detail").value("This network is not monitored"));

    networks.setTrust(id, Trust.IGNORED);
    postJson("/api/v1/observations", body).andExpect(status().isForbidden());

    networks.setTrust(id, Trust.OWNED);
    postJson("/api/v1/observations", body)
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.accepted").value(1))
        .andExpect(jsonPath("$.rejected").value(0));
  }

  @Test
  void rejectsUnknownNetworksOversizedBatchesAndInvalidObservations() throws Exception {
    long id = declare(randomGateway());
    networks.setTrust(id, Trust.OWNED);

    postJson("/api/v1/observations", batch(999_999, arp("a4:83:e7:00:00:01", "10.1.2.10")))
        .andExpect(status().isNotFound());
    String many =
        String.join(
            ",", java.util.Collections.nCopies(1001, arp("a4:83:e7:00:00:01", "10.1.2.10")));
    postJson("/api/v1/observations", batch(id, many)).andExpect(status().isPayloadTooLarge());
    postJson("/api/v1/observations", batch(id, arp("<script>", "10.1.2.10")))
        .andExpect(status().isBadRequest());
    postJson("/api/v1/observations", batch(id, arp("a4:83:e7:00:00:01", "999.1.2.3")))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.rejected").value(1));
  }
}
