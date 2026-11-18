package io.github.chakibselhi.netledger.server.dashboard;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationSource;
import io.github.chakibselhi.netledger.core.model.ServiceAnnouncement;
import io.github.chakibselhi.netledger.server.correlation.CorrelationEngine;
import io.github.chakibselhi.netledger.server.network.NetworkService;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@SpringBootTest
@AutoConfigureMockMvc
class DashboardTest {

  private static final String OLD_PHONE = "3a:00:00:00:00:01";
  private static final String NEW_PHONE = "3a:00:00:00:00:02";
  private static final String HOSTILE = "ec:b5:fa:00:00:09";
  private static final String HOSTILE_NAME = "=HYPERLINK(\"http://x\")";

  @Autowired MockMvc mvc;
  @Autowired NetworkService networkService;
  @Autowired CorrelationEngine engine;
  @Autowired JdbcClient jdbc;
  @Autowired ObjectMapper json;

  private long network;

  @BeforeEach
  void seed() {
    network = networkService.declareCurrent(randomGateway(), "10.20.0.0/24").id();
    Instant now = Instant.now();
    engine.ingest(
        network,
        List.of(
            new Observation(
                now.minus(Duration.ofHours(3)),
                ObservationSource.DHCP,
                OLD_PHONE,
                "10.20.0.10",
                "Sample-iPhone",
                "1,121,3,6",
                null,
                List.of()),
            new Observation(
                now.minus(Duration.ofHours(1)),
                ObservationSource.MDNS,
                NEW_PHONE,
                "10.20.0.11",
                "Sample-iPhone",
                null,
                null,
                List.of(new ServiceAnnouncement("_companion-link._tcp", "Chakib", 49152))),
            new Observation(
                now.minus(Duration.ofHours(2)),
                ObservationSource.DHCP,
                HOSTILE,
                "10.20.0.12",
                HOSTILE_NAME,
                null,
                null,
                List.of())));
  }

  private static String randomGateway() {
    var random = ThreadLocalRandom.current();
    return "02:00:01:%02x:%02x:%02x"
        .formatted(random.nextInt(256), random.nextInt(256), random.nextInt(256));
  }

  private long deviceId(String mac) {
    return jdbc.sql("SELECT id FROM device WHERE network_id = :n AND mac = :m")
        .param("n", network)
        .param("m", mac)
        .query(Long.class)
        .single();
  }

  private ResultActions send(MockHttpServletRequestBuilder request, String body) throws Exception {
    return mvc.perform(request.with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body));
  }

  @Test
  void pagesAreServedWithAStrictContentSecurityPolicy() throws Exception {
    for (String path : List.of("/", "/networks", "/networks/3", "/devices/12", "/events")) {
      mvc.perform(get(path)).andExpect(status().isOk()).andExpect(forwardedUrl("/index.html"));
    }
    mvc.perform(get("/index.html"))
        .andExpect(status().isOk())
        .andExpect(content().string(containsString("/app.js")))
        .andExpect(header().string("Content-Security-Policy", containsString("script-src 'self'")))
        .andExpect(
            header().string("Content-Security-Policy", containsString("frame-ancestors 'none'")))
        .andExpect(header().string("X-Content-Type-Options", "nosniff"))
        .andExpect(header().string("Referrer-Policy", "no-referrer"));
    mvc.perform(get("/app.js")).andExpect(status().isOk());
  }

  @Test
  void listsNetworksAndTheirDevices() throws Exception {
    mvc.perform(get("/ui/networks"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[*].id", hasItem((int) network)));
    mvc.perform(get("/ui/networks/" + network))
        .andExpect(jsonPath("$.trust").value("unset"))
        .andExpect(jsonPath("$.devices").value(3))
        .andExpect(jsonPath("$.newDevices").value(3));
    mvc.perform(get("/ui/networks/" + network + "/devices"))
        .andExpect(jsonPath("$", hasSize(3)))
        .andExpect(jsonPath("$[0].mac").value(NEW_PHONE))
        .andExpect(jsonPath("$[0].randomized").value(true));
    mvc.perform(get("/ui/networks/999999")).andExpect(status().isNotFound());
  }

  @Test
  void changesWithoutTheCsrfTokenAreRefused() throws Exception {
    String owned = "{\"trust\":\"owned\"}";
    mvc.perform(
            patch("/ui/networks/" + network).contentType(MediaType.APPLICATION_JSON).content(owned))
        .andExpect(status().isForbidden());
    mvc.perform(delete("/ui/networks/" + network)).andExpect(status().isForbidden());
    mvc.perform(get("/ui/networks/" + network)).andExpect(jsonPath("$.trust").value("unset"));
  }

  @Test
  void theTokenReadFromTheSessionAuthorizesChanges() throws Exception {
    var csrfResult = mvc.perform(get("/ui/csrf")).andExpect(status().isOk()).andReturn();
    var session = (MockHttpSession) csrfResult.getRequest().getSession(false);
    JsonNode token = json.readTree(csrfResult.getResponse().getContentAsString());

    mvc.perform(
            patch("/ui/networks/" + network)
                .session(session)
                .header(token.get("headerName").asText(), token.get("token").asText())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"trust\":\"authorized\",\"label\":\"  École  \"}"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.trust").value("authorized"))
        .andExpect(jsonPath("$.label").value("École"))
        .andExpect(jsonPath("$.learningUntil", notNullValue()));
  }

  @Test
  void validatesNetworkChanges() throws Exception {
    send(patch("/ui/networks/" + network), "{\"trust\":\"trusted\"}")
        .andExpect(status().isBadRequest());
    send(patch("/ui/networks/" + network), "{\"label\":\"" + "x".repeat(65) + "\"}")
        .andExpect(status().isBadRequest());
    send(patch("/ui/networks/999999"), "{\"label\":\"x\"}").andExpect(status().isNotFound());
  }

  @Test
  void updatesWhatTheUserDecidesAboutADevice() throws Exception {
    long phone = deviceId(OLD_PHONE);
    String path = "/ui/devices/" + phone;

    send(
            patch(path),
            "{\"displayName\":\"Mon iPhone\",\"category\":\"Famille\",\"status\":\"approved\"}")
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.displayName").value("Mon iPhone"))
        .andExpect(jsonPath("$.category").value("Famille"))
        .andExpect(jsonPath("$.status").value("approved"));
    send(patch(path), "{\"displayName\":\"\"}")
        .andExpect(jsonPath("$.displayName", nullValue()))
        .andExpect(jsonPath("$.category").value("Famille"));

    send(patch(path), "{\"status\":\"owner\"}").andExpect(status().isBadRequest());
    send(patch(path), "{\"displayName\":\"" + "x".repeat(65) + "\"}")
        .andExpect(status().isBadRequest());
    send(patch(path), "{\"category\":\"a\\u0007b\"}").andExpect(status().isBadRequest());
    send(patch("/ui/devices/999999"), "{\"status\":\"approved\"}").andExpect(status().isNotFound());
  }

  @Test
  void deviceDetailIncludesHistoryAndMergeCandidates() throws Exception {
    long phone = deviceId(NEW_PHONE);

    mvc.perform(get("/ui/devices/" + phone))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.device.hostname").value("Sample-iPhone"))
        .andExpect(jsonPath("$.network.id").value((int) network))
        .andExpect(jsonPath("$.ips[0].ip").value("10.20.0.11"))
        .andExpect(jsonPath("$.services[0].type").value("_companion-link._tcp"))
        .andExpect(jsonPath("$.observations", hasSize(1)))
        .andExpect(jsonPath("$.mergeCandidates", hasSize(2)));
    mvc.perform(get("/ui/devices/999999")).andExpect(status().isNotFound());
  }

  @Test
  void mergingKeepsTheKnownDeviceAndTakesTheNewAddress() throws Exception {
    long known = deviceId(OLD_PHONE);
    long fresh = deviceId(NEW_PHONE);
    send(patch("/ui/devices/" + known), "{\"displayName\":\"Mon iPhone\",\"status\":\"approved\"}")
        .andExpect(status().isOk());

    send(post("/ui/devices/" + fresh + "/merge"), "{\"into\":" + known + "}")
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value((int) known))
        .andExpect(jsonPath("$.mac").value(NEW_PHONE))
        .andExpect(jsonPath("$.displayName").value("Mon iPhone"))
        .andExpect(jsonPath("$.status").value("approved"))
        .andExpect(jsonPath("$.lastIp").value("10.20.0.11"))
        .andExpect(jsonPath("$.dhcpFingerprint").value("1,121,3,6"));

    mvc.perform(get("/ui/devices/" + fresh)).andExpect(status().isNotFound());
    mvc.perform(get("/ui/devices/" + known))
        .andExpect(jsonPath("$.ips", hasSize(2)))
        .andExpect(jsonPath("$.services", hasSize(1)))
        .andExpect(jsonPath("$.observations", hasSize(2)));
    mvc.perform(get("/ui/networks/" + network + "/devices")).andExpect(jsonPath("$", hasSize(2)));
  }

  @Test
  void refusesInvalidMerges() throws Exception {
    long phone = deviceId(OLD_PHONE);
    send(post("/ui/devices/" + phone + "/merge"), "{\"into\":" + phone + "}")
        .andExpect(status().isBadRequest());
    send(post("/ui/devices/" + phone + "/merge"), "{}").andExpect(status().isBadRequest());
    send(post("/ui/devices/" + phone + "/merge"), "{\"into\":999999}")
        .andExpect(status().isNotFound());

    long other = networkService.declareCurrent(randomGateway(), "10.21.0.0/24").id();
    engine.ingest(
        other,
        List.of(
            Observation.presence(
                Instant.now().minusSeconds(60), ObservationSource.ARP, OLD_PHONE, "10.21.0.5")));
    long elsewhere =
        jdbc.sql("SELECT id FROM device WHERE network_id = :n")
            .param("n", other)
            .query(Long.class)
            .single();
    send(post("/ui/devices/" + phone + "/merge"), "{\"into\":" + elsewhere + "}")
        .andExpect(status().isBadRequest());
  }

  @Test
  void exportsTheInventoryAsCsvWithoutFormulas() throws Exception {
    String csv =
        mvc.perform(get("/ui/networks/" + network + "/inventory.csv"))
            .andExpect(status().isOk())
            .andExpect(
                header()
                    .string(
                        "Content-Disposition",
                        "attachment; filename=\"netledger-network-" + network + ".csv\""))
            .andExpect(content().contentTypeCompatibleWith("text/csv"))
            .andReturn()
            .getResponse()
            .getContentAsString(java.nio.charset.StandardCharsets.UTF_8);

    assertThat(csv).startsWith(InventoryExport.HEADER + "\r\n");
    assertThat(csv.split("\r\n")).hasSize(4);
    assertThat(csv).contains("\"'=HYPERLINK(\"\"http://x\"\")\"").contains("\"" + OLD_PHONE + "\"");
  }

  @Test
  void exportsTheInventoryAsJson() throws Exception {
    mvc.perform(get("/ui/networks/" + network + "/inventory.json"))
        .andExpect(status().isOk())
        .andExpect(header().string("Content-Disposition", containsString("attachment")))
        .andExpect(jsonPath("$.network.id").value((int) network))
        .andExpect(jsonPath("$.exportedAt", notNullValue()))
        .andExpect(jsonPath("$.devices", hasSize(3)))
        .andExpect(jsonPath("$.devices[0].device.mac").value(NEW_PHONE))
        .andExpect(jsonPath("$.devices[0].services[0].type").value("_companion-link._tcp"));
  }

  @Test
  void listsTheTimeline() throws Exception {
    mvc.perform(get("/ui/events").param("network", String.valueOf(network)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$[*].kind", hasItem("new_network")))
        .andExpect(jsonPath("$[*].title", hasItem("Nouveau réseau")));
    mvc.perform(get("/ui/events").param("limit", "100000")).andExpect(status().isOk());
  }

  @Test
  void deletingANetworkForgetsEverythingSeenOnIt() throws Exception {
    long phone = deviceId(OLD_PHONE);

    mvc.perform(delete("/ui/networks/" + network).with(csrf())).andExpect(status().isNoContent());

    mvc.perform(get("/ui/networks/" + network)).andExpect(status().isNotFound());
    mvc.perform(get("/ui/devices/" + phone)).andExpect(status().isNotFound());
    for (String sql :
        List.of(
            "SELECT COUNT(*) FROM device WHERE network_id = :n",
            "SELECT COUNT(*) FROM event WHERE network_id = :n")) {
      assertThat(jdbc.sql(sql).param("n", network).query(Integer.class).single()).isZero();
    }
    assertThat(
            jdbc.sql("SELECT COUNT(*) FROM observation WHERE device_id = :d")
                .param("d", phone)
                .query(Integer.class)
                .single())
        .isZero();
    mvc.perform(delete("/ui/networks/" + network).with(csrf())).andExpect(status().isNotFound());
  }
}
