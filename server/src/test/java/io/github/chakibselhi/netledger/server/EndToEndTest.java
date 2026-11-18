package io.github.chakibselhi.netledger.server;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import io.github.chakibselhi.netledger.core.decode.FrameDecoder;
import io.github.chakibselhi.netledger.core.json.ObservationJson;
import io.github.chakibselhi.netledger.core.model.Observation;
import io.github.chakibselhi.netledger.core.model.ObservationBatch;
import io.github.chakibselhi.netledger.core.pcap.Fixtures;
import io.github.chakibselhi.netledger.server.network.NetworkRepository;
import io.github.chakibselhi.netledger.server.network.Trust;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Replays the anonymized home network captures through the real pipeline: core decoders, JSON
 * exchange format, agent API, correlation and identification.
 */
@SpringBootTest
@AutoConfigureMockMvc
class EndToEndTest {

  private static final String TOKEN = "Bearer test-token-0123456789abcdef0123456789abcdef";

  @Autowired MockMvc mvc;
  @Autowired NetworkRepository networks;
  @Autowired JdbcClient jdbc;

  @Test
  void realCapturesBecomeAnInventory() throws Exception {
    String body =
        mvc.perform(
                post("/api/v1/networks/current")
                    .header("Authorization", TOKEN)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"gatewayMac\":\"02:00:00:e2:e2:e2\",\"subnet\":\"10.0.0.1/24\"}"))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse()
            .getContentAsString();
    long network = Long.parseLong(body.replaceAll(".*\"networkId\":(\\d+).*", "$1"));
    networks.setTrust(network, Trust.OWNED);

    var decoder = new FrameDecoder();
    List<Observation> observations =
        Stream.of("arp", "dhcp", "mdns")
            .flatMap(name -> Fixtures.load(name).records().stream())
            .map(r -> decoder.decode(r.timestamp(), r.data()))
            .flatMap(Optional::stream)
            .toList();
    mvc.perform(
            post("/api/v1/observations")
                .header("Authorization", TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(ObservationJson.write(new ObservationBatch(network, observations))))
        .andExpect(status().isOk());

    List<Map<String, Object>> devices =
        jdbc.sql(
                "SELECT mac, vendor, mac_randomized, guessed_type, hostname, last_ip FROM device WHERE network_id = :n")
            .param("n", network)
            .query()
            .listOfRows();
    Map<Object, Long> types =
        devices.stream()
            .collect(
                java.util.stream.Collectors.groupingBy(
                    d -> d.get("guessed_type"), java.util.stream.Collectors.counting()));

    assertThat(devices).hasSize(25);
    assertThat(types)
        .containsEntry("printer", 1L)
        .containsEntry("iot", 5L)
        .containsEntry("computer", 2L);
    assertThat(type(devices, "dc:e9:94:e8:5e:9c"))
        .as("printer announcing _ipp")
        .isEqualTo("printer");
    assertThat(type(devices, "c2:e4:7c:4a:88:23"))
        .as("Mac with a macOS DHCP fingerprint")
        .isEqualTo("computer");
    assertThat(type(devices, "18:48:be:97:d4:b2"))
        .as("Amazon discovery proxy listing every service type of the network")
        .isEqualTo("unknown");
    assertThat(devices)
        .filteredOn(d -> "Philips Lighting BV".equals(d.get("vendor")))
        .allSatisfy(d -> assertThat(d.get("guessed_type")).isEqualTo("iot"));
    assertThat(devices)
        .filteredOn(d -> Integer.valueOf(1).equals(d.get("mac_randomized")))
        .allSatisfy(d -> assertThat(d.get("vendor")).isNull());
    assertThat(
            jdbc.sql(
                    "SELECT COUNT(*) FROM observation o JOIN device d ON d.id = o.device_id WHERE d.network_id = :n")
                .param("n", network)
                .query(Integer.class)
                .single())
        .isEqualTo(observations.size());
  }

  private static Object type(List<Map<String, Object>> devices, String mac) {
    return devices.stream()
        .filter(d -> mac.equals(d.get("mac")))
        .findFirst()
        .orElseThrow()
        .get("guessed_type");
  }
}
