package io.github.chakibselhi.netledger.server.api;

import static io.github.chakibselhi.netledger.server.api.AgentApiTest.authorized;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityTest {

  @Autowired MockMvc mvc;

  @Test
  void apiRequiresTheExactToken() throws Exception {
    mvc.perform(get("/api/v1/health")).andExpect(status().isUnauthorized());
    mvc.perform(get("/api/v1/health").header("Authorization", "Bearer wrong"))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/api/v1/health").header("Authorization", "Bearer " + AgentApiTest.TOKEN + "x"))
        .andExpect(status().isUnauthorized());
    mvc.perform(get("/api/v1/health").header("Authorization", AgentApiTest.TOKEN))
        .andExpect(status().isUnauthorized());
    mvc.perform(
            post("/api/v1/networks/current").contentType(MediaType.APPLICATION_JSON).content("{}"))
        .andExpect(status().isUnauthorized());
  }

  @Test
  void createsNoSessionAndNoCookie() throws Exception {
    mvc.perform(authorized(get("/api/v1/health")))
        .andExpect(status().isOk())
        .andExpect(header().doesNotExist("Set-Cookie"));
  }

  @Test
  void unknownPathsAreNotFound() throws Exception {
    mvc.perform(get("/actuator/env")).andExpect(status().isNotFound());
    mvc.perform(authorized(get("/api/v1/nope"))).andExpect(status().isNotFound());
  }

  @Test
  void refusesRequestsAddressedToAnotherHostName() throws Exception {
    mvc.perform(authorized(get("/api/v1/health")).header("Host", "evil.example:8080"))
        .andExpect(status().is(421));
    mvc.perform(get("/ui/networks").header("Host", "rebind.attacker.test"))
        .andExpect(status().is(421));
    mvc.perform(authorized(get("/api/v1/health")).header("Host", "127.0.0.1:8080"))
        .andExpect(status().isOk());
    mvc.perform(get("/ui/networks").header("Host", "[::1]:8080")).andExpect(status().isOk());
  }

  @Test
  void rejectsHugeBodiesBeforeReadingThem() throws Exception {
    byte[] huge = new byte[3 * 1024 * 1024];

    mvc.perform(
            authorized(post("/api/v1/observations"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(huge))
        .andExpect(status().isPayloadTooLarge());
  }
}
