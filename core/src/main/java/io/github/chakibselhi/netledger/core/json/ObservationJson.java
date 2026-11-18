package io.github.chakibselhi.netledger.core.json;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.chakibselhi.netledger.core.model.ObservationBatch;

/** JSON exchange format between the agent and the server. Timestamps are ISO 8601 UTC strings. */
public final class ObservationJson {

  private static final ObjectMapper MAPPER =
      JsonMapper.builder()
          .addModule(new JavaTimeModule())
          .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
          // An older server must still accept batches from a newer agent.
          .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
          .serializationInclusion(JsonInclude.Include.NON_NULL)
          .build();

  private ObservationJson() {}

  public static ObjectMapper mapper() {
    return MAPPER.copy();
  }

  public static String write(ObservationBatch batch) {
    try {
      return MAPPER.writeValueAsString(batch);
    } catch (JsonProcessingException e) {
      throw new IllegalStateException("Cannot serialize observation batch", e);
    }
  }

  /**
   * Parses a batch.
   *
   * @throws IllegalArgumentException when the JSON is malformed or an observation is invalid
   */
  public static ObservationBatch read(String json) {
    try {
      return MAPPER.readValue(json, ObservationBatch.class);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("Invalid observation batch: " + e.getOriginalMessage(), e);
    }
  }
}
