package io.github.chakibselhi.netledger.core.model;

import java.util.List;

/** Body of {@code POST /api/v1/observations}: observations sent together by the agent. */
public record ObservationBatch(List<Observation> observations) {

  public ObservationBatch {
    observations = observations == null ? List.of() : List.copyOf(observations);
  }
}
