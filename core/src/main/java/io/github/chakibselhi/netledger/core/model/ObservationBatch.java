package io.github.chakibselhi.netledger.core.model;

import java.util.List;

/**
 * Body of {@code POST /api/v1/observations}: observations captured on one network.
 *
 * @param networkId identifier returned by {@code POST /api/v1/networks/current} for the network the
 *     observations were captured on
 */
public record ObservationBatch(long networkId, List<Observation> observations) {

  public ObservationBatch {
    observations = observations == null ? List.of() : List.copyOf(observations);
  }
}
