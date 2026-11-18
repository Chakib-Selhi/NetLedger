package io.github.chakibselhi.netledger.agent.server;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Server answer to a network declaration.
 *
 * @param capture true only for networks the user declared as theirs or authorized
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record NetworkDecision(long networkId, String trust, boolean capture) {

  /** Active ARP scanning is reserved to networks the user owns (EF-17). */
  public boolean owned() {
    return "owned".equals(trust);
  }
}
