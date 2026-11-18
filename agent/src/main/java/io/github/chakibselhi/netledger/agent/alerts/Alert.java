package io.github.chakibselhi.netledger.agent.alerts;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * An alert pushed by the server.
 *
 * @param path dashboard page to open, relative to the server, such as {@code /devices/12}
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record Alert(
    long id,
    String kind,
    String title,
    String message,
    boolean sound,
    String occurredAt,
    String path) {}
