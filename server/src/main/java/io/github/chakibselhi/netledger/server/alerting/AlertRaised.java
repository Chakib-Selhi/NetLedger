package io.github.chakibselhi.netledger.server.alerting;

/** Published when an alert is stored; delivered to the agent once the transaction commits. */
public record AlertRaised(AlertEvent event) {}
