package io.github.chakibselhi.netledger.agent.server;

/** The server could not be used; {@link #reason()} tells the agent how to react. */
public final class ServerException extends Exception {

  public enum Reason {
    /** Not reachable, timed out or 5xx: retry later, keep the observations. */
    UNAVAILABLE,
    /** 401: the token is wrong; retrying will not help until it is fixed. */
    UNAUTHORIZED,
    /** 403: the network is not monitored (any more); stop capturing on it. */
    NOT_MONITORED,
    /** 404: the server does not know this network (database reset); declare it again. */
    UNKNOWN_NETWORK,
    /** Other 4xx: the request itself is wrong; drop it. */
    REJECTED
  }

  private final Reason reason;

  public ServerException(Reason reason, String message, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }

  public Reason reason() {
    return reason;
  }
}
