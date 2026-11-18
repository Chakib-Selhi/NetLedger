package io.github.chakibselhi.netledger.server.api;

import org.springframework.http.HttpStatus;

/** An expected client error, rendered as an RFC 9457 problem with a safe, explicit message. */
public class ApiException extends RuntimeException {

  private final HttpStatus status;

  public ApiException(HttpStatus status, String message) {
    super(message);
    this.status = status;
  }

  HttpStatus status() {
    return status;
  }
}
