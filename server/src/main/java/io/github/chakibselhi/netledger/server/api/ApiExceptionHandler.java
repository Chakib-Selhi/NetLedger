package io.github.chakibselhi.netledger.server.api;

import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/** Maps errors to problem responses without leaking internals (no stack traces, no SQL). */
@RestControllerAdvice
class ApiExceptionHandler extends ResponseEntityExceptionHandler {

  @ExceptionHandler(ApiException.class)
  ProblemDetail handle(ApiException e) {
    return ProblemDetail.forStatusAndDetail(e.status(), e.getMessage());
  }

  @ExceptionHandler(IllegalArgumentException.class)
  ProblemDetail handle(IllegalArgumentException e) {
    return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, e.getMessage());
  }
}
