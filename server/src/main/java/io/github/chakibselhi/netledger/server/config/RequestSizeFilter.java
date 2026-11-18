package io.github.chakibselhi.netledger.server.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Rejects request bodies above {@value #MAX_BODY_BYTES} bytes before they are read, and bodies of
 * unknown length, so a client cannot exhaust memory with one huge JSON document.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
class RequestSizeFilter extends OncePerRequestFilter {

  static final long MAX_BODY_BYTES = 2L * 1024 * 1024;

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    boolean hasBody =
        "POST".equals(request.getMethod())
            || "PUT".equals(request.getMethod())
            || "PATCH".equals(request.getMethod());
    long length = request.getContentLengthLong();
    if (hasBody && length < 0) {
      response.setStatus(HttpServletResponse.SC_LENGTH_REQUIRED);
      return;
    }
    if (length > MAX_BODY_BYTES) {
      response.setStatus(HttpServletResponse.SC_REQUEST_ENTITY_TOO_LARGE);
      return;
    }
    chain.doFilter(request, response);
  }
}
