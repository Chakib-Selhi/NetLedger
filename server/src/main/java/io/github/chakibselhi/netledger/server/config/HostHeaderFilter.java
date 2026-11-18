package io.github.chakibselhi.netledger.server.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Accepts only requests addressed to a loopback name, against DNS rebinding.
 *
 * <p>A hostile page at {@code evil.example} can make its DNS name resolve to 127.0.0.1 after the
 * browser loaded it. The browser then treats the dashboard as same-origin with the attacker's page
 * and lets its scripts read responses. Such requests still carry {@code Host: evil.example}, which
 * is how they are recognized and refused.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
class HostHeaderFilter extends OncePerRequestFilter {

  static final int MISDIRECTED_REQUEST = 421;

  private final Set<String> allowed;

  HostHeaderFilter(NetLedgerProperties properties) {
    this.allowed =
        properties.allowedHosts().stream()
            .map(h -> h.toLowerCase(Locale.ROOT))
            .collect(Collectors.toUnmodifiableSet());
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String host = request.getHeader("Host");
    String name = host == null ? request.getServerName() : hostName(host);
    if (name == null || !allowed.contains(name.toLowerCase(Locale.ROOT))) {
      response.sendError(MISDIRECTED_REQUEST);
      return;
    }
    chain.doFilter(request, response);
  }

  /** {@code 127.0.0.1:8080} gives {@code 127.0.0.1}, {@code [::1]:8080} gives {@code [::1]}. */
  static String hostName(String host) {
    String h = host.strip();
    if (h.startsWith("[")) {
      int end = h.indexOf(']');
      return end < 0 ? null : h.substring(0, end + 1);
    }
    int colon = h.indexOf(':');
    return colon < 0 ? h : h.substring(0, colon);
  }
}
