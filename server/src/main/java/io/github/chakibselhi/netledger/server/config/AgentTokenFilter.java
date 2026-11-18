package io.github.chakibselhi.netledger.server.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates the agent by its shared token ({@code Authorization: Bearer <token>}).
 *
 * <p>Both values are hashed before comparison, then compared with {@link MessageDigest#isEqual},
 * whose duration does not depend on where the first differing byte is. A plain {@code equals} would
 * return earlier for a wrong first character, letting an attacker guess the token byte by byte from
 * response times.
 */
final class AgentTokenFilter extends OncePerRequestFilter {

  static final String ROLE_AGENT = "ROLE_AGENT";
  private static final String PREFIX = "Bearer ";

  private final byte[] expectedHash;

  AgentTokenFilter(String token) {
    this.expectedHash = sha256(token);
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String header = request.getHeader("Authorization");
    if (header != null
        && header.startsWith(PREFIX)
        && MessageDigest.isEqual(expectedHash, sha256(header.substring(PREFIX.length())))) {
      var authentication =
          UsernamePasswordAuthenticationToken.authenticated(
              "agent", null, List.of(new SimpleGrantedAuthority(ROLE_AGENT)));
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    chain.doFilter(request, response);
  }

  private static byte[] sha256(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is always available", e);
    }
  }
}
