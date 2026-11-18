package io.github.chakibselhi.netledger.server.config;

import jakarta.servlet.DispatcherType;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/** Two filter chains: the agent API, authenticated by token, and the dashboard. */
@Configuration
class SecurityConfig {

  @Bean
  @Order(1)
  SecurityFilterChain agentApi(HttpSecurity http, NetLedgerProperties properties) throws Exception {
    return http.securityMatcher("/api/**")
        // CSRF abuses cookies the browser adds by itself; a bearer token is never added
        // automatically, so CSRF protection does not apply to this API.
        .csrf(AbstractHttpConfigurer::disable)
        .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .addFilterBefore(
            new AgentTokenFilter(properties.agentToken()), BasicAuthenticationFilter.class)
        // The SSE stream completes on an async dispatch, after the request was authenticated.
        .authorizeHttpRequests(
            a ->
                a.dispatcherTypeMatchers(DispatcherType.ASYNC)
                    .permitAll()
                    .anyRequest()
                    .hasRole("AGENT"))
        .exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .build();
  }

  /**
   * The dashboard has no accounts: it is reachable only from the Mac itself (loopback port, Host
   * check). What remains is a hostile web page open in the same browser, which can send requests to
   * 127.0.0.1 but cannot read the answers:
   *
   * <ul>
   *   <li>CSRF: every change needs a token read from {@code /ui/csrf}, which such a page cannot
   *       read; the session cookie is also {@code SameSite=Strict}.
   *   <li>Content Security Policy: only the dashboard's own scripts run, so a hostile host name
   *       shown in a page can never execute as code even if it slipped past escaping.
   * </ul>
   */
  @Bean
  @Order(2)
  SecurityFilterChain dashboard(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(a -> a.anyRequest().permitAll())
        .csrf(Customizer.withDefaults())
        .headers(
            h ->
                h.contentSecurityPolicy(c -> c.policyDirectives(CONTENT_SECURITY_POLICY))
                    .referrerPolicy(
                        r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)))
        .requestCache(AbstractHttpConfigurer::disable)
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .logout(AbstractHttpConfigurer::disable)
        .build();
  }

  static final String CONTENT_SECURITY_POLICY =
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;"
          + " connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

  /** No user accounts: replaces Spring Boot's default user and its generated password. */
  @Bean
  UserDetailsService noUsers() {
    return new InMemoryUserDetailsManager();
  }
}
