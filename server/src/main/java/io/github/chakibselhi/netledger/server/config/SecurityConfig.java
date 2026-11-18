package io.github.chakibselhi.netledger.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Two filter chains: the agent API, authenticated by token, and everything else, closed until the
 * dashboard exists (phase 4).
 */
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
        .authorizeHttpRequests(a -> a.anyRequest().hasRole("AGENT"))
        .exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
        .build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain everythingElse(HttpSecurity http) throws Exception {
    return http.authorizeHttpRequests(
            a -> a.requestMatchers("/error").permitAll().anyRequest().denyAll())
        .httpBasic(AbstractHttpConfigurer::disable)
        .formLogin(AbstractHttpConfigurer::disable)
        .exceptionHandling(
            e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.NOT_FOUND)))
        .build();
  }

  /** No user accounts: replaces Spring Boot's default user and its generated password. */
  @Bean
  UserDetailsService noUsers() {
    return new InMemoryUserDetailsManager();
  }
}
