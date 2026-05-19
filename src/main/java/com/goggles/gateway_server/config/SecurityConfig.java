package com.goggles.gateway_server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
        .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
        .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
        .authorizeExchange(
            auth ->
                auth.pathMatchers(HttpMethod.POST, "/api/v1/users")
                    .permitAll()
                    .pathMatchers(HttpMethod.POST, "/api/v1/auth/login")
                    .permitAll()
                    .pathMatchers("/actuator/health", "/actuator/info")
                    .permitAll()
                    .pathMatchers(HttpMethod.GET, "/api/v1/payments/success", "/api/v1/payments/failure")
                    .permitAll()
                    .pathMatchers("/internal/**")
                    .denyAll()
                    .anyExchange()
                    .authenticated())
        .oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> {}))
        .build();
  }
}
