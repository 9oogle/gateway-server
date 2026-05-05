package com.goggles.gateway_server.filter;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.handler.predicate.HeaderRoutePredicateFactory;
import org.springframework.core.Ordered;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Slf4j
@Component
public class JwtAuthenticationFilter implements GlobalFilter, Ordered {

  private static final String HEADER_USER_ID = "X-User-Id";
  private static final String HEADER_USER_ROLE = "X-User-Role";
  private static final String HEADER_USER_EMAIL = "X-User-Email";
  private static final String HEADER_USER_NAME = "X-User-Name";
  private final HeaderRoutePredicateFactory headerRoutePredicateFactory;

  public JwtAuthenticationFilter(HeaderRoutePredicateFactory headerRoutePredicateFactory) {
    this.headerRoutePredicateFactory = headerRoutePredicateFactory;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    ServerHttpRequest cleanedRequest =
        exchange
            .getRequest()
            .mutate()
            .headers(
                headers -> {
                  headers.remove(HEADER_USER_ID);
                  headers.remove(HEADER_USER_ROLE);
                  headers.remove(HEADER_USER_EMAIL);
                  headers.remove(HEADER_USER_NAME);
                })
            .build();

    ServerWebExchange cleanedExchange = exchange.mutate().request(cleanedRequest).build();

    return cleanedExchange
        .getPrincipal()
        .cast(JwtAuthenticationToken.class)
        .flatMap(
            auth -> {
              Jwt jwt = auth.getToken();

              String userId = jwt.getSubject();
              String email = jwt.getClaimAsString("email");
              String name = jwt.getClaimAsString("given_name");
              String role = extractRole(jwt);

              log.debug("[UserContextFilter] userId={}, role={}", userId, role);

              ServerHttpRequest authedRequest =
                  cleanedExchange
                      .getRequest()
                      .mutate()
                      .header(HEADER_USER_ID, userId != null ? userId : "")
                      .header(HEADER_USER_EMAIL, email != null ? email : "")
                      .header(HEADER_USER_ROLE, role)
                      .header(HEADER_USER_NAME, encodeName(name))
                      .build();

              return chain.filter(cleanedExchange.mutate().request(authedRequest).build());
            })
        .switchIfEmpty(chain.filter(cleanedExchange));
  }

  private String extractRole(Jwt jwt) {
    Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
    if (realmAccess == null) return "";

    List<String> roles = (List<String>) realmAccess.get("roles");
    if (roles == null) return "";

    return roles.stream()
        .filter(r -> r.equals("STUDENT") || r.equals("INSTRUCTOR") || r.equals("MASTER"))
        .findFirst()
        .orElse("");
  }

  private String encodeName(String name) {
    if (name == null || name.isBlank()) {
      return "";
    }
    return URLEncoder.encode(name, StandardCharsets.UTF_8);
  }

  @Override
  public int getOrder() {
    return SecurityWebFiltersOrder.AUTHORIZATION.getOrder() + 1;
  }
}
