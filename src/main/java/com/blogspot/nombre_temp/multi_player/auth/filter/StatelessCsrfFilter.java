package com.blogspot.nombre_temp.multi_player.auth.filter;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

public class StatelessCsrfFilter implements WebFilter {

  public static final String CSRF_KEY = "MULTI-PLAYER-AUTH-CSRF";

  static final Set<HttpMethod> ALLOWED_METHODS =
      new HashSet<>(Arrays.asList(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.TRACE, HttpMethod.OPTIONS));

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    ServerHttpRequest request = exchange.getRequest();

    if (ALLOWED_METHODS.contains(request.getMethod()) || StringUtils.hasText(request.getHeaders().getFirst(CSRF_KEY))) {
      return chain.filter(exchange);
    }

    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
    return Mono.empty();
  }
}
