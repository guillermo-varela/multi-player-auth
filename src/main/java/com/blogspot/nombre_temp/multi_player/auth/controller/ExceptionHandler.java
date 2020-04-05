package com.blogspot.nombre_temp.multi_player.auth.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Component
@Order(-2)
public class ExceptionHandler implements WebExceptionHandler {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExceptionHandler.class);

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, Throwable exception) {
    LOGGER.error(exception.getMessage(), exception);

    HttpStatus status = exception instanceof BadCredentialsException ? UNAUTHORIZED : INTERNAL_SERVER_ERROR;
    return Mono.fromRunnable(() -> exchange.getResponse().setStatusCode(status));
  }
}
