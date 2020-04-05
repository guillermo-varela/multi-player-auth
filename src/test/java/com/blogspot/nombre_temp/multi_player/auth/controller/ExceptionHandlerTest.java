package com.blogspot.nombre_temp.multi_player.auth.controller;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.blogspot.nombre_temp.multi_player.auth.controller.ExceptionHandler;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

@ExtendWith(SpringExtension.class)
public class ExceptionHandlerTest {

  private final ExceptionHandler handler = new ExceptionHandler();

  @Test
  public void test_handle_internalError() {
    Exception exception = new Exception("This is a test!");
    doTest(exception, HttpStatus.INTERNAL_SERVER_ERROR);
  }

  @Test
  public void test_handle_badCredentialsError() {
    BadCredentialsException exception = new BadCredentialsException("Bad credentials...!");
    doTest(exception, HttpStatus.UNAUTHORIZED);
  }

  private void doTest(Throwable exception, HttpStatus httpStatus) {
    Logger handlerLogger = (Logger) LoggerFactory.getLogger(handler.getClass());
    ListAppender<ILoggingEvent> listAppender = new ListAppender<>();
    listAppender.start();
    handlerLogger.addAppender(listAppender);

    MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.post("/").build());

    handler.handle(exchange, exception).doAfterTerminate(() -> {
      assertFalse(listAppender.list.isEmpty());

      ILoggingEvent loggingEvent = listAppender.list.get(0);
      assertEquals(exception.getMessage(), loggingEvent.getMessage());
      assertEquals(Level.ERROR, loggingEvent.getLevel());

      assertEquals(httpStatus, exchange.getResponse().getStatusCode());
    });
  }
}
