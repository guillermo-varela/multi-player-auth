package com.blogspot.nombre_temp.multi_player.auth.filter;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.server.WebFilterChain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@WebFluxTest(StatelessCsrfFilter.class)
@ExtendWith(SpringExtension.class)
public class StatelessCsrfFilterTest {

  @Mock
  private WebFilterChain webFilterChainMock;

  private StatelessCsrfFilter filter = new StatelessCsrfFilter();

  @Test
  public void testFilterSkipAllowedMethods() {
    StatelessCsrfFilter.ALLOWED_METHODS.forEach(method -> {
      MockServerHttpRequest request = MockServerHttpRequest
          .method(method, URI.create("http://test.com"))
          .build();
      MockServerWebExchange exchange = MockServerWebExchange.from(request);

      filter.filter(exchange, webFilterChainMock);

      verify(webFilterChainMock).filter(exchange);
      assertNotEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
    });
  }

  @Test
  public void testFilterForbiddenIfNoHeader() {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(HttpMethod.POST, URI.create("http://test.com"))
        .build();
    MockServerWebExchange exchange = MockServerWebExchange.from(request);

    filter.filter(exchange, webFilterChainMock);

    verifyNoInteractions(webFilterChainMock);
    assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
  }

  @Test
  public void testFilterForbiddenIfBlankHeader() {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(HttpMethod.POST, URI.create("http://test.com"))
        .header(StatelessCsrfFilter.CSRF_KEY, " ")
        .build();
    MockServerWebExchange exchange = MockServerWebExchange.from(request);

    filter.filter(exchange, webFilterChainMock);

    verifyNoInteractions(webFilterChainMock);
    assertEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
  }

  @Test
  public void testFilterChainIfHeaderPresent() {
    MockServerHttpRequest request = MockServerHttpRequest
        .method(HttpMethod.POST, URI.create("http://test.com"))
        .header(StatelessCsrfFilter.CSRF_KEY, "test")
        .build();
    MockServerWebExchange exchange = MockServerWebExchange.from(request);

    filter.filter(exchange, webFilterChainMock);

    verify(webFilterChainMock).filter(exchange);
    assertNotEquals(HttpStatus.FORBIDDEN, exchange.getResponse().getStatusCode());
  }
}
