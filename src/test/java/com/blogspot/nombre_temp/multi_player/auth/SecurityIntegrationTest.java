package com.blogspot.nombre_temp.multi_player.auth;

import java.util.UUID;

import com.blogspot.nombre_temp.multi_player.auth.model.User;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClient.RequestBodySpec;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;
import static com.blogspot.nombre_temp.multi_player.auth.filter.StatelessCsrfFilter.CSRF_KEY;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
@AutoConfigureWebTestClient
@ExtendWith(SpringExtension.class)
public class SecurityIntegrationTest {

  private static final String USERNAME = "user@test.com";

  @Autowired
  private WebTestClient webTestClient;

  @Autowired
  private JWSSigner jwsSigner;

  @Test
  public void testNoCsrfAndNoUser() {
    buildRequest(false, false, null)
        .exchange()
        .expectStatus()
          .isForbidden()
        .expectBody()
          .isEmpty();
  }

  @Test
  public void testWithCsrfAndNoUser() {
    buildRequest(true, false, null)
        .exchange()
        .expectStatus()
          .isUnauthorized()
        .expectBody()
          .isEmpty();
  }

  @Test
  public void testNoCsrfAndInvalidUser() {
    buildRequest(false, true, "invalid@test.com")
        .exchange()
        .expectStatus()
          .isForbidden()
        .expectBody()
          .isEmpty();
  }

  @Test
  public void testNoCsrfAndValidUser() {
    buildRequest(false, true, USERNAME)
        .exchange()
        .expectStatus()
          .isForbidden()
        .expectBody()
          .isEmpty();
  }

  @Test
  public void testWithCsrfAndInvalidUser() {
    buildRequest(true, true, "invalid@test.com")
        .exchange()
        .expectStatus()
          .isUnauthorized()
        .expectBody()
          .isEmpty();
  }

  @Test
  public void testWithCsrfAndValidUser() {
    buildRequest(true, true, USERNAME)
        .exchange()
        .expectStatus()
          .isOk()
        .expectBody(User.class)
          .consumeWith(exchange -> assertEquals(USERNAME, exchange.getResponseBody().getUsername()));
  }

  private RequestBodySpec buildRequest(boolean withCsrf, boolean withJwtCookie, String username) {
    try {
      RequestBodySpec requestBodySpec = webTestClient.post().uri("/checkAuthentication");

      if (withCsrf) {
        requestBodySpec.header(CSRF_KEY, UUID.randomUUID().toString());
      }
      if (withJwtCookie) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
            .subject(username)
            .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        signedJWT.sign(jwsSigner);

        requestBodySpec.cookie(TOKEN_COOKIE_NAME, signedJWT.serialize());
      }

      return requestBodySpec;
    }
    catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}
