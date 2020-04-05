package com.blogspot.nombre_temp.multi_player.auth.controller;

import com.blogspot.nombre_temp.multi_player.auth.config.JsonWebTokenConfig;
import com.blogspot.nombre_temp.multi_player.auth.model.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;
import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInControllerTest.TEST_USERNAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser(TEST_USERNAME)
@WebFluxTest(CheckAuthenticationController.class)
@ExtendWith(SpringExtension.class)
@Import(JsonWebTokenConfig.class)
public class CheckAuthenticationControllerTest {

  @Autowired
  private WebTestClient webClient;

  @Test
  public void testCheckAuthentication() throws JOSEException {
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(TEST_USERNAME).build();
    SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
    signedJWT.sign(new MACSigner("TEST-239CDD65B5AF54)()=623E7272D9"));

    webClient.mutateWith(csrf())
        .post()
        .uri("/checkAuthentication")
        .cookie(TOKEN_COOKIE_NAME, signedJWT.serialize())
        .exchange()
        .expectStatus()
          .isOk()
        .expectBody(User.class)
          .consumeWith(exchange -> assertEquals(TEST_USERNAME, exchange.getResponseBody().getUsername()));
  }
}
