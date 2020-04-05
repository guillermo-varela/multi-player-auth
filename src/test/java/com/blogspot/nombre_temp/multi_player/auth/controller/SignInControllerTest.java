package com.blogspot.nombre_temp.multi_player.auth.controller;

import java.util.Date;

import com.blogspot.nombre_temp.multi_player.auth.config.JsonWebTokenConfig;
import com.blogspot.nombre_temp.multi_player.auth.model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.SIGN_IN_PATH;
import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser(SignInControllerTest.TEST_USERNAME)
@WebFluxTest(SignInController.class)
@ExtendWith(SpringExtension.class)
@Import(JsonWebTokenConfig.class)
public class SignInControllerTest {

  public static final String TEST_USERNAME = "user-test@test.com";

  @Autowired
  private WebTestClient webClient;

  @Test
  public void testSignIn() {
    webClient.mutateWith(csrf())
        .post()
        .uri(SIGN_IN_PATH)
        .exchange()
        .expectStatus()
          .isOk()
        .returnResult(User.class)
          .consumeWith(exchangeResult -> {
            assertFalse(exchangeResult.getResponseCookies().get(TOKEN_COOKIE_NAME).isEmpty());

            User user = exchangeResult.getResponseBody().blockFirst();
            assertNotNull(user);
            assertEquals(TEST_USERNAME, user.getUsername());
            assertFalse(user.getRoles().isEmpty());
            assertTrue(user.getSessionExpirationDate().after(new Date()));
          });
  }
}
