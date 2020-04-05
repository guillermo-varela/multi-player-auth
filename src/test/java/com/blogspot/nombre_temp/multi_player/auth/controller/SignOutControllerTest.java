package com.blogspot.nombre_temp.multi_player.auth.controller;

import com.blogspot.nombre_temp.multi_player.auth.model.User;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.http.HttpCookie;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.csrf;

@WithMockUser
@WebFluxTest(SignOutController.class)
@ExtendWith(SpringExtension.class)
public class SignOutControllerTest {

  @Autowired
  private WebTestClient webClient;

  @Test
  public void testSignOut() {
    webClient.mutateWith(csrf())
        .post()
        .uri("/signOut")
        .exchange()
        .expectStatus()
          .isOk()
        .returnResult(User.class)
          .consumeWith(exchangeResult -> {
            HttpCookie cookie = exchangeResult.getResponseCookies().get(TOKEN_COOKIE_NAME).stream().findFirst().get();
            assertTrue(cookie.getValue() == null || cookie.getValue().isEmpty());
          });
  }
}
