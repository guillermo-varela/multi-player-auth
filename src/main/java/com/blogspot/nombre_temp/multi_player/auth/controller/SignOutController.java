package com.blogspot.nombre_temp.multi_player.auth.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;

@RestController
public class SignOutController {

  @PostMapping("/signOut")
  @ResponseStatus(HttpStatus.OK)
  public void signOut(ServerHttpResponse response) {
    response.addCookie(ResponseCookie.from(TOKEN_COOKIE_NAME, null)
        .maxAge(0L)
        .build());
  }
}
