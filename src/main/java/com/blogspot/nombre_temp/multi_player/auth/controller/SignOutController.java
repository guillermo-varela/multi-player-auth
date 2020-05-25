package com.blogspot.nombre_temp.multi_player.auth.controller;

import com.blogspot.nombre_temp.multi_player.auth.config.OpenApiConfig;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;

@RestController
public class SignOutController {

  @Operation(summary = "If there is a valid JWT for an user then removes the cookie to sign out the user.",
      security = @SecurityRequirement(name = OpenApiConfig.CSRF_SECURITY_SCHEME),
      parameters = @Parameter(ref = OpenApiConfig.JWT_COOKIE_PARAMETER_KEY),
      responses = {
          @ApiResponse(responseCode = "200", description = "JWT is valid for an authenticated user, removes the cookie",
              headers = @Header(name = HttpHeaders.SET_COOKIE,
                  description = "Clear value for the cookie " + TOKEN_COOKIE_NAME,
                  schema = @Schema(type = "string", example = TOKEN_COOKIE_NAME + "=;"))),
          @ApiResponse(responseCode = "401", ref = "401"),
          @ApiResponse(responseCode = "403", ref = "403")})
  @PostMapping("/signOut")
  @ResponseStatus(HttpStatus.OK)
  public void signOut(ServerHttpResponse response) {
    response.addCookie(ResponseCookie.from(TOKEN_COOKIE_NAME, null)
        .maxAge(0L)
        .build());
  }
}
