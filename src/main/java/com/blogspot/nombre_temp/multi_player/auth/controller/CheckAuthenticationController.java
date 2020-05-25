package com.blogspot.nombre_temp.multi_player.auth.controller;

import java.text.ParseException;
import java.util.Date;

import com.blogspot.nombre_temp.multi_player.auth.annotations.RestControllerJson;
import com.blogspot.nombre_temp.multi_player.auth.config.OpenApiConfig;
import com.blogspot.nombre_temp.multi_player.auth.model.User;
import com.nimbusds.jwt.SignedJWT;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import reactor.core.publisher.Mono;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;
import static com.pivovarit.function.ThrowingFunction.unchecked;

@RestControllerJson
public class CheckAuthenticationController {

  @Operation(summary = "If there is a valid JWT for an user then returns the data for that user.",
      security = @SecurityRequirement(name = OpenApiConfig.CSRF_SECURITY_SCHEME),
      parameters = @Parameter(ref = OpenApiConfig.JWT_COOKIE_PARAMETER_KEY),
      responses = {
          @ApiResponse(responseCode = "200", description = "JWT is valid for an authenticated user, returns user data"),
          @ApiResponse(responseCode = "401", ref = "401"),
          @ApiResponse(responseCode = "403", ref = "403")})
  @PostMapping("/checkAuthentication")
  public Mono<User> checkAuthentication(ServerHttpRequest request) {
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .map(Authentication::getPrincipal)
        .cast(UserDetails.class)
        .map(unchecked(userDetails -> buildUser(request, userDetails)));
  }

  private User buildUser(ServerHttpRequest request, UserDetails userDetails) throws ParseException {
    SignedJWT signedJWT = SignedJWT.parse(request.getCookies().getFirst(TOKEN_COOKIE_NAME).getValue());
    Date expirationDate = signedJWT.getJWTClaimsSet().getExpirationTime();
    return new User(userDetails, expirationDate);
  }
}
