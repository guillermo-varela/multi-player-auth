package com.blogspot.nombre_temp.multi_player.auth.controller;

import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.AbstractMap.SimpleEntry;
import java.util.Date;

import com.blogspot.nombre_temp.multi_player.auth.annotations.RestControllerJson;
import com.blogspot.nombre_temp.multi_player.auth.config.OpenApiConfig;
import com.blogspot.nombre_temp.multi_player.auth.model.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.pivovarit.function.ThrowingConsumer;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import reactor.core.publisher.Mono;

import static com.pivovarit.function.ThrowingFunction.unchecked;

@RestControllerJson
public class SignInController {

  public static final String SIGN_IN_PATH = "/signIn";

  public static final String TOKEN_COOKIE_NAME = "MULTI-PLAYER-AUTH-TOKEN";

  private final JWSSigner jwsSigner;

  private final boolean useSecureCookie;

  public SignInController(JWSSigner jwsSigner, @Value("${jwt.cookie.is-secure}") boolean useSecureCookie) {
    this.jwsSigner = jwsSigner;
    this.useSecureCookie = useSecureCookie;
  }

  @Operation(summary = "If credentials are valid then returns the data for the user and sets cookie with JWT.",
      security = @SecurityRequirement(name = OpenApiConfig.CSRF_SECURITY_SCHEME),
      requestBody = @RequestBody(required = true,
          content = @Content(mediaType = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
              schema = @Schema(type = "object", implementation = SignInForm.class))),
      responses = {
          @ApiResponse(responseCode = "200", description = "Credentials are valid, JWT and user data are returned",
              headers = @Header(name = HttpHeaders.SET_COOKIE,
                  description = "JWT in an HttpOnly cookie named " + TOKEN_COOKIE_NAME,
                  schema = @Schema(type = "string", example = TOKEN_COOKIE_NAME + "=abc123…; HttpOnly"))),
          @ApiResponse(responseCode = "401", ref = "401"),
          @ApiResponse(responseCode = "403", ref = "403")})
  @PostMapping(SIGN_IN_PATH)
  public Mono<User> signIn(ServerHttpResponse response) {
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .map(Authentication::getPrincipal)
        .cast(UserDetails.class)
        .map(unchecked(this::buildToken))
        .doOnNext(ThrowingConsumer.unchecked(entry -> buildCookie(entry.getValue(), response)))
        .map(unchecked(this::buildUser));
  }

  private SimpleEntry<UserDetails, SignedJWT> buildToken(UserDetails userDetails) throws JOSEException {
    JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
        .subject(userDetails.getUsername())
        .expirationTime(Date.from(LocalDateTime.now().plusMonths(1L).atZone(ZoneId.systemDefault()).toInstant()))
        .build();

    SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
    signedJWT.sign(jwsSigner);

    return new SimpleEntry<>(userDetails, signedJWT);
  }

  private void buildCookie(SignedJWT token, ServerHttpResponse response) throws ParseException {
    JWTClaimsSet jWTClaimsSet = token.getJWTClaimsSet();
    Date expirationDate = jWTClaimsSet.getExpirationTime();

    response.addCookie(ResponseCookie.from(TOKEN_COOKIE_NAME, token.serialize())
        .httpOnly(true)
        .secure(useSecureCookie)
        .sameSite("None")
        .maxAge(Duration.between(Instant.now(), expirationDate.toInstant()))
        .build());
  }

  private User buildUser(SimpleEntry<UserDetails, SignedJWT> entry) throws ParseException {
    SignedJWT token = entry.getValue();
    JWTClaimsSet jWTClaimsSet = token.getJWTClaimsSet();

    return new User(entry.getKey(), jWTClaimsSet.getExpirationTime());
  }

  // Just for the OpenAPI documentation
  @Schema(description = "Fields on the sign in form")
  @SuppressWarnings("unused")
  private static class SignInForm {
    public String username;

    public String password;
  }
}
