package com.blogspot.nombre_temp.multi_player.auth.config;

import com.blogspot.nombre_temp.multi_player.auth.controller.SignInController;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.pivovarit.function.ThrowingPredicate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import reactor.core.publisher.Mono;

import static com.pivovarit.function.ThrowingFunction.unchecked;

@Configuration
public class JsonWebTokenConfig {

  private final String jwtSecret;

  private final JWSVerifier jwsVerifier;

  public JsonWebTokenConfig(@Value("${jwt.secret}") String jwtSecret) throws JOSEException {
    this.jwtSecret = jwtSecret;
    jwsVerifier = new MACVerifier(jwtSecret);
  }

  @Bean
  public JWSSigner jwsSigner() throws KeyLengthException {
    return new MACSigner(jwtSecret);
  }

  @Bean
  public AuthenticationWebFilter tokenAuthenticationFilter(ReactiveUserDetailsService userDetailsService) {
    AuthenticationWebFilter filter = new AuthenticationWebFilter(tokenAuthenticationManager(userDetailsService));
    filter.setServerAuthenticationConverter(tokenAuthenticationConverter());
    filter.setAuthenticationFailureHandler((exchange, exception) -> Mono.error(exception));
    return filter;
  }

  private ReactiveAuthenticationManager tokenAuthenticationManager(ReactiveUserDetailsService userDetailsService) {
    return authentication -> {
      SignedJWT credentials = (SignedJWT) authentication.getCredentials();
      return Mono.just(credentials)
          .flatMap(unchecked(jwt -> userDetailsService.findByUsername(jwt.getJWTClaimsSet().getSubject())))
          .switchIfEmpty(Mono.error(new BadCredentialsException("Invalid Credentials")))
          .map(user -> new UsernamePasswordAuthenticationToken(user, credentials, user.getAuthorities()));
    };
  }

  private ServerAuthenticationConverter tokenAuthenticationConverter() {
    return exchange -> Mono.justOrEmpty(exchange.getRequest().getCookies().getFirst(SignInController.TOKEN_COOKIE_NAME))
        .map(HttpCookie::getValue)
        .map(unchecked(SignedJWT::parse))
        .filter(ThrowingPredicate.unchecked(signedJwt -> signedJwt.verify(jwsVerifier)))
        .map(signedJwt -> new UsernamePasswordAuthenticationToken(null, signedJwt, AuthorityUtils.NO_AUTHORITIES));
  }
}
