package com.blogspot.nombre_temp.multi_player.auth.config;

import com.blogspot.nombre_temp.multi_player.auth.controller.SignInController;
import com.blogspot.nombre_temp.multi_player.auth.filter.StatelessCsrfFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.WebFilterChainServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import reactor.core.publisher.Mono;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@EnableWebFluxSecurity
public class SecurityConfig {

  @Bean
  public SecurityWebFilterChain securitygWebFilterChain(ServerHttpSecurity http, AuthenticationWebFilter tokenFilter) {
    return http
      .authorizeExchange()
        .pathMatchers(HttpMethod.GET, "/actuator/*")
          .permitAll()
        .anyExchange()
          .authenticated()
      .and()
      .formLogin()
        .loginPage(SignInController.SIGN_IN_PATH)
        .authenticationFailureHandler(
            (exchange, exception) -> setStatus(exchange.getExchange().getResponse(), UNAUTHORIZED))
        .authenticationSuccessHandler(new WebFilterChainServerAuthenticationSuccessHandler())
      .and()
      .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
      .exceptionHandling()
        .authenticationEntryPoint((exchange, exception) -> setStatus(exchange.getResponse(), UNAUTHORIZED))
        .accessDeniedHandler(new HttpStatusServerAccessDeniedHandler(FORBIDDEN))
      .and()
      .csrf()
        .disable()
      .addFilterAt(new StatelessCsrfFilter(), SecurityWebFiltersOrder.CSRF)
      .addFilterAt(tokenFilter, SecurityWebFiltersOrder.AUTHENTICATION)
      .logout()
        .disable()
      .build();
  }

  private Mono<Void> setStatus(ServerHttpResponse response, HttpStatus httpStatus) {
    return Mono.fromRunnable(() -> response.setStatusCode(httpStatus));
  }

  @Bean
  public CorsConfigurationSource corsConfigurationSource(
      @Value("${security.cors.allowed-origin}") String allowedOrigin) {
    CorsConfiguration corsConfig = new CorsConfiguration();
    corsConfig.addAllowedOrigin(allowedOrigin);
    corsConfig.addAllowedMethod("*");
    corsConfig.setAllowCredentials(true);
    corsConfig.addAllowedHeader(StatelessCsrfFilter.CSRF_KEY);

    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", corsConfig);

    return source;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public ReactiveUserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
    return new MapReactiveUserDetailsService(
      User.withUsername("user@test.com").password(passwordEncoder.encode("user@test.com")).roles("USER").build(),
      User.withUsername("admin@test.com").password(passwordEncoder.encode("admin@test.com")).roles("ADMIN").build());
  }
}
