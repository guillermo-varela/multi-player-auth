package com.blogspot.nombre_temp.multi_player.auth.config;

import com.blogspot.nombre_temp.multi_player.auth.filter.StatelessCsrfFilter;
import io.swagger.v3.oas.annotations.enums.ParameterIn;
import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityScheme.In;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static com.blogspot.nombre_temp.multi_player.auth.controller.SignInController.TOKEN_COOKIE_NAME;

@Configuration
public class OpenApiConfig {

  public static final String CSRF_SECURITY_SCHEME = "csrf";

  public static final String JWT_COOKIE_PARAMETER_KEY = "jwtCookieParameter";

  @Bean
  public OpenAPI customOpenAPI() {
    return new OpenAPI()
        .info(new Info()
            .title("multi-player-auth API")
            .description("Authentication API for multi-player applications.")
            .version("1"))
        .components(new Components()
            .addSecuritySchemes(CSRF_SECURITY_SCHEME, new SecurityScheme()
                .type(SecurityScheme.Type.APIKEY)
                .in(In.HEADER)
                .name(StatelessCsrfFilter.CSRF_KEY))
            .addParameters(JWT_COOKIE_PARAMETER_KEY, new Parameter()
                .name(TOKEN_COOKIE_NAME)
                .description("A valid JWT for an authenticated user")
                .in(ParameterIn.COOKIE.name())
                .required(true))
            .addResponses("401", new ApiResponse().description("Invalid authentication credentials"))
            .addResponses("403", new ApiResponse().description("Invalid or missing CSRF token")));
  }
}
