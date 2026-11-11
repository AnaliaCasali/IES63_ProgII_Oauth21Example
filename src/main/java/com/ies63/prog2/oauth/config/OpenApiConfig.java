package com.ies63.prog2.oauth.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.OAuthFlow;
import io.swagger.v3.oas.models.security.OAuthFlows;
import io.swagger.v3.oas.models.security.Scopes;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * Swagger UI con el flujo Authorization Code + PKCE.
 * El botón "Authorize" abre /oauth2/authorize, el usuario inicia sesión y Swagger recibe el token.
 * PKCE y el client-id se configuran en application.properties (springdoc.swagger-ui.oauth.*).
 */
@Configuration
public class OpenApiConfig implements WebMvcConfigurer {

  public static final String OAUTH2_SCHEME = "oauth2";

  private static final String API_TITLE = "API Ejemplo ProgII IES63 Oauth";
  private static final String API_VERSION = "2.0.0";
  private static final String API_DESCRIPTION = "API REST protegida con OAuth 2.1 (Authorization Code + PKCE)";
  private static final String CONTACT_NAME = "Analía Casali";
  private static final String CONTACT_EMAIL = "mail@mail.com";

  @Override
  public void addViewControllers(ViewControllerRegistry registry) {
    registry.addRedirectViewController("/", "/swagger-ui.html");
  }

  @Bean
  public OpenAPI customOpenAPI(@Value("${app.auth-server-url:http://localhost:8080}") String authServerUrl) {
    OAuthFlow authorizationCode = new OAuthFlow()
        .authorizationUrl(authServerUrl + "/oauth2/authorize")
        .tokenUrl(authServerUrl + "/oauth2/token")
        .scopes(new Scopes()
            .addString("openid", "Identidad del usuario (OIDC)")
            .addString("profile", "Perfil básico")
            .addString("api.read", "Leer recursos de la API"));

    return new OpenAPI()
        .info(new Info()
            .title(API_TITLE)
            .version(API_VERSION)
            .description(API_DESCRIPTION)
            .contact(new Contact().name(CONTACT_NAME).email(CONTACT_EMAIL)))
        .components(new Components()
            .addSecuritySchemes(OAUTH2_SCHEME, new SecurityScheme()
                .type(SecurityScheme.Type.OAUTH2)
                .flows(new OAuthFlows().authorizationCode(authorizationCode))));
  }
}
