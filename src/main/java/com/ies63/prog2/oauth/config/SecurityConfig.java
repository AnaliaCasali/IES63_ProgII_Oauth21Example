package com.ies63.prog2.oauth.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

/**
 * Una sola aplicación con tres cadenas de filtros:
 * <ol>
 *   <li>Authorization Server: emite tokens (/oauth2/authorize, /oauth2/token, /.well-known/...).</li>
 *   <li>Resource Server: protege /api/** con tokens JWT (sin sesión, sin cookies).</li>
 *   <li>Login: formulario generado por Spring Security (sin Thymeleaf) y, con el perfil "google", login con Google.</li>
 * </ol>
 * Los clientes (Postman, Swagger, Angular) son públicos: no tienen secreto y deben usar PKCE.
 * Se registran en application.properties.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private static final String ROLES_CLAIM = "roles";
  private static final String ROLE_PREFIX = "ROLE_";

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerChain(HttpSecurity http) throws Exception {
    return http
        .oauth2AuthorizationServer(authorizationServer -> {
          // Esta cadena atiende solo los endpoints del Authorization Server.
          http.securityMatcher(authorizationServer.getEndpointsMatcher());
          authorizationServer.oidc(Customizer.withDefaults());
        })
        .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
        .cors(Customizer.withDefaults())
        // Si el navegador llega a /oauth2/authorize sin sesión, se lo manda al login.
        .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
            new LoginUrlAuthenticationEntryPoint("/login"),
            new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
        .build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain apiChain(HttpSecurity http) throws Exception {
    return http
        .securityMatcher("/api/**")
        .authorizeHttpRequests(auth -> auth
            .requestMatchers(HttpMethod.OPTIONS, "/api/**").permitAll()
            .requestMatchers("/api/publico").permitAll()
            .requestMatchers("/api/saludos").hasAuthority("SCOPE_api.read")
            .requestMatchers("/api/admin").hasRole("ADMIN")
            .anyRequest().authenticated())
        .oauth2ResourceServer(rs -> rs.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        // API stateless con Bearer token: no hay cookie de sesión que proteger con CSRF.
        .csrf(csrf -> csrf.disable())
        .cors(Customizer.withDefaults())
        .build();
  }

  @Bean
  @Order(3)
  public SecurityFilterChain loginChain(HttpSecurity http,
      ObjectProvider<ClientRegistrationRepository> googleClients) throws Exception {
    http
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/", "/error", "/swagger-ui.html", "/swagger-ui/**", "/v3/api-docs/**").permitAll()
            .anyRequest().authenticated())
        .formLogin(Customizer.withDefaults())
        .cors(Customizer.withDefaults());
    // Solo con el perfil "google" existe un ClientRegistrationRepository: aparece el botón de Google en /login.
    if (googleClients.getIfAvailable() != null) {
      http.oauth2Login(oauth2 -> oauth2.loginPage("/login"));
    }
    return http.build();
  }

  /** Copia los roles del usuario al access token, en el claim "roles". */
  @Bean
  public OAuth2TokenCustomizer<JwtEncodingContext> rolesTokenCustomizer() {
    return context -> {
      List<String> roles = context.getPrincipal().getAuthorities().stream()
          .map(GrantedAuthority::getAuthority)
          .filter(authority -> authority.startsWith(ROLE_PREFIX))
          .map(authority -> authority.substring(ROLE_PREFIX.length()))
          .toList();
      context.getClaims().claim(ROLES_CLAIM, roles);
    };
  }

  /** Lee scopes ("scope" → SCOPE_x) y roles ("roles" → ROLE_x) del JWT. */
  private JwtAuthenticationConverter jwtAuthenticationConverter() {
    JwtGrantedAuthoritiesConverter scopes = new JwtGrantedAuthoritiesConverter();
    JwtGrantedAuthoritiesConverter roles = new JwtGrantedAuthoritiesConverter();
    roles.setAuthoritiesClaimName(ROLES_CLAIM);
    roles.setAuthorityPrefix(ROLE_PREFIX);

    JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
    converter.setJwtGrantedAuthoritiesConverter(jwt -> {
      var authorities = new ArrayList<GrantedAuthority>(scopes.convert(jwt));
      authorities.addAll(roles.convert(jwt));
      return authorities;
    });
    return converter;
  }

  /** CORS para el futuro cliente Angular (http://localhost:4200 por defecto). */
  @Bean
  public CorsConfigurationSource corsConfigurationSource(
      @Value("${app.cors.allowed-origins:http://localhost:4200}") List<String> allowedOrigins) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(allowedOrigins);
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setMaxAge(3600L);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/**", config);
    return source;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  /** Usuarios de prueba en memoria (solo para clase). Contraseñas guardadas con BCrypt. */
  @Bean
  public UserDetailsService users(PasswordEncoder encoder) {
    return new InMemoryUserDetailsManager(
        User.withUsername("alumno").password(encoder.encode("alumno123")).roles("USER").build(),
        User.withUsername("profe").password(encoder.encode("profe123")).roles("USER", "ADMIN").build());
  }
}
