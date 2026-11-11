package com.ies63.prog2.oauth.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

import static com.ies63.prog2.oauth.config.OpenApiConfig.OAUTH2_SCHEME;

@RestController
@RequestMapping("/api")
@Tag(name = "API", description = "Endpoints protegidos con OAuth 2.1 (Bearer JWT)")
public class ApiController {

    public record Mensaje(String texto) {}

    public record Perfil(String usuario, List<String> scopes, List<String> roles, String emisor) {}

    @Operation(summary = "Endpoint público: no requiere token")
    @GetMapping("/publico")
    public Mensaje publico() {
        return new Mensaje("Hola! Este endpoint es público");
    }

    @Operation(summary = "Datos del usuario tomados del access token (JWT)",
            security = @SecurityRequirement(name = OAUTH2_SCHEME))
    @GetMapping("/me")
    public Perfil me(@AuthenticationPrincipal Jwt jwt) {
        return new Perfil(jwt.getSubject(),
                jwt.getClaimAsStringList("scope"),
                jwt.getClaimAsStringList("roles"),
                jwt.getClaimAsString("iss"));
    }

    @Operation(summary = "Requiere el scope api.read",
            security = @SecurityRequirement(name = OAUTH2_SCHEME))
    @GetMapping("/saludos")
    public Mensaje saludos(@AuthenticationPrincipal Jwt jwt) {
        return new Mensaje("Hola " + jwt.getSubject() + ", tu token tiene el scope api.read");
    }

    @Operation(summary = "Requiere el rol ADMIN (usuario profe)",
            security = @SecurityRequirement(name = OAUTH2_SCHEME))
    @GetMapping("/admin")
    public Mensaje admin(@AuthenticationPrincipal Jwt jwt) {
        return new Mensaje("Bienvenido/a al panel de administración, " + jwt.getSubject());
    }
}
