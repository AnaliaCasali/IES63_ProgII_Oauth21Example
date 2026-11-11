# API REST con OAuth 2.1 + PKCE

Spring Boot 4.1 · Spring Security 7.1 · Java 25 · springdoc 3.2

Esta rama no usa Thymeleaf. El backend es una API REST pura. Se prueba con **Postman** y **Swagger UI**, y queda lista para un cliente **Angular**.

## Arquitectura

Una sola aplicación cumple dos roles:

| Rol | Qué hace | Endpoints |
|---|---|---|
| Authorization Server | Autentica al usuario y emite tokens JWT | `/oauth2/authorize`, `/oauth2/token`, `/oauth2/jwks`, `/.well-known/openid-configuration`, `/userinfo`, `/login` |
| Resource Server | Protege la API con `Authorization: Bearer <token>` | `/api/**` |

```
Cliente (Postman / Swagger / Angular)
  1. genera code_verifier y code_challenge = BASE64URL(SHA256(code_verifier))
  2. GET /oauth2/authorize?...&code_challenge=...&code_challenge_method=S256
        → el usuario inicia sesión en /login
        → redirect_uri?code=XYZ
  3. POST /oauth2/token  code=XYZ + code_verifier   (sin client_secret)
        → access_token (JWT) + id_token
  4. GET /api/me   Authorization: Bearer <access_token>
```

Claves de OAuth 2.1 en este proyecto:
- Solo se usa el flujo **Authorization Code**. No hay Implicit ni Password.
- **PKCE obligatorio** (`require-proof-key=true`). Sin `code_challenge` el servidor responde `invalid_request`.
- Los clientes son **públicos**, es decir, no tienen secreto (`client-authentication-methods=none`). Así funcionan una SPA o Postman.
- La `redirect_uri` debe coincidir exactamente con la registrada.

## Clientes registrados

Están en `application.properties`:

| client_id | Redirect URI | Uso |
|---|---|---|
| `postman-client` | `https://oauth.pstmn.io/v1/callback` | Postman |
| `swagger-client` | `http://localhost:8080/swagger-ui/oauth2-redirect.html` | Swagger UI |
| `angular-client` | `http://localhost:4200/callback` | Angular (futuro) |

Scopes disponibles: `openid`, `profile`, `api.read`.

## Usuarios de prueba

| Usuario | Contraseña | Roles |
|---|---|---|
| `alumno` | `alumno123` | USER |
| `profe` | `profe123` | USER, ADMIN |

## Endpoints de la API

| Método | Ruta | Requiere |
|---|---|---|
| GET | `/api/publico` | nada |
| GET | `/api/me` | token válido |
| GET | `/api/saludos` | scope `api.read` |
| GET | `/api/admin` | rol `ADMIN` (claim `roles` del token) |

## Ejecutar

```bash
./mvnw spring-boot:run
```

Requiere JDK 25.

### Opcional: login con Google

Con el perfil `google`, la pantalla `/login` muestra también "Google". El token lo sigue emitiendo esta API.

```bash
export CLIENTID=...      # Google Cloud Console
export CLIENTSECRET=...
./mvnw spring-boot:run -Dspring-boot.run.profiles=google
```

En Google Cloud Console hay que registrar esta redirect URI: `http://localhost:8080/login/oauth2/code/google`.

## Probar con Swagger UI

1. Abrir `http://localhost:8080` (redirige a Swagger UI).
2. Probar `GET /api/publico`. Responde sin token.
3. Clic en **Authorize**. El `client_id` ya viene completo (`swagger-client`). Marcar los scopes y clic en **Authorize**.
4. Iniciar sesión con `alumno` / `alumno123`. Swagger recibe el token, y PKCE ya está activado (`springdoc.swagger-ui.oauth.use-pkce-with-authorization-code-grant=true`).
5. Probar `GET /api/me` y `GET /api/saludos`, que responden 200. `GET /api/admin` responde 403.
6. Clic en **Logout** en Authorize, repetir con `profe` / `profe123` y ver que `/api/admin` responde 200.

## Probar con Postman

1. Importar `postman/OAuth21-PKCE.postman_collection.json`.
2. En la colección, pestaña **Authorization**:
   - Grant type: *Authorization Code (With PKCE)*
   - Code challenge method: *SHA-256*
   - Client ID: `postman-client` (sin secret)
   - Callback URL: `https://oauth.pstmn.io/v1/callback`
3. Clic en **Get New Access Token**. Se abre el login. Ingresar con `alumno` o `profe`.
4. Clic en **Use Token** y ejecutar los requests.
5. Para ver qué contiene el token, pegar el `access_token` en https://jwt.io. Se ven `sub`, `scope`, `roles`, `iss` y `exp`.

## Preparado para Angular

- **CORS**: se permite `http://localhost:4200`. Se cambia con `app.cors.allowed-origins`.
- **Cliente**: `angular-client` es público, usa PKCE y su redirect es `http://localhost:4200/callback`.
- **Discovery**: la librería del cliente lee la configuración de `http://localhost:8080/.well-known/openid-configuration`.

Ejemplo con [`angular-auth-oidc-client`](https://www.npmjs.com/package/angular-auth-oidc-client):

```ts
// app.config.ts
provideAuth({
  config: {
    authority: 'http://localhost:8080',
    clientId: 'angular-client',
    redirectUrl: 'http://localhost:4200/callback',
    postLogoutRedirectUri: 'http://localhost:4200/',
    scope: 'openid profile api.read',
    responseType: 'code',   // Authorization Code + PKCE (automático)
    secureRoutes: ['http://localhost:8080/api/'],
  },
}),
provideHttpClient(withInterceptors([authInterceptor()])),
```

El interceptor agrega `Authorization: Bearer ...` a las llamadas a `/api/**`.

## Tests

```bash
./mvnw test
```

`OauthApplicationTests` cubre:
- El flujo completo: login, `/oauth2/authorize` con PKCE, `/oauth2/token` con `code_verifier` y llamada a la API con el token.
- Que un cliente público sin PKCE sea rechazado.
- Las respuestas 401 sin token y 403 sin rol.
- El preflight de CORS desde Angular.
- La configuración OAuth2 de Swagger.
