package com.ies63.prog2.oauth;

import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OauthApplicationTests {

	private static final String CLIENT_ID = "postman-client";
	private static final String REDIRECT_URI = "https://oauth.pstmn.io/v1/callback";

	@Autowired
	private MockMvc mvc;

	@Test
	void discoveryPublicaPkceS256() throws Exception {
		mvc.perform(get("/.well-known/openid-configuration"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.code_challenge_methods_supported", hasItem("S256")));
	}

	@Test
	void swaggerConfiguradoConPkce() throws Exception {
		mvc.perform(get("/v3/api-docs"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.components.securitySchemes.oauth2.flows.authorizationCode.tokenUrl")
						.value("http://localhost:8080/oauth2/token"));
		mvc.perform(get("/v3/api-docs/swagger-config"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.oauth2RedirectUrl").exists());
	}

	@Test
	void endpointPublicoSinToken() throws Exception {
		mvc.perform(get("/api/publico")).andExpect(status().isOk());
	}

	@Test
	void endpointProtegidoSinTokenDevuelve401() throws Exception {
		mvc.perform(get("/api/me")).andExpect(status().isUnauthorized());
	}

	@Test
	void adminSinRolDevuelve403() throws Exception {
		mvc.perform(get("/api/admin").with(jwt().authorities(() -> "ROLE_USER")))
				.andExpect(status().isForbidden());
	}

	@Test
	void clientePublicoSinPkceEsRechazado() throws Exception {
		mvc.perform(get(authorizeUri(null))
						.with(user("alumno").roles("USER")))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string("Location", containsString("error=invalid_request")));
	}

	@Test
	void corsPermiteAngular() throws Exception {
		mvc.perform(options("/api/me")
						.header("Origin", "http://localhost:4200")
						.header("Access-Control-Request-Method", "GET")
						.header("Access-Control-Request-Headers", "Authorization"))
				.andExpect(status().isOk())
				.andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:4200"));
	}

	/** Flujo completo Authorization Code + PKCE, como lo hacen Postman, Swagger o Angular. */
	@Test
	void flujoCompletoAuthorizationCodeConPkce() throws Exception {
		// 1. El cliente genera code_verifier y code_challenge = BASE64URL(SHA-256(code_verifier))
		byte[] random = new byte[32];
		new SecureRandom().nextBytes(random);
		String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
		String codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(
				MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII)));

		// 2. El usuario inicia sesión en el formulario /login del Authorization Server
		MockHttpSession session = (MockHttpSession) mvc.perform(post("/login")
						.param("username", "profe")
						.param("password", "profe123")
						.with(csrf()))
				.andExpect(status().is3xxRedirection())
				.andReturn().getRequest().getSession();

		// 3. Con la sesión iniciada, pide autorización enviando solo el code_challenge
		String location = mvc.perform(get(authorizeUri(codeChallenge)).session(session))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string("Location", startsWith(REDIRECT_URI)))
				.andReturn().getResponse().getHeader("Location");
		String code = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");

		// 4. Canje del code por el token enviando el code_verifier (sin client_secret)
		String tokenResponse = mvc.perform(post("/oauth2/token")
						.param("grant_type", "authorization_code")
						.param("code", code)
						.param("redirect_uri", REDIRECT_URI)
						.param("client_id", CLIENT_ID)
						.param("code_verifier", codeVerifier))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").exists())
				.andExpect(jsonPath("$.id_token").exists())
				.andReturn().getResponse().getContentAsString();
		String accessToken = JsonPath.read(tokenResponse, "$.access_token");

		// 5. Uso del access token contra la API
		mvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.usuario").value("profe"))
				.andExpect(jsonPath("$.roles", hasItem("ADMIN")))
				.andExpect(jsonPath("$.scopes", hasItem("api.read")));
		mvc.perform(get("/api/admin").header("Authorization", "Bearer " + accessToken))
				.andExpect(status().isOk());
	}

	/** Los parámetros de /oauth2/authorize viajan en la query string, como en el navegador. */
	private static URI authorizeUri(String codeChallenge) {
		UriComponentsBuilder uri = UriComponentsBuilder.fromPath("/oauth2/authorize")
				.queryParam("response_type", "code")
				.queryParam("client_id", CLIENT_ID)
				.queryParam("redirect_uri", REDIRECT_URI)
				.queryParam("scope", "openid api.read")
				.queryParam("state", "xyz");
		if (codeChallenge != null) {
			uri.queryParam("code_challenge", codeChallenge)
					.queryParam("code_challenge_method", "S256");
		}
		return uri.encode().build().toUri();
	}
}
