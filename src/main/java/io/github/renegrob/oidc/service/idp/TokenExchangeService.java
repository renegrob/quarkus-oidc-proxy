package io.github.renegrob.oidc.service.idp;

import io.github.renegrob.oidc.config.OAuthConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.core.Cookie;

import java.io.StringReader;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

@ApplicationScoped
public class TokenExchangeService {

    private final IdpConfigurationService idpConfigurationService;
    private final OAuthConfig.FederatedClientConfig clientConfig;

    @Inject
    TokenExchangeService(OAuthConfig config, IdpConfigurationService idpConfigurationService) {
        this.clientConfig = config.provider().client();
        this.idpConfigurationService = idpConfigurationService;
    }

    public JsonObject exchangeCodeForToken(String code, Cookie codeVerifierCookie) {
        try {
            StringBuilder formBuilder = new StringBuilder()
                    .append("grant_type=authorization_code")
                    .append("&client_id=").append(URLEncoder.encode(clientConfig.clientId(), StandardCharsets.UTF_8))
                    .append("&client_secret=").append(URLEncoder.encode(clientConfig.clientSecret(), StandardCharsets.UTF_8))
                    .append("&code=").append(URLEncoder.encode(code, StandardCharsets.UTF_8))
                    .append("&redirect_uri=").append(URLEncoder.encode(clientConfig.redirectUri().toString(), StandardCharsets.UTF_8));

            if (clientConfig.pkceMethod().isPresent() && codeVerifierCookie != null) {
                formBuilder.append("&code_verifier=").append(URLEncoder.encode(codeVerifierCookie.getValue(), StandardCharsets.UTF_8));
            }

            String form = formBuilder.toString();

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(idpConfigurationService.tokenEndpoint())
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            try (HttpClient httpClient = HttpClient.newHttpClient()) {
                HttpResponse<String> response = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
                // TODO: improve error handling
                if (response.statusCode() == 400) {
                    throw new BadRequestException("Failed to exchange token: " + response.body());
                }
                if (response.statusCode() != 200) {
                    throw new InternalServerErrorException("Failed to exchange token: " + response.body());
                }
                return Json.createReader(new StringReader(response.body())).readObject();
            }
        } catch (Exception e) {
            throw new RuntimeException("Token exchange failed", e);
        }
    }
}
