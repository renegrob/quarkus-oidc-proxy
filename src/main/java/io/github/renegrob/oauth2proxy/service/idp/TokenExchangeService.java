package io.github.renegrob.oauth2proxy.service.idp;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.core.Response;

import java.io.StringReader;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

@ApplicationScoped
public class TokenExchangeService {

    private final ConfigurationService configurationService;
    private final OAuthConfig.FederatedClientConfig clientConfig;

    @Inject
    TokenExchangeService(OAuthConfig config, ConfigurationService configurationService) {
        this.clientConfig = config.provider().client();
        this.configurationService = configurationService;
    }

    public JsonObject exchangeCodeForToken(String code) {
        try {
            String form = "grant_type=authorization_code" +
                    "&client_id=" + URLEncoder.encode(clientConfig.clientId(), StandardCharsets.UTF_8) +
                    "&client_secret=" + URLEncoder.encode(clientConfig.clientSecret(), StandardCharsets.UTF_8) +
                    "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8) +
                    "&redirect_uri=" + URLEncoder.encode(clientConfig.redirectUri().toString(), StandardCharsets.UTF_8);

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(configurationService.tokenEndpoint())
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
