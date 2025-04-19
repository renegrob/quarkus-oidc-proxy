package io.github.renegrob.oidc.service.idp;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.ws.rs.InternalServerErrorException;
import org.jose4j.jwt.JwtClaims;

import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

@ApplicationScoped
public class UserInfoService {

    private final URI userInfoEndpoint;

    @Inject
    UserInfoService(ConfigurationService configurationService) {
        this.userInfoEndpoint = configurationService.userInfoEndpoint().orElse(null);
    }

    public JwtClaims getUserInfo(String accessToken) {
        if (userInfoEndpoint == null) {
            throw new InternalServerErrorException("User info endpoint is not configured");
        }
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(userInfoEndpoint)
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            try (HttpClient httpClient = HttpClient.newHttpClient()) {
                HttpResponse<String> response = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() != 200) {
                    throw new InternalServerErrorException("Failed to fetch user info: " + response.body());
                }
                return JwtClaims.parse(response.body());
            }
        } catch (Exception e) {
            throw new RuntimeException("User info query failed", e);
        }
    }
}