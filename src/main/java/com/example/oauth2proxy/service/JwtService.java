package com.example.oauth2proxy.service;

import com.example.oauth2proxy.config.OAuthConfig;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.Instant;

@ApplicationScoped
public class JwtService {

    @Inject
    OAuthConfig config;

    @Inject
    JWTParser jwtParser;

    public boolean validateToken(String token) {
        try {
            JsonWebToken jwt = jwtParser.parse(token);

            // Check if token is expired
            Long expiration = jwt.getClaim(config.jwt().expirationKey());
            if (expiration != null) {
                Instant expirationInstant = Instant.ofEpochSecond(expiration);
                if (Instant.now().isAfter(expirationInstant)) {
                    return false;
                }
            }

            return true;
        } catch (ParseException e) {
            return false;
        }
    }

    public String getUserId(String token) {
        try {
            JsonWebToken jwt = jwtParser.parse(token);
            return jwt.getClaim(config.jwt().subjectKey());
        } catch (ParseException e) {
            return null;
        }
    }

    public String getIssuer(String token) {
        try {
            JsonWebToken jwt = jwtParser.parse(token);
            return jwt.getClaim(config.jwt().issuerKey());
        } catch (ParseException e) {
            return null;
        }
    }
}