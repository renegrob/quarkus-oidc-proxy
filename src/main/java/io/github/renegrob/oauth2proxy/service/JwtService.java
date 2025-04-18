package io.github.renegrob.oauth2proxy.service;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
@SuppressWarnings("unused")
public class JwtService {

    @Inject
    OAuthConfig config;

    @Inject
    JWTParser jwtParser;

    public boolean validateToken(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        try {
            JsonWebToken jwt = jwtParser.parse(token);

            // Check if token is expired
            Long expiration = jwt.getClaim(config.jwt().expirationKey());
            if (expiration != null) {
                Instant expirationInstant = Instant.ofEpochSecond(expiration);
                return !Instant.now().isAfter(expirationInstant);
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

    /**
     * Extract specific claims from the JWT token based on configuration
     */
    public Map<String, Object> extractClaims(String token) {
        Map<String, Object> claims = new HashMap<>();
        try {
            JsonWebToken jwt = jwtParser.parse(token);

            // Extract standard claims
            claims.put(config.jwt().subjectKey(), jwt.getClaim(config.jwt().subjectKey()));
            claims.put(config.jwt().issuerKey(), jwt.getClaim(config.jwt().issuerKey()));

            // Extract Azure EntraID specific claims that were configured to pass through
            for (String claimName : config.jwt().passThroughClaims()) {
                if (jwt.containsClaim(claimName)) {
                    claims.put(claimName, jwt.getClaim(claimName));
                }
            }

            // Extract roles if they exist (Azure AD roles/groups)
            if (jwt.containsClaim("roles")) {
                claims.put("roles", jwt.getClaim("roles"));
            }

            // Extract groups if they exist
            if (jwt.containsClaim("groups")) {
                claims.put("groups", jwt.getClaim("groups"));
            }

            // Extract scope if it exists
            if (jwt.containsClaim("scp")) {
                claims.put("scope", jwt.getClaim("scp"));
            }

        } catch (ParseException e) {
            // Log error but return empty map
        }
        return claims;
    }
}