package io.github.renegrob.oauth2proxy.service;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.NewCookie;

@ApplicationScoped
public class CookieService {

    @Inject
    OAuthConfig config;

    @Inject
    JwtService jwtService;

    public NewCookie createAuthCookie(String token) {
        return new NewCookie.Builder(config.cookie().name())
                .value(token)
                .path(config.cookie().path())
                .domain(config.cookie().domain())
                .maxAge((int) config.cookie().maxAge().toSeconds())
                .secure(config.cookie().secure())
                .httpOnly(config.cookie().httpOnly())
                .sameSite(config.cookie().sameSite())
                .build();
    }

    public NewCookie createLogoutCookie() {
        return new NewCookie.Builder(config.cookie().name())
                .value("")
                .path(config.cookie().path())
                .domain(config.cookie().domain())
                .maxAge(0)
                .secure(config.cookie().secure())
                .httpOnly(config.cookie().httpOnly())
                .sameSite(config.cookie().sameSite())
                .build();
    }

    public boolean isValidToken(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        return jwtService.validateToken(token);
    }
}