package com.example.oauth2proxy.service;

import com.example.oauth2proxy.config.OAuthConfig;
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
                .maxAge(config.cookie().maxAge())
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