package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.OAuthConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.NewCookie;

import java.time.Duration;

@ApplicationScoped
public class CookieService {

    private final OAuthConfig.CookieConfig config;

    @Inject
    CookieService(OAuthConfig config) {
        this.config = config.cookie();
    }

    public NewCookie createCookie(String name, String value) {
        return createCookie(name, value, config.maxAge());
    }

    public NewCookie createCookie(String name, String value, Duration maxAge) {
        return new NewCookie.Builder(name)
                .value(value)
                .path(config.path())
                .domain(config.domain())
                .maxAge((int) maxAge.toSeconds())
                .secure(config.secure())
                .httpOnly(config.httpOnly())
                .sameSite(config.sameSite())
                .build();
    }

    public NewCookie createSessionCookie(String name, String value) {
        return new NewCookie.Builder(name)
                .value(value)
                .path(config.path())
                .domain(config.domain())
                .maxAge(-1)
                .secure(config.secure())
                .httpOnly(config.httpOnly())
                .sameSite(config.sameSite())
                .build();
    }

    public NewCookie createAuthCookie(String token) {
        return createCookie(config.name(), token, config.maxAge());
    }

    public NewCookie createLogoutCookie() {
        return createCookie(config.name(), "", Duration.ZERO);
    }
}