package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.OAuthConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.NewCookie;

import java.time.Duration;

@ApplicationScoped
public class CookieService {

    private final OAuthConfig.CookieConfig config;
    private final EncryptionService encryptionService;

    @Inject
    CookieService(OAuthConfig config, EncryptionService encryptionService) {
        this.config = config.cookie();
        this.encryptionService = encryptionService;
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
        try {
            String encryptedToken = encryptionService.encrypt(token);
            return createCookie(config.name(), encryptedToken, config.maxAge());
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt token", e);
        }
    }

    public String decryptAuthCookie(String encryptedToken) {
        try {
            return encryptionService.decrypt(encryptedToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt token", e);
        }
    }

    public NewCookie createLogoutCookie() {
        return createCookie(config.name(), "", Duration.ZERO);
    }
}