package com.example.oauth2proxy.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import io.vertx.core.http.CookieSameSite;
import jakarta.ws.rs.core.NewCookie;

@ConfigMapping(prefix = "oauth2proxy")
public interface OAuthConfig {

    @WithName("cookie")
    CookieConfig cookie();

    @WithName("jwt")
    JwtConfig jwt();

    interface CookieConfig {
        @WithName("name")
        @WithDefault("AUTH_TOKEN")
        String name();

        @WithName("path")
        @WithDefault("/")
        String path();

        @WithName("domain")
        String domain();

        @WithName("secure")
        @WithDefault("true")
        boolean secure();

        @WithName("http-only")
        @WithDefault("true")
        boolean httpOnly();

        @WithName("same-site")
        @WithDefault("Lax")
        NewCookie.SameSite sameSite();

        @WithName("max-age")
        @WithDefault("86400") // 24 hours
        int maxAge();
    }

    interface JwtConfig {
        @WithName("issuer-key")
        @WithDefault("iss")
        String issuerKey();

        @WithName("subject-key")
        @WithDefault("sub")
        String subjectKey();

        @WithName("expiration-key")
        @WithDefault("exp")
        String expirationKey();

        @WithName("header-name")
        @WithDefault("X-Auth-Token")
        String headerName();
    }
}