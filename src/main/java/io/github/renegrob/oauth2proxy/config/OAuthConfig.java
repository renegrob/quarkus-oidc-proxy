package io.github.renegrob.oauth2proxy.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import jakarta.ws.rs.core.NewCookie;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

@ConfigMapping(prefix = "oauth2-proxy")
public interface OAuthConfig {

    @WithName("cookie")
    CookieConfig cookie();

    @WithName("jwt")
    JwtConfig jwt();

    @WithName("provider")
    ProviderConfig provider();

    interface CookieConfig {
        @WithName("name")
        @WithDefault("AUTH_TOKEN")
        String name();

        @WithName("path")
        @WithDefault("/")
        String path();

        @WithName("domain")
        @WithDefault("localhost") // TODO: remove
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
        @WithDefault("24h")
        Duration maxAge();
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

        @WithName("pass-through-claims")
        @WithDefault("roles,groups,scp,email")
        List<String> passThroughClaims();

        @WithName("pass-through-headers")
        @WithDefault("true")
        boolean passThroughHeaders();

        @WithName("claim-to-header-prefix")
        @WithDefault("X-Auth-")
        String claimToHeaderPrefix();
    }

    interface ProviderConfig {
        @WithName("discovery-url")
        Optional<String> discoveryUrl();

        @WithName("discovery-enabled")
        @WithDefault("true")
        boolean discoveryEnabled();

        @WithName("discovery-path")
        @WithDefault(".well-known/openid-configuration")
        String discoveryPath();

        @WithName("auth-server-url")
        URI authServerUrl();

        @WithName("token-path")
        Optional<String> tokenPath();

        @WithName("authorization-path")
        Optional<String> authorizationPath();

        @WithName("jwks-path")
        Optional<String> jwksPath();

        @WithName("userinfo-path")
        Optional<String> userinfoPath();

        @WithName("end-session-path")
        Optional<String> endSessionPath();

        @WithName("issuer")
        Optional<String> issuer();
    }
}