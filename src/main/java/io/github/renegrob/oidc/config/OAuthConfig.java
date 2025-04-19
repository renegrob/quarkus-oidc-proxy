package io.github.renegrob.oidc.config;

import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;
import io.smallrye.config.WithName;
import io.smallrye.jwt.algorithm.SignatureAlgorithm;
import io.smallrye.jwt.auth.cdi.OptionalClaimTypeProducer;
import jakarta.ws.rs.core.NewCookie;

import javax.swing.text.html.Option;
import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@ConfigMapping(prefix = "oidc")
public interface OAuthConfig {

    @WithName("cookie")
    CookieConfig cookie();

    @WithName("federated-idp")
    FederatedProviderConfig provider();

    @WithName("jwt")
    JwtConfig jwt();

    @WithName("internal-issuer")
    InternalIssuerConfig internalIssuer();

    @WithName("state-secret")
    String stateSecret();

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

    interface FederatedProviderConfig {

        @WithName("client")
        FederatedClientConfig client();

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

        @WithName("audience")
        Optional<Set<String>> audience();

        @WithName("userinfo-path")
        Optional<String> userInfoPath();
    }

    interface FederatedClientConfig {
        @WithName("client-id")
        String clientId();

        @WithName("client-secret")
        String clientSecret();

        @WithName("redirect-uri")
        URI redirectUri();

        @WithName("scope")
        Optional<String> scope();
    }

    interface InternalIssuerConfig {
        @WithName("issuer")
        String issuer();

        @WithName("audience")
        @WithDefault("oauth2-proxy")
        String audience();

        @WithName("expiration")
        @WithDefault("8h")
        Duration expiration();

        @WithName("scope")
        Optional<String> scope();

        @WithName("pass-through-claims")
        @WithDefault("email")
        List<String> passThroughClaims();

        @WithName("optional-pass-through-claims")
        @WithDefault("family_name,given_name")
        List<String> optionalPassThroughClaims();

        @WithName("map-claims")
        Optional<List<ClaimMapping>> mapClaims();

        @WithName("key")
        KeyConfig keyConfig();
    }

    interface ClaimMapping {
        @WithName("from")
        String from();

        @WithName("to")
        String to();

        @WithName("required")
        @WithDefault("false")
        boolean required();

        @WithName("separator")
        @WithDefault(",")
        String separator();

        @WithName("target-type")
        @WithDefault("string")
        ClaimType targetType();
    }

    interface KeyConfig {
        @WithName("key-id")
        Optional<String> keyId();

        @WithName("signature-algorithm")
        @WithDefault("ES256")
        SignatureAlgorithm signatureAlgorithm();

        @WithName("private-key")
        String privateKey();

        @WithName("public-key")
        String publicKey();
    }
}