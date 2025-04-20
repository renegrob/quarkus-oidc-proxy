package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.quarkus.logging.Log;
import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.util.KeyUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jose4j.jwt.consumer.JwtContext;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Set;

@ApplicationScoped
@SuppressWarnings("unused")
public class InternalJwtValidatorService {

    private final DefaultJWTTokenParser jwtParser;;

    private final OAuthConfig config;
    private final PublicKey publicKey;
    private final JWTAuthContextInfo jwtAuthContextInfo;

    @Inject
    InternalJwtValidatorService(OAuthConfig config) throws GeneralSecurityException {
        this.config = config;
        if (config.federationMode() == FederationMode.PASS_THROUGH) {
            throw new IllegalStateException("Internal issuer is disabled.");
        }
        this.jwtParser = new DefaultJWTTokenParser();
        var keyConfig = config.internalIssuer().keyConfig();
        this.publicKey = KeyUtils.decodePublicKey(keyConfig.publicKey(), keyConfig.signatureAlgorithm());
        this.jwtAuthContextInfo = new JWTAuthContextInfo(publicKey, config.internalIssuer().issuer());
        this.jwtAuthContextInfo.setSignatureAlgorithm(Set.of(keyConfig.signatureAlgorithm()));
    }

    public boolean validateToken(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        try {
            JwtContext jwt = jwtParser.parse(token, jwtAuthContextInfo);
            return true;
        } catch (ParseException e) {
            Log.debug("Failed to parse JWT: " + e.getMessage(), e);
            return false;
        }
    }
}