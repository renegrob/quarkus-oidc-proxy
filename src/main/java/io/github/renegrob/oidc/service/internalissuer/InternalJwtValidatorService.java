package io.github.renegrob.oidc.service.internalissuer;

import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.quarkus.logging.Log;
import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtContext;

import java.security.GeneralSecurityException;
import java.util.Set;

@ApplicationScoped
@SuppressWarnings("unused")
public class InternalJwtValidatorService {

    private final DefaultJWTTokenParser jwtParser;;

    private final JWTAuthContextInfo jwtAuthContextInfo;

    @Inject
    InternalJwtValidatorService(OAuthConfig config, InternalKeyInfo internalKeyInfo) throws GeneralSecurityException {
        if (config.federationMode() == FederationMode.PASS_THROUGH) {
            throw new IllegalStateException("Internal issuer is disabled.");
        }
        this.jwtParser = new DefaultJWTTokenParser();
        var keyConfig = config.internalIssuer().keyConfig();
        var publicKey = internalKeyInfo.publicKey();
        this.jwtAuthContextInfo = new JWTAuthContextInfo(publicKey, config.internalIssuer().issuer());
        this.jwtAuthContextInfo.setSignatureAlgorithm(Set.of(keyConfig.signatureAlgorithm()));
    }

    public JwtClaims validateToken(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        try {
            return jwtParser.parse(token, jwtAuthContextInfo).getJwtClaims();
        } catch (ParseException e) {
            Log.debug("Failed to parse JWT: " + e.getMessage(), e);
            return null;
        }
    }
}