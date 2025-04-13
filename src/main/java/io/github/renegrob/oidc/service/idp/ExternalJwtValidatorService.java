package io.github.renegrob.oidc.service.idp;

import io.quarkus.logging.Log;
import io.smallrye.jwt.auth.principal.*;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jose4j.jwt.consumer.JwtContext;

@ApplicationScoped
@SuppressWarnings("unused")
public class ExternalJwtValidatorService {

    private final DefaultJWTTokenParser jwtParser;;
    private final JWTAuthContextInfo jwtAuthContextInfo;

    @Inject
    ExternalJwtValidatorService(IdpConfigurationService idpConfigurationService) {
        this.jwtParser = new DefaultJWTTokenParser();
        this.jwtAuthContextInfo = idpConfigurationService.jwtAuthContextInfo();
    }

    public boolean validateToken(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        try {
            parse(token);
            return true;
        } catch (ParseException e) {
            Log.debug("Failed to parse JWT: " + e.getMessage(), e);
            return false;
        }
    }

    public JwtContext parse(String token) throws ParseException {
        return jwtParser.parse(token, jwtAuthContextInfo);
    }
}