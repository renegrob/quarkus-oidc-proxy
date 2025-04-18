package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.build.JwtClaimsBuilder;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

import static java.util.Collections.emptySet;
import static java.util.stream.Collectors.toSet;

/**
 * See <a href="https://quarkus.io/guides/security-jwt-build">Quarkus security-jwt-build</a>
 */
@ApplicationScoped
@SuppressWarnings("unused")
public class JwtManager {

    private static final Logger LOG = LoggerFactory.getLogger(JwtManager.class);

    private final OAuthConfig.InternalIssuerConfig issuerConfig;

    @Inject
    JwtManager(OAuthConfig config) {
        this.issuerConfig = config.internalIssuer();
    }

    @PostConstruct
    public void initialize() throws GeneralSecurityException {
        // KeyUtils.decodePrivateKey(issuerConfig.signingKey());

    }

    public String createInternalJwt(JsonWebToken externalJwt) {
        try {
            JwtClaimsBuilder claimsBuilder = new FakeClaimsBuilder()
                    .subject(externalJwt.getSubject())
                    .issuer(issuerConfig.issuer())
                    .audience(issuerConfig.audience())
                    .issuedAt(Instant.now())
                    .expiresAt(Instant.now().plus(issuerConfig.expiration()))
                    .scope(issuerConfig.scope()
                            .map(sc -> Arrays.stream(sc.split(" ")).collect(toSet())).orElse(emptySet()));

            for (String name : issuerConfig.passThroughClaims()) {
                Object value = externalJwt.getClaim(name);
                if (value == null) {
                    throw new BadRequestException(String.format("Missing claim: %s", name));
                }
                claimsBuilder.claim(name, value);
            }
            for (String name : issuerConfig.optionalPassThroughClaims()) {
                Object value = externalJwt.getClaim(name);
                if (value != null) {
                    claimsBuilder.claim(name, value);
                }
            }

            for (OAuthConfig.ClaimMapping claimMapping : issuerConfig.mapClaims().orElse(List.of())) {
                Object value = externalJwt.getClaim(claimMapping.from());
                if (value != null) {
                    claimsBuilder.claim(claimMapping.to(), value);
                } else {
                    if (claimMapping.required()) {
                        throw new BadRequestException(String.format("Missing claim: %s", claimMapping.from()));
                    }
                }
            }

            //TODO: add issuerConfig.scope().ifPresent(sc -> claimsBuilder.claim());

            // Sign and build the JWT
            // TODO: FIMXE: Sign!
            String signed = claimsBuilder.toString();

            LOG.info("Internal JWT: {}", claimsBuilder.toString());

            return signed;
        } catch (Exception e) {
            LOG.error("Failed to create JWT", e);
            throw new RuntimeException("Failed to create internal JWT token", e);
        }
    }

    /**
     * Gets the public JWK that can be used to verify tokens
     *
     * @return The public JWK in JSON format
     */
    public String getPublicJwk() {
        // SmallRye JWT does not directly expose a method to retrieve the public JWK.
        // You can configure the public key in your application properties for verification.
        LOG.warn("Public JWK retrieval is not implemented. Configure the public key in your application properties.");
        return "{}";
    }
}