package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.jwt.ClaimsMapBuilder;
import io.github.renegrob.oidc.util.HashBuilder;
import io.smallrye.jwt.build.Jwt;
import io.smallrye.jwt.util.KeyUtils;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
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
public class InternalIssuerService {

    private static final Logger LOG = LoggerFactory.getLogger(InternalIssuerService.class);

    private final OAuthConfig.InternalIssuerConfig issuerConfig;
    private PrivateKey privateKey;
    private String keyId;
    private FederationMode federationMode;

    @Inject
    InternalIssuerService(OAuthConfig config) {
        this.issuerConfig = config.internalIssuer();
        this.federationMode = config.federationMode();
    }

    @PostConstruct
    public void initialize() throws GeneralSecurityException {
        if (!isEnabled()) {
            LOG.info("Internal issuer is disabled");
            return;
        }
        var keyConfig = issuerConfig.keyConfig();
        privateKey = KeyUtils.decodePrivateKey(keyConfig.privateKey(), keyConfig.signatureAlgorithm());
        keyId = keyConfig.keyId().orElseGet(() -> toKeyId(keyConfig.publicKey()));
    }

    public String createInternalJwt(JwtClaims source) {
        if (!isEnabled()) {
            throw new IllegalStateException("Internal issuer is disabled.");
        }
        try {
            ClaimsMapBuilder claims = ClaimsMapBuilder.claims()
                    .subject(source.getSubject())
                    .issuer(issuerConfig.issuer())
                    .audience(issuerConfig.audience())
                    .issuedAt(Instant.now())
                    .expiresIn(issuerConfig.expiration())
                    .scope(issuerConfig.scope()
                            .map(sc -> Arrays.stream(sc.split(" ")).collect(toSet())).orElse(emptySet()));

            for (String name : issuerConfig.passThroughClaims()) {
                Object value = source.getClaimValue(name);
                if (value == null) {
                    throw new BadRequestException(String.format("Missing claim: %s", name));
                }
                claims.claim(name, value);
            }
            for (String name : issuerConfig.optionalPassThroughClaims()) {
                Object value = source.getClaimValue(name);
                if (value != null) {
                    claims.claim(name, value);
                }
            }

            for (OAuthConfig.ClaimMapping claimMapping : issuerConfig.mapClaims().orElse(List.of())) {
                Object value = source.getClaimValue(claimMapping.from());
                if (value != null) {
                    claims.claim(claimMapping.to(), value);
                } else {
                    if (claimMapping.required()) {
                        throw new BadRequestException(String.format("Missing claim: %s", claimMapping.from()));
                    }
                }
            }

            //TODO: add issuerConfig.scope().ifPresent(sc -> claimsBuilder.claim());

            LOG.info("Internal claims: {}", claims.toMap());

            var keyConfig = issuerConfig.keyConfig();

            String signed = Jwt.claims(claims.toMap()).jws()
                    .keyId(keyId)
                    .algorithm(keyConfig.signatureAlgorithm())
                    .sign(privateKey);

            return signed;
        } catch (Exception e) {

            LOG.error("Failed to create JWT", e);
            throw new RuntimeException("Failed to create internal JWT token", e);
        }
    }

    private static String toKeyId(String publicKey) {
        return HashBuilder.sha256(publicKey).toBase64().substring(0, 10);
    }

    public boolean isEnabled() {
        return federationMode != FederationMode.PASS_THROUGH;
    }
}