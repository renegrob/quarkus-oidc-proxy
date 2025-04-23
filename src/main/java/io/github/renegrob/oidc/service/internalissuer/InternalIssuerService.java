package io.github.renegrob.oidc.service.internalissuer;

import io.github.renegrob.oidc.config.ClaimType;
import io.github.renegrob.oidc.config.FederationMode;
import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.RandomService;
import io.github.renegrob.oidc.service.internalissuer.claims.ClaimTranslationFactory;
import io.github.renegrob.oidc.service.internalissuer.claims.ClaimTranslationRule;
import io.github.renegrob.oidc.service.jwt.ClaimsMapBuilder;
import io.github.renegrob.oidc.util.Base64Util;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.BadRequestException;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.*;

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
    private final RandomService randomService;
    private final FederationMode federationMode;
    private final PrivateKey privateKey;
    private final String keyId;
    private final Map<String, ClaimTranslationRule> claimTranslations;

    @Inject
    InternalIssuerService(OAuthConfig config, InternalKeyInfo internalKeyInfo, ClaimTranslationFactory claimTranslationFactory, RandomService randomService) {
        this.federationMode = config.federationMode();
        this.issuerConfig = config.internalIssuer();
        this.privateKey = internalKeyInfo.privateKey();
        this.keyId = internalKeyInfo.keyId();
        this.randomService = randomService;
        this.claimTranslations = claimTranslationFactory.createClaimTranslations();
    }

    public String createInternalJwt(JwtClaims source) {
        if (federationMode == FederationMode.PASS_THROUGH) {
            throw new IllegalStateException("Internal issuer is disabled.");
        }
        try {
            ClaimsMapBuilder claims = ClaimsMapBuilder.claims()
                    .subject(source.getSubject())
                    .scope(issuerConfig.scope()
                            .map(sc -> Arrays.stream(sc.split(" ")).collect(toSet())).orElse(emptySet()));

            processClaims(source, claims);

            // These claims cannot be overridden
            claims.issuer(issuerConfig.issuer())
                    .audience(issuerConfig.audience())
                    .issuedAt(Instant.now())
                    .expiresIn(issuerConfig.expiration())
                    .nonce(generateNonce());

            LOG.info("Internal claims: {}", claims.toMap());

            var keyConfig = issuerConfig.keyConfig();

            return Jwt.claims(claims.toMap()).jws()
                    .keyId(keyId)
                    .algorithm(keyConfig.signatureAlgorithm())
                    .sign(privateKey);

        } catch (Exception e) {
            LOG.error("Failed to create JWT", e);
            throw new RuntimeException("Failed to create internal JWT token", e);
        }
    }

    private void processClaims(JwtClaims source, ClaimsMapBuilder claims) {
        processPassThroughClaims(source, claims);
        processOptionalPassThroughClaims(source, claims);
        processMappedClaims(source, claims);
        translateClaims(claims);
        addAdditionalClaims(claims);
    }

    private void processPassThroughClaims(JwtClaims source, ClaimsMapBuilder claims) {
        for (String name : issuerConfig.passThroughClaims()) {
            Object value = source.getClaimValue(name);
            if (value == null) {
                throw new BadRequestException(String.format("Missing claim: %s", name));
            }
            claims.claim(name, value);
        }
    }

    private void processOptionalPassThroughClaims(JwtClaims source, ClaimsMapBuilder claims) {
        for (String name : issuerConfig.optionalPassThroughClaims()) {
            Object value = source.getClaimValue(name);
            if (value != null) {
                claims.claim(name, value);
            }
        }
    }

    private void processMappedClaims(JwtClaims source, ClaimsMapBuilder claims) {
        for (OAuthConfig.ClaimMapping claimMapping : issuerConfig.mapClaims().orElse(List.of())) {
            Object value = source.getClaimValue(claimMapping.from());
            if (value != null) {
                claims.claim(claimMapping.to(), mapValue(value, claimMapping));
            } else if (claimMapping.required()) {
                throw new BadRequestException(String.format("Missing claim: %s", claimMapping.from()));
            }
        }
    }

    private void addAdditionalClaims(ClaimsMapBuilder claims) {
        for (OAuthConfig.AdditionalClaim additionalClaim : issuerConfig.additionalClaims().orElse(List.of())) {
            if (claims.get(additionalClaim.name()) == null) {
                if (additionalClaim.value().isPresent()) {
                    if (additionalClaim.values().isPresent()) {
                        throw new BadRequestException("Additional claim can have either value or values, not both");
                    }
                    claims.claim(additionalClaim.name(), additionalClaim.value().orElseThrow());
                } else {
                    claims.claim(additionalClaim.name(), additionalClaim.values().orElseThrow());
                }
            }
        }
    }

    private void translateClaims(ClaimsMapBuilder claims) {
        for (String claimName : claims.keySet()) {
            ClaimTranslationRule translations = claimTranslations.get(claimName);
            if (translations != null) {
                Object value = claims.get(claimName);
                var translatedValue = translations.translateClaimValue(value);
                claims.claim(claimName, translatedValue);
            }
        }
    }


    private Object mapValue(Object value, OAuthConfig.ClaimMapping claimMapping) {
        if (claimMapping.targetType() == ClaimType.STRING) {
            if (value instanceof Collection) {
                return String.join(claimMapping.separator(),
                        ((Collection<?>) value).stream().map(Object::toString).toList());
            } else {
                return String.valueOf(value);
            }
        } else if (claimMapping.targetType() == ClaimType.ARRAY) {
            return switch (value) {
                case Collection<?> objects ->
                        objects.stream().map(Object::toString).toList();
                case Object[] objects -> new LinkedHashSet<>(Arrays.asList(objects));
                case String s -> new LinkedHashSet<>(Arrays.asList(s.split(claimMapping.separator())));
                default -> new LinkedHashSet<>(List.of(value));
            };
        } else if (claimMapping.targetType() == ClaimType.BOOLEAN) {
            if (value instanceof Boolean) {
                return value;
            } else if (value instanceof Number) {
                return ((Number) value).intValue() != 0;
            } else {
                return Boolean.parseBoolean(String.valueOf(value));
            }
        } else if (value instanceof Number) {
            if (claimMapping.targetType() == ClaimType.INTEGER) {
                return ((Number) value).intValue();
            } else if (claimMapping.targetType() == ClaimType.LONG) {
                return ((Number) value).longValue();
            } else if (claimMapping.targetType() == ClaimType.DOUBLE) {
                return ((Number) value).doubleValue();
            } else if (claimMapping.targetType() == ClaimType.FLOAT) {
                return((Number) value).floatValue();
            } else {
                return value;
            }
        } else {
            return value;
        }
    }

    private String generateNonce() {
        return Base64Util.toBase64(randomService.randomBytes(32), true);
    }
}