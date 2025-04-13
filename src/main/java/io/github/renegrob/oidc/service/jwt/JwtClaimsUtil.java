package io.github.renegrob.oidc.service.jwt;

import org.jose4j.jwt.JwtClaims;

import java.util.Set;

public final class JwtClaimsUtil {

    private JwtClaimsUtil() {
        // Utility class, no instantiation
    }

    public static JwtClaims copy(JwtClaims originalClaims, Set<String> claimsToOmit) {
        JwtClaims newClaims = new JwtClaims();
        originalClaims.getClaimsMap().forEach((key, value) -> {
            if (!claimsToOmit.contains(key)) {
                newClaims.setClaim(key, value);
            }
        });
        return newClaims;
    }
}