package io.github.renegrob.oidc.service.jwt;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ClaimsMapBuilder {
    private final Map<String, Object> claims = new HashMap<>();

    private ClaimsMapBuilder() {
    }

    public static ClaimsMapBuilder claims() {
        return new ClaimsMapBuilder();
    }

    public ClaimsMapBuilder issuer(String s) {
        claims.put("iss", s);
        return this;
    }

    public ClaimsMapBuilder subject(String s) {
        claims.put("sub", s);
        return this;
    }

    public ClaimsMapBuilder upn(String s) {
        claims.put("upn", s);
        return this;
    }

    public ClaimsMapBuilder preferredUserName(String s) {
        claims.put("preferred_username", s);
        return this;
    }

    public ClaimsMapBuilder issuedAt(long l) {
        claims.put("iat", l);
        return this;
    }

    public ClaimsMapBuilder issuedAt(Instant issuedAt) {
        claims.put("iat", issuedAt.getEpochSecond());
        return this;
    }

    public ClaimsMapBuilder expiresAt(long l) {
        claims.put("exp", l);
        return this;
    }

    public ClaimsMapBuilder expiresAt(Instant expiresAt) {
        claims.put("exp", expiresAt.getEpochSecond());
        return this;
    }

    public ClaimsMapBuilder expiresIn(long l) {
        // Current time in seconds + expiration interval
        long expirationTime = System.currentTimeMillis() / 1000 + l;
        claims.put("exp", expirationTime);
        return this;
    }

    public ClaimsMapBuilder expiresIn(Duration expiresIn) {
        return expiresAt(Instant.now().plus(expiresIn));
    }

    public ClaimsMapBuilder groups(Set<String> set) {
        claims.put("groups", set);
        return this;
    }

    public ClaimsMapBuilder scope(Set<String> set) {
        claims.put("scope", set);
        return this;
    }

    public ClaimsMapBuilder audience(String s) {
        claims.put("aud", s);
        return this;
    }

    public ClaimsMapBuilder audience(Set<String> set) {
        claims.put("aud", set);
        return this;
    }

    public ClaimsMapBuilder claim(String s, Object o) {
        claims.put(s, o);
        return this;
    }

    public ClaimsMapBuilder remove(String s) {
        claims.remove(s);
        return this;
    }

    public ClaimsMapBuilder claim(String s, String s1) {
        claims.put(s, s1);
        return this;
    }

    public ClaimsMapBuilder nonce(String nonce) {
        claims.put("nonce", nonce);
        return this;
    }

    /**
     * Returns the map of claims
     * @return A map containing all the JWT claims
     */
    public Map<String, Object> toMap() {
        return new HashMap<>(claims);
    }

    public Set<String> keySet() {
        return claims.keySet();
    }

    public String toString() {
        return getClass().getSimpleName() + "{claims=" + claims + "}";
    }

    public Object get(String claimName) {
        return claims.get(claimName);
    }
}