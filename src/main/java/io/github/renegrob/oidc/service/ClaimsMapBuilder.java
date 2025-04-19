package io.github.renegrob.oidc.service;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class ClaimsMapBuilder {
    private final Map<String, Object> claims = new HashMap<>();

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

    public ClaimsMapBuilder expiresAt(long l) {
        claims.put("exp", l);
        return this;
    }

    public ClaimsMapBuilder expiresIn(long l) {
        // Current time in seconds + expiration interval
        long expirationTime = System.currentTimeMillis() / 1000 + l;
        claims.put("exp", expirationTime);
        return this;
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

    /**
     * Returns the map of claims
     * @return A map containing all the JWT claims
     */
    public Map<String, Object> toMap() {
        return new HashMap<>(claims);
    }

    public String toString() {
        return getClass().getSimpleName() + "{claims=" + claims + "}";
    }
}