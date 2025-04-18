package io.github.renegrob.oidc.service;

import io.smallrye.jwt.build.JwtClaimsBuilder;
import io.smallrye.jwt.build.JwtEncryptionBuilder;
import io.smallrye.jwt.build.JwtSignatureBuilder;
import io.smallrye.jwt.build.JwtSignatureException;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class FakeClaimsBuilder implements JwtClaimsBuilder {
    private final Map<String, Object> claims = new HashMap<>();

    @Override
    public JwtClaimsBuilder issuer(String s) {
        claims.put("iss", s);
        return this;
    }

    @Override
    public JwtClaimsBuilder subject(String s) {
        claims.put("sub", s);
        return this;
    }

    @Override
    public JwtClaimsBuilder upn(String s) {
        claims.put("upn", s);
        return this;
    }

    @Override
    public JwtClaimsBuilder preferredUserName(String s) {
        claims.put("preferred_username", s);
        return this;
    }

    @Override
    public JwtClaimsBuilder issuedAt(long l) {
        claims.put("iat", l);
        return this;
    }

    @Override
    public JwtClaimsBuilder expiresAt(long l) {
        claims.put("exp", l);
        return this;
    }

    @Override
    public JwtClaimsBuilder expiresIn(long l) {
        // Current time in seconds + expiration interval
        long expirationTime = System.currentTimeMillis() / 1000 + l;
        claims.put("exp", expirationTime);
        return this;
    }

    @Override
    public JwtClaimsBuilder groups(Set<String> set) {
        claims.put("groups", set);
        return this;
    }

    @Override
    public JwtClaimsBuilder scope(Set<String> set) {
        claims.put("scope", set);
        return this;
    }

    @Override
    public JwtClaimsBuilder audience(String s) {
        claims.put("aud", s);
        return this;
    }

    @Override
    public JwtClaimsBuilder audience(Set<String> set) {
        claims.put("aud", set);
        return this;
    }

    @Override
    public JwtClaimsBuilder claim(String s, Object o) {
        claims.put(s, o);
        return this;
    }

    @Override
    public JwtClaimsBuilder remove(String s) {
        claims.remove(s);
        return this;
    }

    @Override
    public JwtSignatureBuilder jws() {
        // Implementation not needed for testing
        return null;
    }

    @Override
    public JwtEncryptionBuilder jwe() {
        // Implementation not needed for testing
        return null;
    }

    @Override
    public String sign(PrivateKey privateKey) throws JwtSignatureException {
        return "";
    }

    @Override
    public String sign(SecretKey secretKey) throws JwtSignatureException {
        return "";
    }

    @Override
    public String sign(String s) throws JwtSignatureException {
        return "";
    }

    @Override
    public String sign() throws JwtSignatureException {
        return "";
    }

    @Override
    public String signWithSecret(String s) throws JwtSignatureException {
        return "";
    }

    @Override
    public JwtEncryptionBuilder innerSign(PrivateKey privateKey) throws JwtSignatureException {
        return null;
    }

    @Override
    public JwtEncryptionBuilder innerSign(SecretKey secretKey) throws JwtSignatureException {
        return null;
    }

    @Override
    public JwtEncryptionBuilder innerSign(String s) throws JwtSignatureException {
        return null;
    }

    @Override
    public JwtEncryptionBuilder innerSign() throws JwtSignatureException {
        return null;
    }

    @Override
    public JwtEncryptionBuilder innerSignWithSecret(String s) throws JwtSignatureException {
        return null;
    }

    /**
     * Returns the map of claims
     * @return A map containing all the JWT claims
     */
    public Map<String, Object> toMap() {
        return new HashMap<>(claims);
    }

    @Override
    public String toString() {
        return "FakeClaimsBuilder{claims=" + claims + "}";
    }
}