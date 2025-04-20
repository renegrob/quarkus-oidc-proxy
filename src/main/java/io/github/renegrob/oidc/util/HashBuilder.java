package io.github.renegrob.oidc.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashBuilder {

    private final MessageDigest digest;

    private HashBuilder(HashAlgorithm algorithm) {
        try {
            this.digest = MessageDigest.getInstance(algorithm.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(algorithm.getAlgorithm() + " algorithm not available", e);
        }
    }

    public static HashBuilder builder(HashAlgorithm algorithm) {
        return new HashBuilder(algorithm);
    }

    public static HashBuilder sha512(String input) {
        return new HashBuilder(HashAlgorithm.SHA_512).update(input);
    }

    public static HashBuilder sha384(String input) {
        return new HashBuilder(HashAlgorithm.SHA_384).update(input);
    }

    public static HashBuilder sha256(String input) {
        return new HashBuilder(HashAlgorithm.SHA_256).update(input);
    }

    public HashBuilder update(String input) {
        digest.update(input.getBytes(StandardCharsets.UTF_8));
        return this;
    }

    public HashBuilder update(byte[] input) {
        digest.update(input);
        return this;
    }

    public String toBase64() {
        return toBase64(false);
    }

    public String toBase64(boolean withoutPadding) {
        if (withoutPadding) {
            return Base64.getEncoder().withoutPadding().encodeToString(digest.digest());
        }
        return Base64.getEncoder().encodeToString(digest.digest());
    }

    public String toHex() {
        byte[] hashBytes = digest.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte b : hashBytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    public byte[] toBytes() {
        return digest.digest();
    }
}