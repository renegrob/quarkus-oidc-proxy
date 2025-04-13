package io.github.renegrob.oidc.util;

public enum HashAlgorithm {
    SHA_512("SHA-512"),
    SHA_384("SHA-384"),
    SHA_256("SHA-256");

    private final String algorithm;

    HashAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}