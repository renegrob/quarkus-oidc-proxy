package io.github.renegrob.oidc.config;

public enum PkceMethod {
    S256("S256"),
    PLAIN("plain");

    private final String value;

    PkceMethod(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
} 