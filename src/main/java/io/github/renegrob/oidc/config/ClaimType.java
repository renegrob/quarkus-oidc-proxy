package io.github.renegrob.oidc.config;

public enum ClaimType {
    STRING("string"),
    INTEGER("integer"),
    LONG("long"),
    BOOLEAN("boolean"),
    DOUBLE("double"),
    FLOAT("float"),
    DATE_TIME("date-time"),
    ARRAY("array"),
    OBJECT("object");

    private final String type;

    ClaimType(String type) {
        this.type = type;
    }

    public String getType() {
        return type;
    }
}
