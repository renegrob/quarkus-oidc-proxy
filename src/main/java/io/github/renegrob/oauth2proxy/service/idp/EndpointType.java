package io.github.renegrob.oauth2proxy.service.idp;

import java.util.HashMap;
import java.util.Map;

public enum EndpointType {
    ISSUER("issuer"),
    AUTHORIZATION_ENDPOINT("authorization_endpoint"),
    TOKEN_ENDPOINT("token_endpoint"),
    USERINFO_ENDPOINT("userinfo_endpoint"),
    JWKS_URI("jwks_uri"),
    END_SESSION_ENDPOINT("end_session_endpoint");

    private final String type;
    private static final Map<String, EndpointType> lookup = new HashMap<>();

    static {
        for (EndpointType endpoint : EndpointType.values()) {
            lookup.put(endpoint.type, endpoint);
        }
    }

    EndpointType(String type) {
        this.type = type;
    }

    public String type() {
        return type;
    }

    public static EndpointType fromString(String type) {
        return lookup.getOrDefault(type, null);
    }
}