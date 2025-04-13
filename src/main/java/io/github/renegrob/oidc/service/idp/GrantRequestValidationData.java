package io.github.renegrob.oidc.service.idp;

import jakarta.ws.rs.core.NewCookie;

public record GrantRequestValidationData(String state, NewCookie cookie) {
    public GrantRequestValidationData {
        if (cookie == null) {
            throw new IllegalArgumentException("Cookie cannot be null");
        }
        if (state == null) {
            throw new IllegalArgumentException("State cannot be null");
        }
    }
}
