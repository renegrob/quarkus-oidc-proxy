package io.github.renegrob.oidc.service.idp;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

import java.net.URI;

public interface IdpConfiguration {
    URI authorizationEndpoint();

    URI tokenEndpoint();

    String clientId();

    URI redirectUri();

    Object scope();

    JWTAuthContextInfo jwtAuthContextInfo();
}
