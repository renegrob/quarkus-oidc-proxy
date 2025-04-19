package io.github.renegrob.oidc.service.idp;

import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;

import java.net.URI;
import java.util.Optional;

public interface IdpConfiguration {
    URI authorizationEndpoint();

    URI tokenEndpoint();

    Optional<URI> userInfoEndpoint();

    String clientId();

    URI redirectUri();

    Object scope();

    JWTAuthContextInfo jwtAuthContextInfo();
}
