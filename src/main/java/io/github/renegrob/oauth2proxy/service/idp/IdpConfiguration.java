package io.github.renegrob.oauth2proxy.service.idp;

import java.net.URI;

public interface IdpConfiguration {
    URI authorizationEndpoint();

    URI tokenEndpoint();

    String clientId();

    URI redirectUri();

    Object scope();
}
