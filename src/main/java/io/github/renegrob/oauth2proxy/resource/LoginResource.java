package io.github.renegrob.oauth2proxy.resource;

import io.github.renegrob.oauth2proxy.service.idp.GrantRequestVerificationService;
import io.github.renegrob.oauth2proxy.service.idp.IdpConfiguration;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;

@Path("/auth/login")
public class LoginResource {

    @Inject
    IdpConfiguration config;

    @Inject
    GrantRequestVerificationService grantRequestVerificationService;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response login() {
        var validationData = grantRequestVerificationService.createStateCookie();

        URI redirectUri = UriBuilder
                .fromUri(config.authorizationEndpoint())
                .queryParam("client_id", config.clientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", config.redirectUri())
                .queryParam("response_mode", "query")
                .queryParam("scope", config.scope())
                .queryParam("state", validationData.state())
                .build();
        return Response.seeOther(redirectUri).cookie(validationData.cookie()).build();
    }
}
