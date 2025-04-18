package io.github.renegrob.oauth2proxy.resource;

import io.github.renegrob.oauth2proxy.service.CookieService;
import io.github.renegrob.oauth2proxy.service.idp.IdpConfiguration;
import io.github.renegrob.oauth2proxy.service.RandomService;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriBuilder;

import java.net.URI;

import static io.github.renegrob.oauth2proxy.constants.CookieNames.OAUTH_STATE;

@Path("/auth/login")
public class LoginResource {

    @Inject
    RandomService randomService;

    @Inject
    IdpConfiguration config;

    @Inject
    CookieService cookieService;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response login() {

        String state = randomService.generateSecureState(16);

        NewCookie stateCookie = cookieService.createSessionCookie(OAUTH_STATE, state);

        URI redirectUri = UriBuilder
                .fromUri(config.authorizationEndpoint())
                .queryParam("client_id", config.clientId())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", config.redirectUri())
                .queryParam("response_mode", "query")
                .queryParam("scope", config.scope())
                .queryParam("state", state)
                .build();
        return Response.seeOther(redirectUri).cookie(stateCookie).build();
    }
}
