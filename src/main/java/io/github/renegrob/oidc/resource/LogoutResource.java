package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.config.OAuthConfig;
import io.github.renegrob.oidc.service.*;
import io.github.renegrob.oidc.service.idp.DiscoveryService;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.jboss.resteasy.reactive.RestResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;

import static io.github.renegrob.oidc.service.idp.EndpointType.*;

@Path("/auth/logout")
@SuppressWarnings("unused")
public class LogoutResource {

    private static final Logger LOG = LoggerFactory.getLogger(LogoutResource.class);

    @Inject
    CookieService cookieService;

    @Inject
    OAuthConfig config;

    @Inject
    DiscoveryService discoveryService;


    @GET
    public RestResponse<Void> logout() {
        LOG.debug("Processing logout request");
        NewCookie logoutCookie = cookieService.createLogoutCookie();

        // Try to get end session endpoint from discovery
        String endSessionEndpoint = discoveryService.getEndpoint(END_SESSION_ENDPOINT);
        if (endSessionEndpoint != null) {
            LOG.debug("Redirecting to provider end session endpoint: {}", endSessionEndpoint);
            return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                    .location(URI.create(endSessionEndpoint))
                    .cookie(logoutCookie)
                    .build();
        } else {
            LOG.debug("No end session endpoint found, logging out locally only");
            return RestResponse.ResponseBuilder.<Void>create(Response.Status.FOUND)
                    .location(URI.create("/"))
                    .cookie(logoutCookie)
                    .build();
        }
    }
}