package io.github.renegrob.oauth2proxy.resource;

import io.github.renegrob.oauth2proxy.service.CookieService;
import io.github.renegrob.oauth2proxy.service.idp.TokenExchangeService;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.github.renegrob.oauth2proxy.constants.CookieNames.OAUTH_STATE;


@Path("/auth/callback")
@SuppressWarnings("unused")
public class CallbackResource {

    private static final Logger LOG = LoggerFactory.getLogger(CallbackResource.class);

    @Inject
    TokenExchangeService tokenService;

    @Inject
    CookieService cookieService;

    @GET
    public Response handleCode(@QueryParam("code") String code, @QueryParam("state") String state, @CookieParam(OAUTH_STATE) String cookieState) {
        if (code == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing code").build();
        }
        if (state == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing state").build();
        }
        if (cookieState == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing cookie").build();
        }
        if (!state.equals(cookieState)) {
            return Response.status(Response.Status.BAD_REQUEST).entity("State mismatch").build();
        }

        JsonObject tokenResponse = tokenService.exchangeCodeForToken(code);
        String accessToken = tokenResponse.getString("access_token");
        String idToken = tokenResponse.getString("id_token");

        LOG.info("Access token: {}", accessToken);
        LOG.info("ID token: {}", idToken);

        NewCookie cookie = cookieService.createCookie("access_token", accessToken);

        return Response.ok("Logged in!\naccess_token:\n" + accessToken + "\nid_token:\n" + idToken).cookie(cookie).build();
    }
}