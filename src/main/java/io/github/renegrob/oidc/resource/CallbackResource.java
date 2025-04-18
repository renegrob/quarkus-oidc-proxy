package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.service.CookieService;
import io.github.renegrob.oidc.service.JwtManager;
import io.github.renegrob.oidc.service.idp.ConfigurationService;
import io.github.renegrob.oidc.service.idp.GrantRequestVerificationService;
import io.github.renegrob.oidc.service.idp.TokenExchangeService;
import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static io.github.renegrob.oidc.constants.CookieNames.OAUTH_STATE;


@Path("/auth/callback")
@SuppressWarnings("unused")
public class CallbackResource {

    private static final Logger LOG = LoggerFactory.getLogger(CallbackResource.class);

    @Inject
    TokenExchangeService tokenService;

    @Inject
    ConfigurationService configurationService;

    @Inject
    CookieService cookieService;

    @Inject
    GrantRequestVerificationService grantRequestVerificationService;

    @Inject
    DefaultJWTParser jwtParser;

    @Inject
    JwtManager jwtManager;

    @GET
    public Response handleCode(@QueryParam("code") String code, @QueryParam("state") String state, @CookieParam(OAUTH_STATE) String cookieState) throws ParseException {
        if (code == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing code").build();
        }
        grantRequestVerificationService.verifyState(state, cookieState);

        JsonObject tokenResponse = tokenService.exchangeCodeForToken(code);
        String accessToken = tokenResponse.getString("access_token");
        String idToken = tokenResponse.getString("id_token");

        LOG.info("Access token: {}", accessToken);
        LOG.info("ID token: {}", idToken);

        JsonWebToken jsonWebToken = jwtParser.parse(idToken, configurationService.jwtAuthContextInfo());

        NewCookie cookie = cookieService.createCookie("access_token", accessToken);

        String internalJwt = jwtManager.createInternalJwt(jsonWebToken);

        return Response.ok(String.format(
                        """
                        Logged in as %s!
                        
                        access_token:
                        %s
                        
                        external_id_token:
                        %s
                        
                        internal_id_token:
                        %s
                        """,
                jsonWebToken.getClaim("email"), accessToken, idToken, internalJwt)).cookie(cookie).build();
    }
}