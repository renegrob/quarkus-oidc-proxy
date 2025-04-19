package io.github.renegrob.oidc.resource;

import io.github.renegrob.oidc.service.CookieService;
import io.github.renegrob.oidc.service.InternalIssuerService;
import io.github.renegrob.oidc.service.idp.ConfigurationService;
import io.github.renegrob.oidc.service.idp.GrantRequestVerificationService;
import io.github.renegrob.oidc.service.idp.TokenExchangeService;
import io.github.renegrob.oidc.service.idp.UserInfoService;
import io.github.renegrob.oidc.service.jwt.JwtClaimsUtil;
import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.DefaultJWTTokenParser;
import io.smallrye.jwt.auth.principal.ParseException;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

import static io.github.renegrob.oidc.constants.CookieNames.OAUTH_STATE;


@Path("/auth/callback")
@SuppressWarnings("unused")
public class CallbackResource {

    private static final Logger LOG = LoggerFactory.getLogger(CallbackResource.class);

    private final DefaultJWTTokenParser jwtTokenParser = new DefaultJWTTokenParser();

    @Inject
    TokenExchangeService tokenService;

    @Inject
    UserInfoService userInfoService;

    @Inject
    ConfigurationService configurationService;

    @Inject
    CookieService cookieService;

    @Inject
    GrantRequestVerificationService grantRequestVerificationService;

    @Inject
    DefaultJWTParser jwtParser;

    @Inject
    InternalIssuerService internalIssuerService;

    @GET
    public Response handleCode(@QueryParam("code") String code, @QueryParam("state") String state, @CookieParam(OAUTH_STATE) String cookieState) throws ParseException {
        if (code == null) {
            return Response.status(Response.Status.BAD_REQUEST).entity("Missing code").build();
        }
        grantRequestVerificationService.verifyState(state, cookieState);

        JsonObject tokenResponse = tokenService.exchangeCodeForToken(code);
        String idToken = tokenResponse.getString("id_token");
        String accessToken = tokenResponse.getString("access_token");

        JwtClaims claims;
        if (idToken == null) {
            LOG.info("Getting claims from access_token");
            claims = userInfoService.getUserInfo(accessToken);
        } else {
            LOG.info("Getting claims from id_token");
            JwtContext jsonWebToken = jwtTokenParser.parse(idToken, configurationService.jwtAuthContextInfo());
            claims = JwtClaimsUtil.copy(jsonWebToken.getJwtClaims(), Set.of("raw_token"));
        }
        LOG.info("Claims: {}", claims);

        String internalJwt = internalIssuerService.createInternalJwt(claims);
        NewCookie cookie = cookieService.createAuthCookie(internalJwt);

        return Response.ok(String.format(
                        """
                        Logged in as %s!
                        
                        claims:
                        %s
                        
                        access_token:
                        %s
                        
                        external_id_token:
                        %s
                        
                        internal_id_token:
                        %s
                        """,
                claims.getClaimValue("email"), claims, accessToken, idToken, internalJwt)).cookie(cookie).build();
    }
}