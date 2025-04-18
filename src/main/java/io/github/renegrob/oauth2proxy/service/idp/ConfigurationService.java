package io.github.renegrob.oauth2proxy.service.idp;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.util.Optional;

import static io.github.renegrob.oauth2proxy.util.OAuth2Util.uri;


@ApplicationScoped
public class ConfigurationService implements IdpConfiguration {

    private final OAuthConfig.FederatedProviderConfig provider;
    private final OAuthConfig.FederatedClientConfig clientConfig;
    private final DiscoveryService discoveryService;
    private JWTAuthContextInfo jwtAuthContextInfo;
    private URI authorizationEndpoint;
    private URI tokenEndpoint;
    private String issuer;
    private URI jwksUri;

    @Inject
    ConfigurationService(OAuthConfig config, DiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
        provider = config.provider();
        clientConfig = provider.client();
    }

    @PostConstruct
    void init() {
        if (provider.discoveryEnabled()) {
            authorizationEndpoint= uri(discoveryService.getEndpoint(EndpointType.AUTHORIZATION_ENDPOINT));
            tokenEndpoint= uri(discoveryService.getEndpoint(EndpointType.TOKEN_ENDPOINT));
            issuer = discoveryService.getIssuer();
            jwksUri = discoveryService.getJwksUri();
        } else {
            authorizationEndpoint = combineURI(provider.authServerUrl(), provider.authorizationPath());
            tokenEndpoint = combineURI(provider.authServerUrl(), provider.tokenPath());
            issuer = provider.issuer().orElse(null);
            jwksUri = combineURI(provider.authServerUrl(), provider.jwksPath());
        }
        jwtAuthContextInfo = new JWTAuthContextInfo(jwksUri.toString(), issuer);
        provider.audience().ifPresent(jwtAuthContextInfo::setExpectedAudience);
    }

    @Override
    public URI authorizationEndpoint() {
        return authorizationEndpoint;
    }

    public URI tokenEndpoint() {
        return tokenEndpoint;
    }

    @Override
    public String clientId() {
        return clientConfig.clientId();
    }

    @Override
    public URI redirectUri() {
        return clientConfig.redirectUri();
    }

    @Override
    public Object scope() {
        return clientConfig.scope().orElse("");
    }

    @Override
    public JWTAuthContextInfo jwtAuthContextInfo() {
        return jwtAuthContextInfo;
    }

    private URI combineURI(URI uri, Optional<String> path) {
        return path.map(uri::resolve).orElse(uri);
    }
}
