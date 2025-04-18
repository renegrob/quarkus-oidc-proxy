package io.github.renegrob.oauth2proxy.service.idp;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Optional;

@ApplicationScoped
public class ConfigurationService implements IdpConfiguration {

    private final OAuthConfig.FederatedProviderConfig provider;
    private final OAuthConfig.FederatedClientConfig clientConfig;
    private final DiscoveryService discoveryService;
    private URI authorizationEndpoint;
    private URI tokenEndpoint;

    @Inject
    ConfigurationService(OAuthConfig config, DiscoveryService discoveryService) {
        this.discoveryService = discoveryService;
        provider = config.provider();
        clientConfig = provider.client();
    }

    @PostConstruct
    void init() {
        if (provider.discoveryEnabled()) {
            try {
                authorizationEndpoint= new URI(discoveryService.getEndpoint(EndpointType.AUTHORIZATION_ENDPOINT));
                tokenEndpoint= new URI(discoveryService.getEndpoint(EndpointType.TOKEN_ENDPOINT));
            } catch (URISyntaxException e) {
                throw new RuntimeException(e);
            }
        } else {
            authorizationEndpoint = compbineURI(provider.authServerUrl(), provider.authorizationPath());
            tokenEndpoint = compbineURI(provider.authServerUrl(), provider.tokenPath());
        }
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

    private URI compbineURI(URI uri, Optional<String> path) {
        return path.map(uri::resolve).orElse(uri);
    }
}
