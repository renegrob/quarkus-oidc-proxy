package io.github.renegrob.oauth2proxy.service.idp;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.arc.Unremovable;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static io.github.renegrob.oauth2proxy.OAuth2Util.uri;

@ApplicationScoped
@Unremovable
@SuppressWarnings("unused")
public class DiscoveryService {
    private static final Logger LOG = LoggerFactory.getLogger(DiscoveryService.class);
    
    @Inject
    OAuthConfig config;
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Map<EndpointType, String> discoveredEndpoints = new ConcurrentHashMap<>();
    private String jwksUri;
    private String issuer;
    
    @PostConstruct
    void init() {
        if (config.provider().discoveryEnabled()) {
            discoverEndpoints();
        } else {
            LOG.info("OIDC discovery is disabled, using configured endpoints");
        }
    }
    
    private void discoverEndpoints() {
        try (Client client = ClientBuilder.newClient()) {
            String discoveryUrl = buildDiscoveryUrl();
            LOG.info("Discovering OIDC endpoints from {}", discoveryUrl);

            Response response = client
                    .target(discoveryUrl)
                    .request()
                    .get();
            
            if (response.getStatus() != 200) {
                LOG.error("Failed to discover OIDC endpoints: HTTP {}", response.getStatus());
                return;
            }
            
            String jsonString = response.readEntity(String.class);
            JsonNode json = objectMapper.readTree(jsonString);
            
            // Extract standard OIDC discovery endpoints
            for (EndpointType endpointType : EndpointType.values()) {
                String endpoint = getStringValue(json, endpointType.type());
                if (endpoint != null) {
                    discoveredEndpoints.put(endpointType, endpoint);
                }
            }
            jwksUri = getStringValue(json, "jwks_uri");
            issuer = getStringValue(json, "issuer");

            LOG.info("Discovered OIDC endpoints: {}", discoveredEndpoints);
        } catch (Exception e) {
            LOG.error("Error discovering OIDC endpoints", e);
        }
    }
    
    private String buildDiscoveryUrl() throws URISyntaxException {

        if (config.provider().discoveryUrl().isPresent()) {
            return config.provider().discoveryUrl().get();
        }

        // Strip trailing slash if present
        String authServerUrl = authServerUrl();
        String baseUrl = authServerUrl.endsWith("/")
                ? authServerUrl.substring(0, authServerUrl.length() - 1) 
                : authServerUrl;
        
        // Check if the URL already includes the discovery path
        if (baseUrl.endsWith(config.provider().discoveryPath())) {
            return baseUrl;
        }
        
        // Check if URL already has a path that should be preserved
        URI uri = new URI(baseUrl);
        String path = uri.getPath();
        
        // If there's no path or just "/", append the discovery path
        if (path == null || path.isEmpty() || path.equals("/")) {
            return baseUrl + "/" + config.provider().discoveryPath();
        }
        
        // If there's already a path, ensure discovery path is correctly appended
        return baseUrl + (path.endsWith("/") ? "" : "/") + config.provider().discoveryPath();
    }

    private String authServerUrl() {
        return config.provider().authServerUrl().toString();
    }

    private String getStringValue(JsonNode json, String field) {
        JsonNode node = json.get(field);
        return node != null ? node.asText() : null;
    }
    
public String getEndpoint(EndpointType endpointType) {
        if (config.provider().discoveryEnabled() && discoveredEndpoints.containsKey(endpointType)) {
            return discoveredEndpoints.get(endpointType);
        }
        var authServerUrl = authServerUrl();

        // Fallback to configured values if discovery is disabled or endpoint not found
        String endpoint = switch (endpointType) {
            case ISSUER -> config.provider().issuer().orElse(authServerUrl);
            case AUTHORIZATION_ENDPOINT -> config.provider().authorizationPath()
                    .map(path -> combinePath(authServerUrl, path))
                    .orElse(null);
            case TOKEN_ENDPOINT -> config.provider().tokenPath()
                    .map(path -> combinePath(authServerUrl, path))
                    .orElse(null);
            case USERINFO_ENDPOINT -> config.provider().userinfoPath()
                    .map(path -> combinePath(authServerUrl, path))
                    .orElse(null);
            case JWKS_URI -> config.provider().jwksPath()
                    .map(path -> combinePath(authServerUrl, path))
                    .orElse(null);
            case END_SESSION_ENDPOINT -> config.provider().endSessionPath()
                    .map(path -> combinePath(authServerUrl, path))
                    .orElse(null);
            default -> null;
        };
        if (endpoint != null) {
            discoveredEndpoints.put(endpointType, endpoint);
        }
        return endpoint;
    }
    
    private String combinePath(String baseUrl, String path) {
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String pathToAppend = path.startsWith("/") ? path : "/" + path;
        return base + pathToAppend;
    }

    public String getIssuer() {
        return issuer;
    }

    public URI getJwksUri() {
        return uri(jwksUri);
    }
}
