package io.github.renegrob.oauth2proxy.service;

import io.github.renegrob.oauth2proxy.config.OAuthConfig;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.arc.Unremovable;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;

@ApplicationScoped
@Unremovable
public class DiscoveryService {
    private static final Logger LOG = LoggerFactory.getLogger(DiscoveryService.class);
    
    @Inject
    OAuthConfig config;
    
    @ConfigProperty(name = "quarkus.oidc.auth-server-url")
    String authServerUrl;
    
    @ConfigProperty(name = "quarkus.oidc.discovery-enabled", defaultValue = "true")
    boolean discoveryEnabled;
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private Map<String, String> discoveredEndpoints = new HashMap<>();
    
    @PostConstruct
    void init() {
        if (discoveryEnabled) {
            discoverEndpoints();
        } else {
            LOG.info("OIDC discovery is disabled, using configured endpoints");
        }
    }
    
    private void discoverEndpoints() {
        try {
            String discoveryUrl = buildDiscoveryUrl();
            LOG.info("Discovering OIDC endpoints from {}", discoveryUrl);
            
            Response response = ClientBuilder.newClient()
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
            discoveredEndpoints.put("issuer", getStringValue(json, "issuer"));
            discoveredEndpoints.put("authorization_endpoint", getStringValue(json, "authorization_endpoint"));
            discoveredEndpoints.put("token_endpoint", getStringValue(json, "token_endpoint"));
            discoveredEndpoints.put("userinfo_endpoint", getStringValue(json, "userinfo_endpoint"));
            discoveredEndpoints.put("jwks_uri", getStringValue(json, "jwks_uri"));
            discoveredEndpoints.put("end_session_endpoint", getStringValue(json, "end_session_endpoint"));
            
            LOG.info("Discovered OIDC endpoints: {}", discoveredEndpoints);
        } catch (Exception e) {
            LOG.error("Error discovering OIDC endpoints", e);
        }
    }
    
    private String buildDiscoveryUrl() throws URISyntaxException {
        // Strip trailing slash if present
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
    
    private String getStringValue(JsonNode json, String field) {
        JsonNode node = json.get(field);
        return node != null ? node.asText() : null;
    }
    
    public String getEndpoint(String endpointType) {
        if (discoveryEnabled && discoveredEndpoints.containsKey(endpointType)) {
            return discoveredEndpoints.get(endpointType);
        }
        
        // Fallback to configured values if discovery is disabled or endpoint not found
        switch (endpointType) {
            case "issuer":
                return config.provider().issuer().orElse(authServerUrl);
            case "authorization_endpoint":
                return config.provider().authorizationPath()
                        .map(path -> combinePath(authServerUrl, path))
                        .orElse(null);
            case "token_endpoint":
                return config.provider().tokenPath()
                        .map(path -> combinePath(authServerUrl, path))
                        .orElse(null);
            case "userinfo_endpoint":
                return config.provider().userinfoPath()
                        .map(path -> combinePath(authServerUrl, path))
                        .orElse(null);
            case "jwks_uri":
                return config.provider().jwksPath()
                        .map(path -> combinePath(authServerUrl, path))
                        .orElse(null);
            case "end_session_endpoint":
                return config.provider().endSessionPath()
                        .map(path -> combinePath(authServerUrl, path))
                        .orElse(null);
            default:
                return null;
        }
    }
    
    private String combinePath(String baseUrl, String path) {
        if (path.startsWith("http://") || path.startsWith("https://")) {
            return path;
        }
        
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String pathToAppend = path.startsWith("/") ? path : "/" + path;
        return base + pathToAppend;
    }
}
