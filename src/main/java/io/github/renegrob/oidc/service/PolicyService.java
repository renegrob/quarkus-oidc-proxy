package io.github.renegrob.oidc.service;

import io.github.renegrob.oidc.config.OAuthConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static java.util.stream.Collectors.toMap;


@ApplicationScoped
public class PolicyService {

    private static final Logger LOG = LoggerFactory.getLogger(PolicyService.class);

    private final String roleClaim;
    private final Map<String, OAuthConfig.Policy> policyMap;

    @Inject
    PolicyService(OAuthConfig config) {
        this.policyMap = config.policies().map(p ->
                p.stream().collect(
                    toMap(OAuthConfig.Policy::name, Function.identity())))
                .orElse(Map.of());
        this.roleClaim = config.roleClaimName();
    }

    public void checkPolicy(JwtClaims claims, String policyName) {
        OAuthConfig.Policy policy = policyMap.get(policyName);

        if (policy == null) {
            LOG.debug("Policy not found: {}", policyName);
            throw new InternalServerErrorException("Policy not found.");
        }

        Collection<String> userRoles = getRoleClaim(claims);
        boolean authorized = policy.roleSets().stream()
                .anyMatch(userRoles::containsAll);

        if (!authorized) {
            LOG.debug("User roles do not satisfy the policy: {}", policyName);
            throw new NotAuthorizedException("User is not authorized.");
        }
    }

    public void checkRequiredRoles(JwtClaims claims, String[] requiredRoles) {
        Collection<String> userRoles = getRoleClaim(claims);
        for (String role : requiredRoles) {
            if (!userRoles.contains(role)) {
                LOG.debug("User does not have required role: {}", role);
                throw new NotAuthorizedException("User is not authorized.");
            }
        }
    }

    private Collection<String> getRoleClaim(JwtClaims claims) {
        Object claimValue = claims.getClaimValue(roleClaim);
        switch (claimValue) {
            case null -> {
                LOG.debug("Role claim not found: {}", roleClaim);
                throw new NotAuthorizedException("User is not authorized.");
            }
            case String s -> {
                return List.of(s.split("\\s*,\\s*"));
            }
            case Collection collection -> {
                return (Collection<String>) collection;
            }
            default -> {
                LOG.debug("Invalid role claim type: {}", claimValue.getClass());
                throw new NotAuthorizedException("User is not authorized.");
            }
        }
    }
}
