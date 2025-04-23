package io.github.renegrob.oidc.service.internalissuer.claims;

import io.github.renegrob.oidc.config.OAuthConfig;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Singleton
public class ClaimTranslationFactory {

    private final OAuthConfig config;

    @Inject
    ClaimTranslationFactory(OAuthConfig config) {
        this.config = config;
    }

    public Map<String, ClaimTranslationRule> createClaimTranslations() {
        var translateClaimItems = config.internalIssuer().translateClaimItems();
        Map<String, ClaimTranslationRule> claimTranslations = new HashMap<>();
        if (translateClaimItems.isPresent()) {
            for (OAuthConfig.TranslateClaimItems item : translateClaimItems.get()) {
                Map<String, List<String>> translations = new HashMap<>();
                claimTranslations.put(item.claimName(), new ClaimTranslationRule(item.claimName(), translations, item.removeNonMatching()));
                for (OAuthConfig.ValueMapping valueMapping : item.valueMappings()) {
                    String fromValue = valueMapping.from();
                    List<String> toValues = valueMapping.to();
                    translations.put(fromValue, toValues);
                }
            }
        }
        return claimTranslations;
    }
}
