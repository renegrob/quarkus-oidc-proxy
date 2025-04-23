package io.github.renegrob.oidc.service.internalissuer.claims;

import java.util.*;

public class ClaimTranslationRule {

    private final String claim;
    private final Map<String, List<String>> valueTranslations;
    private final boolean removeUnmatchedValues;

    public ClaimTranslationRule(String claim, Map<String, List<String>> valueTranslations, boolean removeUnmatchedValues) {
        this.claim = claim;
        this.valueTranslations = valueTranslations;
        this.removeUnmatchedValues = removeUnmatchedValues;
    }

    public Object translateClaimValue(Object value) {
        if (value instanceof Collection<?> collection) {
            Set<String> translatedValues = new LinkedHashSet<>();
            for (Object item : collection) {
                List<String> translatedValue = valueTranslations.get(item.toString());
                if (translatedValue != null) {
                    translatedValues.addAll(translatedValue);
                } else if (!removeUnmatchedValues) {
                    translatedValues.add(item.toString());
                }
            }
            return translatedValues;
        } else {
            List<String> translatedValues = valueTranslations.get(value.toString());
            if ((translatedValues != null && !translatedValues.isEmpty())) {
                return translatedValues.getFirst();
            } else if (removeUnmatchedValues) {
                return null;
            }
            return value;
        }
    }
}
