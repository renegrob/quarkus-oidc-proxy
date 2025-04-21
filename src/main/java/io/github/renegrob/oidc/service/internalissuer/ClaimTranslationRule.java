package io.github.renegrob.oidc.service.internalissuer;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

public class ClaimTranslationRule {

    private final String claim;
    private final Map<String, String> valueTranslations;
    private final boolean removeUnmatchedValues;

    public ClaimTranslationRule(String claim, Map<String, String> valueTranslations, boolean removeUnmatchedValues) {
        this.claim = claim;
        this.valueTranslations = valueTranslations;
        this.removeUnmatchedValues = removeUnmatchedValues;
    }
    public String getClaim() {
        return claim;
    }

    public boolean isRemoveUnmatchedValues() {
        return removeUnmatchedValues;
    }

    public Object translateClaimValue(Object value) {
        if (value instanceof Collection<?> collection) {
            Set<String> translatedValues = new LinkedHashSet<>();
            for (Object item : collection) {
                String translatedValue = valueTranslations.get(item.toString());
                if (translatedValue != null) {
                    translatedValues.add(translatedValue);
                } else if (!removeUnmatchedValues) {
                    translatedValues.add(item.toString());
                }
            }
            return translatedValues;
        } else {
            String translatedValue = valueTranslations.get(value.toString());
            if (translatedValue != null || removeUnmatchedValues) {
                return translatedValue;
            }
            return value;
        }
    }
}
