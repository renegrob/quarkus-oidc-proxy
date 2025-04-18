package io.github.renegrob.oauth2proxy.service;

import jakarta.inject.Singleton;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.random.RandomGenerator;
import java.util.random.RandomGeneratorFactory;

@Singleton
public class RandomService {

    private final RandomGenerator randomGenerator;

    private List<RandomGeneratorFactory<RandomGenerator>> createFactories(List<String> factoryNames) {
        return factoryNames.stream()
                .map(name -> RandomGeneratorFactory.all()
                        .filter(factory -> factory.name().equals(name))
                        .findFirst()
                        .orElse(null))
                .filter(Objects::nonNull)
                .toList();
    }

    RandomService() {
        List<String> factoryNames = List.of("NativePRNGNonBlocking", "NativePRNG", "NativePRNGBlocking");
        List<RandomGeneratorFactory<RandomGenerator>> factories = createFactories(factoryNames);
        if (factories.isEmpty()) {
            this.randomGenerator = new SecureRandom();
        } else {
            this.randomGenerator = factories.getFirst().create();
        }
    }

    public RandomGenerator getRandomGenerator() {
        return randomGenerator;
    }

    public String generateSecureState(int numberOfBytes) {
        // Generate random bytes using IntStream and convert to byte array
        byte[] stateBytes = randomGenerator.ints(numberOfBytes, 0, 256)
                .map(i -> i & 0xFF)
                .collect(ByteArrayOutputStream::new,
                        (baos, i) -> baos.write(i),
                        (baos1, baos2) -> baos1.write(baos2.toByteArray(), 0, baos2.size()))
                .toByteArray();

        return Base64.getUrlEncoder().withoutPadding().encodeToString(stateBytes);
    }
}
