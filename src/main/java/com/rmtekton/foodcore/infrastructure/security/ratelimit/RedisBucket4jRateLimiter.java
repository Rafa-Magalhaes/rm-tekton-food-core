package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.BucketConfiguration;
import io.github.bucket4j.ConsumptionProbe;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;

@Service
@RequiredArgsConstructor
public class RedisBucket4jRateLimiter implements DistributedRateLimiter {

    private final ProxyManager<byte[]> proxyManager;
    private final RateLimitProperties properties;

    @Override
    public ConsumptionProbe tryConsume(String bucketKey, RateLimitBucketTier tier) {
        if (bucketKey == null || bucketKey.isBlank()) {
            throw new IllegalArgumentException("A chave do balde de rate limit não pode ser vazia");
        }
        if (tier == null) {
            throw new IllegalArgumentException("A categoria do balde de rate limit é obrigatória");
        }

        byte[] keyBytes = bucketKey.getBytes(StandardCharsets.UTF_8);
        Bucket bucket = proxyManager.builder().build(keyBytes, () -> buildConfiguration(tier));
        return bucket.tryConsumeAndReturnRemaining(1);
    }

    BucketConfiguration buildConfiguration(RateLimitBucketTier tier) {
        long capacity = switch (tier) {
            case AUTH_STRICT -> properties.getAuthRequestsPerMinute();
            case WRITE_MODERATE -> properties.getWriteRequestsPerMinute();
            case READ_GENERAL -> properties.getReadRequestsPerMinute();
        };

        Bandwidth limit = Bandwidth.builder()
                .capacity(capacity)
                .refillGreedy(capacity, Duration.ofMinutes(1))
                .build();

        return BucketConfiguration.builder()
                .addLimit(limit)
                .build();
    }
}