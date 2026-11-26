package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import io.github.bucket4j.ConsumptionProbe;

public interface DistributedRateLimiter {

    ConsumptionProbe tryConsume(String bucketKey, RateLimitBucketTier tier);
}