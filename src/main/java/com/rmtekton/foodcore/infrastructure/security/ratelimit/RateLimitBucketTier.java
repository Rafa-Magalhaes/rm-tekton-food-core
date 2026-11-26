package com.rmtekton.foodcore.infrastructure.security.ratelimit;

public enum RateLimitBucketTier {
    AUTH_STRICT,
    WRITE_MODERATE,
    READ_GENERAL
}