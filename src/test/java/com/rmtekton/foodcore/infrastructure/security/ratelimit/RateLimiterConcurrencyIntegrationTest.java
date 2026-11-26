package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import io.github.bucket4j.ConsumptionProbe;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class RateLimiterConcurrencyIntegrationTest {

    @Autowired
    private DistributedRateLimiter distributedRateLimiter;

    @Autowired
    private RateLimitProperties rateLimitProperties;

    @Test
    @DisplayName("Deve consumir exatamente o limite AUTH_STRICT e bloquear excedentes sob 10 threads simultâneas no Redis real")
    void shouldEnforceExactAuthStrictLimitUnderConcurrentBurstInRealRedis() throws InterruptedException {
        int limit = Math.toIntExact(rateLimitProperties.getAuthRequestsPerMinute());
        int totalRequests = limit + 5;
        String uniqueBucketKey = "foodcore:ratelimit:test:" + UUID.randomUUID();

        CountDownLatch readyLatch = new CountDownLatch(totalRequests);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(totalRequests);

        AtomicInteger consumedCount = new AtomicInteger();
        AtomicInteger rejectedCount = new AtomicInteger();
        AtomicInteger unexpectedErrorCount = new AtomicInteger();

        ExecutorService executor = Executors.newFixedThreadPool(totalRequests);
        try {
            for (int i = 0; i < totalRequests; i++) {
                executor.submit(() -> {
                    readyLatch.countDown();
                    try {
                        startLatch.await();
                        ConsumptionProbe probe = distributedRateLimiter.tryConsume(
                                uniqueBucketKey,
                                RateLimitBucketTier.AUTH_STRICT
                        );
                        if (probe.isConsumed()) {
                            consumedCount.incrementAndGet();
                        } else {
                            rejectedCount.incrementAndGet();
                        }
                    } catch (Throwable ex) {
                        unexpectedErrorCount.incrementAndGet();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            assertThat(readyLatch.await(10, TimeUnit.SECONDS)).isTrue();
            startLatch.countDown();
            assertThat(doneLatch.await(20, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }

        assertThat(unexpectedErrorCount.get()).isZero();
        assertThat(consumedCount.get()).isEqualTo(limit);
        assertThat(rejectedCount.get()).isEqualTo(totalRequests - limit);
    }
}