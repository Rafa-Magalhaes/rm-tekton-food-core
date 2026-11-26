package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy;
import io.github.bucket4j.distributed.proxy.ProxyManager;
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager;
import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.codec.ByteArrayCodec;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import java.time.Duration;

@Configuration
public class RateLimitConfig {

    @Bean(destroyMethod = "shutdown")
    public RedisClient bucket4jRedisClient(Environment environment) {
        String host = environment.getProperty("spring.data.redis.host", "localhost");
        int port = environment.getProperty("spring.data.redis.port", Integer.class, 6379);
        String password = environment.getProperty("spring.data.redis.password");

        RedisURI.Builder uriBuilder = RedisURI.builder()
                .withHost(host)
                .withPort(port)
                .withTimeout(Duration.ofSeconds(2));

        if (password != null && !password.isBlank()) {
            uriBuilder.withPassword(password.toCharArray());
        }

        return RedisClient.create(uriBuilder.build());
    }

    @Bean(destroyMethod = "close")
    public StatefulRedisConnection<byte[], byte[]> bucket4jRedisConnection(RedisClient bucket4jRedisClient) {
        return bucket4jRedisClient.connect(ByteArrayCodec.INSTANCE);
    }

    @Bean
    public ProxyManager<byte[]> bucket4jProxyManager(StatefulRedisConnection<byte[], byte[]> bucket4jRedisConnection) {
        return LettuceBasedProxyManager.builderFor(bucket4jRedisConnection)
                .withExpirationStrategy(
                        ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(Duration.ofSeconds(10))
                )
                .build();
    }
}