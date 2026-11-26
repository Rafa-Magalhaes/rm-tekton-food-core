package com.rmtekton.foodcore.domain.user;

import com.rmtekton.foodcore.domain.exception.ConflictException;
import org.junit.jupiter.api.AfterEach;
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
class UserRegistrationConcurrencyIntegrationTest {

    @Autowired
    private UserService userService;

    @Autowired
    private UserRepository userRepository;

    private String createdTestEmail;

    @AfterEach
    void tearDown() {
        if (createdTestEmail != null) {
            userRepository.findByEmailAndActiveTrue(createdTestEmail)
                    .ifPresent(user -> userRepository.deleteById(user.getId()));
        }
    }

    @Test
    @DisplayName("Deve permitir apenas 1 cadastro e rejeitar 9 com ConflictException sob 10 threads simultâneas no PostgreSQL real")
    void shouldPreventDuplicateUserCreationUnderConcurrentRegistration() throws InterruptedException {
        int threadCount = 10;
        createdTestEmail = "concurrency-" + UUID.randomUUID() + "@rmtekton.com";

        CountDownLatch readyLatch = new CountDownLatch(threadCount);
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);

        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger conflictCount = new AtomicInteger();
        AtomicInteger unexpectedErrorCount = new AtomicInteger();

        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        try {
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executor.submit(() -> {
                    readyLatch.countDown();
                    try {
                        startLatch.await();
                        String emailVariant = (index % 2 == 0)
                                ? "  " + createdTestEmail.toUpperCase() + "  "
                                : createdTestEmail;
                        userService.register("Operador " + index, emailVariant, "SenhaConcorrente2026");
                        successCount.incrementAndGet();
                    } catch (ConflictException ex) {
                        conflictCount.incrementAndGet();
                    } catch (Throwable ex) {
                        unexpectedErrorCount.incrementAndGet();
                    } finally {
                        doneLatch.countDown();
                    }
                });
            }

            assertThat(readyLatch.await(10, TimeUnit.SECONDS)).isTrue();
            startLatch.countDown();
            assertThat(doneLatch.await(30, TimeUnit.SECONDS)).isTrue();
        } finally {
            executor.shutdownNow();
        }

        assertThat(unexpectedErrorCount.get()).isZero();
        assertThat(successCount.get()).isEqualTo(1);
        assertThat(conflictCount.get()).isEqualTo(threadCount - 1);
        assertThat(userRepository.existsByEmail(createdTestEmail)).isTrue();
    }
}