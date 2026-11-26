package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import com.rmtekton.foodcore.infrastructure.security.SecurityErrorResponseWriter;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock
    private DistributedRateLimiter rateLimiter;

    @Mock
    private FilterChain filterChain;

    private RateLimitProperties properties;
    private SecurityErrorResponseWriter errorWriter;
    private RateLimitFilter filter;

    @BeforeEach
    void setUp() {
        properties = new RateLimitProperties();
        properties.setEnabled(true);
        properties.setTrustProxyHeaders(false);
        errorWriter = new SecurityErrorResponseWriter();
        filter = new RateLimitFilter(rateLimiter, properties, errorWriter);
    }

    @Nested
    @DisplayName("Cenários Padrão de Rate Limiting Multicamada")
    class StandardScenarios {

        @Test
        @DisplayName("Deve aplicar balde AUTH_STRICT no login e retornar X-Rate-Limit-Remaining quando permitido")
        void shouldAllowLoginWithinLimitUsingStrictTier() throws Exception {
            when(rateLimiter.tryConsume(eq("foodcore:ratelimit:AUTH_STRICT:192.168.1.10"), eq(RateLimitBucketTier.AUTH_STRICT)))
                    .thenReturn(ConsumptionProbe.consumed(4, 0));

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setRemoteAddr("192.168.1.10");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(200);
            assertThat(response.getHeader(RateLimitFilter.HEADER_RATE_LIMIT_REMAINING)).isEqualTo("4");
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve bloquear com 429, Retry-After e JSON em português quando limite for excedido")
        void shouldReturn429WithPortugueseJsonWhenLimitExceeded() throws Exception {
            long nanosToWait = TimeUnit.SECONDS.toNanos(42);
            when(rateLimiter.tryConsume(anyString(), eq(RateLimitBucketTier.AUTH_STRICT)))
                    .thenReturn(ConsumptionProbe.rejected(0, nanosToWait, nanosToWait));

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/users");
            request.setRemoteAddr("10.0.0.5");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(429);
            assertThat(response.getHeader(RateLimitFilter.HEADER_RATE_LIMIT_REMAINING)).isEqualTo("0");
            assertThat(response.getHeader(RateLimitFilter.HEADER_RETRY_AFTER)).isEqualTo("42");
            assertThat(response.getContentAsString())
                    .contains("\"status\":429")
                    .contains("Muitas requisições")
                    .contains("42 segundos");
            verify(filterChain, never()).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve classificar POST de negócio como WRITE_MODERATE e GET como READ_GENERAL")
        void shouldClassifyWriteAndReadTiersCorrectly() {
            MockHttpServletRequest postStore = new MockHttpServletRequest("POST", "/api/v1/stores");
            MockHttpServletRequest getStore = new MockHttpServletRequest("GET", "/api/v1/stores");

            assertThat(filter.resolveTier(postStore)).isEqualTo(RateLimitBucketTier.WRITE_MODERATE);
            assertThat(filter.resolveTier(getStore)).isEqualTo(RateLimitBucketTier.READ_GENERAL);
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros do Rate Limiting")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve ignorar cabeçalhos X-Forwarded-For forjados quando trustProxyHeaders estiver desligado")
        void shouldIgnoreSpoofedForwardedForHeadersWhenProxyNotTrusted() throws Exception {
            when(rateLimiter.tryConsume(eq("foodcore:ratelimit:AUTH_STRICT:203.0.113.9"), eq(RateLimitBucketTier.AUTH_STRICT)))
                    .thenReturn(ConsumptionProbe.consumed(3, 0));

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setRemoteAddr("203.0.113.9");
            request.addHeader("X-Forwarded-For", "1.2.3.4");
            request.addHeader("CF-Connecting-IP", "5.6.7.8");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            verify(rateLimiter).tryConsume("foodcore:ratelimit:AUTH_STRICT:203.0.113.9", RateLimitBucketTier.AUTH_STRICT);
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve rejeitar cabeçalhos de IP envenenados (CRLF, sufixo hexadecimal ou zero à esquerda) e usar o remoteAddr real")
        void shouldRejectPoisonedProxyIpHeadersAndFallbackToRemoteAddr() {
            properties.setTrustProxyHeaders(true);

            MockHttpServletRequest crlfInjectionReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            crlfInjectionReq.setRemoteAddr("203.0.113.50");
            crlfInjectionReq.addHeader("X-Forwarded-For", "198.51.100.7\r\nFLUSHALL, 10.0.0.1");

            MockHttpServletRequest hexSuffixReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            hexSuffixReq.setRemoteAddr("203.0.113.50");
            hexSuffixReq.addHeader("X-Forwarded-For", "198.51.100.7FA");

            MockHttpServletRequest leadingZeroReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            leadingZeroReq.setRemoteAddr("203.0.113.50");
            leadingZeroReq.addHeader("CF-Connecting-IP", "01.2.3.4");

            MockHttpServletRequest allInvalidReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            allInvalidReq.setRemoteAddr("999.999.999.999");
            allInvalidReq.addHeader("CF-Connecting-IP", "invalid:::ip");

            assertThat(filter.resolveClientIp(crlfInjectionReq)).isEqualTo("203.0.113.50");
            assertThat(filter.resolveClientIp(hexSuffixReq)).isEqualTo("203.0.113.50");
            assertThat(filter.resolveClientIp(leadingZeroReq)).isEqualTo("203.0.113.50");
            assertThat(filter.resolveClientIp(allInvalidReq)).isEqualTo("unknown");
        }

        @Test
        @DisplayName("Deve aceitar IPv4 e IPv6 válidos (comprimido e completo) quando trustProxyHeaders estiver ativo")
        void shouldAcceptValidIpv4AndIpv6HeadersWhenProxyTrusted() {
            properties.setTrustProxyHeaders(true);

            MockHttpServletRequest ipv4Req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            ipv4Req.addHeader("X-Forwarded-For", "198.51.100.7, 10.0.0.1");

            MockHttpServletRequest ipv6CompressedReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            ipv6CompressedReq.addHeader("CF-Connecting-IP", "2001:db8::1");

            MockHttpServletRequest ipv6LocalhostFullReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            ipv6LocalhostFullReq.addHeader("CF-Connecting-IP", "0:0:0:0:0:0:0:1");

            MockHttpServletRequest ipv6LoopbackReq = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            ipv6LoopbackReq.addHeader("CF-Connecting-IP", "::1");

            assertThat(filter.resolveClientIp(ipv4Req)).isEqualTo("198.51.100.7");
            assertThat(filter.resolveClientIp(ipv6CompressedReq)).isEqualTo("2001:db8::1");
            assertThat(filter.resolveClientIp(ipv6LocalhostFullReq)).isEqualTo("0:0:0:0:0:0:0:1");
            assertThat(filter.resolveClientIp(ipv6LoopbackReq)).isEqualTo("::1");
        }

        @Test
        @DisplayName("Deve aplicar fail-open controlado e permitir requisição se o Redis falhar momentaneamente")
        void shouldFailOpenGracefullyWhenRedisThrowsException() throws Exception {
            when(rateLimiter.tryConsume(anyString(), any()))
                    .thenThrow(new RuntimeException("Redis connection refused"));

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve arredondar Retry-After para no mínimo 1 segundo mesmo em espera sub-segundo")
        void shouldNeverReturnZeroSecondRetryAfter() throws Exception {
            when(rateLimiter.tryConsume(anyString(), any()))
                    .thenReturn(ConsumptionProbe.rejected(0, 150_000L, 150_000L));

            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/auth/login");
            request.setRemoteAddr("127.0.0.1");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(response.getStatus()).isEqualTo(429);
            assertThat(response.getHeader(RateLimitFilter.HEADER_RETRY_AFTER)).isEqualTo("1");
        }

        @Test
        @DisplayName("Não deve filtrar OPTIONS pre-flight, Actuator nem Swagger UI")
        void shouldBypassInfrastructureAndPreflightEndpoints() throws Exception {
            MockHttpServletRequest optionsReq = new MockHttpServletRequest("OPTIONS", "/api/v1/auth/login");
            MockHttpServletRequest actuatorReq = new MockHttpServletRequest("GET", "/actuator/health");
            MockHttpServletRequest swaggerReq = new MockHttpServletRequest("GET", "/swagger-ui/index.html");

            filter.doFilter(optionsReq, new MockHttpServletResponse(), filterChain);
            filter.doFilter(actuatorReq, new MockHttpServletResponse(), filterChain);
            filter.doFilter(swaggerReq, new MockHttpServletResponse(), filterChain);

            verify(rateLimiter, never()).tryConsume(anyString(), any());
        }
    }
}