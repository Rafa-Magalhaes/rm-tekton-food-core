package com.rmtekton.foodcore.infrastructure.security.ratelimit;

import com.rmtekton.foodcore.infrastructure.security.SecurityErrorResponseWriter;
import io.github.bucket4j.ConsumptionProbe;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Slf4j
@RequiredArgsConstructor
public class RateLimitFilter extends OncePerRequestFilter {

    public static final String HEADER_RATE_LIMIT_REMAINING = "X-Rate-Limit-Remaining";
    public static final String HEADER_RETRY_AFTER = "Retry-After";
    private static final String KEY_PREFIX = "foodcore:ratelimit:";

    private final DistributedRateLimiter rateLimiter;
    private final RateLimitProperties properties;
    private final SecurityErrorResponseWriter errorResponseWriter;

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        if (!properties.isEnabled()) {
            return true;
        }
        if (HttpMethod.OPTIONS.matches(request.getMethod())) {
            return true;
        }
        String path = request.getRequestURI();
        if (path == null) {
            return true;
        }
        return path.startsWith("/actuator")
                || path.startsWith("/swagger-ui")
                || path.startsWith("/v3/api-docs")
                || path.equals("/error");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        RateLimitBucketTier tier = resolveTier(request);
        String clientIp = resolveClientIp(request);
        String bucketKey = KEY_PREFIX + tier.name() + ":" + clientIp;

        try {
            ConsumptionProbe probe = rateLimiter.tryConsume(bucketKey, tier);
            if (probe.isConsumed()) {
                response.setHeader(HEADER_RATE_LIMIT_REMAINING, String.valueOf(probe.getRemainingTokens()));
                filterChain.doFilter(request, response);
                return;
            }

            long waitSeconds = Math.max(1L, TimeUnit.NANOSECONDS.toSeconds(probe.getNanosToWaitForRefill()));
            response.setHeader(HEADER_RATE_LIMIT_REMAINING, "0");
            response.setHeader(HEADER_RETRY_AFTER, String.valueOf(waitSeconds));

            errorResponseWriter.writeError(
                    request,
                    response,
                    HttpStatus.TOO_MANY_REQUESTS,
                    "Muitas requisições",
                    "Limite de requisições excedido. Aguarde " + waitSeconds + " segundos e tente novamente."
            );
        } catch (RuntimeException ex) {
            // Fail-open controlado: falha transitória no Redis não derruba a operação comercial
            log.error("Falha ao consultar Rate Limiter no Redis para a chave {}", bucketKey, ex);
            filterChain.doFilter(request, response);
        }
    }

    RateLimitBucketTier resolveTier(HttpServletRequest request) {
        String method = request.getMethod();
        String path = request.getRequestURI();

        if (HttpMethod.POST.matches(method)
                && ("/api/v1/auth/login".equals(path) || "/api/v1/users".equals(path))) {
            return RateLimitBucketTier.AUTH_STRICT;
        }
        if (HttpMethod.POST.matches(method)
                || HttpMethod.PUT.matches(method)
                || HttpMethod.PATCH.matches(method)
                || HttpMethod.DELETE.matches(method)) {
            return RateLimitBucketTier.WRITE_MODERATE;
        }
        return RateLimitBucketTier.READ_GENERAL;
    }

    String resolveClientIp(HttpServletRequest request) {
        if (properties.isTrustProxyHeaders()) {
            String cfIp = parseValidIp(request.getHeader("CF-Connecting-IP"));
            if (cfIp != null) {
                return cfIp;
            }
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                String firstEntry = forwarded.split(",", -1)[0];
                String validForwardedIp = parseValidIp(firstEntry);
                if (validForwardedIp != null) {
                    return validForwardedIp;
                }
            }
        }

        String validRemoteAddr = parseValidIp(request.getRemoteAddr());
        return validRemoteAddr != null ? validRemoteAddr : "unknown";
    }

    private String parseValidIp(String rawIp) {
        if (rawIp == null || rawIp.indexOf('\r') >= 0 || rawIp.indexOf('\n') >= 0) {
            return null;
        }
        String candidate = rawIp.trim();
        if (isValidIpv4(candidate) || isValidIpv6(candidate)) {
            return candidate;
        }
        return null;
    }

    private boolean isValidIpv4(String ip) {
        String[] octets = ip.split("\\.", -1);
        if (octets.length != 4) {
            return false;
        }
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) {
                return false;
            }
            if (octet.length() > 1 && octet.charAt(0) == '0') {
                return false;
            }
            for (int i = 0; i < octet.length(); i++) {
                char c = octet.charAt(i);
                if (c < '0' || c > '9') {
                    return false;
                }
            }
            int value = Integer.parseInt(octet);
            if (value < 0 || value > 255) {
                return false;
            }
        }
        return true;
    }

    private boolean isValidIpv6(String ip) {
        if (ip.length() < 2 || ip.length() > 39 || !ip.contains(":") || ip.contains(":::")) {
            return false;
        }
        int doubleColonIndex = ip.indexOf("::");
        if (doubleColonIndex >= 0) {
            if (doubleColonIndex != ip.lastIndexOf("::")) {
                return false;
            }
            String leftPart = ip.substring(0, doubleColonIndex);
            String rightPart = ip.substring(doubleColonIndex + 2);
            String[] leftGroups = leftPart.isEmpty() ? new String[0] : leftPart.split(":", -1);
            String[] rightGroups = rightPart.isEmpty() ? new String[0] : rightPart.split(":", -1);

            if (leftGroups.length + rightGroups.length >= 8) {
                return false;
            }
            return areAllHexGroups(leftGroups) && areAllHexGroups(rightGroups);
        }

        String[] groups = ip.split(":", -1);
        return groups.length == 8 && areAllHexGroups(groups);
    }

    private boolean areAllHexGroups(String[] groups) {
        for (String group : groups) {
            if (group.isEmpty() || group.length() > 4) {
                return false;
            }
            for (int i = 0; i < group.length(); i++) {
                char c = group.charAt(i);
                boolean isHex = (c >= '0' && c <= '9')
                        || (c >= 'a' && c <= 'f')
                        || (c >= 'A' && c <= 'F');
                if (!isHex) {
                    return false;
                }
            }
        }
        return true;
    }
}