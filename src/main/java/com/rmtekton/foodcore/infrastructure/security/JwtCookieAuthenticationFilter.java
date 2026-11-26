package com.rmtekton.foodcore.infrastructure.security;

import com.rmtekton.foodcore.infrastructure.config.OpenApiConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtCookieAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenService jwtTokenService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            extractUniqueAccessTokenCookie(request)
                    .flatMap(jwtTokenService::validateAndExtractClaims)
                    .ifPresent(claims -> authenticateRequest(claims, request));
        }

        filterChain.doFilter(request, response);
    }

    private Optional<String> extractUniqueAccessTokenCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return Optional.empty();
        }

        String foundToken = null;
        for (Cookie cookie : cookies) {
            if (cookie == null || !OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                continue;
            }
            String value = cookie.getValue();
            if (value == null || value.isBlank()) {
                continue;
            }
            String trimmed = value.trim();
            if (foundToken != null && !foundToken.equals(trimmed)) {
                // Mitigação contra ataque de Cookie Tossing (múltiplos cookies access_token divergentes)
                return Optional.empty();
            }
            foundToken = trimmed;
        }

        return Optional.ofNullable(foundToken);
    }

    private void authenticateRequest(JwtUserClaims claims, HttpServletRequest request) {
        List<SimpleGrantedAuthority> authorities = claims.getRoles()
                .stream()
                .map(SimpleGrantedAuthority::new)
                .toList();

        JwtAuthenticationToken authentication = new JwtAuthenticationToken(
                claims.getUserId(),
                claims.getEmail(),
                authorities
        );
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}