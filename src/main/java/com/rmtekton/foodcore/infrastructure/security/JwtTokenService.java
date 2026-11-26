package com.rmtekton.foodcore.infrastructure.security;

import com.rmtekton.foodcore.domain.user.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtTokenService {

    public static final String TOKEN_ISSUER = "rm-tekton-food-core";
    public static final String CLAIM_EMAIL = "email";
    public static final String CLAIM_ROLES = "roles";
    private static final int MIN_SECRET_BYTES = 32;

    private final SecurityProperties securityProperties;
    private final Clock clock;

    private SecretKey signingKey;

    @PostConstruct
    void initializeSigningKey() {
        String secret = securityProperties.getJwt().getSecret();
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("Chave secreta JWT não configurada");
        }
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < MIN_SECRET_BYTES) {
            throw new IllegalStateException("Chave secreta JWT deve possuir no mínimo 32 bytes");
        }
        this.signingKey = Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(User user) {
        if (user == null || user.getId() == null || user.getEmail() == null || user.getEmail().isBlank() || user.getRole() == null) {
            throw new IllegalArgumentException("Dados obrigatórios do usuário ausentes para geração do token");
        }
        Long expirationHours = securityProperties.getJwt().getExpirationHours();
        if (expirationHours == null || expirationHours < 1) {
            throw new IllegalStateException("Tempo de expiração do JWT inválido");
        }

        Instant now = Instant.now(clock);
        Instant expiresAt = now.plus(Duration.ofHours(expirationHours));
        List<String> roles = List.of("ROLE_" + user.getRole().name());

        return Jwts.builder()
                .issuer(TOKEN_ISSUER)
                .subject(user.getId().toString())
                .claim(CLAIM_EMAIL, user.getEmail())
                .claim(CLAIM_ROLES, roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .signWith(resolveSigningKey(), Jwts.SIG.HS256)
                .compact();
    }

    public Optional<JwtUserClaims> validateAndExtractClaims(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(resolveSigningKey())
                    .requireIssuer(TOKEN_ISSUER)
                    .clock(() -> Date.from(Instant.now(clock)))
                    .build()
                    .parseSignedClaims(token.trim())
                    .getPayload();

            UUID userId = parseUuidStrict(claims.getSubject());
            String email = claims.get(CLAIM_EMAIL, String.class);
            List<String> roles = extractRoles(claims.get(CLAIM_ROLES));

            if (userId == null || email == null || email.isBlank() || roles.isEmpty()) {
                return Optional.empty();
            }

            return Optional.of(JwtUserClaims.builder()
                    .userId(userId)
                    .email(email)
                    .roles(roles)
                    .build());
        } catch (JwtException | IllegalArgumentException ex) {
            return Optional.empty();
        }
    }

    private SecretKey resolveSigningKey() {
        if (this.signingKey == null) {
            initializeSigningKey();
        }
        return this.signingKey;
    }

    private UUID parseUuidStrict(String subject) {
        if (subject == null || subject.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(subject);
        } catch (IllegalArgumentException ex) {
            return null;
        }
    }

    private List<String> extractRoles(Object rawRoles) {
        if (!(rawRoles instanceof Collection<?> collection)) {
            return List.of();
        }
        return collection.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .map(String::trim)
                .filter(role -> !role.isBlank())
                .toList();
    }
}