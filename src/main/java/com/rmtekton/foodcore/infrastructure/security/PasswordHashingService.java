package com.rmtekton.foodcore.infrastructure.security;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class PasswordHashingService {

    private static final String DUMMY_TIMING_GUARD_INPUT = "RmTektonTimingAttackGuardDummy2026";

    private final SecurityProperties securityProperties;
    private final Argon2PasswordEncoder argon2PasswordEncoder =
            Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    private volatile String dummyHash;

    @PostConstruct
    void initializeDummyHash() {
        this.dummyHash = encode(DUMMY_TIMING_GUARD_INPUT);
    }

    public String encode(String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("A senha não pode ser nula ou em branco");
        }
        return argon2PasswordEncoder.encode(applyPepper(rawPassword));
    }

    public boolean matches(String rawPassword, String encodedHash) {
        if (rawPassword == null || rawPassword.isBlank() || encodedHash == null || encodedHash.isBlank()) {
            return false;
        }
        return argon2PasswordEncoder.matches(applyPepper(rawPassword), encodedHash);
    }

    public void performTimingAttackMitigation(String rawPassword) {
        String safeInput = (rawPassword == null) ? "" : rawPassword;
        String targetHash = this.dummyHash;
        if (targetHash == null) {
            targetHash = encode(DUMMY_TIMING_GUARD_INPUT);
            this.dummyHash = targetHash;
        }
        argon2PasswordEncoder.matches(applyPepper(safeInput), targetHash);
    }

    private String applyPepper(String rawPassword) {
        String pepper = securityProperties.getPepper();
        if (pepper == null || pepper.isBlank()) {
            throw new IllegalStateException("Chave pepper de segurança não configurada");
        }
        return rawPassword + pepper;
    }
}