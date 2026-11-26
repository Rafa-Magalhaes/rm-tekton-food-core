package com.rmtekton.foodcore.domain.user;

import com.rmtekton.foodcore.domain.exception.ConflictException;
import com.rmtekton.foodcore.domain.exception.ResourceNotFoundException;
import com.rmtekton.foodcore.infrastructure.security.PasswordHashingService;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Locale;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private static final String EMAIL_CONFLICT_MESSAGE = "Já existe uma conta cadastrada com este e-mail";
    private static final String USER_NOT_FOUND_MESSAGE = "Usuário não encontrado";

    private final UserRepository userRepository;
    private final PasswordHashingService passwordHashingService;

    public User register(String rawName, String rawEmail, String rawPassword) {
        String sanitizedName = sanitizeRequiredText(rawName, "O nome é obrigatório");
        String normalizedEmail = normalizeEmail(rawEmail);
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("A senha é obrigatória");
        }

        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new ConflictException(EMAIL_CONFLICT_MESSAGE);
        }

        String passwordHash = passwordHashingService.encode(rawPassword);

        User newUser = User.builder()
                .name(sanitizedName)
                .email(normalizedEmail)
                .passwordHash(passwordHash)
                .role(UserRole.USER)
                .active(true)
                .build();

        try {
            return userRepository.saveAndFlush(newUser);
        } catch (DataIntegrityViolationException ex) {
            throw new ConflictException(EMAIL_CONFLICT_MESSAGE);
        }
    }

    @Transactional(readOnly = true)
    public User findActiveById(UUID userId) {
        if (userId == null) {
            throw new ResourceNotFoundException(USER_NOT_FOUND_MESSAGE);
        }
        return userRepository.findByIdAndActiveTrue(userId)
                .orElseThrow(() -> new ResourceNotFoundException(USER_NOT_FOUND_MESSAGE));
    }

    @Transactional
    public void deactivateAccount(UUID userId) {
        User activeUser = findActiveById(userId);
        activeUser.deactivate();
        userRepository.save(activeUser);
    }

    private String sanitizeRequiredText(String value, String errorMessage) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(errorMessage);
        }
        return value.trim();
    }

    private String normalizeEmail(String rawEmail) {
        if (rawEmail == null || rawEmail.isBlank()) {
            throw new IllegalArgumentException("O e-mail é obrigatório");
        }
        return rawEmail.trim().toLowerCase(Locale.ROOT);
    }
}