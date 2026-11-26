package com.rmtekton.foodcore.domain.auth;

import com.rmtekton.foodcore.domain.exception.InvalidCredentialsException;
import com.rmtekton.foodcore.domain.user.User;
import com.rmtekton.foodcore.domain.user.UserRepository;
import com.rmtekton.foodcore.infrastructure.security.JwtTokenService;
import com.rmtekton.foodcore.infrastructure.security.PasswordHashingService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private static final String INVALID_CREDENTIALS_MESSAGE = "E-mail ou senha inválidos";

    private final UserRepository userRepository;
    private final PasswordHashingService passwordHashingService;
    private final JwtTokenService jwtTokenService;

    public AuthenticatedSession authenticate(String rawEmail, String rawPassword) {
        if (rawEmail == null || rawEmail.isBlank() || rawPassword == null || rawPassword.isBlank()) {
            passwordHashingService.performTimingAttackMitigation(rawPassword);
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        String normalizedEmail = rawEmail.trim().toLowerCase(Locale.ROOT);
        Optional<User> optionalUser = userRepository.findByEmailAndActiveTrue(normalizedEmail);

        if (optionalUser.isEmpty()) {
            passwordHashingService.performTimingAttackMitigation(rawPassword);
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        User user = optionalUser.get();
        if (!passwordHashingService.matches(rawPassword, user.getPasswordHash())) {
            throw new InvalidCredentialsException(INVALID_CREDENTIALS_MESSAGE);
        }

        String accessToken = jwtTokenService.generateToken(user);

        return AuthenticatedSession.builder()
                .user(user)
                .accessToken(accessToken)
                .build();
    }
}