package com.rmtekton.foodcore.api.auth;

import com.rmtekton.foodcore.api.auth.dto.AuthSessionResponseDTO;
import com.rmtekton.foodcore.api.auth.dto.LoginRequestDTO;
import com.rmtekton.foodcore.api.auth.dto.LogoutResponseDTO;
import com.rmtekton.foodcore.api.user.UserConverter;
import com.rmtekton.foodcore.domain.auth.AuthService;
import com.rmtekton.foodcore.domain.auth.AuthenticatedSession;
import com.rmtekton.foodcore.infrastructure.security.AuthCookieFactory;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Autenticação", description = "Login e logout com entrega exclusiva de JWT via Cookie HttpOnly")
public class AuthController {

    private final AuthService authService;
    private final UserConverter userConverter;
    private final AuthCookieFactory authCookieFactory;

    @PostMapping("/login")
    @Operation(summary = "Autenticar usuário", description = "Valida credenciais e entrega o token JWT exclusivamente via Cookie HttpOnly")
    public ResponseEntity<AuthSessionResponseDTO> login(@Valid @RequestBody LoginRequestDTO request) {
        AuthenticatedSession session = authService.authenticate(request.getEmail(), request.getPassword());
        ResponseCookie cookie = authCookieFactory.createAccessTokenCookie(session.getAccessToken());

        AuthSessionResponseDTO body = AuthSessionResponseDTO.builder()
                .message("Autenticação realizada com sucesso")
                .user(userConverter.toResponse(session.getUser()))
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(body);
    }

    @PostMapping("/logout")
    @Operation(summary = "Encerrar sessão", description = "Expira imediatamente o Cookie HttpOnly de autenticação")
    public ResponseEntity<LogoutResponseDTO> logout() {
        ResponseCookie expiredCookie = authCookieFactory.createLogoutCookie();

        LogoutResponseDTO body = LogoutResponseDTO.builder()
                .message("Sessão encerrada com sucesso")
                .build();

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, expiredCookie.toString())
                .body(body);
    }
}