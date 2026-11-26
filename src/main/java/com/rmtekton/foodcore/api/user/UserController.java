package com.rmtekton.foodcore.api.user;

import com.rmtekton.foodcore.api.user.dto.UserRegistrationRequestDTO;
import com.rmtekton.foodcore.api.user.dto.UserResponseDTO;
import com.rmtekton.foodcore.domain.user.User;
import com.rmtekton.foodcore.domain.user.UserService;
import com.rmtekton.foodcore.infrastructure.security.AuthCookieFactory;
import com.rmtekton.foodcore.infrastructure.security.JwtAuthenticationToken;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Tag(name = "Usuários", description = "Cadastro e gestão da conta do usuário autenticado")
public class UserController {

    private final UserService userService;
    private final UserConverter userConverter;
    private final AuthCookieFactory authCookieFactory;

    @PostMapping
    @Operation(summary = "Cadastrar novo usuário", description = "Cria uma nova conta de usuário com senha protegida via Argon2id + Pepper")
    public ResponseEntity<UserResponseDTO> register(@Valid @RequestBody UserRegistrationRequestDTO request) {
        User createdUser = userService.register(request.getName(), request.getEmail(), request.getPassword());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(userConverter.toResponse(createdUser));
    }

    @GetMapping("/me")
    @Operation(summary = "Consultar perfil autenticado", description = "Retorna os dados do usuário dono do Cookie HttpOnly ativo")
    public ResponseEntity<UserResponseDTO> getCurrentUser(JwtAuthenticationToken authentication) {
        User activeUser = userService.findActiveById(authentication.getUserId());
        return ResponseEntity.ok(userConverter.toResponse(activeUser));
    }

    @DeleteMapping("/me")
    @Operation(summary = "Desativar conta autenticada", description = "Realiza exclusão lógica (Soft Delete) da conta do usuário e encerra o cookie de sessão")
    public ResponseEntity<Void> deactivateCurrentUser(JwtAuthenticationToken authentication) {
        userService.deactivateAccount(authentication.getUserId());
        ResponseCookie expiredCookie = authCookieFactory.createLogoutCookie();
        return ResponseEntity.noContent()
                .header(HttpHeaders.SET_COOKIE, expiredCookie.toString())
                .build();
    }
}