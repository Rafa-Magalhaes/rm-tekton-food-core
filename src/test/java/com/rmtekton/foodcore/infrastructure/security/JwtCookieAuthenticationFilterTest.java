package com.rmtekton.foodcore.infrastructure.security;

import com.rmtekton.foodcore.infrastructure.config.OpenApiConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtCookieAuthenticationFilterTest {

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private FilterChain filterChain;

    private JwtCookieAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        filter = new JwtCookieAuthenticationFilter(jwtTokenService);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    @DisplayName("Cenários Padrão do Filtro JWT via Cookie")
    class StandardScenarios {

        @Test
        @DisplayName("Deve autenticar requisição com JwtAuthenticationToken quando cookie access_token for válido")
        void shouldAuthenticateWhenAccessTokenCookieIsValid() throws Exception {
            UUID userId = UUID.randomUUID();
            JwtUserClaims claims = JwtUserClaims.builder()
                    .userId(userId)
                    .email("rafael@rmtekton.com")
                    .roles(List.of("ROLE_USER"))
                    .build();

            when(jwtTokenService.validateAndExtractClaims("valid.jwt.token")).thenReturn(Optional.of(claims));

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
            request.setCookies(
                    new Cookie("other_cookie", "abc"),
                    new Cookie(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, "valid.jwt.token")
            );
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            assertThat(auth).isInstanceOf(JwtAuthenticationToken.class);
            JwtAuthenticationToken jwtAuth = (JwtAuthenticationToken) auth;
            assertThat(jwtAuth.getUserId()).isEqualTo(userId);
            assertThat(jwtAuth.getEmail()).isEqualTo("rafael@rmtekton.com");
            assertThat(jwtAuth.getCredentials()).isNull();
            assertThat(jwtAuth.getAuthorities())
                    .extracting("authority")
                    .containsExactly("ROLE_USER");

            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve seguir cadeia sem autenticar quando não houver cookies")
        void shouldProceedUnauthenticatedWhenNoCookiesPresent() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verify(jwtTokenService, never()).validateAndExtractClaims(anyString());
            verify(filterChain).doFilter(request, response);
        }
    }

    @Nested
    @DisplayName("Cenários Extremos e Cisnes Negros do Filtro JWT")
    class BlackSwanScenarios {

        @Test
        @DisplayName("Deve recusar autenticação em ataque de Cookie Tossing (múltiplos cookies access_token divergentes)")
        void shouldRejectCookieTossingWithConflictingAccessTokenCookies() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
            request.setCookies(
                    new Cookie(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, "attacker.fake.token"),
                    new Cookie(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, "victim.real.token")
            );
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verify(jwtTokenService, never()).validateAndExtractClaims(anyString());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve ignorar cookie access_token vazio ou composto apenas por espaços")
        void shouldIgnoreBlankAccessTokenCookie() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
            request.setCookies(new Cookie(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, "   "));
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verify(jwtTokenService, never()).validateAndExtractClaims(anyString());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Deve ignorar cabeçalho Authorization Bearer e aceitar exclusivamente Cookie HttpOnly")
        void shouldIgnoreAuthorizationBearerHeaderAndEnforceCookieOnly() throws Exception {
            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
            request.addHeader("Authorization", "Bearer stolen.jwt.token");
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            verify(jwtTokenService, never()).validateAndExtractClaims(anyString());
            verify(filterChain).doFilter(request, response);
        }

        @Test
        @DisplayName("Não deve sobrescrever autenticação já existente no SecurityContext")
        void shouldNotOverwriteExistingAuthentication() throws Exception {
            UUID existingUserId = UUID.randomUUID();
            JwtAuthenticationToken existingAuth = new JwtAuthenticationToken(
                    existingUserId,
                    "existing@rmtekton.com",
                    List.of(new SimpleGrantedAuthority("ROLE_ADMIN"))
            );
            SecurityContextHolder.getContext().setAuthentication(existingAuth);

            MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/users/me");
            request.setCookies(new Cookie(OpenApiConfig.ACCESS_TOKEN_COOKIE_NAME, "other.token"));
            MockHttpServletResponse response = new MockHttpServletResponse();

            filter.doFilter(request, response, filterChain);

            assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(existingAuth);
            verify(jwtTokenService, never()).validateAndExtractClaims(anyString());
            verify(filterChain).doFilter(request, response);
        }
    }
}