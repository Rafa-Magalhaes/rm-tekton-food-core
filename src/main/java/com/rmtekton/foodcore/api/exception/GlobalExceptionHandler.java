package com.rmtekton.foodcore.api.exception;

import com.rmtekton.foodcore.domain.exception.BusinessRuleException;
import com.rmtekton.foodcore.domain.exception.ConflictException;
import com.rmtekton.foodcore.domain.exception.ResourceNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import com.rmtekton.foodcore.domain.exception.InvalidCredentialsException;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.stream.Stream;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final String DEFAULT_NOT_FOUND_MESSAGE = "O recurso solicitado não foi encontrado";
    private static final String DEFAULT_CONFLICT_MESSAGE = "Ocorreu um conflito de dados";
    private static final String DEFAULT_BUSINESS_RULE_MESSAGE = "Uma regra de negócio foi violada";
    private static final String DEFAULT_FIELD_ERROR_MESSAGE = "Valor inválido";
    private static final String DEFAULT_GLOBAL_ERROR_MESSAGE = "Corpo da requisição inválido";
    private static final String UNKNOWN_FIELD = "desconhecido";
    private static final String GLOBAL_REQUEST_FIELD = "requisicao";
    private static final String UNKNOWN_PATH = "N/A";
    private static final String DEFAULT_INVALID_CREDENTIALS_MESSAGE = "E-mail ou senha inválidos";

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponseDTO> handleResourceNotFound(
            ResourceNotFoundException ex,
            HttpServletRequest request) {
        String safeMessage = sanitizeMessage(ex.getMessage(), DEFAULT_NOT_FOUND_MESSAGE);
        return buildResponse(HttpStatus.NOT_FOUND, "Recurso não encontrado", safeMessage, request, null);
    }

    @ExceptionHandler(ConflictException.class)
    public ResponseEntity<ErrorResponseDTO> handleConflict(
            ConflictException ex,
            HttpServletRequest request) {
        String safeMessage = sanitizeMessage(ex.getMessage(), DEFAULT_CONFLICT_MESSAGE);
        return buildResponse(HttpStatus.CONFLICT, "Conflito de dados", safeMessage, request, null);
    }

    @ExceptionHandler(BusinessRuleException.class)
    public ResponseEntity<ErrorResponseDTO> handleBusinessRule(
            BusinessRuleException ex,
            HttpServletRequest request) {
        String safeMessage = sanitizeMessage(ex.getMessage(), DEFAULT_BUSINESS_RULE_MESSAGE);
        return buildResponse(HttpStatus.valueOf(422), "Violação de regra de negócio", safeMessage, request, null);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponseDTO> handleInvalidCredentials(
            InvalidCredentialsException ex,
            HttpServletRequest request) {
        String safeMessage = sanitizeMessage(ex.getMessage(), DEFAULT_INVALID_CREDENTIALS_MESSAGE);
        return buildResponse(HttpStatus.UNAUTHORIZED, "Não autorizado", safeMessage, request, null);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponseDTO> handleValidationErrors(
            MethodArgumentNotValidException ex,
            HttpServletRequest request) {
        List<FieldErrorDTO> validationErrors = extractValidationErrors(ex);

        return buildResponse(
                HttpStatus.BAD_REQUEST,
                "Erro de validação",
                "Um ou mais campos informados são inválidos",
                request,
                validationErrors
        );
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponseDTO> handleMalformedJson(
            HttpMessageNotReadableException ex,
            HttpServletRequest request) {
        return buildResponse(
                HttpStatus.BAD_REQUEST,
                "Requisição malformada",
                "O corpo da requisição está inválido ou contém tipos de dados incompatíveis",
                request,
                null
        );
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponseDTO> handleUnexpectedError(
            Exception ex,
            HttpServletRequest request) {
        String safeLogPath = sanitizeForLog(resolvePath(request));
        log.error("Erro interno inesperado na rota {}", safeLogPath, ex);

        return buildResponse(
                HttpStatus.INTERNAL_SERVER_ERROR,
                "Erro interno do servidor",
                "Ocorreu um erro inesperado. Tente novamente mais tarde.",
                request,
                null
        );
    }

    private List<FieldErrorDTO> extractValidationErrors(MethodArgumentNotValidException ex) {
        List<FieldErrorDTO> fieldErrors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(error -> FieldErrorDTO.builder()
                        .field(sanitizeMessage(error.getField(), UNKNOWN_FIELD))
                        .message(sanitizeMessage(error.getDefaultMessage(), DEFAULT_FIELD_ERROR_MESSAGE))
                        .build())
                .toList();

        List<FieldErrorDTO> globalErrors = ex.getBindingResult()
                .getGlobalErrors()
                .stream()
                .map(error -> FieldErrorDTO.builder()
                        .field(sanitizeMessage(error.getObjectName(), GLOBAL_REQUEST_FIELD))
                        .message(sanitizeMessage(error.getDefaultMessage(), DEFAULT_GLOBAL_ERROR_MESSAGE))
                        .build())
                .toList();

        List<FieldErrorDTO> allErrors = Stream.concat(fieldErrors.stream(), globalErrors.stream()).toList();
        return allErrors.isEmpty() ? null : allErrors;
    }

    private ResponseEntity<ErrorResponseDTO> buildResponse(
            HttpStatus status,
            String error,
            String message,
            HttpServletRequest request,
            List<FieldErrorDTO> fields) {
        ErrorResponseDTO body = ErrorResponseDTO.builder()
                .timestamp(OffsetDateTime.now())
                .status(status.value())
                .error(error)
                .message(message)
                .path(resolvePath(request))
                .fields(fields)
                .build();

        return ResponseEntity.status(status).body(body);
    }

    private String sanitizeMessage(String message, String fallback) {
        if (message == null || message.isBlank()) {
            return fallback;
        }
        return message.trim();
    }

    private String resolvePath(HttpServletRequest request) {
        if (request == null || request.getRequestURI() == null || request.getRequestURI().isBlank()) {
            return UNKNOWN_PATH;
        }
        return request.getRequestURI();
    }

    private String sanitizeForLog(String value) {
        return value.replaceAll("[\\r\\n]", "_");
    }
}