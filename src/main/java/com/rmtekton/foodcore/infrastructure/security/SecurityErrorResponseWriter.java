package com.rmtekton.foodcore.infrastructure.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;

@Component
public class SecurityErrorResponseWriter {

    private static final String UNKNOWN_PATH = "N/A";

    public void writeError(
            HttpServletRequest request,
            HttpServletResponse response,
            HttpStatus status,
            String error,
            String message) throws IOException {
        response.setStatus(status.value());
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        String path = (request == null || request.getRequestURI() == null || request.getRequestURI().isBlank())
                ? UNKNOWN_PATH
                : request.getRequestURI();

        String json = "{"
                + "\"timestamp\":\"" + escapeJson(OffsetDateTime.now().toString()) + "\","
                + "\"status\":" + status.value() + ","
                + "\"error\":\"" + escapeJson(error) + "\","
                + "\"message\":\"" + escapeJson(message) + "\","
                + "\"path\":\"" + escapeJson(path) + "\""
                + "}";

        response.getWriter().write(json);
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}