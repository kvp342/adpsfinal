package com.example.security.config;

import com.example.security.model.SecurityLog;
import com.example.security.service.DetectionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;
import java.util.UUID;

@Component
public class AttackPreventionRequestLoggingFilter extends OncePerRequestFilter {
    private final DetectionService detectionService;
    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");

    private static final Set<String> EXCLUDED_PATHS = Set.of(
            "/api",
            "/h2-console"
    );

    public AttackPreventionRequestLoggingFilter(DetectionService detectionService) {
        this.detectionService = detectionService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String uri = request.getRequestURI();
        String query = request.getQueryString();
        String path = query == null || query.isBlank() ? uri : (uri + "?" + query);
        boolean excluded = EXCLUDED_PATHS.stream().anyMatch(uri::startsWith);
        String existingId = request.getHeader("X-Request-Id");
        String requestId = existingId == null || existingId.isBlank() ? UUID.randomUUID().toString() : existingId.trim();

        long startMs = System.currentTimeMillis();
        MDC.put("requestId", requestId);
        response.setHeader("X-Request-Id", requestId);
        try {
            if (!excluded) {
                String ip = getClientIp(request);
                String method = request.getMethod();
                String userAgent = request.getHeader("User-Agent");
                AUDIT.info("incoming ip={} method={} path={} ua={}", ip, method, path, userAgent);
                SecurityLog log = detectionService.logRequest(ip, method, path, userAgent, null);
                if (log != null && "BLOCKED".equalsIgnoreCase(log.getStatus())) {
                    response.setStatus(429);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"blocked\":true,\"ip\":\"" + escapeJson(ip) + "\",\"reason\":\"" + escapeJson(log.getReason()) + "\"}");
                    return;
                }
            }
            filterChain.doFilter(request, response);
        } catch (Exception e) {
            AUDIT.warn("request_error path={} status={} err={}", path, safeStatus(response), e.toString());
            throw e;
        } finally {
            long durationMs = System.currentTimeMillis() - startMs;
            if (!excluded) {
                AUDIT.info("completed path={} status={} durationMs={}", path, safeStatus(response), durationMs);
            }
            MDC.remove("requestId");
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        String xri = request.getHeader("X-Real-IP");
        if (xri != null && !xri.isBlank()) {
            return xri.trim();
        }
        return request.getRemoteAddr();
    }

    private int safeStatus(HttpServletResponse response) {
        try {
            return response.getStatus();
        } catch (Exception e) {
            return 0;
        }
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ");
    }
}
