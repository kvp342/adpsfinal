package com.example.security.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

@RestController
public class ReverseProxyController {

    private static final String PREFIX = "/proxy";
    private static final List<String> HOP_BY_HOP_HEADERS = List.of(
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "host"
    );

    private final HttpClient httpClient;

    @Value("${apds.proxy.upstreamBase:}")
    private String upstreamBase;

    public ReverseProxyController() {
        this.httpClient = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
    }

    @RequestMapping(PREFIX + "/**")
    public void proxy(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String base = upstreamBase == null ? "" : upstreamBase.trim();
        if (base.isEmpty()) {
            response.setStatus(400);
            response.setContentType("application/json");
            response.getWriter().write("{\"ok\":false,\"error\":\"apds.proxy.upstreamBase is not configured\"}");
            return;
        }

        String uri = request.getRequestURI();
        String rest = uri.startsWith(PREFIX) ? uri.substring(PREFIX.length()) : uri;
        if (rest.isEmpty()) rest = "/";

        String query = request.getQueryString();
        String target = joinUrl(base, rest) + (query == null || query.isBlank() ? "" : ("?" + query));

        byte[] bodyBytes = readBody(request);
        HttpRequest.BodyPublisher bodyPublisher = bodyBytes == null
                ? HttpRequest.BodyPublishers.noBody()
                : HttpRequest.BodyPublishers.ofByteArray(bodyBytes);

        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(URI.create(target))
                .timeout(Duration.ofSeconds(30));

        copyRequestHeaders(request, builder);
        addForwardedHeaders(request, builder);

        builder.method(request.getMethod(), bodyPublisher);

        HttpResponse<InputStream> upstreamResp = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());

        response.setStatus(upstreamResp.statusCode());
        copyResponseHeaders(upstreamResp, response);

        try (InputStream is = upstreamResp.body()) {
            if (is != null) {
                is.transferTo(response.getOutputStream());
            }
        }
    }

    private void copyRequestHeaders(HttpServletRequest request, HttpRequest.Builder builder) {
        Enumeration<String> names = request.getHeaderNames();
        while (names != null && names.hasMoreElements()) {
            String name = names.nextElement();
            if (name == null) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP_HEADERS.contains(lower)) continue;
            Enumeration<String> values = request.getHeaders(name);
            while (values != null && values.hasMoreElements()) {
                String v = values.nextElement();
                if (v == null) continue;
                builder.header(name, v);
            }
        }
    }

    private void addForwardedHeaders(HttpServletRequest request, HttpRequest.Builder builder) {
        String remoteAddr = request.getRemoteAddr();
        String xff = request.getHeader("X-Forwarded-For");
        String newXff = (xff == null || xff.isBlank()) ? remoteAddr : (xff + ", " + remoteAddr);
        builder.header("X-Forwarded-For", newXff);
        String host = request.getHeader("Host");
        if (host != null && !host.isBlank()) builder.header("X-Forwarded-Host", host);
        builder.header("X-Forwarded-Proto", request.isSecure() ? "https" : "http");
    }

    private void copyResponseHeaders(HttpResponse<?> upstreamResp, HttpServletResponse response) {
        HttpHeaders headers = new HttpHeaders();
        upstreamResp.headers().map().forEach((k, v) -> headers.put(k, v));
        for (String name : headers.keySet()) {
            if (name == null) continue;
            String lower = name.toLowerCase(Locale.ROOT);
            if (HOP_BY_HOP_HEADERS.contains(lower)) continue;
            for (String v : headers.get(name)) {
                response.addHeader(name, v);
            }
        }
    }

    private byte[] readBody(HttpServletRequest request) throws Exception {
        String method = request.getMethod();
        if (method == null) return null;
        String m = method.toUpperCase(Locale.ROOT);
        boolean allowsBody = m.equals("POST") || m.equals("PUT") || m.equals("PATCH") || m.equals("DELETE");
        if (!allowsBody) return null;
        try (InputStream in = request.getInputStream()) {
            if (in == null) return null;
            byte[] b = in.readAllBytes();
            return b.length == 0 ? null : b;
        }
    }

    private String joinUrl(String base, String path) {
        if (base.endsWith("/") && path.startsWith("/")) return base.substring(0, base.length() - 1) + path;
        if (!base.endsWith("/") && !path.startsWith("/")) return base + "/" + path;
        return base + path;
    }
}

