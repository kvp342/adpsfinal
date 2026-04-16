package com.example.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.net.URI;
import java.util.Arrays;

@SpringBootApplication
@EnableScheduling
public class SecurityApplication {

    @Value("${apds.cors.allowedOrigins:http://localhost:5173,http://localhost:3000}")
    private String corsAllowedOrigins;

    @Value("${apds.cors.allowedOriginPatterns:}")
    private String corsAllowedOriginPatterns;

    public static void main(String[] args) {
        applyDatabaseUrlIfPresent();
        SpringApplication.run(SecurityApplication.class, args);
    }

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                String[] origins = splitCsv(corsAllowedOrigins);
                String[] patterns = splitCsv(corsAllowedOriginPatterns);

                CorsRegistration api = registry.addMapping("/api/**")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*");
                if (origins.length > 0) api.allowedOrigins(origins);
                if (patterns.length > 0) api.allowedOriginPatterns(patterns);

                CorsRegistration proxy = registry.addMapping("/proxy/**")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD")
                        .allowedHeaders("*");
                if (origins.length > 0) proxy.allowedOrigins(origins);
                if (patterns.length > 0) proxy.allowedOriginPatterns(patterns);
            }
        };
    }


    private static String[] splitCsv(String csv) {
        if (csv == null) return new String[0];
        return Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toArray(String[]::new);
    }

    private static void applyDatabaseUrlIfPresent() {
        String raw = System.getenv("DATABASE_URL");
        if (raw == null || raw.trim().isEmpty()) return;
        raw = raw.trim();

        try {
            if (raw.startsWith("jdbc:")) {
                System.setProperty("spring.datasource.url", raw);
                return;
            }

            URI uri = URI.create(raw);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase();
            if (!scheme.equals("postgres") && !scheme.equals("postgresql")) return;

            String host = uri.getHost();
            int port = uri.getPort();
            String db = uri.getPath() == null ? "" : uri.getPath().replaceFirst("^/", "");
            if (host == null || host.isBlank() || db.isBlank()) return;

            String jdbc = "jdbc:postgresql://" + host + (port > 0 ? ":" + port : "") + "/" + db;
            if (uri.getQuery() != null && !uri.getQuery().isBlank()) jdbc = jdbc + "?" + uri.getQuery();
            System.setProperty("spring.datasource.url", jdbc);

            String userInfo = uri.getUserInfo();
            if (userInfo != null && !userInfo.isBlank()) {
                String[] parts = userInfo.split(":", 2);
                if (parts.length > 0 && !parts[0].isBlank()) System.setProperty("spring.datasource.username", parts[0]);
                if (parts.length > 1 && !parts[1].isBlank()) System.setProperty("spring.datasource.password", parts[1]);
            }

            System.setProperty("spring.datasource.driver-class-name", "org.postgresql.Driver");
            System.setProperty("spring.jpa.database-platform", "org.hibernate.dialect.PostgreSQLDialect");
            System.setProperty("spring.jpa.hibernate.ddl-auto", "update");
        } catch (Exception ignored) {
        }
    }
}
