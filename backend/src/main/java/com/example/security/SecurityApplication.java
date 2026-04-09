package com.example.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.Arrays;

@SpringBootApplication
@EnableScheduling
public class SecurityApplication {

    @Value("${apds.cors.allowedOrigins:http://localhost:5173,http://localhost:3000}")
    private String corsAllowedOrigins;

    @Value("${apds.cors.allowedOriginPatterns:}")
    private String corsAllowedOriginPatterns;

    public static void main(String[] args) {
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
}
