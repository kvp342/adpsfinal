package com.example.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@RestController
public class DemoController {

    @GetMapping("/")
    public Map<String, Object> root() {
        Map<String, Object> res = new HashMap<>();
        res.put("service", "Attack Prevention & Detection System");
        res.put("time", LocalDateTime.now().toString());
        res.put("status", "OK");
        return res;
    }

    @GetMapping("/hello")
    public Map<String, Object> hello() {
        Map<String, Object> res = new HashMap<>();
        res.put("message", "Hello from backend");
        res.put("time", LocalDateTime.now().toString());
        return res;
    }

    @GetMapping("/products")
    public Map<String, Object> products(@RequestParam Map<String, String> query) {
        Map<String, Object> res = new HashMap<>();
        res.put("endpoint", "/products");
        res.put("query", query);
        res.put("time", LocalDateTime.now().toString());
        res.put("items", new String[]{"Keyboard", "Mouse", "Monitor"});
        return res;
    }

    @GetMapping("/search")
    public Map<String, Object> search(@RequestParam Map<String, String> query) {
        Map<String, Object> res = new HashMap<>();
        res.put("endpoint", "/search");
        res.put("query", query);
        res.put("time", LocalDateTime.now().toString());
        return res;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(@RequestBody(required = false) Map<String, Object> body) {
        Map<String, Object> res = new HashMap<>();
        res.put("endpoint", "/login");
        res.put("received", body == null ? Map.of() : body);
        res.put("time", LocalDateTime.now().toString());
        res.put("result", "OK");
        return ResponseEntity.ok(res);
    }
}
