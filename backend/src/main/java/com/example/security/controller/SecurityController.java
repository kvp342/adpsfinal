package com.example.security.controller;

import com.example.security.model.IpBlock;
import com.example.security.model.SecurityLog;
import com.example.security.service.DetectionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class SecurityController {

    @Autowired
    private DetectionService detectionService;

    @GetMapping("/logs")
    public List<SecurityLog> getAllLogs(
            @RequestParam(value = "limit", defaultValue = "200") int limit,
            @RequestParam(value = "ip", required = false) String ip,
            @RequestParam(value = "status", required = false) String status,
            @RequestParam(value = "onlyFlagged", required = false) Boolean onlyFlagged
    ) {
        List<SecurityLog> recent = detectionService.getRecentLogs(Math.max(limit, 1));
        List<SecurityLog> filtered = new ArrayList<>();
        for (SecurityLog log : recent) {
            if (ip != null && !ip.isBlank() && (log.getSourceIp() == null || !log.getSourceIp().contains(ip.trim()))) continue;
            if (status != null && !status.isBlank() && (log.getStatus() == null || !log.getStatus().equalsIgnoreCase(status.trim()))) continue;
            if (onlyFlagged != null && onlyFlagged && (log.getStatus() == null || "NORMAL".equalsIgnoreCase(log.getStatus()))) continue;
            filtered.add(log);
        }
        return filtered;
    }

    @GetMapping("/stats")
    public Map<String, Object> getStats() {
        return detectionService.getStats();
    }

    @GetMapping("/blocks")
    public List<IpBlock> getActiveBlocks() {
        return detectionService.getActiveBlocks();
    }

    @PostMapping("/unblock")
    public ResponseEntity<Void> unblock(@RequestBody Map<String, String> payload) {
        String ip = payload.get("ip");
        if (ip == null || ip.isBlank()) return ResponseEntity.badRequest().build();
        detectionService.unblockIp(ip.trim());
        return ResponseEntity.ok().build();
    }

    // Endpoint to simulate/ingest a log
    @PostMapping("/log")
    public ResponseEntity<SecurityLog> createLog(@RequestBody Map<String, String> payload) {
        String ip = payload.get("ip");
        String method = payload.get("method");
        String path = payload.get("path");
        String userAgent = payload.get("userAgent");
        String attackType = payload.get("attackType");
        
        if (ip == null || method == null) {
             // Fallback if not provided, e.g. for simple testing
             return ResponseEntity.badRequest().build();
        }

        SecurityLog log = detectionService.logRequest(ip, method, path, userAgent, attackType);
        return ResponseEntity.ok(log);
    }
}
