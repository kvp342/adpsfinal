package com.example.security.service;

import com.example.security.model.IpBlock;
import com.example.security.model.SecurityLog;
import com.example.security.repository.IpBlockRepository;
import com.example.security.repository.SecurityLogRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

@Service
public class DetectionService {

    private static final Logger AUDIT = LoggerFactory.getLogger("SECURITY_AUDIT");

    @Autowired
    private SecurityLogRepository repository;

    @Autowired
    private IpBlockRepository ipBlockRepository;

    @Autowired
    private MlRandomForestService mlService;

    private static final Set<String> TRUSTED_IPS = Set.of("127.0.0.1", "::1", "0:0:0:0:0:0:0:1", "localhost");

    private static final Pattern SQLI_PATTERN = Pattern.compile("(?i)(\\bunion\\b\\s+\\bselect\\b|\\bor\\b\\s+1\\s*=\\s*1\\b|\\bdrop\\b\\s+\\btable\\b|\\bselect\\b\\s+.+\\s+\\bfrom\\b|\\binformation_schema\\b)");
    private static final Pattern XSS_PATTERN = Pattern.compile("(?i)(<\\s*script|%3c\\s*script|javascript:|onerror\\s*=|onload\\s*=)");
    private static final Pattern COMMAND_INJECTION_PATTERN = Pattern.compile("(?i)(\\$\\(|`|\\b(cmd\\.exe|powershell|bash|sh)\\b|\\b(cat|ls|whoami|id|uname)\\b|[;&|]{1,2}\\s*\\w+)");
    private static final Pattern SSRF_PATTERN = Pattern.compile("(?i)(https?://(localhost|127\\.0\\.0\\.1|0\\.0\\.0\\.0)\\b|169\\.254\\.169\\.254\\b|file://|gopher://|ftp://)");
    private static final Pattern LFI_PATTERN = Pattern.compile("(?i)(/etc/passwd\\b|/proc/self/environ\\b|windows/win\\.ini\\b|php://filter\\b)");

    private final Map<String, StrikeState> strikeStates = new ConcurrentHashMap<>();

    // Simulate/Log a request and check for suspicious activity
    public SecurityLog logRequest(String ip, String method) {
        return logRequest(ip, method, "/", null, null);
    }

    public SecurityLog logRequest(String ip, String method, String path, String userAgent, String declaredAttackType) {
        LocalDateTime now = LocalDateTime.now();
        String normalizedIp = ip == null || ip.isBlank() ? "UNKNOWN" : ip.trim();

        SecurityLog log = new SecurityLog();
        log.setSourceIp(normalizedIp);
        log.setRequestMethod(method == null || method.isBlank() ? "GET" : method.trim().toUpperCase());
        log.setRequestPath(path == null || path.isBlank() ? "/" : path);
        log.setUserAgent(userAgent);
        log.setTimestamp(now);

        Optional<IpBlock> activeBlock = ipBlockRepository.findBySourceIp(normalizedIp)
                .filter(b -> b.getBlockedUntil() != null && b.getBlockedUntil().isAfter(now));

        if (activeBlock.isPresent()) {
            IpBlock block = activeBlock.get();
            log.setStatus("BLOCKED");
            log.setAttackType("BLOCKED_IP");
            log.setRiskScore(100);
            log.setReason(block.getReason() == null || block.getReason().isBlank() ? "IP is currently blocked" : block.getReason());
            log.setSuspicious(true);
            applyMlPrediction(log);
            AUDIT.info("decision status={} attackType={} riskScore={} ip={} method={} path={} mlProb={} mlPred={} reason={}",
                    log.getStatus(),
                    log.getAttackType(),
                    log.getRiskScore(),
                    normalizedIp,
                    log.getRequestMethod(),
                    log.getRequestPath(),
                    log.getMlIntrusionProbability(),
                    log.isMlIntrusionPredicted(),
                    log.getReason());
            return repository.save(log);
        }

        int riskScore = 0;
        String attackType = "NONE";
        LinkedHashSet<String> reasons = new LinkedHashSet<>();

        if (declaredAttackType != null && !declaredAttackType.isBlank()) {
            String t = declaredAttackType.trim().toUpperCase();
            switch (t) {
                case "SQLI":
                case "SQL_INJECTION":
                    riskScore += 70;
                    attackType = "SQL_INJECTION";
                    reasons.add("SQL injection signature (simulated)");
                    break;
                case "XSS":
                    riskScore += 60;
                    attackType = "XSS";
                    reasons.add("XSS signature (simulated)");
                    break;
                case "BRUTE_FORCE":
                    riskScore += 55;
                    attackType = "BRUTE_FORCE";
                    reasons.add("Brute-force pattern (simulated)");
                    break;
                case "CREDENTIAL_STUFFING":
                    riskScore += 60;
                    attackType = "CREDENTIAL_STUFFING";
                    reasons.add("Credential stuffing pattern (simulated)");
                    break;
                case "PORT_SCAN":
                    riskScore += 45;
                    attackType = "PORT_SCAN";
                    reasons.add("Port-scan pattern (simulated)");
                    break;
                case "RATE_LIMIT":
                    riskScore += 15;
                    attackType = "RATE_LIMIT";
                    reasons.add("Rate abuse pattern (simulated)");
                    break;
                case "PATH_TRAVERSAL":
                    riskScore += 45;
                    attackType = "PATH_TRAVERSAL";
                    reasons.add("Path traversal pattern (simulated)");
                    break;
                case "PROBING":
                    riskScore += 25;
                    attackType = "PROBING";
                    reasons.add("Endpoint probing (simulated)");
                    break;
                case "SCANNER":
                    riskScore += 55;
                    attackType = "SCANNER";
                    reasons.add("Scanner activity (simulated)");
                    break;
                case "COMMAND_INJECTION":
                    riskScore += 85;
                    attackType = "COMMAND_INJECTION";
                    reasons.add("Command injection signature (simulated)");
                    break;
                case "SSRF":
                    riskScore += 85;
                    attackType = "SSRF";
                    reasons.add("SSRF signature (simulated)");
                    break;
                case "LFI":
                case "FILE_INCLUSION":
                    riskScore += 75;
                    attackType = "LFI";
                    reasons.add("Local file inclusion signature (simulated)");
                    break;
                default:
                    riskScore += 20;
                    attackType = t;
                    reasons.add("Suspicious activity type (simulated)");
                    break;
            }
        }

        LocalDateTime tenSecondsAgo = now.minusSeconds(10);
        long requestCount10s = "UNKNOWN".equals(normalizedIp) ? 0 : repository.countBySourceIpAndTimestampAfter(normalizedIp, tenSecondsAgo);
        if (requestCount10s >= 5) {
            riskScore += 30;
            reasons.add("High request rate (>5 requests/10s)");
            if ("NONE".equals(attackType)) attackType = "RATE_LIMIT";
        }
        if (requestCount10s >= 10) {
            riskScore += 30;
            reasons.add("Very high request rate (>10 requests/10s)");
            if ("NONE".equals(attackType)) attackType = "RATE_LIMIT";
        }

        String rawPath = log.getRequestPath() == null ? "" : log.getRequestPath();
        String p = rawPath.toLowerCase();
        String decoded = decodeLenient(p);

        String m = log.getRequestMethod() == null ? "" : log.getRequestMethod();
        if ("TRACE".equals(m) || "CONNECT".equals(m)) {
            riskScore += 20;
            reasons.add("Uncommon HTTP method");
            if ("NONE".equals(attackType)) attackType = "PROBING";
        }

        if (decoded.contains("../") || decoded.contains("..\\") || decoded.contains("%2e%2e")) {
            riskScore += 25;
            reasons.add("Path traversal signature");
            if ("NONE".equals(attackType)) attackType = "PATH_TRAVERSAL";
        }
        if (SQLI_PATTERN.matcher(decoded).find() || decoded.contains("'--") || decoded.contains("\"--")) {
            riskScore += 75;
            reasons.add("SQL injection signature");
            attackType = "SQL_INJECTION";
        }
        if (XSS_PATTERN.matcher(decoded).find()) {
            riskScore += 65;
            reasons.add("XSS signature");
            if (!"SQL_INJECTION".equals(attackType)) attackType = "XSS";
        }
        if (COMMAND_INJECTION_PATTERN.matcher(decoded).find()) {
            riskScore += 85;
            reasons.add("Command injection signature");
            attackType = "COMMAND_INJECTION";
        }
        if (SSRF_PATTERN.matcher(decoded).find()) {
            riskScore += 85;
            reasons.add("SSRF signature");
            if (!"COMMAND_INJECTION".equals(attackType)) attackType = "SSRF";
        }
        if (LFI_PATTERN.matcher(decoded).find()) {
            riskScore += 75;
            reasons.add("Local file inclusion signature");
            if ("NONE".equals(attackType) || "PROBING".equals(attackType) || "PATH_TRAVERSAL".equals(attackType)) attackType = "LFI";
        }
        if (decoded.contains("/wp-admin") || decoded.contains("wp-login") || decoded.contains("/admin") || decoded.contains("/.env")) {
            riskScore += 20;
            reasons.add("Sensitive endpoint probing");
            if ("NONE".equals(attackType)) attackType = "PROBING";
        }

        if ("POST".equals(log.getRequestMethod()) && decoded.contains("/login") && requestCount10s >= 5) {
            riskScore += 20;
            reasons.add("Rapid login attempts");
            if ("NONE".equals(attackType)) attackType = "BRUTE_FORCE";
        }

        String ua = userAgent == null ? "" : userAgent.toLowerCase();
        if (!ua.isBlank() && (ua.contains("sqlmap") || ua.contains("nikto") || ua.contains("nmap"))) {
            riskScore += 60;
            reasons.add("Scanner user-agent signature");
            if ("NONE".equals(attackType)) attackType = "SCANNER";
        } else if (ua.isBlank()) {
            riskScore += 5;
            reasons.add("Missing user-agent");
        }

        String status;
        boolean trusted = TRUSTED_IPS.contains(normalizedIp);
        StrikeState st = getStrikeState(normalizedIp, now);
        if (riskScore >= 80) {
            if (trusted) {
                status = "SUSPICIOUS";
                reasons.add("Trusted IP not auto-blocked");
            } else if (riskScore >= 90 || st.strikes >= 1 || requestCount10s >= 10) {
                status = "BLOCKED";
                IpBlock block = ipBlockRepository.findBySourceIp(normalizedIp).orElseGet(IpBlock::new);
                block.setSourceIp(normalizedIp);
                block.setCreatedAt(block.getCreatedAt() == null ? now : block.getCreatedAt());
                block.setBlockedUntil(now.plusMinutes(5));
                block.setReason(String.join("; ", reasons));
                ipBlockRepository.save(block);
                clearStrikes(normalizedIp);
            } else {
                status = "SUSPICIOUS";
                addStrike(normalizedIp, now);
                reasons.add("Strike recorded (block on repeated high-risk)");
            }
        } else if (riskScore >= 30) {
            status = "SUSPICIOUS";
            addStrike(normalizedIp, now);
        } else {
            status = "NORMAL";
            clearStrikes(normalizedIp);
        }

        log.setStatus(status);
        log.setAttackType(attackType);
        log.setRiskScore(riskScore);
        log.setReason(reasons.isEmpty() ? null : String.join("; ", reasons));
        log.setSuspicious(!"NORMAL".equals(status));
        applyMlPrediction(log);

        AUDIT.info("decision status={} attackType={} riskScore={} ip={} method={} path={} mlProb={} mlPred={} reason={}",
                log.getStatus(),
                log.getAttackType(),
                log.getRiskScore(),
                normalizedIp,
                log.getRequestMethod(),
                log.getRequestPath(),
                log.getMlIntrusionProbability(),
                log.isMlIntrusionPredicted(),
                log.getReason());
        return repository.save(log);
    }

    public List<SecurityLog> getAllLogs() {
        return repository.findAll();
    }

    public List<SecurityLog> getRecentLogs(int limit) {
        List<SecurityLog> recent = repository.findTop200ByOrderByTimestampDesc();
        if (limit <= 0 || limit >= recent.size()) return recent;
        return recent.subList(0, limit);
    }

    public List<IpBlock> getActiveBlocks() {
        return ipBlockRepository.findByBlockedUntilAfterOrderByBlockedUntilAsc(LocalDateTime.now());
    }

    public void unblockIp(String ip) {
        AUDIT.info("unblock ip={}", ip);
        ipBlockRepository.deleteBySourceIp(ip);
    }

    public Map<String, Object> getStats() {
        LocalDateTime now = LocalDateTime.now();
        Map<String, Object> stats = new HashMap<>();
        stats.put("suspicious", repository.countBySuspiciousTrue());
        stats.put("normal", repository.countBySuspiciousFalse());
        stats.put("recent_flagged", repository.findTop10BySuspiciousTrueOrderByTimestampDesc());
        stats.put("blocked", repository.countByStatus("BLOCKED"));
        stats.put("active_blocks", ipBlockRepository.countByBlockedUntilAfter(now));

        Map<String, Long> breakdown = new HashMap<>();
        for (Object[] row : repository.countByAttackType()) {
            if (row == null || row.length < 2) continue;
            String key = row[0] == null ? "NONE" : row[0].toString();
            long count = row[1] instanceof Number ? ((Number) row[1]).longValue() : 0L;
            breakdown.put(key, count);
        }
        stats.put("attack_type_breakdown", breakdown);
        return stats;
    }

    private void applyMlPrediction(SecurityLog log) {
        MlRandomForestService.Prediction pred = mlService.predict(log);
        log.setMlIntrusionProbability(pred.getProbability());
        log.setMlIntrusionPredicted(pred.isIntrusion());
    }

    private String decodeLenient(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return value;
        }
    }

    private StrikeState getStrikeState(String ip, LocalDateTime now) {
        StrikeState existing = strikeStates.get(ip);
        if (existing == null) return new StrikeState(0, now);
        if (existing.updatedAt.isBefore(now.minusMinutes(10))) return new StrikeState(0, now);
        return existing;
    }

    private void addStrike(String ip, LocalDateTime now) {
        if (ip == null || ip.isBlank() || "UNKNOWN".equals(ip)) return;
        strikeStates.compute(ip, (k, v) -> {
            if (v == null || v.updatedAt.isBefore(now.minusMinutes(10))) return new StrikeState(1, now);
            return new StrikeState(Math.min(v.strikes + 1, 5), now);
        });
    }

    private void clearStrikes(String ip) {
        if (ip == null || ip.isBlank() || "UNKNOWN".equals(ip)) return;
        strikeStates.remove(ip);
    }

    private static class StrikeState {
        private final int strikes;
        private final LocalDateTime updatedAt;

        private StrikeState(int strikes, LocalDateTime updatedAt) {
            this.strikes = strikes;
            this.updatedAt = updatedAt;
        }
    }
}
