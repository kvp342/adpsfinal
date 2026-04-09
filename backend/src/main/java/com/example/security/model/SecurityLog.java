package com.example.security.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Table(name = "security_log")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class SecurityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "source_ip", nullable = false)
    private String sourceIp;

    @Column(name = "request_method", nullable = false)
    private String requestMethod;

    @Column(name = "request_path")
    private String requestPath;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "request_timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "status", nullable = false)
    private String status;

    @Column(name = "attack_type")
    private String attackType;

    @Column(name = "reason")
    private String reason;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "ml_intrusion_probability", nullable = false)
    private double mlIntrusionProbability;

    @Column(name = "ml_intrusion_predicted", nullable = false)
    private boolean mlIntrusionPredicted;

    @Column(name = "is_suspicious")
    private boolean suspicious;

    public SecurityLog(String sourceIp, String requestMethod, LocalDateTime timestamp) {
        this.sourceIp = sourceIp;
        this.requestMethod = requestMethod;
        this.requestPath = "/";
        this.userAgent = null;
        this.timestamp = timestamp;
        this.status = "NORMAL";
        this.attackType = "NONE";
        this.reason = null;
        this.riskScore = 0;
        this.mlIntrusionProbability = 0.0;
        this.mlIntrusionPredicted = false;
        this.suspicious = false;
    }
}
