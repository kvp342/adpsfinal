package com.example.security.controller;

import com.example.security.model.SecurityLog;
import com.example.security.repository.SecurityLogRepository;
import com.example.security.service.MlRandomForestService;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ml")
public class MlController {
    private final MlRandomForestService mlService;
    private final SecurityLogRepository logRepository;

    public MlController(MlRandomForestService mlService, SecurityLogRepository logRepository) {
        this.mlService = mlService;
        this.logRepository = logRepository;
    }

    @GetMapping("/status")
    public MlRandomForestService.Status status() {
        return mlService.status();
    }

    @PostMapping("/train")
    public ResponseEntity<Map<String, Object>> train(
            @RequestParam(value = "limit", defaultValue = "2000") int limit,
            @RequestParam(value = "model", defaultValue = "RANDOM_FOREST") String model
    ) {
        int safeLimit = Math.min(Math.max(limit, 50), 20000);
        List<SecurityLog> logs = logRepository.findAll(PageRequest.of(0, safeLimit, Sort.by(Sort.Direction.DESC, "timestamp"))).getContent();
        try {
            MlRandomForestService.TrainResult res = mlService.train(logs, model);
            Map<String, Object> out = new HashMap<>();
            out.put("trained", res.isTrained());
            out.put("samples", res.getSamples());
            out.put("holdoutAccuracy", res.getHoldoutAccuracy());
            out.put("modelType", mlService.status().getModelType());
            return ResponseEntity.ok(out);
        } catch (Exception e) {
            Map<String, Object> out = new HashMap<>();
            out.put("trained", false);
            out.put("error", e.getMessage());
            return ResponseEntity.internalServerError().body(out);
        }
    }

    @GetMapping("/explain")
    public ResponseEntity<MlRandomForestService.Explanation> explain(
            @RequestParam("logId") long logId,
            @RequestParam(value = "topK", defaultValue = "8") int topK
    ) {
        SecurityLog log = logRepository.findById(logId).orElse(null);
        if (log == null) return ResponseEntity.notFound().build();
        MlRandomForestService.Explanation exp = mlService.explain(log, topK);
        if (exp == null) return ResponseEntity.badRequest().build();
        return ResponseEntity.ok(exp);
    }
}
