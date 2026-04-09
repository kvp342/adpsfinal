package com.example.security.controller;

import com.example.security.service.DatasetWekaService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/ml/dataset")
public class DatasetMlController {

    private final DatasetWekaService datasetWekaService;

    public DatasetMlController(DatasetWekaService datasetWekaService) {
        this.datasetWekaService = datasetWekaService;
    }

    @GetMapping("/status")
    public DatasetWekaService.Status status() {
        return datasetWekaService.status();
    }

    @PostMapping("/train")
    public ResponseEntity<DatasetWekaService.Status> train(
            @RequestParam("datasetId") String datasetId,
            @RequestParam(value = "model", defaultValue = "RANDOM_FOREST") String model,
            @RequestParam(value = "maxRows", defaultValue = "50000") int maxRows
    ) {
        try {
            return ResponseEntity.ok(datasetWekaService.startTraining(datasetId, model, maxRows));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/evaluate")
    public ResponseEntity<DatasetWekaService.EvaluationResult> evaluateGet(
            @RequestParam("datasetId") String datasetId,
            @RequestParam(value = "model", defaultValue = "RANDOM_FOREST") String model,
            @RequestParam(value = "maxRows", defaultValue = "50000") int maxRows,
            @RequestParam(value = "samples", defaultValue = "10") int samples,
            @RequestParam(value = "folds", defaultValue = "5") int folds
    ) {
        try {
            return ResponseEntity.ok(datasetWekaService.evaluate(datasetId, model, maxRows, samples, folds));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/evaluate")
    public ResponseEntity<DatasetWekaService.EvaluationResult> evaluatePost(
            @RequestParam("datasetId") String datasetId,
            @RequestParam(value = "model", defaultValue = "RANDOM_FOREST") String model,
            @RequestParam(value = "maxRows", defaultValue = "50000") int maxRows,
            @RequestParam(value = "samples", defaultValue = "10") int samples,
            @RequestParam(value = "folds", defaultValue = "5") int folds
    ) {
        try {
            return ResponseEntity.ok(datasetWekaService.evaluate(datasetId, model, maxRows, samples, folds));
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }
}
