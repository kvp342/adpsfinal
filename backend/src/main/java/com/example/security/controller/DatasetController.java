package com.example.security.controller;

import com.example.security.model.ImportedDataset;
import com.example.security.repository.ImportedDatasetRepository;
import com.example.security.service.DatasetImportService;
import com.example.security.service.DatasetProfile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/datasets")
public class DatasetController {

    private final DatasetImportService datasetImportService;
    private final ImportedDatasetRepository importedDatasetRepository;

    public DatasetController(DatasetImportService datasetImportService, ImportedDatasetRepository importedDatasetRepository) {
        this.datasetImportService = datasetImportService;
        this.importedDatasetRepository = importedDatasetRepository;
    }

    @GetMapping
    public List<ImportedDataset> list() {
        return importedDatasetRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<ImportedDataset> get(@PathVariable("id") String id) {
        return importedDatasetRepository.findById(id).map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/upload")
    public ResponseEntity<ImportedDataset> upload(
            @RequestParam("file") MultipartFile file,
            @RequestParam("profile") String profile
    ) {
        try {
            DatasetProfile p = DatasetProfile.valueOf(profile);
            ImportedDataset ds = datasetImportService.importDataset(file, p);
            return ResponseEntity.ok(ds);
        } catch (Exception e) {
            return ResponseEntity.badRequest().build();
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable("id") String id) {
        if (!importedDatasetRepository.existsById(id)) return ResponseEntity.notFound().build();
        importedDatasetRepository.deleteById(id);
        return ResponseEntity.ok(Map.of("deleted", true));
    }
}
