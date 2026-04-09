package com.example.security.service;

import com.example.security.model.ImportedDataset;
import com.example.security.repository.ImportedDatasetRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class DatasetImportService {

    private final ImportedDatasetRepository importedDatasetRepository;

    public DatasetImportService(ImportedDatasetRepository importedDatasetRepository) {
        this.importedDatasetRepository = importedDatasetRepository;
    }

    public ImportedDataset importDataset(MultipartFile file, DatasetProfile profile) throws Exception {
        if (file == null || file.isEmpty()) throw new IllegalArgumentException("file is required");
        if (profile == null) throw new IllegalArgumentException("profile is required");

        String id = UUID.randomUUID().toString().replace("-", "");
        String originalName = safeName(file.getOriginalFilename());
        Path baseDir = Paths.get("data", "uploads");
        Files.createDirectories(baseDir);
        Path target = baseDir.resolve(id + "_" + originalName);
        Files.copy(file.getInputStream(), target);

        DatasetMeta meta = sniffMeta(target, profile);
        ImportedDataset ds = new ImportedDataset(
                id,
                profile.name(),
                originalName,
                target.toAbsolutePath().toString(),
                LocalDateTime.now(),
                meta.rowCount,
                meta.featureCount,
                meta.labelColumn,
                meta.normalLabel
        );
        return importedDatasetRepository.save(ds);
    }

    private DatasetMeta sniffMeta(Path path, DatasetProfile profile) throws Exception {
        long rows = 0;
        int featureCount = 0;
        String labelColumn = null;
        String normalLabel = null;

        try (BufferedReader br = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String first = br.readLine();
            if (first == null) return new DatasetMeta(0, 0, null, null);
            if (profile == DatasetProfile.CICIDS2017) {
                List<String> header = CsvUtils.parseLine(first);
                int labelIdx = findLabelIndex(header);
                labelColumn = labelIdx >= 0 ? header.get(labelIdx) : "Label";
                normalLabel = "BENIGN";
                while (br.readLine() != null) rows++;
                featureCount = Math.max(header.size() - 1, 0);
            } else {
                List<String> cols = CsvUtils.parseLine(first);
                featureCount = Math.max(cols.size() - 1, 0);
                normalLabel = "normal";
                rows = 1;
                while (br.readLine() != null) rows++;
            }
        }
        return new DatasetMeta(rows, featureCount, labelColumn, normalLabel);
    }

    private int findLabelIndex(List<String> header) {
        if (header == null) return -1;
        for (int i = 0; i < header.size(); i++) {
            String h = header.get(i);
            if (h == null) continue;
            String k = h.trim().toLowerCase(Locale.ROOT);
            if (k.equals("label") || k.equals("class") || k.equals("attack") || k.equals("target")) return i;
        }
        return -1;
    }

    private String safeName(String name) {
        if (name == null || name.isBlank()) return "dataset.csv";
        return name.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private static final class DatasetMeta {
        final long rowCount;
        final int featureCount;
        final String labelColumn;
        final String normalLabel;

        DatasetMeta(long rowCount, int featureCount, String labelColumn, String normalLabel) {
            this.rowCount = rowCount;
            this.featureCount = featureCount;
            this.labelColumn = labelColumn;
            this.normalLabel = normalLabel;
        }
    }
}

