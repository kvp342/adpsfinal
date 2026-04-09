package com.example.security.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "imported_dataset")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ImportedDataset {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    private String id;

    @Column(name = "profile", nullable = false, length = 32)
    private String profile;

    @Column(name = "original_file_name", nullable = false, length = 256)
    private String originalFileName;

    @Column(name = "stored_path", nullable = false, length = 512)
    private String storedPath;

    @Column(name = "uploaded_at", nullable = false)
    private LocalDateTime uploadedAt;

    @Column(name = "row_count", nullable = false)
    private long rowCount;

    @Column(name = "feature_count", nullable = false)
    private int featureCount;

    @Column(name = "label_column", length = 128)
    private String labelColumn;

    @Column(name = "normal_label", length = 64)
    private String normalLabel;
}

