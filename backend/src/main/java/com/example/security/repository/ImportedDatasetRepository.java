package com.example.security.repository;

import com.example.security.model.ImportedDataset;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ImportedDatasetRepository extends JpaRepository<ImportedDataset, String> {
}

