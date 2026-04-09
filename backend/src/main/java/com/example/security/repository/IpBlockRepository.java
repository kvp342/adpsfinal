package com.example.security.repository;

import com.example.security.model.IpBlock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface IpBlockRepository extends JpaRepository<IpBlock, Long> {
    Optional<IpBlock> findBySourceIp(String sourceIp);
    List<IpBlock> findByBlockedUntilAfterOrderByBlockedUntilAsc(LocalDateTime now);
    long countByBlockedUntilAfter(LocalDateTime now);
    void deleteBySourceIp(String sourceIp);
}
