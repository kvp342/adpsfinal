package com.example.security.repository;

import com.example.security.model.SecurityLog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {

    // Count recent requests from an IP
    long countBySourceIpAndTimestampAfter(String sourceIp, LocalDateTime timestamp);

    // Get logs for stats
    long countBySuspiciousTrue();
    long countBySuspiciousFalse();
    long countByStatus(String status);

    // Get recent suspicious logs for table
    List<SecurityLog> findTop10BySuspiciousTrueOrderByTimestampDesc();

    List<SecurityLog> findTop200ByOrderByTimestampDesc();

    @Query("select coalesce(l.attackType, 'NONE') as attackType, count(l) as cnt from SecurityLog l group by coalesce(l.attackType, 'NONE')")
    List<Object[]> countByAttackType();
}
