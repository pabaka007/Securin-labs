package com.securin.cve_assessment;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface CveRepository extends JpaRepository<Cve, String> {

    // Find CVE by ID
    Optional<Cve> findByCveId(String cveId);

    // Paginated list of all CVEs
    Page<Cve> findAll(Pageable pageable);

    // Find CVEs by year
    @Query("SELECT c FROM Cve c WHERE YEAR(c.publishedDate) = :year")
    Page<Cve> findByYear(@Param("year") int year, Pageable pageable);

    // Find CVEs by CVSS V3 score greater than or equal to threshold
    @Query("SELECT c FROM Cve c WHERE c.cvssV3Score >= :score OR c.cvssV2Score >= :score")
    Page<Cve> findByCvssScore(@Param("score") Double score, Pageable pageable);

    // Find CVEs modified in last N days
    @Query("SELECT c FROM Cve c WHERE c.lastModifiedDate >= :startDate ORDER BY c.lastModifiedDate DESC")
    Page<Cve> findByLastModifiedDate(@Param("startDate") LocalDateTime startDate, Pageable pageable);

    // Find CVEs by status
    Page<Cve> findByCveStatus(String status, Pageable pageable);

    // Count total CVEs
    long count();

    // Delete all CVEs (for batch refresh)
    void deleteAll();

    // Check if CVE exists
    boolean existsByCveId(String cveId);
}
