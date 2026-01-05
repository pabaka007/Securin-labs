package com.securin.cve_assessment;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "cves")
public class Cve {

    @Id
    @Column(name = "cve_id")
    private String cveId;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "cvss_v2_score")
    private Double cvssV2Score;

    @Column(name = "cvss_v3_score")
    private Double cvssV3Score;

    @Column(name = "published_date")
    private LocalDateTime publishedDate;

    @Column(name = "last_modified_date")
    private LocalDateTime lastModifiedDate;

    @Column(name = "cve_status")
    private String cveStatus;

    @Column(name = "vector_string_v2")
    private String vectorStringV2;

    @Column(name = "vector_string_v3")
    private String vectorStringV3;

    // Constructors
    public Cve() {
    }

    public Cve(String cveId, String description, Double cvssV2Score, Double cvssV3Score,
               LocalDateTime publishedDate, LocalDateTime lastModifiedDate, String cveStatus) {
        this.cveId = cveId;
        this.description = description;
        this.cvssV2Score = cvssV2Score;
        this.cvssV3Score = cvssV3Score;
        this.publishedDate = publishedDate;
        this.lastModifiedDate = lastModifiedDate;
        this.cveStatus = cveStatus;
    }

    // Getters and Setters
    public String getCveId() {
        return cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Double getCvssV2Score() {
        return cvssV2Score;
    }

    public void setCvssV2Score(Double cvssV2Score) {
        this.cvssV2Score = cvssV2Score;
    }

    public Double getCvssV3Score() {
        return cvssV3Score;
    }

    public void setCvssV3Score(Double cvssV3Score) {
        this.cvssV3Score = cvssV3Score;
    }

    public LocalDateTime getPublishedDate() {
        return publishedDate;
    }

    public void setPublishedDate(LocalDateTime publishedDate) {
        this.publishedDate = publishedDate;
    }

    public LocalDateTime getLastModifiedDate() {
        return lastModifiedDate;
    }

    public void setLastModifiedDate(LocalDateTime lastModifiedDate) {
        this.lastModifiedDate = lastModifiedDate;
    }

    public String getCveStatus() {
        return cveStatus;
    }

    public void setCveStatus(String cveStatus) {
        this.cveStatus = cveStatus;
    }

    public String getVectorStringV2() {
        return vectorStringV2;
    }

    public void setVectorStringV2(String vectorStringV2) {
        this.vectorStringV2 = vectorStringV2;
    }

    public String getVectorStringV3() {
        return vectorStringV3;
    }

    public void setVectorStringV3(String vectorStringV3) {
        this.vectorStringV3 = vectorStringV3;
    }

    @Override
    public String toString() {
        return "Cve{" +
                "cveId='" + cveId + '\'' +
                ", description='" + description + '\'' +
                ", cvssV2Score=" + cvssV2Score +
                ", cvssV3Score=" + cvssV3Score +
                ", publishedDate=" + publishedDate +
                ", lastModifiedDate=" + lastModifiedDate +
                ", cveStatus='" + cveStatus + '\'' +
                '}';
    }
}
