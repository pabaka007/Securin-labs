package com.securin.cve_assessment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashSet;
import java.util.Set;

@Service
public class CveService {

    @Autowired
    private CveRepository cveRepository;

    private static final String NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static final int RESULTS_PER_PAGE = 100;
    private static final DateTimeFormatter dateFormatter = DateTimeFormatter.ISO_DATE_TIME;

    /**
     * Fetch and store CVEs from NVD API to database
     * Implements pagination, deduplication, and data cleansing
     */
    public void fetchAndStoreCves(int startIndex, int maxResults) {
        RestTemplate restTemplate = new RestTemplate();
        ObjectMapper mapper = new ObjectMapper();
        Set<String> duplicateCheck = new HashSet<>();
        int processedCount = 0;

        try {
            int index = startIndex;
            while (processedCount < maxResults) {
                String url = String.format("%s?startIndex=%d&resultsPerPage=%d", 
                    NVD_API_URL, index, RESULTS_PER_PAGE);

                System.out.println("Fetching CVEs from: " + url);
                String response = restTemplate.getForObject(url, String.class);

                JsonNode rootNode = mapper.readTree(response);
                JsonNode vulnerabilities = rootNode.get("vulnerabilities");

                if (vulnerabilities == null || vulnerabilities.size() == 0) {
                    System.out.println("No more CVEs to fetch");
                    break;
                }

                // Process each CVE
                for (JsonNode item : vulnerabilities) {
                    try {
                        Cve cve = parseCveFromJson(item);
                        
                        // Deduplication check
                        if (duplicateCheck.contains(cve.getCveId())) {
                            System.out.println("Duplicate found: " + cve.getCveId() + ", skipping");
                            continue;
                        }

                        // Data quality check
                        if (isValidCve(cve)) {
                            // Save or update CVE
                            if (!cveRepository.existsByCveId(cve.getCveId())) {
                                cveRepository.save(cve);
                                duplicateCheck.add(cve.getCveId());
                                processedCount++;
                                System.out.println("Stored CVE: " + cve.getCveId());
                            }
                        }
                    } catch (Exception e) {
                        System.err.println("Error processing CVE: " + e.getMessage());
                    }
                }

                index += RESULTS_PER_PAGE;
            }

            System.out.println("Successfully processed " + processedCount + " CVEs");
        } catch (Exception e) {
            System.err.println("Error fetching CVEs: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Parse CVE from JSON node
     */
    private Cve parseCveFromJson(JsonNode item) {
        Cve cve = new Cve();

        // Extract CVE ID
        cve.setCveId(item.get("cve").get("id").asText());

        // Extract description
        JsonNode descriptions = item.get("cve").get("descriptions");
        if (descriptions != null && descriptions.isArray() && descriptions.size() > 0) {
            cve.setDescription(descriptions.get(0).get("value").asText());
        } else {
            cve.setDescription("No description available");
        }

        // Extract CVSS Scores
        JsonNode metrics = item.get("cve").get("metrics");
        if (metrics != null) {
            // CVSS V3 Score
            JsonNode cvssV3 = metrics.get("cvssV3");
            if (cvssV3 != null && cvssV3.isArray() && cvssV3.size() > 0) {
                try {
                    Double score = cvssV3.get(0).get("cvssData").get("baseScore").asDouble();
                    cve.setCvssV3Score(score);
                } catch (Exception e) {
                    cve.setCvssV3Score(null);
                }
            }

            // CVSS V2 Score
            JsonNode cvssV2 = metrics.get("cvssV2");
            if (cvssV2 != null && cvssV2.isArray() && cvssV2.size() > 0) {
                try {
                    Double score = cvssV2.get(0).get("cvssData").get("baseScore").asDouble();
                    cve.setCvssV2Score(score);
                } catch (Exception e) {
                    cve.setCvssV2Score(null);
                }
            }
        }

        // Extract published date
        String publishedStr = item.get("cve").get("published").asText();
        cve.setPublishedDate(parseDateTime(publishedStr));

        // Extract last modified date
        String lastModifiedStr = item.get("cve").get("lastModified").asText();
        cve.setLastModifiedDate(parseDateTime(lastModifiedStr));

        // Extract CVE status
        JsonNode sourceIdentifier = item.get("cve").get("sourceIdentifier");
        cve.setCveStatus("ANALYZED"); // Default status

        return cve;
    }

    /**
     * Parse ISO 8601 datetime string to LocalDateTime
     */
    private LocalDateTime parseDateTime(String dateString) {
        try {
            return LocalDateTime.parse(dateString, dateFormatter);
        } catch (Exception e) {
            System.err.println("Error parsing date: " + dateString);
            return LocalDateTime.now(ZoneOffset.UTC);
        }
    }

    /**
     * Validate CVE data quality
     */
    private boolean isValidCve(Cve cve) {
        // CVE ID is mandatory
        if (cve.getCveId() == null || cve.getCveId().trim().isEmpty()) {
            return false;
        }

        // Description should not be empty
        if (cve.getDescription() == null || cve.getDescription().trim().isEmpty()) {
            return false;
        }

        // At least one CVSS score should be present
        if (cve.getCvssV2Score() == null && cve.getCvssV3Score() == null) {
            return true; // Some CVEs may not have scores, but we'll store them
        }

        return true;
    }

    /**
     * Get total CVE count
     */
    public long getTotalCveCount() {
        return cveRepository.count();
    }

    /**
     * Clear all CVEs from database (for full refresh)
     */
    public void deleteAllCves() {
        cveRepository.deleteAll();
        System.out.println("All CVEs cleared from database");
    }
}
