package com.securin.cve_assessment;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
public class CveController {

    @Autowired
    private CveRepository cveRepository;

    @Autowired
    private CveService cveService;

    @GetMapping("/hello")
    public String hello() {
        return "CVE Assessment API is running";
    }
    @GetMapping("/cves/all")
public String getAllCves() {
    String url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10";
    RestTemplate restTemplate = new RestTemplate();
    return restTemplate.getForObject(url, String.class);
}

@GetMapping("/cves/fetch")
public List<Map<String, String>> fetchCves() throws Exception {

    String nvdUrl =
            "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5";

    RestTemplate restTemplate = new RestTemplate();
    String response = restTemplate.getForObject(nvdUrl, String.class);

    ObjectMapper mapper = new ObjectMapper();
    JsonNode rootNode = mapper.readTree(response);
    JsonNode vulnerabilities = rootNode.get("vulnerabilities");

    List<Map<String, String>> cveList = new ArrayList<>();

    if (vulnerabilities != null && vulnerabilities.isArray()) {
        for (JsonNode item : vulnerabilities) {
            Map<String, String> cveData = new HashMap<>();
            
            // Extract CVE ID
            String cveId = item.get("cve").get("id").asText();
            cveData.put("id", cveId);
            
            // Extract description
            JsonNode descriptions = item.get("cve").get("descriptions");
            String description = "";
            if (descriptions != null && descriptions.isArray() && descriptions.size() > 0) {
                description = descriptions.get(0).get("value").asText();
            }
            cveData.put("description", description);
            
            // Extract CVSS score if available
            JsonNode metrics = item.get("cve").get("metrics");
            String cvssScore = "N/A";
            if (metrics != null) {
                JsonNode cvssV3 = metrics.get("cvssV3");
                if (cvssV3 != null && cvssV3.isArray() && cvssV3.size() > 0) {
                    cvssScore = cvssV3.get(0).get("cvssData").get("baseScore").asText();
                }
            }
            cveData.put("cvssScore", cvssScore);
            
            // Extract last modified date
            String lastModified = item.get("cve").get("lastModified").asText();
            cveData.put("lastModified", lastModified);
            
            cveList.add(cveData);
        }
    }

    return cveList;
}


    @GetMapping("/cves/ids")
    public List<String> getCveIds() throws Exception {

        String nvdUrl =
                "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=5";

        RestTemplate restTemplate = new RestTemplate();
        String response = restTemplate.getForObject(nvdUrl, String.class);

        ObjectMapper mapper = new ObjectMapper();
        JsonNode rootNode = mapper.readTree(response);
        JsonNode vulnerabilities = rootNode.get("vulnerabilities");

        List<String> cveIds = new ArrayList<>();

        for (JsonNode item : vulnerabilities) {
            cveIds.add(item.get("cve").get("id").asText());
        }

        return cveIds;
    }

    // ========== NEW ENDPOINTS FOR DATABASE ==========

    /**
     * Get paginated list of CVEs from database
     * @param page Page number (0-indexed)
     * @param size Results per page (10, 50, 100)
     * @return Page of CVEs with pagination metadata
     */
    @GetMapping("/api/cves/list")
    public Map<String, Object> getCvesList(@RequestParam(defaultValue = "0") int page,
                                           @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Cve> cves = cveRepository.findAll(pageable);
        
        Map<String, Object> response = new HashMap<>();
        response.put("totalRecords", cves.getTotalElements());
        response.put("totalPages", cves.getTotalPages());
        response.put("currentPage", page);
        response.put("pageSize", size);
        response.put("cves", cves.getContent());
        
        return response;
    }

    /**
     * Get single CVE by ID from database
     * @param cveId CVE ID (e.g., CVE-2021-12345)
     * @return CVE details
     */
    @GetMapping("/cves/{cveId}")
    public Map<String, Object> getCveById(@PathVariable String cveId) {
        Optional<Cve> cve = cveRepository.findByCveId(cveId);
        
        Map<String, Object> response = new HashMap<>();
        if (cve.isPresent()) {
            response.put("found", true);
            response.put("cve", cve.get());
        } else {
            response.put("found", false);
            response.put("message", "CVE not found: " + cveId);
        }
        
        return response;
    }

    /**
     * Filter CVEs by year
     * @param year Published year
     * @param page Page number
     * @param size Results per page
     * @return Paginated CVEs from specified year
     */
    @GetMapping("/api/cves/filter/year/{year}")
    public Map<String, Object> getCvesByYear(@PathVariable int year,
                                             @RequestParam(defaultValue = "0") int page,
                                             @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Cve> cves = cveRepository.findByYear(year, pageable);
        
        Map<String, Object> response = new HashMap<>();
        response.put("totalRecords", cves.getTotalElements());
        response.put("year", year);
        response.put("currentPage", page);
        response.put("cves", cves.getContent());
        
        return response;
    }

    /**
     * Filter CVEs by CVSS score (V3 or V2)
     * @param score Minimum CVSS score
     * @param page Page number
     * @param size Results per page
     * @return Paginated CVEs with score >= specified threshold
     */
    @GetMapping("/api/cves/filter/score/{score}")
    public Map<String, Object> getCvesByScore(@PathVariable Double score,
                                              @RequestParam(defaultValue = "0") int page,
                                              @RequestParam(defaultValue = "10") int size) {
        Pageable pageable = PageRequest.of(page, size);
        Page<Cve> cves = cveRepository.findByCvssScore(score, pageable);
        
        Map<String, Object> response = new HashMap<>();
        response.put("totalRecords", cves.getTotalElements());
        response.put("minimumScore", score);
        response.put("currentPage", page);
        response.put("cves", cves.getContent());
        
        return response;
    }

    /**
     * Filter CVEs modified in last N days
     * @param days Number of days
     * @param page Page number
     * @param size Results per page
     * @return Paginated CVEs modified in last N days
     */
    @GetMapping("/api/cves/filter/modified/{days}")
    public Map<String, Object> getCvesModifiedInDays(@PathVariable int days,
                                                     @RequestParam(defaultValue = "0") int page,
                                                     @RequestParam(defaultValue = "10") int size) {
        LocalDateTime startDate = LocalDateTime.now(ZoneOffset.UTC).minusDays(days);
        Pageable pageable = PageRequest.of(page, size);
        Page<Cve> cves = cveRepository.findByLastModifiedDate(startDate, pageable);
        
        Map<String, Object> response = new HashMap<>();
        response.put("totalRecords", cves.getTotalElements());
        response.put("daysBack", days);
        response.put("currentPage", page);
        response.put("cves", cves.getContent());
        
        return response;
    }

    /**
     * Get total CVE count in database
     * @return Total count
     */
    @GetMapping("/api/cves/count")
    public Map<String, Object> getCveCount() {
        Map<String, Object> response = new HashMap<>();
        response.put("totalCves", cveRepository.count());
        return response;
    }

    /**
     * Trigger fetching and storing CVEs from NVD API to database
     * @param startIndex Starting index for pagination
     * @param maxResults Maximum CVEs to fetch
     * @return Status message
     */
    @GetMapping("/api/cves/sync")
    public Map<String, Object> syncCves(@RequestParam(defaultValue = "0") int startIndex,
                                        @RequestParam(defaultValue = "100") int maxResults) {
        Map<String, Object> response = new HashMap<>();
        try {
            cveService.fetchAndStoreCves(startIndex, maxResults);
            response.put("status", "success");
            response.put("message", "CVE sync completed");
            response.put("totalCvesInDb", cveRepository.count());
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }

    /**
     * Clear all CVEs and perform fresh sync
     * @param maxResults Maximum CVEs to fetch in fresh sync
     * @return Status message
     */
    @GetMapping("/api/cves/sync-fresh")
    public Map<String, Object> freshSync(@RequestParam(defaultValue = "500") int maxResults) {
        Map<String, Object> response = new HashMap<>();
        try {
            cveService.deleteAllCves();
            cveService.fetchAndStoreCves(0, maxResults);
            response.put("status", "success");
            response.put("message", "Fresh sync completed");
            response.put("totalCvesInDb", cveRepository.count());
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }
}
