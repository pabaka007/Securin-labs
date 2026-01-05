package com.securin.cve_assessment;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class CveUiController {

    /**
     * Serve CVE list page
     */
    @GetMapping("/cves/list")
    public String getCveListPage() {
        return "cves-list";
    }

    /**
     * Serve CVE detail page - different path to avoid conflict with API
     * The view page will use JavaScript to fetch from /api/cves/{cveId}
     */
    @GetMapping("/view/cve/{cveId}")
    public String getCveDetailPage(@PathVariable String cveId) {
        return "cve-detail";
    }

    /**
     * Home page
     */
    @GetMapping("/")
    public String home() {
        return "index";
    }
}
