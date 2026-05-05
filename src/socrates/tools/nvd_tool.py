"""NVD (National Vulnerability Database) search tool for CrewAI.

Fetches CVE data from the NVD REST API v2.0.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

from typing import Any

import httpx
from crewai.tools import BaseTool

from socrates.config import NVD_API_KEY, NVD_BASE_URL


class NVDSearchTool(BaseTool):
    """Search the NVD database for CVE vulnerability information."""

    name: str = "nvd_cve_search"
    description: str = (
        "Search the National Vulnerability Database (NVD) for CVE information. "
        "Input should be a CVE ID (e.g., 'CVE-2024-3400') or a keyword to search for. "
        "Returns structured vulnerability data including CVSS scores, descriptions, "
        "affected products, and references."
    )

    def _run(self, query: str) -> str:
        """Fetch CVE data from NVD API."""
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        # Determine if query is a CVE ID or keyword
        params: dict[str, Any] = {}
        if query.upper().startswith("CVE-"):
            params["cveId"] = query.upper()
        else:
            params["keywordSearch"] = query
            params["resultsPerPage"] = 5

        try:
            response = httpx.get(
                NVD_BASE_URL,
                params=params,
                headers=headers,
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as e:
            return f"Error fetching from NVD API: {e}"

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return f"No CVE data found for query: {query}"

        results = []
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "Unknown")

            # Get description
            descriptions = cve.get("descriptions", [])
            desc = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                "No description available",
            )

            # Get CVSS score
            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            attack_vector = "N/A"

            for version_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics:
                    metric = metrics[version_key][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", metric.get("baseSeverity", "N/A"))
                    attack_vector = cvss_data.get("attackVector", "N/A")
                    break

            # Get affected configurations (CPE)
            configs = cve.get("configurations", [])
            affected = []
            for config in configs:
                for node in config.get("nodes", []):
                    for match in node.get("cpeMatch", []):
                        if match.get("vulnerable"):
                            affected.append(match.get("criteria", ""))

            # Get references
            refs = cve.get("references", [])
            ref_urls = [r.get("url", "") for r in refs[:5]]

            result = (
                f"## {cve_id}\n"
                f"**CVSS Score:** {cvss_score} ({severity})\n"
                f"**Attack Vector:** {attack_vector}\n"
                f"**Description:** {desc}\n"
                f"**Affected Systems:** {', '.join(affected[:5]) if affected else 'See references'}\n"
                f"**References:** {', '.join(ref_urls) if ref_urls else 'None'}\n"
            )
            results.append(result)

        return "\n---\n".join(results)
