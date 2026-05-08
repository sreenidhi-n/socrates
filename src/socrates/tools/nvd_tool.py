"""NVD (National Vulnerability Database) search tool for CrewAI.

Fetches CVE data from the NVD REST API v2.0.
Docs: https://nvd.nist.gov/developers/vulnerabilities
"""

import html
import re
import time
from typing import Any

import httpx
from crewai.tools import BaseTool

from socrates.config import NVD_API_KEY, NVD_BASE_URL

_VENDOR_DOMAINS = [
    "api.msrc.microsoft.com",       # MSRC JSON API — cleanest, structured
    "msrc.microsoft.com",
    "security.paloaltonetworks.com",
    "fortiguard.fortinet.com",
    "tools.cisco.com/security/center",
    "access.redhat.com/security",
    "vmware.com/security/advisories",
    "support.apple.com/en-us/HT",
]

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s{2,}")


def _html_to_text(raw: str) -> str:
    """Strip HTML tags and normalise whitespace — stdlib only."""
    text = _TAG_RE.sub(" ", raw)
    text = html.unescape(text)
    return _WS_RE.sub(" ", text).strip()


def _fetch_vendor_advisory(ref_urls: list[str]) -> str | None:
    """Fetch the first vendor advisory URL found in ref_urls.

    Returns up to 800 chars of plain text, or None on any failure.
    """
    for url in ref_urls:
        url_lower = url.lower()
        if not any(domain in url_lower for domain in _VENDOR_DOMAINS):
            continue

        # MSRC JSON API: swap /cvrf/ HTML page for the structured JSON endpoint
        if "api.msrc.microsoft.com" in url_lower or "msrc.microsoft.com/update-guide" in url_lower:
            # Try structured JSON if it looks like an MSRC advisory URL
            pass  # fall through to fetch as-is; MSRC HTML is still informative

        try:
            resp = httpx.get(url, timeout=8.0, follow_redirects=True, headers={"User-Agent": "SOCrates/1.0"})
            resp.raise_for_status()
            # Guard against huge pages — read first 200 KB only
            content = resp.text[:204_800]
            text = _html_to_text(content)
            if len(text) > 800:
                text = text[:797] + "..."
            return text if text else None
        except Exception:
            continue  # next URL

    return None

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_KEV_TTL = 3600  # seconds — refresh catalog every hour

_kev_cache: dict[str, dict] = {}
_kev_cache_ts: float = 0.0


def _get_kev_entry(cve_id: str) -> dict | None:
    """Return the CISA KEV entry for a CVE ID, or None if not in the catalog."""
    global _kev_cache, _kev_cache_ts
    now = time.time()
    if not _kev_cache or (now - _kev_cache_ts) > _KEV_TTL:
        try:
            resp = httpx.get(_KEV_URL, timeout=10.0)
            resp.raise_for_status()
            data = resp.json()
            _kev_cache = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
            _kev_cache_ts = now
        except Exception:
            pass  # fail silently — KEV enrichment is best-effort
    return _kev_cache.get(cve_id.upper())


class NVDSearchTool(BaseTool):
    """Search the NVD database for CVE vulnerability information."""

    name: str = "nvd_cve_search"
    description: str = (
        "Search the National Vulnerability Database (NVD) for CVE information. "
        "Input should be a CVE ID (e.g., 'CVE-2024-3400') or a keyword to search for. "
        "Returns structured vulnerability data including CVSS scores, descriptions, "
        "affected products, references, and CISA KEV status."
    )

    def _run(self, query: str) -> str:
        """Fetch CVE data from NVD API with CISA KEV enrichment."""
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
            cve_upper = query.upper()
            if cve_upper.startswith("CVE-"):
                return (
                    f"## {cve_upper} — No Data Available\n"
                    "**Status:** This CVE ID returned no results from the NVD. "
                    "Possible reasons:\n"
                    "- **Reserved/Embargoed:** The CVE has been reserved but not yet published "
                    "(common for CVEs < 48 hours old or under coordinated disclosure).\n"
                    "- **Rejected:** The CVE was rejected and will not receive an entry.\n"
                    "- **Typo:** Double-check the CVE ID format (e.g., CVE-2024-3400).\n\n"
                    "**Recommendation:** Check the vendor's security advisory directly, or "
                    "search the CISA KEV catalog and vendor bulletin boards for this identifier. "
                    "Proceed with analysis using any available contextual information."
                )
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

            # Get CVSS score — prefer v4 > v3.1 > v3.0 > v2
            metrics = cve.get("metrics", {})
            cvss_score = "N/A"
            severity = "N/A"
            attack_vector = "N/A"
            cvss_version = "N/A"
            supplemental = {}  # CVSSv4-only enrichment fields

            for version_key in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if version_key in metrics:
                    metric = metrics[version_key][0]
                    cvss_data = metric.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    severity = cvss_data.get("baseSeverity", metric.get("baseSeverity", "N/A"))
                    attack_vector = cvss_data.get("attackVector", "N/A")
                    cvss_version = cvss_data.get("version", version_key)
                    # CVSSv4 supplemental metrics — high-value threat intel signals
                    if version_key == "cvssMetricV40":
                        for field in ("exploitMaturity", "automatable", "providerUrgency", "recovery"):
                            val = cvss_data.get(field)
                            if val and val != "NOT_DEFINED":
                                supplemental[field] = val
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
            ref_urls = [r.get("url", "") for r in refs[:10]]  # wider scan for vendor domains

            # CISA KEV enrichment
            kev_str = ""
            kev_entry = _get_kev_entry(cve_id)
            if kev_entry:
                ransomware = kev_entry.get("knownRansomwareCampaignUse", "Unknown")
                date_added = kev_entry.get("dateAdded", "N/A")
                required_action = kev_entry.get("requiredAction", "N/A")
                kev_str = (
                    f"**⚠️ CISA KEV: ACTIVELY EXPLOITED IN THE WILD**\n"
                    f"**KEV Date Added:** {date_added} | "
                    f"**Ransomware Use:** {ransomware}\n"
                    f"**CISA Required Action:** {required_action}\n"
                )

            supplemental_str = ""
            if supplemental:
                parts = [f"{k}: {v}" for k, v in supplemental.items()]
                supplemental_str = f"**CVSSv4 Enrichment:** {' | '.join(parts)}\n"

            # Vendor advisory enrichment (best-effort, fail silently)
            advisory_str = ""
            advisory_text = _fetch_vendor_advisory(ref_urls)
            if advisory_text:
                advisory_str = f"**Vendor Advisory Excerpt:**\n> {advisory_text}\n"

            result = (
                f"## {cve_id}\n"
                f"{kev_str}"
                f"**CVSS {cvss_version} Score:** {cvss_score} ({severity})\n"
                f"**Attack Vector:** {attack_vector}\n"
                f"{supplemental_str}"
                f"**Description:** {desc}\n"
                f"**Affected Systems:** {', '.join(affected[:5]) if affected else 'See references'}\n"
                f"{advisory_str}"
                f"**References:** {', '.join(ref_urls[:5]) if ref_urls else 'None'}\n"
            )
            results.append(result)

        return "\n---\n".join(results)
