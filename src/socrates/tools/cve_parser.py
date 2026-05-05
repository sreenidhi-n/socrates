"""CVE data parser and structuring utilities."""

import re


def extract_cve_id(text: str) -> str | None:
    """Extract a CVE ID from text (e.g., CVE-2024-3400)."""
    match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def format_cvss_severity(score: float) -> str:
    """Convert a CVSS score to a human-readable severity label."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    return "NONE"
