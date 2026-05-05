"""MITRE ATT&CK lookup tool for CrewAI.

Provides technique lookups from a local subset of the ATT&CK framework.
Uses a curated JSON of common techniques to avoid loading the full STIX bundle.
"""

import json
import os

from crewai.tools import BaseTool

from socrates.config import MITRE_DATA_PATH


class MITRELookupTool(BaseTool):
    """Look up MITRE ATT&CK techniques by keyword or technique ID."""

    name: str = "mitre_attack_lookup"
    description: str = (
        "Search MITRE ATT&CK techniques by keyword or technique ID (e.g., 'T1190' or 'initial access'). "
        "Returns technique details including tactic, description, and detection guidance. "
        "Use this to map attack steps to the ATT&CK framework."
    )

    def _run(self, query: str) -> str:
        """Look up MITRE ATT&CK techniques."""
        if not os.path.exists(MITRE_DATA_PATH):
            return (
                "MITRE ATT&CK data not found. Using built-in knowledge to map techniques. "
                "Please ensure attack.json is in the data directory."
            )

        with open(MITRE_DATA_PATH) as f:
            techniques = json.load(f)

        query_lower = query.lower()
        matches = []

        for tech in techniques:
            tech_id = tech.get("id", "").lower()
            name = tech.get("name", "").lower()
            tactic = tech.get("tactic", "").lower()
            description = tech.get("description", "").lower()

            if (
                query_lower in tech_id
                or query_lower in name
                or query_lower in tactic
                or query_lower in description
            ):
                matches.append(tech)

        if not matches:
            return f"No MITRE ATT&CK techniques found for: {query}. Try a broader search term."

        results = []
        for tech in matches[:10]:
            result = (
                f"**{tech.get('id', 'N/A')} — {tech.get('name', 'Unknown')}**\n"
                f"  Tactic: {tech.get('tactic', 'N/A')}\n"
                f"  Description: {tech.get('description', 'N/A')}\n"
                f"  Detection: {tech.get('detection', 'N/A')}\n"
            )
            results.append(result)

        return "\n".join(results)
